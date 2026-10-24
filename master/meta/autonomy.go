package meta

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"atoll/pkg/transferbudget"
	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

var (
	keyProfileRevision    = []byte("autonomy_profile_revision")
	ErrProtectionConflict = errors.New("protection plan conflicts with current state")
	ErrProtectionBudget   = errors.New("insufficient protection capacity budget")
)

func autonomyKey(kind, id string) []byte { return []byte(kind + "/" + id) }

func readAutonomy(tx *bolt.Tx, kind, id string, out any) error {
	raw := tx.Bucket(bucketAutonomy).Get(autonomyKey(kind, id))
	if raw == nil {
		return ErrNotExist
	}
	return json.Unmarshal(raw, out)
}

func putAutonomy(w *txw, kind, id string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return w.put(bcAutonomy, bucketAutonomy, autonomyKey(kind, id), raw)
}

func walkAutonomy(tx *bolt.Tx, kind string, visit func([]byte) error) error {
	prefix := []byte(kind + "/")
	cursor := tx.Bucket(bucketAutonomy).Cursor()
	for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
		if err := visit(v); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) RecordNodeSample(nodeID uint64, sample NodeSample) error {
	if nodeID == 0 || sample.At.IsZero() || sample.UsedBytes < 0 || sample.TotalBytes < 0 ||
		sample.RTTMillis < 0 || math.IsInf(sample.RTTMillis, 0) || math.IsNaN(sample.RTTMillis) {
		return errors.New("invalid node observation")
	}
	// Liveness history survives local restart/snapshot but does not amplify the synchronous WAL.
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketNodes).Get(u64be(nodeID)) == nil {
			return ErrNotExist
		}
		var history NodeObservation
		if err := readAutonomy(tx, "observation", fmt.Sprint(nodeID), &history); err != nil && !errors.Is(err, ErrNotExist) {
			return err
		}
		history.NodeID = nodeID
		if len(history.Samples) > 0 {
			last := &history.Samples[len(history.Samples)-1]
			if sample.At.Before(last.At) {
				return errors.New("observation time moved backwards")
			}
			if sample.At.Equal(last.At) {
				*last = sample
			} else {
				history.Samples = append(history.Samples, sample)
			}
		} else {
			history.Samples = []NodeSample{sample}
		}
		if len(history.Samples) > MaxObservationSamples {
			history.Samples = history.Samples[len(history.Samples)-MaxObservationSamples:]
		}
		raw, err := json.Marshal(history)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketAutonomy).Put(autonomyKey("observation", fmt.Sprint(nodeID)), raw)
	})
}

func (s *Store) SetNodePlacementProfile(profile NodePlacementProfile) error {
	if profile.NodeID == 0 || profile.HeadroomBytes < 0 || len(profile.FailureDomains) > 16 ||
		profile.UploadBPS > transferbudget.MaxRate || profile.DownloadBPS > transferbudget.MaxRate ||
		profile.MaxTransferConcurrency < 0 || profile.MaxTransferConcurrency > 32 {
		return errors.New("invalid node placement profile")
	}
	for key, value := range profile.FailureDomains {
		if key == "" || value == "" || len(key) > 64 || len(value) > 128 {
			return errors.New("invalid failure domain")
		}
	}
	return s.write(func(w *txw) error {
		if w.tx.Bucket(bucketNodes).Get(u64be(profile.NodeID)) == nil {
			return ErrNotExist
		}
		if err := putAutonomy(w, "profile", fmt.Sprint(profile.NodeID), profile); err != nil {
			return err
		}
		revision := profileRevisionTx(w.tx)
		if revision == math.MaxUint64 {
			return ErrProtectionConflict
		}
		return w.put(bcMeta, bucketMeta, keyProfileRevision, u64be(revision+1))
	})
}

func liveObjectsTx(tx *bolt.Tx) ([]types.ObjectIntegrity, error) {
	var objects []types.ObjectIntegrity
	err := tx.Bucket(bucketInodes).ForEach(func(_, raw []byte) error {
		var in types.Inode
		if err := json.Unmarshal(raw, &in); err != nil {
			return err
		}
		if in.Type != types.TypeFile || in.Staging || in.Size <= 0 {
			return nil
		}
		if in.Chunked {
			for _, ch := range in.Chunks {
				if d, ok := describeInodeObject(in, types.ChunkObjID(ch, in.ID)); ok {
					objects = append(objects, d)
				}
			}
		} else if d, ok := describeInodeObject(in, types.ObjIDFor(in)); ok {
			objects = append(objects, d)
		}
		return nil
	})
	return objects, err
}

func checkedBytesAdd(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, ErrProtectionBudget
	}
	return a + b, nil
}

func capacitiesTx(tx *bolt.Tx) ([]NodeCapacity, error) {
	writeReservations, err := capacityReservationsTx(tx)
	if err != nil {
		return nil, err
	}
	allocated := map[uint64]int64{}
	seen := map[[2]uint64]bool{}
	addObject := func(id uint64, size int64, replicas []uint64) error {
		for _, nodeID := range replicas {
			retired, err := retirementConfirmedTx(tx, id, nodeID)
			if err != nil {
				return err
			}
			if retired {
				continue
			}
			key := [2]uint64{id, nodeID}
			if _, pending := writeReservations[key]; pending {
				continue
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			value, err := checkedBytesAdd(allocated[nodeID], size)
			if err != nil {
				return err
			}
			allocated[nodeID] = value
		}
		return nil
	}
	if err := tx.Bucket(bucketInodes).ForEach(func(_, raw []byte) error {
		var in types.Inode
		if err := json.Unmarshal(raw, &in); err != nil {
			return err
		}
		if in.Type != types.TypeFile {
			return nil
		}
		if in.Chunked {
			for _, ch := range in.Chunks {
				if err := addObject(types.ChunkObjID(ch, in.ID), ch.Size, ch.Replicas); err != nil {
					return err
				}
			}
			return nil
		}
		return addObject(types.ObjIDFor(in), in.Size, in.Replicas)
	}); err != nil {
		return nil, err
	}
	if err := tx.Bucket(bucketObjects).ForEach(func(_, raw []byte) error {
		var obj ObjectRecord
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		// Pending and retired data remain charged until their registry records disappear.
		return addObject(obj.ID, obj.Size, obj.Replicas)
	}); err != nil {
		return nil, err
	}
	if err := tx.Bucket(bucketRetired).ForEach(func(key, raw []byte) error {
		rec, err := decodeRetirementRecord(key, raw)
		if err != nil {
			return err
		}
		if rec.State == RetirementConfirmed {
			return nil
		}
		return addObject(rec.ObjectID, rec.Expected.Size, []uint64{rec.NodeID})
	}); err != nil {
		return nil, err
	}
	reserved := map[uint64]int64{}
	for key, size := range writeReservations {
		value, err := checkedBytesAdd(reserved[key[1]], size)
		if err != nil {
			return nil, err
		}
		reserved[key[1]] = value
	}
	var out []NodeCapacity
	err = tx.Bucket(bucketNodes).ForEach(func(_, raw []byte) error {
		var node types.NodeInfo
		if err := json.Unmarshal(raw, &node); err != nil {
			return err
		}
		if node.TotalBytes < 0 || node.UsedBytes < 0 || node.UsageFloorBytes < 0 {
			return ErrProtectionBudget
		}
		var profile NodePlacementProfile
		if err := readAutonomy(tx, "profile", fmt.Sprint(node.ID), &profile); err != nil && !errors.Is(err, ErrNotExist) {
			return err
		}
		c := NodeCapacity{NodeID: node.ID, Capacity: node.TotalBytes, Accounted: max(max(node.UsedBytes, node.UsageFloorBytes), allocated[node.ID]),
			Reserved: reserved[node.ID], Headroom: profile.HeadroomBytes}
		used, err := checkedBytesAdd(c.Accounted, c.Reserved)
		if err != nil {
			return err
		}
		used, err = checkedBytesAdd(used, c.Headroom)
		if err != nil {
			return err
		}
		c.Free = max(int64(0), c.Capacity-used)
		out = append(out, c)
		return nil
	})
	return out, err
}

func profileRevisionTx(tx *bolt.Tx) uint64 {
	if raw := tx.Bucket(bucketMeta).Get(keyProfileRevision); raw != nil {
		return beU64(raw)
	}
	return 0
}

func (s *Store) AutonomySnapshot() (AutonomySnapshot, error) {
	var result AutonomySnapshot
	err := s.db.View(func(tx *bolt.Tx) error {
		result.ProfileRevision = profileRevisionTx(tx)
		var cursor autonomyScanCursor
		if err := readAutonomy(tx, "cursor", "planning", &cursor); err != nil && !errors.Is(err, ErrNotExist) {
			return err
		}
		result.ScanAfter = cursor.After
		if err := tx.Bucket(bucketNodes).ForEach(func(_, raw []byte) error {
			var node types.NodeInfo
			if err := json.Unmarshal(raw, &node); err != nil {
				return err
			}
			result.Nodes = append(result.Nodes, node)
			return nil
		}); err != nil {
			return err
		}
		for _, kind := range []string{"profile", "observation", "plan"} {
			if err := walkAutonomy(tx, kind, func(raw []byte) error {
				switch kind {
				case "profile":
					var value NodePlacementProfile
					if err := json.Unmarshal(raw, &value); err != nil {
						return err
					}
					result.Profiles = append(result.Profiles, value)
				case "observation":
					var value NodeObservation
					if err := json.Unmarshal(raw, &value); err != nil {
						return err
					}
					result.Observations = append(result.Observations, value)
				case "plan":
					var value ProtectionPlan
					if err := json.Unmarshal(raw, &value); err != nil {
						return err
					}
					result.Plans = append(result.Plans, value)
				}
				return nil
			}); err != nil {
				return err
			}
		}
		var err error
		result.Objects, err = liveObjectsTx(tx)
		if err != nil {
			return err
		}
		result.Capacity, err = capacitiesTx(tx)
		return err
	})
	return result, err
}

func planTx(tx *bolt.Tx, id string) (ProtectionPlan, error) {
	var plan ProtectionPlan
	err := readAutonomy(tx, "plan", id, &plan)
	return plan, err
}

func exactProtectionIdentity(a, b types.ObjectIntegrity) bool {
	return sameObjectContents(a, b) && a.InodeID == b.InodeID && a.Generation == b.Generation && a.IntegrityEpoch == b.IntegrityEpoch
}

func (s *Store) ReserveProtection(req ProtectionRequest, now time.Time) (ProtectionPlan, error) {
	if len(req.ID) == 0 || len(req.ID) > 128 || strings.ContainsAny(req.ID, "/\\\x00") ||
		req.Expected.PlanID != "" || !req.Expected.ChecksumKnown || req.Expected.Size <= 0 ||
		len(req.Targets) == 0 || len(req.Targets) > 32 || req.MaxBytes <= 0 || req.NodeMaxAge <= 0 || now.IsZero() {
		return ProtectionPlan{}, errors.New("invalid protection reservation")
	}
	if req.Expected.Size > req.MaxBytes/int64(len(req.Targets)) {
		return ProtectionPlan{}, ErrProtectionBudget
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return ProtectionPlan{}, err
	}
	inputHash := fmt.Sprintf("%x", sha256.Sum256(raw))
	var out ProtectionPlan
	err = s.write(func(w *txw) error {
		if prior, err := planTx(w.tx, req.ID); err == nil {
			if prior.InputHash != inputHash {
				return ErrProtectionConflict
			}
			out = prior
			return nil
		} else if !errors.Is(err, ErrNotExist) {
			return err
		}
		if profileRevisionTx(w.tx) != req.ProfileRevision {
			return ErrProtectionConflict
		}
		current, err := integrityTx(w.tx, req.Expected.ObjectID)
		if err != nil {
			return err
		}
		if !exactProtectionIdentity(current, req.Expected) || current.InodeID == 0 {
			return ErrProtectionConflict
		}
		in, err := getInodeTx(w.tx, current.InodeID)
		if err != nil {
			return err
		}
		if in.Staging || (current.ObjectID < types.StagingInodeBase<<8 && in.ObjID == 0) {
			return ErrProtectionConflict
		}
		if err := walkAutonomy(w.tx, "plan", func(raw []byte) error {
			var plan ProtectionPlan
			if err := json.Unmarshal(raw, &plan); err != nil {
				return err
			}
			if plan.State == ProtectionPending && plan.Expected.ObjectID == current.ObjectID {
				return ErrProtectionConflict
			}
			return nil
		}); err != nil {
			return err
		}
		capacity, err := capacitiesTx(w.tx)
		if err != nil {
			return err
		}
		free := map[uint64]int64{}
		for _, c := range capacity {
			free[c.NodeID] = c.Free
		}
		out = ProtectionPlan{ID: req.ID, InputHash: inputHash, ProfileRevision: req.ProfileRevision, State: ProtectionPending, Expected: current,
			NodeMaxAge: req.NodeMaxAge, CreatedAt: now, UpdatedAt: now, Reason: req.Reason}
		seen := map[uint64]bool{}
		for _, id := range req.Targets {
			if seen[id] || id == 0 || types.ContainsUint64(current.Replicas, id) {
				return ErrProtectionConflict
			}
			seen[id] = true
			var node types.NodeInfo
			if err := json.Unmarshal(w.tx.Bucket(bucketNodes).Get(u64be(id)), &node); err != nil {
				return ErrNotExist
			}
			if now.Sub(node.LastHeartbeat) > req.NodeMaxAge || node.LastHeartbeat.After(now.Add(time.Second)) {
				return ErrProtectionConflict
			}
			if free[id] < current.Size {
				return ErrProtectionBudget
			}
			out.Targets = append(out.Targets, ProtectionTarget{NodeID: id, Addr: node.Addr})
		}
		return putAutonomy(w, "plan", out.ID, out)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func (s *Store) ProtectionPlan(id string) (ProtectionPlan, error) {
	var result ProtectionPlan
	err := s.db.View(func(tx *bolt.Tx) error { var err error; result, err = planTx(tx, id); return err })
	return result, err
}

func (s *Store) ProtectionDescriptor(planID string, objectID, nodeID uint64) (types.ObjectIntegrity, error) {
	if err := s.EnsureDurable(); err != nil {
		return types.ObjectIntegrity{}, err
	}
	var result types.ObjectIntegrity
	err := s.db.View(func(tx *bolt.Tx) error {
		plan, err := planTx(tx, planID)
		if err != nil {
			return err
		}
		if plan.State != ProtectionPending && plan.State != ProtectionCompleted {
			return ErrProtectionConflict
		}
		if plan.Expected.ObjectID != objectID || plan.ProfileRevision != profileRevisionTx(tx) {
			return ErrProtectionConflict
		}
		allowed := false
		for _, t := range plan.Targets {
			if t.NodeID == nodeID && (t.Done || t.Attempts > 0) {
				var node types.NodeInfo
				if err := json.Unmarshal(tx.Bucket(bucketNodes).Get(u64be(nodeID)), &node); err != nil {
					return err
				}
				allowed = node.Addr == t.Addr && (t.Done || time.Now().Before(t.NextAttempt))
				result.PlanLeaseUntil = t.NextAttempt
			}
		}
		if !allowed {
			return ErrProtectionConflict
		}
		current, err := integrityTx(tx, objectID)
		if err != nil {
			return err
		}
		if !exactProtectionIdentity(current, plan.Expected) {
			return ErrProtectionConflict
		}
		leaseUntil := result.PlanLeaseUntil
		result = current
		result.PlanID = planID
		result.PlanLeaseUntil = leaseUntil
		result.Replicas = appendUnique(append([]uint64(nil), current.Replicas...), nodeID)
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return result, err
}

func (s *Store) markProtectionDone(expected types.ObjectIntegrity, nodeID uint64, usage *types.NodeUsage) (bool, error) {
	marked := false
	err := s.write(func(w *txw) error {
		plan, err := planTx(w.tx, expected.PlanID)
		if err != nil {
			return err
		}
		if plan.State != ProtectionPending && plan.State != ProtectionCompleted {
			return nil
		}
		if plan.Expected.ObjectID != expected.ObjectID || plan.ProfileRevision != profileRevisionTx(w.tx) {
			return nil
		}
		idx := -1
		for i, t := range plan.Targets {
			if t.NodeID == nodeID {
				idx = i
			}
		}
		if idx < 0 || plan.Targets[idx].Attempts == 0 {
			return nil
		}
		current, err := integrityTx(w.tx, expected.ObjectID)
		if errors.Is(err, ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !sameObjectContents(current, expected) || current.InodeID != expected.InodeID || current.Generation != expected.Generation {
			return nil
		}
		var node types.NodeInfo
		if err := json.Unmarshal(w.tx.Bucket(bucketNodes).Get(u64be(nodeID)), &node); err != nil {
			return err
		}
		if node.Addr != plan.Targets[idx].Addr {
			return ErrProtectionConflict
		}
		if plan.Targets[idx].Done {
			marked = types.ContainsUint64(current.Done, nodeID) && !types.ContainsUint64(current.Suspect, nodeID)
			if marked {
				return recordProtectionUsage(w, current, nodeID, usage)
			}
			return nil
		}
		if !exactProtectionIdentity(current, plan.Expected) || !exactProtectionIdentity(current, expected) ||
			!expected.PlanLeaseUntil.Equal(plan.Targets[idx].NextAttempt) || !time.Now().Before(plan.Targets[idx].NextAttempt) {
			return nil
		}
		in, err := getInodeTx(w.tx, current.InodeID)
		if err != nil {
			return err
		}
		if in.Staging {
			return nil
		}
		if err := recordProtectionUsage(w, current, nodeID, usage); err != nil {
			return err
		}
		if current.Chunked {
			found := false
			for i := range in.Chunks {
				ch := &in.Chunks[i]
				if types.ChunkObjID(*ch, in.ID) != current.ObjectID {
					continue
				}
				if err := bumpIntegrityEpoch(&ch.IntegrityEpoch); err != nil {
					return err
				}
				ch.Replicas = appendUnique(ch.Replicas, nodeID)
				ch.Done = appendUnique(ch.Done, nodeID)
				ch.Suspect = withoutReplica(ch.Suspect, nodeID)
				found = true
				break
			}
			if !found {
				return ErrChunkNotExist
			}
		} else {
			if err := bumpIntegrityEpoch(&in.IntegrityEpoch); err != nil {
				return err
			}
			in.Replicas = appendUnique(in.Replicas, nodeID)
			in.DoneReplicas = appendUnique(in.DoneReplicas, nodeID)
			in.SuspectReplicas = withoutReplica(in.SuspectReplicas, nodeID)
		}
		if err := w.putInode(&in); err != nil {
			return err
		}
		updated, ok := describeInodeObject(in, current.ObjectID)
		if !ok {
			return ErrProtectionConflict
		}
		plan.Expected = updated
		plan.Targets[idx].Done = true
		plan.Targets[idx].LastError = ""
		plan.Targets[idx].NextAttempt = time.Time{}
		plan.UpdatedAt = time.Now()
		complete := true
		for _, t := range plan.Targets {
			if !t.Done {
				complete = false
			}
		}
		if complete {
			plan.State = ProtectionCompleted
		}
		marked = true
		return putAutonomy(w, "plan", plan.ID, plan)
	})
	if err == nil && marked {
		err = s.EnsureDurable()
	}
	return marked, err
}

// ---- 多源绑定：每个计划目标在事务内绑定一个已校验源与保守的每流速率 ----

// errNoProtectionSource 表示本轮挑不到可用的已校验源；调用方必须放弃这次 claim
// 而不是先领走租约，下一轮再挑。
var errNoProtectionSource = errors.New("no healthy protection source")

// protectionLeaseView 是 claim 事务内看到的传输占用快照。Loads 分方向记账（一条租约占
// 目标 1 下行 + 绑定源 1 上行，两侧记同一实际流速）；QueuedTargets/QueuedSources 是
// pending 计划里租约已空的块工作，与活跃租约一起分摊 profile 预算。Leases 是去重后的
// 活跃保护租约数：一条只计一次，写入侧的流不计入全局 MaxConcurrent。
type protectionLeaseView struct {
	Loads         map[uint64]TransferLoad
	Leases        int
	QueuedTargets map[uint64]int
	QueuedSources map[uint64]int
}

func protectionLeaseViewTx(tx *bolt.Tx, now time.Time) (protectionLeaseView, error) {
	v := protectionLeaseView{Loads: map[uint64]TransferLoad{}, QueuedTargets: map[uint64]int{}, QueuedSources: map[uint64]int{}}
	walkErr := walkAutonomy(tx, "plan", func(raw []byte) error {
		var plan ProtectionPlan
		if err := json.Unmarshal(raw, &plan); err != nil {
			return err
		}
		if plan.State != ProtectionPending {
			return nil
		}
		var queued []ProtectionTarget
		for _, t := range plan.Targets {
			if t.Done {
				continue
			}
			if t.Attempts == 0 || !now.Before(t.NextAttempt) {
				queued = append(queued, t)
				continue
			}
			// 活跃租约：全局计数只加一次；速率与流数按上传/下载方向分账。
			v.Leases++
			dk := v.Loads[t.NodeID]
			dk.Downloads++
			var err error
			if dk.DownloadBPS, err = addTransferRate(dk.DownloadBPS, t.DownloadBPS); err != nil {
				return err
			}
			v.Loads[t.NodeID] = dk
			if t.SourceID != 0 {
				uk := v.Loads[t.SourceID]
				uk.Uploads++
				if uk.UploadBPS, err = addTransferRate(uk.UploadBPS, t.UploadBPS); err != nil {
					return err
				}
				v.Loads[t.SourceID] = uk
			}
		}
		for _, t := range queued {
			v.QueuedTargets[t.NodeID]++
			candidates, err := protectionSourceCandidatesTx(tx, plan.Expected, map[uint64]bool{t.NodeID: true}, plan.NodeMaxAge, now)
			if err != nil {
				return err
			}
			for _, c := range candidates {
				v.QueuedSources[c.ID]++
			}
		}
		return nil
	})
	return v, walkErr
}

// protectionLeaseLoadTx 暴露保护侧的分方向负载与去重后的活跃租约数，供写入侧预算校验
// 合并（同包调用）。速率与流数只含已领走的租约，不含排队中的工作。
func protectionLeaseLoadTx(tx *bolt.Tx, now time.Time) (map[uint64]TransferLoad, int, error) {
	v, err := protectionLeaseViewTx(tx, now)
	return v.Loads, v.Leases, err
}

// mergeTransferLoads 把两组分方向负载相加。写入侧与保护侧共用同一份节点 profile 预算，
// 所以两侧占用必须累加，否则会互相超额分配。
func mergeTransferLoads(dst map[uint64]TransferLoad, src map[uint64]TransferLoad) error {
	for id, l := range src {
		cur := dst[id]
		up, err := addTransferRate(cur.UploadBPS, l.UploadBPS)
		if err != nil {
			return err
		}
		down, err := addTransferRate(cur.DownloadBPS, l.DownloadBPS)
		if err != nil {
			return err
		}
		dst[id] = TransferLoad{UploadBPS: up, DownloadBPS: down, Uploads: cur.Uploads + l.Uploads, Downloads: cur.Downloads + l.Downloads}
	}
	return nil
}

// nodeAtTx 在给定事务里读取一个节点的元数据；节点不存在返回 ErrNotExist。
func nodeAtTx(tx *bolt.Tx, nodeID uint64) (types.NodeInfo, error) {
	var node types.NodeInfo
	if err := json.Unmarshal(tx.Bucket(bucketNodes).Get(u64be(nodeID)), &node); err != nil {
		return node, ErrNotExist
	}
	return node, nil
}

// protectionSourceCandidatesTx 是源资格闸：本对象当前的已校验副本（Done ∧ ¬Suspect）、
// 地址非空、心跳在 maxAge 窗口内、且不是本计划的目标。速率未配置不排除任何源。
// maxAge<=0（升级前的遗留计划）不做无限期信任：退化为「必须至少上报过一次心跳」的
// 身份判定，零心跳节点永远不能充当源。结果按节点 ID 升序，选择确定性可复算。
func protectionSourceCandidatesTx(tx *bolt.Tx, expected types.ObjectIntegrity, exclude map[uint64]bool, maxAge time.Duration, now time.Time) ([]types.NodeInfo, error) {
	var out []types.NodeInfo
	seen := map[uint64]bool{}
	for _, id := range expected.Replicas {
		if seen[id] || exclude[id] || !types.ContainsUint64(expected.Done, id) || types.ContainsUint64(expected.Suspect, id) {
			continue
		}
		seen[id] = true
		var node types.NodeInfo
		if err := json.Unmarshal(tx.Bucket(bucketNodes).Get(u64be(id)), &node); err != nil {
			return nil, ErrNotExist
		}
		if node.Addr == "" || node.LastHeartbeat.IsZero() {
			continue
		}
		if maxAge > 0 && (now.Sub(node.LastHeartbeat) > maxAge || node.LastHeartbeat.After(now.Add(time.Second))) {
			continue
		}
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// availableRate 返回方向预算还剩多少可分配速率。已分配达到声明预算时返回 0，
// 永不回绕：held>declared 也必须收敛为 0 而不是 uint64 上溢成满额。
func availableRate(declared, held uint64) uint64 {
	if held >= declared {
		return 0
	}
	return declared - held
}

// concurrencyCap 返回本方向可同时承载的流数：节点声明并发与运行期预算上限取小。
// 任一为 0 表示不设上限（遗留节点没有 profile），因此未配置的节点不会被 0 误判成只能跑 0 流。
func concurrencyCap(declaredCap, budgetCap int) int {
	limit := budgetCap
	if declaredCap > 0 && (limit <= 0 || declaredCap < limit) {
		limit = declaredCap
	}
	return limit
}

// fairShare 把剩余速率在 slots 个槽位之间均分。这是单轮的保守界：slots 取「活跃+排队」
// 并按并发上限截断（slots 最小为 1，租约不会被除成 0）；slots≥available 时单条租约
// 拿走整段剩余——总占用不越过声明预算，也不是跨轮的公平保证（每次分配都在扣减剩余，
// 先后声明的工作份额会不同，约束只是不超额、不把速率截成 0）。
// 返回 false 表示剩余为 0，本轮不能再分配。
func fairShare(available uint64, slots int) (uint64, bool) {
	if available == 0 {
		return 0, false
	}
	if slots < 1 {
		slots = 1
	}
	if n := uint64(slots); n >= available {
		return available, true
	}
	return available / uint64(slots), true
}

// endpointBudget 是一个节点声明的传输预算。profile 只读一次，上传/下载两个方向与
// 并发上限共用同一次读取。
type endpointBudget struct {
	upload        uint64
	download      uint64
	maxConcurrent int
}

func endpointBudgetTx(tx *bolt.Tx, nodeID uint64) (endpointBudget, error) {
	var profile NodePlacementProfile
	if err := readAutonomy(tx, "profile", fmt.Sprint(nodeID), &profile); err != nil && !errors.Is(err, ErrNotExist) {
		return endpointBudget{}, err
	}
	return endpointBudget{upload: profile.UploadBPS, download: profile.DownloadBPS, maxConcurrent: profile.MaxTransferConcurrency}, nil
}

// assignProtectionSourceTx 为已选中的目标持久化源绑定与实际的每流速率。
// 速率 = min(目标下行份额, 源上行份额, 可选天花板)，份额按「活跃+排队」分摊：首条租约
// 拿不到整段预算，多源可共同填满同一目标。同一实际流速双侧入账——把快侧账面记满会让
// held 超过声明速率、剩余恒为 0，端点永久假饱和。速率是否声明由目标侧决定（接收端必须
// 配置了本地预算才能强制执行流速，否则数据面硬失败）；未配置持久化 0 = 未分配而非无限。
// 选择规则：完成成本 (上行流数+1)×字节/实际流速 最小的源，无速率时退化为字节数且不编造
// 速度；浮点避免整数除法截断；候选 ID 升序、严格更优才替换，平局最小 ID，可复算。
func assignProtectionSourceTx(tx *bolt.Tx, plan *ProtectionPlan, target *ProtectionTarget, budget *ProtectionExecutionBudget, view *protectionLeaseView, now time.Time) error {
	maxAge := plan.NodeMaxAge
	if maxAge <= 0 && budget != nil {
		maxAge = budget.NodeMaxAge
	}
	sources, err := protectionSourceCandidatesTx(tx, plan.Expected, map[uint64]bool{target.NodeID: true}, maxAge, now)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return errNoProtectionSource
	}
	targetBudget, err := endpointBudgetTx(tx, target.NodeID)
	if err != nil {
		return err
	}
	targetCap := concurrencyCap(targetBudget.maxConcurrent, budgetTargetCap(budget))
	tLoad := view.Loads[target.NodeID]
	if targetCap > 0 && tLoad.Downloads >= targetCap {
		return errNoProtectionSource
	}
	tSlots := tLoad.Downloads + view.QueuedTargets[target.NodeID]
	if targetCap > 0 && tSlots > targetCap {
		tSlots = targetCap
	}
	// declared>0 才算已配置；已配置但剩余为 0 = 被活跃租约占满，本轮等释放。
	// declared=0 是遗留未配置，保持不限速绑定而不是把 0 当 0 份额。
	targetConfigured := targetBudget.download > 0
	down, _ := fairShare(availableRate(targetBudget.download, tLoad.DownloadBPS), tSlots)
	if targetConfigured && down == 0 {
		return errNoProtectionSource
	}
	ratesToPersist := targetConfigured
	size := uint64(plan.Expected.Size)
	var bestID uint64
	bestAddr := ""
	var bestFlow uint64
	bestCost := math.Inf(1)
	bestSourceConfigured := false
	bound := false
	for _, node := range sources {
		sLoad := view.Loads[node.ID]
		sourceBudget, err := endpointBudgetTx(tx, node.ID)
		if err != nil {
			return err
		}
		sourceCap := concurrencyCap(sourceBudget.maxConcurrent, budgetSourceCap(budget))
		if sourceCap > 0 && sLoad.Uploads >= sourceCap {
			continue
		}
		sSlots := sLoad.Uploads + view.QueuedSources[node.ID]
		if sourceCap > 0 && sSlots > sourceCap {
			sSlots = sourceCap
		}
		sourceConfigured := sourceBudget.upload > 0
		up, _ := fairShare(availableRate(sourceBudget.upload, sLoad.UploadBPS), sSlots)
		if sourceConfigured && up == 0 {
			continue // 该源上行已被活跃+排队工作占满，本轮不选它
		}
		// 实际流速 = min(目标下行份额, 源上行份额)，天花板只压低分配不淘汰源。
		flow := down
		if sourceConfigured && up < flow {
			flow = up
		}
		if c := budgetCeiling(budget); c > 0 && flow > c {
			flow = c
		}
		// 无速率保证时退化为字节成本（流数加权，仍以并发负载分布），不编造速度。
		cost := float64(sLoad.Uploads+1) * float64(size)
		if ratesToPersist {
			cost /= float64(flow)
		}
		if !bound || cost < bestCost || (cost == bestCost && node.ID < bestID) {
			bestID, bestAddr, bestFlow, bestCost = node.ID, node.Addr, flow, cost
			bestSourceConfigured = sourceConfigured
			bound = true
		}
	}
	if !bound {
		return errNoProtectionSource
	}
	target.SourceID = bestID
	target.SourceAddr = bestAddr
	if ratesToPersist {
		target.UploadBPS = bestFlow
		target.DownloadBPS = bestFlow
	} else {
		// 未配置带宽：保留并发与字节上限，不声明速率。
		target.UploadBPS = 0
		target.DownloadBPS = 0
	}
	// 同一条实际流速双侧入账，供同事务内复用同一份快照；流数无论如何都占槽位。
	tk := view.Loads[target.NodeID]
	tk.Downloads++
	if ratesToPersist {
		if tk.DownloadBPS, err = addTransferRate(tk.DownloadBPS, target.DownloadBPS); err != nil {
			return err
		}
	}
	view.Loads[target.NodeID] = tk
	sk := view.Loads[target.SourceID]
	sk.Uploads++
	if ratesToPersist && bestSourceConfigured {
		if sk.UploadBPS, err = addTransferRate(sk.UploadBPS, target.UploadBPS); err != nil {
			return err
		}
	}
	view.Loads[target.SourceID] = sk
	return nil
}

// budgetSourceCap / budgetTargetCap / budgetCeiling 在遗留调用（没有传预算）时返回 0，
// 表示「不设上限」而不是「上限为 0」。源与目标的并发上限各自独立生效。
func budgetSourceCap(b *ProtectionExecutionBudget) int {
	if b == nil {
		return 0
	}
	return b.MaxSourceConcurrent
}

func budgetTargetCap(b *ProtectionExecutionBudget) int {
	if b == nil {
		return 0
	}
	return b.MaxTargetConcurrent
}

func budgetCeiling(b *ProtectionExecutionBudget) uint64 {
	if b == nil {
		return 0
	}
	if b.MaxSourceUploadBPS == 0 || b.MaxTargetDownloadBPS == 0 {
		return b.MaxSourceUploadBPS + b.MaxTargetDownloadBPS
	}
	if b.MaxSourceUploadBPS < b.MaxTargetDownloadBPS {
		return b.MaxSourceUploadBPS
	}
	return b.MaxTargetDownloadBPS
}

// protectionSourceMatchesTx 校验一次 peer 读取是否落在计划绑定的源上。sender 是发起
// 拉取的目标节点，audience 是提供数据的源节点。没有 plan_id 时返回真（写路径走
// writeTransfer 的腿表校验，不受本票据约束）。带 plan_id 时只放行两种：升级前遗留的
// 未绑定目标（SourceID==0，执行侧按 Attempts 轮转——现在 claim 总会写绑定，未绑定
// 只可能来自旧数据），或者目标持有有效租约且 audience 正是绑定源。其余一律返回假。
// 只读 tx，供票据校验在已有写事务内调用。
func protectionSourceMatchesTx(tx *bolt.Tx, planID string, senderNodeID, audienceNodeID uint64, now time.Time) (bool, error) {
	if planID == "" || audienceNodeID == 0 {
		return true, nil
	}
	plan, err := planTx(tx, planID)
	if err != nil {
		if errors.Is(err, ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if plan.State != ProtectionPending || plan.ProfileRevision != profileRevisionTx(tx) {
		return false, nil
	}
	for _, t := range plan.Targets {
		if t.NodeID != senderNodeID || t.Attempts == 0 || !now.Before(t.NextAttempt) {
			continue
		}
		// 遗留未绑定目标（SourceID==0）保持原有的执行轮转；新计划必须精确匹配绑定源。
		if t.SourceID == 0 {
			return true, nil
		}
		return t.SourceID == audienceNodeID, nil
	}
	return false, nil
}

// ProtectionTransfer 返回本计划目标已提交的传输绑定，供复制描述符交给接收节点。
// 返回 nil 表示该目标从未绑定源（升级前的遗留计划），调用方必须保持原有的不限速行为；
// 返回错误表示身份、地址、租约、profile revision 或绑定本身已经漂移。描述符是速率的
// 唯一权威，拉取请求体不携带速率。校验在同一个只读事务内完成：状态 pending/completed、
// 对象 ID 与 profile revision、identity 代际、目标与源的当前地址都必须仍等于绑定值。
// pending 计划额外要求租约窗口有效且源仍是有效副本（Done ∧ ¬Suspect）；completed 计划
// 的 NextAttempt 已被 markProtectionDone 清零，绑定作为历史事实返回，不再查窗口与副本
// 状态——verify 路径仍要能取回 descriptor。
func (s *Store) ProtectionTransfer(planID string, objectID, nodeID uint64) (*types.ReplicaTransfer, error) {
	var out *types.ReplicaTransfer
	err := s.db.View(func(tx *bolt.Tx) error {
		plan, err := planTx(tx, planID)
		if err != nil {
			return err
		}
		if plan.State != ProtectionPending && plan.State != ProtectionCompleted {
			return ErrProtectionConflict
		}
		if plan.Expected.ObjectID != objectID || plan.ProfileRevision != profileRevisionTx(tx) {
			return ErrProtectionConflict
		}
		current, err := integrityTx(tx, objectID)
		if err != nil {
			return err
		}
		if !exactProtectionIdentity(current, plan.Expected) {
			return ErrProtectionConflict
		}
		targetNode, err := nodeAtTx(tx, nodeID)
		if err != nil {
			return ErrProtectionConflict
		}
		for _, t := range plan.Targets {
			if t.NodeID != nodeID {
				continue
			}
			if t.SourceID == 0 {
				return nil
			}
			if t.SourceAddr == "" || t.Attempts == 0 {
				return ErrProtectionConflict
			}
			if t.Addr != "" && t.Addr != targetNode.Addr {
				return ErrProtectionConflict
			}
			sourceNode, err := nodeAtTx(tx, t.SourceID)
			if err != nil || sourceNode.Addr == "" || sourceNode.Addr != t.SourceAddr {
				return ErrProtectionConflict
			}
			if plan.State == ProtectionPending {
				if !time.Now().Before(t.NextAttempt) {
					return ErrProtectionConflict
				}
				if !types.ContainsUint64(plan.Expected.Done, t.SourceID) || types.ContainsUint64(plan.Expected.Suspect, t.SourceID) {
					return ErrProtectionConflict
				}
			}
			out = &types.ReplicaTransfer{SourceID: t.SourceID, TargetID: t.NodeID,
				UploadBPS: t.UploadBPS, DownloadBPS: t.DownloadBPS, ExpiresAt: t.NextAttempt}
			return nil
		}
		return ErrProtectionConflict
	})
	return out, err
}

func (s *Store) ClaimProtectionTarget(planID string, now time.Time, retryAfter time.Duration, budgets ...ProtectionExecutionBudget) (ProtectionPlan, *ProtectionTarget, error) {
	var plan ProtectionPlan
	var target *ProtectionTarget
	if retryAfter <= 0 {
		return plan, nil, errors.New("invalid retry interval")
	}
	err := s.write(func(w *txw) error {
		var err error
		plan, err = planTx(w.tx, planID)
		if err != nil {
			return err
		}
		if plan.State != ProtectionPending {
			return nil
		}
		current, err := integrityTx(w.tx, plan.Expected.ObjectID)
		if errors.Is(err, ErrNotExist) || (err == nil && (!exactProtectionIdentity(current, plan.Expected) || plan.ProfileRevision != profileRevisionTx(w.tx))) {
			plan.State = ProtectionStale
			plan.LastError = "content or layout changed"
			plan.UpdatedAt = now
			return putAutonomy(w, "plan", plan.ID, plan)
		}
		if err != nil {
			return err
		}
		var budget *ProtectionExecutionBudget
		if len(budgets) > 0 {
			b := budgets[0]
			budget = &b
			// 显式空预算必须拒绝：0 不是「不限制」，遗留行为由「不传预算」表示。
			if budget.MaxConcurrent < 1 || budget.MaxBytes < plan.Expected.Size ||
				budget.MaxSourceConcurrent < 0 || budget.MaxTargetConcurrent < 0 ||
				budget.MaxSourceUploadBPS > transferbudget.MaxRate || budget.MaxTargetDownloadBPS > transferbudget.MaxRate {
				return nil
			}
		}
		// 负载快照无论是否带预算都要算：遗留路径不声明速率，仍要基于真实负载挑健康源。
		view, err := protectionLeaseViewTx(w.tx, now)
		if err != nil {
			return err
		}
		writeLoads, err := writeTransferLoadsTx(w.tx, now)
		if err != nil {
			return err
		}
		if err := mergeTransferLoads(view.Loads, writeLoads); err != nil {
			return err
		}
		// 全局派工闸只数保护租约（去重后一条一次），不把写入侧的流当保护租约。
		if budget != nil && view.Leases >= budget.MaxConcurrent {
			return nil
		}
		for i := range plan.Targets {
			t := &plan.Targets[i]
			if t.Done || now.Before(t.NextAttempt) {
				continue
			}
			if t.Attempts == math.MaxUint32 {
				return errors.New("protection attempts exhausted")
			}
			// 源绑定在事务内随租约一起持久化：挑不到源不占租约，绝不先领租约再失败。
			if err := assignProtectionSourceTx(w.tx, &plan, t, budget, &view, now); err != nil {
				if errors.Is(err, errNoProtectionSource) {
					return nil
				}
				return err
			}
			view.Leases++
			t.Attempts++
			t.NextAttempt = now.Add(retryAfter)
			plan.UpdatedAt = now
			copy := *t
			target = &copy
			return putAutonomy(w, "plan", plan.ID, plan)
		}
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return plan, target, err
}

func (s *Store) RecordProtectionError(planID string, nodeID uint64, message string) error {
	if len(message) > 512 {
		message = message[:512]
	}
	return s.write(func(w *txw) error {
		plan, err := planTx(w.tx, planID)
		if err != nil {
			return err
		}
		if plan.State != ProtectionPending {
			return nil
		}
		for i := range plan.Targets {
			if plan.Targets[i].NodeID == nodeID && !plan.Targets[i].Done {
				plan.Targets[i].LastError = message
			}
		}
		plan.LastError = message
		plan.UpdatedAt = time.Now()
		return putAutonomy(w, "plan", plan.ID, plan)
	})
}

func (s *Store) CancelProtection(planID string) error {
	err := s.write(func(w *txw) error {
		plan, err := planTx(w.tx, planID)
		if err != nil {
			return err
		}
		if plan.State != ProtectionPending {
			return nil
		}
		plan.State = ProtectionCancelled
		plan.UpdatedAt = time.Now()
		return putAutonomy(w, "plan", plan.ID, plan)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}

func SortProtectionPlans(plans []ProtectionPlan) {
	sort.Slice(plans, func(i, j int) bool {
		if !plans[i].CreatedAt.Equal(plans[j].CreatedAt) {
			return plans[i].CreatedAt.Before(plans[j].CreatedAt)
		}
		return plans[i].ID < plans[j].ID
	})
}
