package meta

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

// ErrWriteRecoveryRetry 表示恢复请求所依据的快照/完成状态在规划与事务提交之间
// 发生变化（例如规划窗口内新完成的副本正被所选布局丢弃），需要以同一
// epoch/op/failed 重新发起恢复以便重新规划。它与计划身份冲突（ErrWritePlanConflict）
// 是两类错误：前者事务未落任何状态、重试即按新快照重新规划，后者是请求本身过期。
var ErrWriteRecoveryRetry = errors.New("write recovery snapshot changed; re-plan required")

func enableWriteRecoveryTx(w *txw) error {
	var cfg writeConfig
	if err := json.Unmarshal(w.tx.Bucket(bucketWrites).Get(keyWriteConfig), &cfg); err != nil {
		return err
	}
	if cfg.Version == 3 {
		return nil
	}
	if cfg.Version != 1 && cfg.Version != 2 {
		return ErrWritePlanConflict
	}
	cfg.Version = 3
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return w.put(bcWrites, bucketWrites, keyWriteConfig, raw)
}

func sameRecoveryPlan(a, b types.WriteChunkPlan) bool {
	left, lerr := json.Marshal(a)
	right, rerr := json.Marshal(b)
	return lerr == nil && rerr == nil && string(left) == string(right)
}

func RecoveryRequestHash(req types.RecoverWriteChunkRequest) string {
	identity := struct {
		types.WriteBinding
		Index         int      `json:"index"`
		ExpectedEpoch uint64   `json:"expected_epoch"`
		OpID          string   `json:"op_id"`
		FailedNodes   []uint64 `json:"failed_nodes"`
	}{WriteBinding: req.WriteBinding, Index: req.Index, ExpectedEpoch: req.ExpectedEpoch, OpID: req.OpID, FailedNodes: append([]uint64(nil), req.FailedNodes...)}
	sort.Slice(identity.FailedNodes, func(i, j int) bool { return identity.FailedNodes[i] < identity.FailedNodes[j] })
	raw, _ := json.Marshal(identity)
	return BodySHA256(raw)
}

func validRecoveryRequest(req types.RecoverWriteChunkRequest) bool {
	if req.Index < 0 || req.Index >= types.MaxChunksPerFile || req.ExpectedEpoch == 0 || !validRecoveryOp(req.OpID) || len(req.FailedNodes) == 0 || len(req.FailedNodes) > 32 {
		return false
	}
	seen := map[uint64]bool{}
	for _, id := range req.FailedNodes {
		if id == 0 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func recoveryChunk(rec plannedWriteRecord, in types.Inode, index int) (types.WriteChunkPlan, types.ChunkInfo, error) {
	for _, plan := range rec.Upload.Chunks {
		if plan.Index != index {
			continue
		}
		for _, chunk := range in.Chunks {
			if chunk.Index == index && chunkMatchesPlan(chunk, plan) {
				return plan, chunk, nil
			}
		}
		return types.WriteChunkPlan{}, types.ChunkInfo{}, ErrWritePlanConflict
	}
	return types.WriteChunkPlan{}, types.ChunkInfo{}, ErrNotExist
}

// A lost recovery response replays the same epoch; it never consumes another attempt.
func checkRecoveryRequest(req types.RecoverWriteChunkRequest, plan types.WriteChunkPlan, now time.Time) (bool, error) {
	if !validRecoveryRequest(req) || plan.Recovery == nil {
		return false, ErrWritePlanConflict
	}
	r := plan.Recovery
	if !now.Before(r.HardUntil) {
		return false, ErrWriteExpired
	}
	if r.OperationID == req.OpID {
		if r.Epoch != req.ExpectedEpoch+1 || r.RequestHash != RecoveryRequestHash(req) {
			return false, ErrWritePlanConflict
		}
		return true, nil
	}
	if r.Epoch != req.ExpectedEpoch || r.Attempts >= types.MaxWriteRecoveries {
		return false, ErrWritePlanConflict
	}
	for _, id := range req.FailedNodes {
		if !types.ContainsUint64(plan.Layout.Nodes, id) {
			return false, ErrWritePlanConflict
		}
	}
	return false, nil
}

func (s *Store) RecoverableWriteChunk(actor WriteActor, req types.RecoverWriteChunkRequest, now time.Time) (types.WriteUpload, types.WriteChunkPlan, types.ChunkInfo, bool, error) {
	var upload types.WriteUpload
	var plan types.WriteChunkPlan
	var chunk types.ChunkInfo
	var replay bool
	err := s.db.View(func(tx *bolt.Tx) error {
		rec, err := authorizePlannedTx(tx, actor, req.WriteBinding, now, false)
		if err != nil {
			return err
		}
		in, err := getInodeTx(tx, req.UploadID)
		if err != nil || !in.Staging {
			return ErrWritePlanConflict
		}
		plan, chunk, err = recoveryChunk(rec, in, req.Index)
		if err != nil {
			return err
		}
		replay, err = checkRecoveryRequest(req, plan, now)
		upload = rec.Upload
		return err
	})
	return upload, plan, chunk, replay, err
}

func recoveryExcluded(plan types.WriteChunkPlan, failed []uint64) []uint64 {
	out := append([]uint64(nil), plan.Recovery.Excluded...)
	for _, id := range failed {
		out = appendUnique(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func expectedRecoveryExclusions(old, next types.WriteChunkPlan, failed []uint64) []uint64 {
	out := recoveryExcluded(old, failed)
	for _, id := range old.Layout.Nodes {
		if !types.ContainsUint64(next.Layout.Nodes, id) {
			out = appendUnique(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *Store) RecoverWriteChunk(actor WriteActor, req types.RecoverWriteChunkRequest, previous types.WriteChunkPlan, choice types.WriteChunkPlan, profileRevision uint64, nodeMaxAge time.Duration, now time.Time) (types.WriteChunkPlan, types.ChunkInfo, error) {
	var out types.WriteChunkPlan
	var result types.ChunkInfo
	err := s.write(func(w *txw) error {
		rec, err := authorizePlannedTx(w.tx, actor, req.WriteBinding, now, false)
		if err != nil {
			return err
		}
		in, err := getInodeTx(w.tx, req.UploadID)
		if err != nil || !in.Staging {
			return ErrWritePlanConflict
		}
		old, chunk, err := recoveryChunk(rec, in, req.Index)
		if err != nil {
			return err
		}
		replay, err := checkRecoveryRequest(req, old, now)
		if err != nil {
			return err
		}
		if replay {
			out, result = old, chunk
			return nil
		}
		if !sameRecoveryPlan(old, previous) || profileRevision != profileRevisionTx(w.tx) {
			return ErrWritePlanConflict
		}
		if choice.Index != old.Index || choice.Object != old.Object || choice.RequiredConfirmations < old.RequiredConfirmations || len(choice.Layout.Nodes) < len(old.Layout.Nodes) || choice.Layout.Epoch != old.Layout.Epoch+1 || choice.Recovery == nil || choice.Recovery.Epoch != choice.Layout.Epoch || choice.Recovery.Attempts != old.Recovery.Attempts+1 || !choice.Recovery.HardUntil.Equal(old.Recovery.HardUntil) || choice.Recovery.OperationID != req.OpID || choice.Recovery.RequestHash != RecoveryRequestHash(req) || !reflect.DeepEqual(choice.Recovery.Excluded, expectedRecoveryExclusions(old, choice, req.FailedNodes)) || !reflect.DeepEqual(choice.Recovery.FailedNodes, req.FailedNodes) {
			return ErrWritePlanConflict
		}
		geometry := types.PlanWriteChunkRequest{WriteBinding: req.WriteBinding, Index: req.Index, LogicalSize: old.Object.LogicalSize, StoredSize: old.Object.StoredSize, Encoding: old.Object.Encoding, Checksum: old.Object.Checksum}
		if err := types.ValidateWriteChunkPlan(geometry, choice); err != nil {
			return ErrWritePlanConflict
		}
		if (old.Transfer == nil) != (choice.Transfer == nil) || choice.Transfer != nil && !now.Before(choice.Transfer.ExpiresAt) {
			return ErrWritePlanConflict
		}
		// 完成副本保护：被移出布局的已完成副本，只有客户端申报失败或此前已排除
		// 时才允许丢弃。removed 节点虽然也会进入 Recovery.Excluded（累计排除与
		// 回收语义），但不构成丢弃豁免——规划窗口内新完成的副本（late Done）必须
		// 走重新规划，而不是静默丢弃并回收。
		doneExempt := recoveryExcluded(old, req.FailedNodes)
		for _, id := range chunk.Done {
			if types.ContainsUint64(chunk.Suspect, id) || types.ContainsUint64(choice.Layout.Nodes, id) || types.ContainsUint64(doneExempt, id) {
				continue
			}
			if liveWriteNodeTx(w.tx, id, nodeMaxAge, now) == nil {
				return ErrWriteRecoveryRetry
			}
		}
		capacity, err := capacitiesTx(w.tx)
		if err != nil {
			return err
		}
		free, unclamped := recoveryFreeViews(capacity)
		for _, id := range choice.Layout.Nodes {
			if err := liveWriteNodeTx(w.tx, id, nodeMaxAge, now); err != nil {
				return err
			}
			if _, err := retirementTx(w.tx, choice.Object.ID, id); err == nil {
				return ErrWritePlanConflict
			} else if !errors.Is(err, ErrNotExist) {
				return err
			}
			if !types.ContainsUint64(old.Layout.Nodes, id) {
				// 新目标节点：必须以真实余量容纳完整副本。
				if free[id] < choice.Object.StoredSize {
					return ErrWriteBudget
				}
				continue
			}
			// 旧布局节点的 (object,node) 预留继续有效：保留/重选不产生新占用。
			if types.ContainsUint64(chunk.Done, id) {
				continue // 已完成副本：数据已在节点上，无需新写入空间。
			}
			if unclamped[id] < 0 {
				// 未完成副本的预留必须有真实（未截断）余量支撑，
				// 不得靠截断后的伪余量通过。
				return ErrWriteBudget
			}
		}
		expected, ok := describeInodeObject(in, old.Object.ID)
		if !ok {
			return ErrWritePlanConflict
		}
		for _, id := range old.Layout.Nodes {
			if !types.ContainsUint64(choice.Layout.Nodes, id) {
				if err := w.queueRetirement(expected, id, false, "write-reassigned", now); err != nil {
					return err
				}
			}
		}
		if err := bumpIntegrityEpoch(&chunk.IntegrityEpoch); err != nil {
			return err
		}
		chunk.Replicas = append([]uint64(nil), choice.Layout.Nodes...)
		chunk.WriteEpoch = choice.Recovery.Epoch
		var done, suspect []uint64
		for _, id := range chunk.Done {
			if types.ContainsUint64(chunk.Replicas, id) {
				done = append(done, id)
			}
		}
		for _, id := range chunk.Suspect {
			if types.ContainsUint64(chunk.Replicas, id) {
				suspect = append(suspect, id)
			}
		}
		chunk.Done, chunk.Suspect = done, suspect
		for i := range in.Chunks {
			if in.Chunks[i].Index == req.Index {
				in.Chunks[i] = chunk
			}
		}
		for i := range rec.Upload.Chunks {
			if rec.Upload.Chunks[i].Index == req.Index {
				rec.Upload.Chunks[i] = choice
			}
		}
		in.Mtime = now
		if err := w.putInode(&in); err != nil {
			return err
		}
		if err := putPlannedWrite(w, rec); err != nil {
			return err
		}
		if err := validateCurrentWriteTransferBudgetTx(w.tx, now); err != nil {
			return err
		}
		out, result = choice, chunk
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, result, err
}
