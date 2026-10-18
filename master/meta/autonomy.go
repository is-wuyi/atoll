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
	if profile.NodeID == 0 || profile.HeadroomBytes < 0 || len(profile.FailureDomains) > 16 {
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
		out = ProtectionPlan{ID: req.ID, InputHash: inputHash, ProfileRevision: req.ProfileRevision, State: ProtectionPending, Expected: current, CreatedAt: now, UpdatedAt: now, Reason: req.Reason}
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
		if len(budgets) > 0 {
			budget := budgets[0]
			if budget.MaxConcurrent < 1 || budget.MaxBytes < plan.Expected.Size {
				return nil
			}
			active := 0
			if err := walkAutonomy(w.tx, "plan", func(raw []byte) error {
				var other ProtectionPlan
				if err := json.Unmarshal(raw, &other); err != nil {
					return err
				}
				for _, t := range other.Targets {
					if !t.Done && t.Attempts > 0 && now.Before(t.NextAttempt) {
						active++
					}
				}
				return nil
			}); err != nil {
				return err
			}
			if active >= budget.MaxConcurrent {
				return nil
			}
		}
		for i := range plan.Targets {
			t := &plan.Targets[i]
			if t.Done || now.Before(t.NextAttempt) {
				continue
			}
			if t.Attempts == math.MaxUint32 {
				return errors.New("protection attempts exhausted")
			}
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
