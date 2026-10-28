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

func enableWriteRecoveryTx(w *txw) error {
	var cfg writeConfig
	if err := json.Unmarshal(w.tx.Bucket(bucketWrites).Get(keyWriteConfig), &cfg); err != nil {
		return err
	}
	if cfg.Version == 2 {
		return nil
	}
	if cfg.Version != 1 {
		return ErrWritePlanConflict
	}
	cfg.Version = 2
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
		for _, id := range chunk.Done {
			if !types.ContainsUint64(chunk.Suspect, id) && !types.ContainsUint64(choice.Recovery.Excluded, id) && liveWriteNodeTx(w.tx, id, nodeMaxAge, now) == nil && !types.ContainsUint64(choice.Layout.Nodes, id) {
				return ErrWritePlanConflict
			}
		}
		capacity, err := capacitiesTx(w.tx)
		if err != nil {
			return err
		}
		free := map[uint64]int64{}
		for _, item := range capacity {
			free[item.NodeID] = item.Free
		}
		for _, id := range choice.Layout.Nodes {
			if err := liveWriteNodeTx(w.tx, id, nodeMaxAge, now); err != nil {
				return err
			}
			if _, err := retirementTx(w.tx, choice.Object.ID, id); err == nil {
				return ErrWritePlanConflict
			} else if !errors.Is(err, ErrNotExist) {
				return err
			}
			if !types.ContainsUint64(old.Layout.Nodes, id) && free[id] < choice.Object.StoredSize {
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
