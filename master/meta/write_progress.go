package meta

import (
	"encoding/json"
	"fmt"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

type writeProgressRecord struct {
	Epoch uint64 `json:"epoch"`
	types.WriteNodeProgress
}

func writeProgressKey(objectID, nodeID uint64) []byte {
	return []byte(fmt.Sprintf("progress/%d/%d", objectID, nodeID))
}

// Progress is a liveness hint, never a content receipt or a capacity release.
func (s *Store) RecordWriteProgress(report types.WriteProgress, now time.Time) error {
	if report.ObjectID < types.StagingInodeBase<<8 || report.ObjectID >= types.ObjectIDBase || report.NodeID == 0 || report.Epoch == 0 || report.Attempt == 0 || report.Bytes < 0 || now.IsZero() {
		return ErrWritePlanConflict
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		owner, index := types.ParseChunkID(report.ObjectID)
		rec, err := plannedWriteTx(tx, owner)
		if err != nil {
			return err
		}
		if rec.Upload.State != types.WritePending {
			return ErrWritePlanConflict
		}
		in, err := getInodeTx(tx, owner)
		if err != nil {
			return err
		}
		plan, _, err := recoveryChunk(rec, in, index)
		if err != nil || plan.Recovery == nil || plan.Recovery.Epoch != report.Epoch || !now.Before(plan.Recovery.HardUntil) || !types.ContainsUint64(plan.Layout.Nodes, report.NodeID) || report.Bytes > plan.Object.StoredSize {
			return ErrWritePlanConflict
		}
		key := writeProgressKey(report.ObjectID, report.NodeID)
		var previous writeProgressRecord
		if raw := tx.Bucket(bucketWrites).Get(key); raw != nil {
			if err := json.Unmarshal(raw, &previous); err != nil {
				return err
			}
			if previous.Epoch == report.Epoch && (report.Attempt == previous.Attempt && report.Bytes <= previous.Bytes || now.Before(previous.UpdatedAt)) {
				return nil
			}
		}
		value := writeProgressRecord{Epoch: report.Epoch, WriteNodeProgress: types.WriteNodeProgress{NodeID: report.NodeID, Attempt: report.Attempt, Bytes: report.Bytes, UpdatedAt: now}}
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketWrites).Put(key, raw)
	})
}

func writeNodeProgressTx(tx *bolt.Tx, plan types.WriteChunkPlan) ([]types.WriteNodeProgress, error) {
	if plan.Recovery == nil {
		return nil, nil
	}
	var out []types.WriteNodeProgress
	for _, id := range plan.Layout.Nodes {
		raw := tx.Bucket(bucketWrites).Get(writeProgressKey(plan.Object.ID, id))
		if raw == nil {
			continue
		}
		var progress writeProgressRecord
		if err := json.Unmarshal(raw, &progress); err != nil {
			return nil, err
		}
		if progress.Epoch == plan.Recovery.Epoch && progress.NodeID == id && progress.Attempt > 0 && progress.Bytes >= 0 && progress.Bytes <= plan.Object.StoredSize {
			out = append(out, progress.WriteNodeProgress)
		}
	}
	return out, nil
}
