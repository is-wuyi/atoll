package meta

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

type writeProgressRecord struct {
	Epoch uint64 `json:"epoch"`
	types.WriteNodeProgress
}

type writeProgressAttempt struct {
	Epoch           uint64    `json:"epoch"`
	Attempt         uint64    `json:"attempt"`
	ExpectedAttempt uint64    `json:"expected_attempt"`
	RequestID       string    `json:"request_id"`
	Token           string    `json:"token"`
	CreatedAt       time.Time `json:"created_at"`
}

func writeProgressKey(objectID, nodeID uint64) []byte {
	return []byte(fmt.Sprintf("progress/%d/%d", objectID, nodeID))
}

func writeProgressAttemptKey(objectID, nodeID uint64) []byte {
	return []byte(fmt.Sprintf("progress-attempt/%d/%d", objectID, nodeID))
}

func progressPlanTx(tx *bolt.Tx, objectID, nodeID, epoch uint64, now time.Time) (types.WriteChunkPlan, error) {
	if objectID < types.StagingInodeBase<<8 || objectID >= types.ObjectIDBase || nodeID == 0 || epoch == 0 || now.IsZero() {
		return types.WriteChunkPlan{}, ErrWritePlanConflict
	}
	owner, index := types.ParseChunkID(objectID)
	rec, err := plannedWriteTx(tx, owner)
	if err != nil {
		return types.WriteChunkPlan{}, err
	}
	if rec.Upload.State != types.WritePending || !now.Before(rec.Upload.ExpiresAt) {
		return types.WriteChunkPlan{}, ErrWritePlanConflict
	}
	in, err := getInodeTx(tx, owner)
	if err != nil {
		return types.WriteChunkPlan{}, err
	}
	plan, _, err := recoveryChunk(rec, in, index)
	if err != nil || plan.Recovery == nil || plan.Recovery.Epoch != epoch || !now.Before(plan.Recovery.HardUntil) || !types.ContainsUint64(plan.Layout.Nodes, nodeID) {
		return types.WriteChunkPlan{}, ErrWritePlanConflict
	}
	return plan, nil
}

func progressAttemptTx(tx *bolt.Tx, objectID, nodeID, epoch uint64) (writeProgressAttempt, error) {
	var attempt writeProgressAttempt
	if raw := tx.Bucket(bucketWrites).Get(writeProgressAttemptKey(objectID, nodeID)); raw != nil {
		if err := json.Unmarshal(raw, &attempt); err != nil {
			return attempt, err
		}
		if attempt.Epoch == 0 || attempt.Attempt == 0 || attempt.Attempt <= attempt.ExpectedAttempt || !validRecoveryOp(attempt.RequestID) || !types.ValidRetirementToken(attempt.Token) || attempt.CreatedAt.IsZero() {
			return attempt, ErrWritePlanConflict
		}
		if attempt.Epoch != epoch {
			attempt = writeProgressAttempt{}
		}
	}
	return attempt, nil
}

// Attempts are durably ordered by the Master; a late begin cannot replace a newer attempt.
func (s *Store) BeginWriteProgress(req types.BeginWriteProgressRequest, now time.Time) (types.BeginWriteProgressResponse, error) {
	var out types.BeginWriteProgressResponse
	if !validRecoveryOp(req.RequestID) || req.ExpectedAttempt == math.MaxUint64 {
		return out, ErrWritePlanConflict
	}
	err := s.write(func(w *txw) error {
		if _, err := progressPlanTx(w.tx, req.ObjectID, req.NodeID, req.Epoch, now); err != nil {
			return err
		}
		if err := enableWriteRecoveryTx(w); err != nil {
			return err
		}
		previous, err := progressAttemptTx(w.tx, req.ObjectID, req.NodeID, req.Epoch)
		if err != nil {
			return err
		}
		if previous.RequestID == req.RequestID {
			if previous.ExpectedAttempt != req.ExpectedAttempt {
				return ErrWritePlanConflict
			}
			out = types.BeginWriteProgressResponse{Attempt: previous.Attempt, AttemptToken: previous.Token}
			return nil
		}
		if previous.Attempt != req.ExpectedAttempt {
			return ErrWritePlanConflict
		}
		token, err := retirementToken("wp1_")
		if err != nil {
			return err
		}
		attempt := writeProgressAttempt{Epoch: req.Epoch, Attempt: previous.Attempt + 1, ExpectedAttempt: req.ExpectedAttempt, RequestID: req.RequestID, Token: token, CreatedAt: now}
		raw, err := json.Marshal(attempt)
		if err != nil {
			return err
		}
		if err := w.put(bcWrites, bucketWrites, writeProgressAttemptKey(req.ObjectID, req.NodeID), raw); err != nil {
			return err
		}
		out = types.BeginWriteProgressResponse{Attempt: attempt.Attempt, AttemptToken: attempt.Token}
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func (s *Store) WriteProgressState(objectID, nodeID, epoch uint64, now time.Time) (*types.WriteProgressState, error) {
	var state *types.WriteProgressState
	err := s.db.View(func(tx *bolt.Tx) error {
		owner, _ := types.ParseChunkID(objectID)
		rec, err := plannedWriteTx(tx, owner)
		if err != nil {
			return err
		}
		if rec.Upload.State == types.WriteCommitted {
			return nil
		}
		plan, err := progressPlanTx(tx, objectID, nodeID, epoch, now)
		if err != nil {
			return err
		}
		attempt, err := progressAttemptTx(tx, objectID, nodeID, epoch)
		if err != nil {
			return err
		}
		state = &types.WriteProgressState{Attempt: attempt.Attempt, HardUntil: plan.Recovery.HardUntil}
		return nil
	})
	return state, err
}

// Progress is a liveness hint, never a content receipt or a capacity release.
func (s *Store) RecordWriteProgress(report types.WriteProgress, now time.Time) error {
	if report.Attempt == 0 || !types.ValidRetirementToken(report.AttemptToken) || report.Bytes < 0 {
		return ErrWritePlanConflict
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		plan, err := progressPlanTx(tx, report.ObjectID, report.NodeID, report.Epoch, now)
		if err != nil || report.Bytes > plan.Object.StoredSize {
			return ErrWritePlanConflict
		}
		attempt, err := progressAttemptTx(tx, report.ObjectID, report.NodeID, report.Epoch)
		if err != nil || attempt.Attempt != report.Attempt || subtle.ConstantTimeCompare([]byte(attempt.Token), []byte(report.AttemptToken)) != 1 {
			return ErrWritePlanConflict
		}
		if report.Bytes == 0 {
			return nil
		}
		key := writeProgressKey(report.ObjectID, report.NodeID)
		var previous writeProgressRecord
		if raw := tx.Bucket(bucketWrites).Get(key); raw != nil {
			if err := json.Unmarshal(raw, &previous); err != nil {
				return err
			}
			if previous.Epoch == report.Epoch && previous.Attempt == report.Attempt && previous.RequestID == attempt.RequestID && report.Bytes <= previous.Bytes {
				return nil
			}
		}
		value := writeProgressRecord{Epoch: report.Epoch, WriteNodeProgress: types.WriteNodeProgress{NodeID: report.NodeID, Attempt: report.Attempt, RequestID: attempt.RequestID, Bytes: report.Bytes, UpdatedAt: now}}
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
		attempt, err := progressAttemptTx(tx, plan.Object.ID, id, plan.Recovery.Epoch)
		if err != nil {
			return nil, err
		}
		if progress.Epoch == plan.Recovery.Epoch && progress.NodeID == id && progress.Attempt > 0 && progress.Attempt == attempt.Attempt && progress.RequestID == attempt.RequestID && progress.Bytes > 0 && progress.Bytes <= plan.Object.StoredSize {
			out = append(out, progress.WriteNodeProgress)
		}
	}
	return out, nil
}
