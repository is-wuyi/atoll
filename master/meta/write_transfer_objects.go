package meta

import (
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func writeTransferForObjectTx(tx *bolt.Tx, objectID uint64) (*types.WriteTransferPlan, error) {
	if objectID < types.StagingInodeBase<<8 || objectID >= types.ObjectIDBase {
		return nil, nil
	}
	owner, _ := types.ParseChunkID(objectID)
	if !hasPlannedWriteTx(tx, owner) {
		return nil, nil
	}
	rec, err := plannedWriteTx(tx, owner)
	if err != nil {
		return nil, err
	}
	if rec.Upload.State == types.WriteAborted {
		return nil, ErrWriteExpired
	}
	for _, chunk := range rec.Upload.Chunks {
		if chunk.Object.ID == objectID {
			if rec.Upload.State == types.WriteCommitted && chunk.Transfer != nil && !time.Now().Before(chunk.Transfer.ExpiresAt) {
				return nil, nil
			}
			return chunk.Transfer, nil
		}
	}
	return nil, ErrNotExist
}

func (s *Store) WriteTransferForObject(objectID uint64) (*types.WriteTransferPlan, error) {
	var out *types.WriteTransferPlan
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		out, err = writeTransferForObjectTx(tx, objectID)
		return err
	})
	return out, err
}

func writeTransferAllowsTx(tx *bolt.Tx, objectID, from, to uint64, now time.Time) bool {
	plan, err := writeTransferForObjectTx(tx, objectID)
	if err != nil {
		return false
	}
	if plan == nil {
		return true
	}
	if !now.Before(plan.ExpiresAt) {
		return false
	}
	for _, leg := range plan.Legs {
		if leg.FromNodeID == from && leg.ToNodeID == to {
			return true
		}
	}
	return false
}
