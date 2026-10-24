package meta

import (
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func (s *Store) PlannedWriteStatus(actor WriteActor, binding types.WriteBinding, nodeMaxAge time.Duration, now time.Time) (types.WriteStatus, error) {
	out := types.WriteStatus{UploadID: binding.UploadID}
	err := s.db.View(func(tx *bolt.Tx) error {
		rec, err := authorizePlannedTx(tx, actor, binding, now, true)
		if err != nil {
			return err
		}
		if rec.Upload.State == types.WriteAborted {
			return ErrWritePlanConflict
		}
		if rec.Upload.State == types.WriteCommitted {
			for _, plan := range rec.Upload.Chunks {
				out.Chunks = append(out.Chunks, types.WriteChunkStatus{Index: plan.Index, Ready: true})
			}
			return nil
		}
		in, err := getInodeTx(tx, binding.UploadID)
		if err != nil {
			return err
		}
		for _, plan := range rec.Upload.Chunks {
			ready := false
			for _, chunk := range in.Chunks {
				if !chunkMatchesPlan(chunk, plan) {
					continue
				}
				ready = true
				for _, id := range plan.Confirmations {
					if !types.ContainsUint64(chunk.Done, id) || types.ContainsUint64(chunk.Suspect, id) || liveWriteNodeTx(tx, id, nodeMaxAge, now) != nil {
						ready = false
						break
					}
				}
				break
			}
			out.Chunks = append(out.Chunks, types.WriteChunkStatus{Index: plan.Index, Ready: ready})
		}
		return nil
	})
	return out, err
}
