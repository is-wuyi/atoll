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
				status := types.WriteChunkStatus{Index: plan.Index, Ready: true}
				if plan.Recovery != nil {
					status.Epoch = plan.Recovery.Epoch
					status.Done = append([]uint64(nil), plan.Confirmations...)
				}
				out.Chunks = append(out.Chunks, status)
			}
			return nil
		}
		in, err := getInodeTx(tx, binding.UploadID)
		if err != nil {
			return err
		}
		for _, plan := range rec.Upload.Chunks {
			status := types.WriteChunkStatus{Index: plan.Index}
			if plan.Recovery != nil {
				status.Epoch = plan.Recovery.Epoch
				status.Progress, err = writeNodeProgressTx(tx, plan)
				if err != nil {
					return err
				}
			}
			ready := false
			for _, chunk := range in.Chunks {
				if !chunkMatchesPlan(chunk, plan) {
					continue
				}
				if plan.Recovery != nil {
					for _, id := range chunk.Done {
						if !types.ContainsUint64(chunk.Suspect, id) && liveWriteNodeTx(tx, id, nodeMaxAge, now) == nil {
							status.Done = append(status.Done, id)
						}
					}
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
			status.Ready = ready
			out.Chunks = append(out.Chunks, status)
		}
		return nil
	})
	return out, err
}
