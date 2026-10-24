package meta

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

type TransferLoad struct {
	UploadBPS   uint64
	DownloadBPS uint64
	Uploads     int
	Downloads   int
}

func addTransferRate(current, next uint64) (uint64, error) {
	if next > 1<<40 || current > ^uint64(0)-next {
		return 0, errors.New("transfer bandwidth accounting overflow")
	}
	return current + next, nil
}

func writeTransferLoadsTx(tx *bolt.Tx, now time.Time) (map[uint64]TransferLoad, error) {
	loads := map[uint64]TransferLoad{}
	b := tx.Bucket(bucketWrites)
	if b == nil {
		return loads, nil
	}
	err := b.ForEach(func(key, raw []byte) error {
		if !strings.HasPrefix(string(key), "upload/") {
			return nil
		}
		var rec plannedWriteRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if rec.Upload.State != types.WritePending && rec.Upload.State != types.WriteCommitted {
			return nil
		}
		inodeID := rec.Upload.ID
		if rec.Upload.State == types.WriteCommitted {
			if rec.Upload.Result == nil {
				return ErrWritePlanConflict
			}
			inodeID = rec.Upload.Result.ID
		}
		in, err := getInodeTx(tx, inodeID)
		if err != nil {
			if rec.Upload.State == types.WriteCommitted && errors.Is(err, ErrNotExist) {
				in = *rec.Upload.Result
			} else {
				return err
			}
		}
		for _, plan := range rec.Upload.Chunks {
			if plan.Transfer == nil || !now.Before(plan.Transfer.ExpiresAt) {
				continue
			}
			var chunk types.ChunkInfo
			for _, current := range in.Chunks {
				if current.ID == plan.Object.ID {
					chunk = current
					break
				}
			}
			if chunk.ID == 0 && rec.Upload.State == types.WriteCommitted {
				for _, previous := range rec.Upload.Result.Chunks {
					if previous.ID == plan.Object.ID {
						chunk = previous
						break
					}
				}
			}
			if chunk.ID == 0 {
				return ErrWritePlanConflict
			}
			for _, leg := range plan.Transfer.Legs {
				if types.ContainsUint64(chunk.Done, leg.ToNodeID) && !types.ContainsUint64(chunk.Suspect, leg.ToNodeID) {
					continue
				}
				if leg.FromNodeID != 0 {
					from := loads[leg.FromNodeID]
					from.UploadBPS, err = addTransferRate(from.UploadBPS, leg.BPS)
					if err != nil {
						return err
					}
					from.Uploads++
					loads[leg.FromNodeID] = from
				}
				to := loads[leg.ToNodeID]
				to.DownloadBPS, err = addTransferRate(to.DownloadBPS, leg.BPS)
				if err != nil {
					return err
				}
				to.Downloads++
				loads[leg.ToNodeID] = to
			}
		}
		return nil
	})
	return loads, err
}

func (s *Store) WriteTransferLoads(now time.Time) (map[uint64]TransferLoad, error) {
	var out map[uint64]TransferLoad
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		out, err = writeTransferLoadsTx(tx, now)
		if err != nil {
			return err
		}
		protection, _, err := protectionLeaseLoadTx(tx, now)
		if err != nil {
			return err
		}
		return mergeTransferLoads(out, protection)
	})
	return out, err
}

func validateWriteTransferBudgetTx(tx *bolt.Tx, choice types.WriteChunkPlan, now time.Time) error {
	if choice.Transfer == nil {
		return nil
	}
	loads, err := writeTransferLoadsTx(tx, now)
	if err != nil {
		return err
	}
	protection, _, err := protectionLeaseLoadTx(tx, now)
	if err != nil {
		return err
	}
	if err := mergeTransferLoads(loads, protection); err != nil {
		return err
	}
	for _, leg := range choice.Transfer.Legs {
		if leg.FromNodeID != 0 {
			from := loads[leg.FromNodeID]
			from.UploadBPS, err = addTransferRate(from.UploadBPS, leg.BPS)
			if err != nil {
				return err
			}
			from.Uploads++
			loads[leg.FromNodeID] = from
		}
		to := loads[leg.ToNodeID]
		to.DownloadBPS, err = addTransferRate(to.DownloadBPS, leg.BPS)
		if err != nil {
			return err
		}
		to.Downloads++
		loads[leg.ToNodeID] = to
	}
	for id, load := range loads {
		var profile NodePlacementProfile
		if err := readAutonomy(tx, "profile", fmt.Sprint(id), &profile); err != nil {
			return ErrWriteBudget
		}
		if profile.UploadBPS == 0 || profile.DownloadBPS == 0 || profile.MaxTransferConcurrency < 1 || load.UploadBPS > profile.UploadBPS || load.DownloadBPS > profile.DownloadBPS || load.Uploads > profile.MaxTransferConcurrency || load.Downloads > profile.MaxTransferConcurrency {
			return ErrWriteBudget
		}
	}
	return nil
}
