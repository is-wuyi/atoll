package meta

import (
	"encoding/json"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func storedUsageCoveredTx(tx *bolt.Tx, objectID, nodeID uint64) (bool, error) {
	covered, err := writeUsageCoveredTx(tx, objectID, nodeID)
	if err != nil || covered {
		return covered, err
	}
	return protectionUsageCoveredTx(tx, objectID, nodeID)
}

// Metadata allocation alone cannot show that a node sample already includes new bytes.
func capacityReservationsTx(tx *bolt.Tx) (map[[2]uint64]int64, error) {
	out, err := writeReservationsTx(tx)
	if err != nil {
		return nil, err
	}
	reserve := func(objectID, nodeID uint64, size int64) error {
		retired, err := retirementConfirmedTx(tx, objectID, nodeID)
		if err != nil || retired {
			return err
		}
		if objectID == 0 || nodeID == 0 || size < 0 {
			return ErrProtectionBudget
		}
		key := [2]uint64{objectID, nodeID}
		if previous, ok := out[key]; ok && previous != size {
			return ErrProtectionBudget
		}
		out[key] = size
		return nil
	}
	uncovered := func(d types.ObjectIntegrity) error {
		for _, nodeID := range d.Replicas {
			covered := false
			if types.ContainsUint64(d.Done, nodeID) && !types.ContainsUint64(d.Suspect, nodeID) {
				var err error
				covered, err = storedUsageCoveredTx(tx, d.ObjectID, nodeID)
				if err != nil {
					return err
				}
			}
			if !covered {
				if err := reserve(d.ObjectID, nodeID, d.Size); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := tx.Bucket(bucketInodes).ForEach(func(_, raw []byte) error {
		var in types.Inode
		if err := json.Unmarshal(raw, &in); err != nil {
			return err
		}
		if in.Type != types.TypeFile || !in.Chunked && in.ObjID == 0 {
			return nil
		}
		for _, d := range inodeObjects(in) {
			if err := uncovered(d); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if err := tx.Bucket(bucketObjects).ForEach(func(_, raw []byte) error {
		var obj ObjectRecord
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		return uncovered(types.ObjectIntegrity{ObjectID: obj.ID, Size: obj.Size, Replicas: obj.Replicas, Done: obj.Done, Suspect: obj.Suspect})
	}); err != nil {
		return nil, err
	}
	if err := tx.Bucket(bucketRetired).ForEach(func(key, raw []byte) error {
		rec, err := decodeRetirementRecord(key, raw)
		if err != nil || rec.State == RetirementConfirmed {
			return err
		}
		covered, err := storedUsageCoveredTx(tx, rec.ObjectID, rec.NodeID)
		if err != nil {
			return err
		}
		if !covered {
			return reserve(rec.ObjectID, rec.NodeID, rec.Expected.Size)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if err := walkAutonomy(tx, "plan", func(raw []byte) error {
		var plan ProtectionPlan
		if err := json.Unmarshal(raw, &plan); err != nil {
			return err
		}
		for _, target := range plan.Targets {
			if !target.Done && plan.State != ProtectionPending && target.Attempts == 0 {
				continue
			}
			covered := false
			if target.Done {
				var err error
				covered, err = protectionUsageCoveredTx(tx, plan.Expected.ObjectID, target.NodeID)
				if err != nil {
					return err
				}
			}
			if !covered {
				if err := reserve(plan.Expected.ObjectID, target.NodeID, plan.Expected.Size); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}
