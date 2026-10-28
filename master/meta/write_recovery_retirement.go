package meta

import (
	"encoding/json"
	"strings"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func retirementDetachedReplicaTx(tx *bolt.Tx, rec RetirementRecord) (bool, error) {
	if rec.Reason != "write-reassigned" {
		return retirementUnreferencedTx(tx, rec.ObjectID)
	}
	if rec.ObjectID < types.StagingInodeBase<<8 || rec.ObjectID >= types.ObjectIDBase {
		return false, ErrRetirementConflict
	}
	origin, index := types.ParseChunkID(rec.ObjectID)
	write, err := plannedWriteTx(tx, origin)
	if err != nil {
		return false, err
	}
	found := false
	for _, plan := range write.Upload.Chunks {
		if plan.Index != index || plan.Object.ID != rec.ObjectID {
			continue
		}
		if plan.Recovery == nil || !types.ContainsUint64(plan.Recovery.Excluded, rec.NodeID) || types.ContainsUint64(plan.Layout.Nodes, rec.NodeID) {
			return false, ErrRetirementConflict
		}
		found = true
	}
	if !found {
		return false, ErrRetirementConflict
	}
	protected := false
	check := func(d types.ObjectIntegrity) {
		if d.ObjectID == rec.ObjectID && types.ContainsUint64(d.Replicas, rec.NodeID) {
			protected = true
		}
	}
	if err := tx.Bucket(bucketInodes).ForEach(func(_, raw []byte) error {
		var in types.Inode
		if err := json.Unmarshal(raw, &in); err != nil {
			return err
		}
		for _, d := range inodeObjects(in) {
			check(d)
		}
		return nil
	}); err != nil {
		return false, err
	}
	if raw := tx.Bucket(bucketObjects).Get(u64be(rec.ObjectID)); raw != nil {
		var object ObjectRecord
		if err := json.Unmarshal(raw, &object); err != nil {
			return false, err
		}
		if types.ContainsUint64(object.Replicas, rec.NodeID) {
			protected = true
		}
	}
	if err := tx.Bucket(bucketRetired).ForEach(func(key, raw []byte) error {
		other, err := decodeRetirementRecord(key, raw)
		if err != nil {
			return err
		}
		if other.ObjectID == rec.ObjectID && other.NodeID == rec.NodeID && other.State == RetirementHeld {
			protected = true
		}
		return nil
	}); err != nil {
		return false, err
	}
	if err := walkAutonomy(tx, "plan", func(raw []byte) error {
		var plan ProtectionPlan
		if err := json.Unmarshal(raw, &plan); err != nil {
			return err
		}
		if plan.Expected.ObjectID != rec.ObjectID || plan.State != ProtectionPending {
			return nil
		}
		check(plan.Expected)
		for _, target := range plan.Targets {
			if target.NodeID == rec.NodeID {
				protected = true
			}
		}
		return nil
	}); err != nil {
		return false, err
	}
	if err := tx.Bucket(bucketWrites).ForEach(func(key, raw []byte) error {
		if !strings.HasPrefix(string(key), "upload/") {
			return nil
		}
		var other plannedWriteRecord
		if err := json.Unmarshal(raw, &other); err != nil {
			return err
		}
		if other.Upload.ID == origin || other.Upload.State == types.WriteAborted {
			return nil
		}
		for _, plan := range other.Upload.Chunks {
			if plan.Object.ID == rec.ObjectID && types.ContainsUint64(plan.Layout.Nodes, rec.NodeID) {
				protected = true
			}
		}
		return nil
	}); err != nil {
		return false, err
	}
	return !protected, nil
}
