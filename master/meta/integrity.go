package meta

import (
	"encoding/json"
	"errors"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func describeInodeObject(in types.Inode, objectID uint64) (types.ObjectIntegrity, bool) {
	if in.Type != types.TypeFile {
		return types.ObjectIntegrity{}, false
	}
	d := types.ObjectIntegrity{ObjectID: objectID, InodeID: in.ID, Generation: in.Generation, ChunkIndex: -1}
	if in.Chunked {
		for _, ch := range in.Chunks {
			if types.ChunkObjID(ch, in.ID) != objectID {
				continue
			}
			d.Chunked, d.ChunkIndex = true, ch.Index
			d.Size, d.Checksum, d.ChecksumKnown = ch.Size, ch.Checksum, ch.ChecksumKnown || ch.Checksum != 0
			d.IntegrityEpoch = ch.IntegrityEpoch
			d.WriteEpoch = ch.WriteEpoch
			d.Replicas, d.Done, d.Suspect = ch.Replicas, ch.Done, ch.Suspect
			return d, true
		}
		return types.ObjectIntegrity{}, false
	}
	if types.ObjIDFor(in) != objectID {
		return types.ObjectIntegrity{}, false
	}
	d.Size, d.Checksum, d.ChecksumKnown = in.Size, in.Checksum, in.ObjID != 0 || in.Checksum != 0
	d.IntegrityEpoch = in.IntegrityEpoch
	d.Replicas, d.Done, d.Suspect = in.Replicas, in.DoneReplicas, in.SuspectReplicas
	return d, true
}

func integrityTx(tx *bolt.Tx, id uint64) (types.ObjectIntegrity, error) {
	if id >= types.ObjectIDBase {
		obj, err := objectTx(tx, id)
		if err != nil {
			return types.ObjectIntegrity{}, err
		}
		if obj.State != objectLive && obj.State != objectPending {
			return types.ObjectIntegrity{}, ErrNotExist
		}
		if obj.State == objectPending {
			return types.ObjectIntegrity{ObjectID: obj.ID, InodeID: obj.FileID, Generation: obj.Generation,
				ChunkIndex: -1, Size: obj.Size, Checksum: obj.Checksum, ChecksumKnown: true,
				IntegrityEpoch: obj.IntegrityEpoch, Replicas: obj.Replicas, Done: obj.Done, Suspect: obj.Suspect}, nil
		}
		in, err := getInodeTx(tx, obj.FileID)
		if err != nil {
			return types.ObjectIntegrity{}, err
		}
		if d, ok := describeInodeObject(in, id); ok {
			return d, nil
		}
		return types.ObjectIntegrity{}, ErrNotExist
	}
	owner := id
	if id >= types.StagingInodeBase<<8 {
		owner, _ = types.ParseChunkID(id)
		if hasPlannedWriteTx(tx, owner) {
			rec, err := plannedWriteTx(tx, owner)
			if err != nil {
				return types.ObjectIntegrity{}, err
			}
			if rec.Upload.State == types.WriteAborted || (rec.Upload.State == types.WritePending && !time.Now().Before(rec.Upload.ExpiresAt)) {
				return types.ObjectIntegrity{}, ErrWriteExpired
			}
			if rec.Upload.State == types.WritePending {
				for _, plan := range rec.Upload.Chunks {
					if plan.Object.ID == id && plan.Recovery != nil && !time.Now().Before(plan.Recovery.HardUntil) {
						return types.ObjectIntegrity{}, ErrWriteExpired
					}
				}
			}
		}
	}
	if in, err := getInodeTx(tx, owner); err == nil {
		if d, ok := describeInodeObject(in, id); ok {
			return d, nil
		}
	} else if !errors.Is(err, ErrNotExist) {
		return types.ObjectIntegrity{}, err
	}
	// Adopted chunks outlive their staging inode; match physical IDs, never an index alone.
	var result types.ObjectIntegrity
	found := false
	err := tx.Bucket(bucketInodes).ForEach(func(_, raw []byte) error {
		if found {
			return nil
		}
		var in types.Inode
		if err := json.Unmarshal(raw, &in); err != nil {
			return err
		}
		if d, ok := describeInodeObject(in, id); ok {
			result, found = d, true
		}
		return nil
	})
	if err != nil {
		return types.ObjectIntegrity{}, err
	}
	if !found {
		return types.ObjectIntegrity{}, ErrNotExist
	}
	return result, nil
}

func (s *Store) ObjectIntegrity(id uint64) (types.ObjectIntegrity, error) {
	var result types.ObjectIntegrity
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		result, err = integrityTx(tx, id)
		return err
	})
	return result, err
}

func sameObjectContents(a, b types.ObjectIntegrity) bool {
	if a.ObjectID != b.ObjectID || a.Size != b.Size || a.ChecksumKnown != b.ChecksumKnown || a.Checksum != b.Checksum || a.Chunked != b.Chunked || a.WriteEpoch != b.WriteEpoch {
		return false
	}
	if a.Chunked && a.ChunkIndex != b.ChunkIndex {
		return false
	}
	if a.InodeID == b.InodeID && a.Generation == b.Generation {
		return true
	}
	// Only the recorded pending/staging origin may cross the publication boundary.
	if a.ObjectID >= types.ObjectIDBase {
		return b.InodeID == 0 && b.Generation == 0
	}
	if a.Chunked && a.ObjectID >= types.StagingInodeBase<<8 {
		origin, _ := types.ParseChunkID(a.ObjectID)
		return b.InodeID == origin && b.Generation == 0
	}
	return false
}

func withoutReplica(ids []uint64, nodeID uint64) []uint64 {
	out := make([]uint64, 0, len(ids))
	for _, id := range ids {
		if id != nodeID {
			out = append(out, id)
		}
	}
	return out
}

func bumpIntegrityEpoch(epoch *uint64) error {
	if *epoch == ^uint64(0) {
		return errors.New("integrity epoch exhausted")
	}
	*epoch++
	return nil
}

func (s *Store) MarkVerifiedObjectDone(expected types.ObjectIntegrity, nodeID uint64) (bool, error) {
	return s.MarkVerifiedObjectDoneWithUsage(expected, nodeID, nil)
}

func (s *Store) MarkVerifiedObjectDoneWithUsage(expected types.ObjectIntegrity, nodeID uint64, usage *types.NodeUsage) (bool, error) {
	if usage != nil && !validNodeUsage(*usage) {
		return false, ErrWritePlanConflict
	}
	if !expected.ChecksumKnown {
		return false, nil
	}
	if expected.PlanID != "" {
		return s.markProtectionDone(expected, nodeID, usage)
	}
	return s.markIntegrityDone(expected, nodeID, true, usage)
}

// Length-only compatibility receipts never clear a suspect replica or claim content verification.
func (s *Store) MarkObjectPresent(expected types.ObjectIntegrity, nodeID uint64) (bool, error) {
	if expected.ChecksumKnown || expected.PlanID != "" {
		return false, nil
	}
	return s.markIntegrityDone(expected, nodeID, false, nil)
}

func (s *Store) markIntegrityDone(expected types.ObjectIntegrity, nodeID uint64, verified bool, usage *types.NodeUsage) (bool, error) {
	marked := false
	err := s.write(func(w *txw) error {
		current, err := integrityTx(w.tx, expected.ObjectID)
		if errors.Is(err, ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !sameObjectContents(current, expected) || current.IntegrityEpoch != expected.IntegrityEpoch ||
			!types.ContainsUint64(current.Replicas, nodeID) || (!verified && types.ContainsUint64(current.Suspect, nodeID)) {
			return nil
		}
		if err := recordWriteUsage(w, current, nodeID, usage); err != nil {
			return err
		}
		if types.ContainsUint64(current.Done, nodeID) && !types.ContainsUint64(current.Suspect, nodeID) {
			marked = true
			return nil
		}
		if current.InodeID == 0 && current.ObjectID >= types.ObjectIDBase {
			obj, err := objectTx(w.tx, current.ObjectID)
			if err != nil {
				return err
			}
			obj.Done = appendUnique(obj.Done, nodeID)
			obj.Suspect = withoutReplica(obj.Suspect, nodeID)
			marked = true
			return w.putObject(obj)
		}
		in, err := getInodeTx(w.tx, current.InodeID)
		if err != nil {
			return err
		}
		if current.Chunked {
			for i := range in.Chunks {
				ch := &in.Chunks[i]
				if types.ChunkObjID(*ch, in.ID) == current.ObjectID {
					ch.Done = appendUnique(ch.Done, nodeID)
					ch.Suspect = withoutReplica(ch.Suspect, nodeID)
					marked = true
					return w.putInode(&in)
				}
			}
			return ErrChunkNotExist
		}
		in.DoneReplicas = appendUnique(in.DoneReplicas, nodeID)
		in.SuspectReplicas = withoutReplica(in.SuspectReplicas, nodeID)
		marked = true
		return w.putInode(&in)
	})
	if err == nil && marked {
		err = s.EnsureDurable()
	}
	return marked, err
}

func markSuspectTx(w *txw, current types.ObjectIntegrity, nodeID uint64) (bool, error) {
	if !types.ContainsUint64(current.Replicas, nodeID) || types.ContainsUint64(current.Suspect, nodeID) {
		return false, nil
	}
	if current.InodeID == 0 && current.ObjectID >= types.ObjectIDBase {
		obj, err := objectTx(w.tx, current.ObjectID)
		if err != nil {
			return false, err
		}
		if err := bumpIntegrityEpoch(&obj.IntegrityEpoch); err != nil {
			return false, err
		}
		obj.Done = withoutReplica(obj.Done, nodeID)
		obj.Suspect = appendUnique(obj.Suspect, nodeID)
		return true, w.putObject(obj)
	}
	in, err := getInodeTx(w.tx, current.InodeID)
	if err != nil {
		return false, err
	}
	if current.Chunked {
		for i := range in.Chunks {
			ch := &in.Chunks[i]
			if types.ChunkObjID(*ch, in.ID) != current.ObjectID {
				continue
			}
			if err := bumpIntegrityEpoch(&ch.IntegrityEpoch); err != nil {
				return false, err
			}
			ch.Done = withoutReplica(ch.Done, nodeID)
			ch.Suspect = appendUnique(ch.Suspect, nodeID)
			return true, w.putInode(&in)
		}
		return false, ErrChunkNotExist
	}
	if err := bumpIntegrityEpoch(&in.IntegrityEpoch); err != nil {
		return false, err
	}
	in.DoneReplicas = withoutReplica(in.DoneReplicas, nodeID)
	in.SuspectReplicas = appendUnique(in.SuspectReplicas, nodeID)
	return true, w.putInode(&in)
}

func (s *Store) MarkChunkSuspect(fileID, generation uint64, index int, objectID, nodeID uint64, size int64, checksum uint32) (bool, error) {
	changed := false
	err := s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, fileID)
		if errors.Is(err, ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		d, ok := describeInodeObject(in, objectID)
		if !ok || !d.Chunked || d.Generation != generation || d.ChunkIndex != index || d.Size != size || d.Checksum != checksum {
			return nil
		}
		changed, err = markSuspectTx(w, d, nodeID)
		return err
	})
	return changed, err
}

func (s *Store) MarkPhysicalObjectSuspect(expected types.ObjectIntegrity, nodeID uint64) (bool, error) {
	changed := false
	err := s.write(func(w *txw) error {
		current, err := integrityTx(w.tx, expected.ObjectID)
		if errors.Is(err, ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !sameObjectContents(current, expected) {
			return nil
		}
		changed, err = markSuspectTx(w, current, nodeID)
		return err
	})
	return changed, err
}

func (s *Store) ReplaceChunkReplicaIfCurrent(expected types.ObjectIntegrity, oldNodeID, newNodeID uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, expected.InodeID)
		if err != nil {
			return err
		}
		if err := rejectPlannedStagingTx(w.tx, in); err != nil {
			return err
		}
		current, ok := describeInodeObject(in, expected.ObjectID)
		if !ok || !current.Chunked || current.Generation != expected.Generation ||
			!sameObjectContents(current, expected) || current.IntegrityEpoch != expected.IntegrityEpoch {
			return ErrObjectChanged
		}
		for i := range in.Chunks {
			ch := &in.Chunks[i]
			if types.ChunkObjID(*ch, in.ID) != expected.ObjectID {
				continue
			}
			if newNodeID == 0 || types.ContainsUint64(ch.Replicas, newNodeID) {
				return ErrReplicaDup
			}
			for j, id := range ch.Replicas {
				if id != oldNodeID {
					continue
				}
				if err := bumpIntegrityEpoch(&ch.IntegrityEpoch); err != nil {
					return err
				}
				ch.Replicas[j] = newNodeID
				ch.Done = withoutReplica(ch.Done, oldNodeID)
				ch.Suspect = withoutReplica(ch.Suspect, oldNodeID)
				return w.putInode(&in)
			}
			return ErrObjectChanged
		}
		return ErrChunkNotExist
	})
}
