package meta

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

const (
	objectPending     = "pending"
	objectLive        = "live"
	objectRetired     = "retired"
	objectDeleting    = "deleting"
	objectUploadTTL   = 24 * time.Hour
	objectRetireGrace = 10 * time.Minute
)

var ErrObjectChanged = fmt.Errorf("%w: content object changed", ErrCommitFailed)

// ObjectRecord also protects reserved uploads from GC before their inode is published.
type ObjectRecord struct {
	ID             uint64           `json:"id"`
	FileID         uint64           `json:"file_id,omitempty"`
	Generation     uint64           `json:"generation,omitempty"`
	State          string           `json:"state"`
	Size           int64            `json:"size"`
	Checksum       uint32           `json:"checksum"`
	Replicas       []uint64         `json:"replicas"`
	Done           []uint64         `json:"done,omitempty"`
	Suspect        []uint64         `json:"suspect,omitempty"`
	IntegrityEpoch uint64           `json:"integrity_epoch,omitempty"`
	ExpiresAt      time.Time        `json:"expires_at,omitempty"`
	Target         *SmallFileTarget `json:"target,omitempty"`
}

type SmallFileTarget struct {
	ParentID           uint64    `json:"parent_id"`
	Name               string    `json:"name"`
	RemotePath         string    `json:"remote_path,omitempty"`
	FileID             uint64    `json:"expected_file_id,omitempty"`
	ExpectedGeneration uint64    `json:"expected_generation,omitempty"`
	ObjectID           uint64    `json:"object_id,omitempty"`
	Size               int64     `json:"size"`
	Checksum           uint32    `json:"checksum"`
	Replicas           []uint64  `json:"replicas"`
	PrimaryID          uint64    `json:"primary_id"`
	Mtime              time.Time `json:"mtime"`
	Overwrite          bool      `json:"overwrite"`
	OpID               string    `json:"op_id,omitempty"`
	Fingerprint        string    `json:"fingerprint,omitempty"`
}

func objectTx(tx *bolt.Tx, id uint64) (ObjectRecord, error) {
	var obj ObjectRecord
	raw := tx.Bucket(bucketObjects).Get(u64be(id))
	if raw == nil {
		return obj, ErrNotExist
	}
	err := json.Unmarshal(raw, &obj)
	return obj, err
}

func (w *txw) putObject(obj ObjectRecord) error {
	raw, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return w.put(bcObjects, bucketObjects, u64be(obj.ID), raw)
}

func (w *txw) nextObjectID() (uint64, error) {
	id := types.ObjectIDBase
	if raw := w.tx.Bucket(bucketMeta).Get(keyNextObject); raw != nil {
		id = beU64(raw)
	}
	if id < types.ObjectIDBase || id == ^uint64(0) {
		return 0, errors.New("invalid or exhausted content object id allocator")
	}
	if err := w.put(bcMeta, bucketMeta, keyNextObject, u64be(id+1)); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) AllocateObjectID() (uint64, error) {
	var id uint64
	err := s.write(func(w *txw) error {
		var err error
		id, err = w.nextObjectID()
		return err
	})
	return id, err
}

func resolvePathTx(tx *bolt.Tx, remote string) (types.Inode, error) {
	in, err := getInodeTx(tx, RootID)
	if err != nil {
		return in, err
	}
	for _, name := range strings.Split(path.Clean("/"+remote), "/") {
		if name == "" {
			continue
		}
		if in.Type != types.TypeDir {
			return types.Inode{}, ErrNotDir
		}
		id := tx.Bucket(bucketChildren).Get(childKey(in.ID, name))
		if id == nil {
			return types.Inode{}, ErrNotExist
		}
		in, err = getInodeTx(tx, beU64(id))
		if err != nil {
			return types.Inode{}, err
		}
	}
	return in, nil
}

func smallTargetTx(tx *bolt.Tx, t SmallFileTarget) (types.Inode, bool, error) {
	parent, err := getInodeTx(tx, t.ParentID)
	if err != nil {
		return types.Inode{}, false, err
	}
	if parent.Type != types.TypeDir {
		return types.Inode{}, false, ErrNotDir
	}
	if t.RemotePath != "" {
		resolved, err := resolvePathTx(tx, path.Dir(t.RemotePath))
		if err != nil {
			return types.Inode{}, false, err
		}
		if resolved.ID != t.ParentID || path.Base(t.RemotePath) != t.Name {
			return types.Inode{}, false, ErrObjectChanged
		}
	}
	raw := tx.Bucket(bucketChildren).Get(childKey(t.ParentID, t.Name))
	if raw == nil {
		return types.Inode{}, false, nil
	}
	in, err := getInodeTx(tx, beU64(raw))
	return in, true, err
}

// PrepareSmallFile reserves an immutable content address in the same transaction as its upload record.
func (s *Store) PrepareSmallFile(t SmallFileTarget) (ObjectRecord, *OpRecord, error) {
	if err := validateName(t.Name); err != nil {
		return ObjectRecord{}, nil, err
	}
	if t.Size <= 0 || t.Size > types.SmallFileMax || t.PrimaryID == 0 ||
		!types.ContainsUint64(t.Replicas, t.PrimaryID) {
		return ObjectRecord{}, nil, errors.New("invalid small file upload")
	}
	var obj ObjectRecord
	var replay *OpRecord
	err := s.write(func(w *txw) error {
		if rec, ok, err := opResultTx(w.tx, t.OpID, "small", t.Fingerprint); err != nil {
			return err
		} else if ok {
			replay = &rec
			return nil
		}
		in, exists, err := smallTargetTx(w.tx, t)
		if err != nil {
			return err
		}
		if exists && (in.Type == types.TypeDir || !t.Overwrite) {
			return ErrExist
		}
		if exists {
			t.FileID, t.ExpectedGeneration = in.ID, in.Generation
		} else {
			t.FileID, t.ExpectedGeneration = 0, 0
		}
		id, err := w.nextObjectID()
		if err != nil {
			return err
		}
		t.ObjectID = id
		obj = ObjectRecord{ID: id, State: objectPending, Size: t.Size, Checksum: t.Checksum,
			Replicas: append([]uint64(nil), t.Replicas...), ExpiresAt: time.Now().Add(objectUploadTTL), Target: &t}
		return w.putObject(obj)
	})
	return obj, replay, err
}

func (s *Store) CommitSmallFile(objectID uint64) (types.Inode, types.Inode, bool, bool, error) {
	var out, old types.Inode
	var hadOld, replay bool
	err := s.write(func(w *txw) error {
		obj, err := objectTx(w.tx, objectID)
		if err != nil {
			return err
		}
		if obj.Target == nil {
			return ErrObjectChanged
		}
		t := *obj.Target
		if rec, ok, err := opResultTx(w.tx, t.OpID, "small", t.Fingerprint); err != nil {
			return err
		} else if ok {
			out, replay = rec.Inode, true
			if obj.State == objectPending {
				return w.retireObject(objectID)
			}
			return nil
		}
		if obj.State != objectPending || time.Now().After(obj.ExpiresAt) {
			return ErrObjectChanged
		}
		current, exists, err := smallTargetTx(w.tx, t)
		if err != nil {
			return err
		}
		if exists && (!t.Overwrite || current.Type == types.TypeDir) {
			return ErrExist
		}
		if exists != (t.FileID != 0) || (exists && (current.ID != t.FileID || current.Generation != t.ExpectedGeneration)) {
			return ErrObjectChanged
		}
		if exists {
			old, hadOld = current, true
			if current.Type == types.TypeFile {
				if current.Generation == ^uint64(0) {
					return errors.New("generation exhausted")
				}
				out = current
				out.Generation++
			} else {
				if err := w.delInode(current.ID); err != nil {
					return err
				}
			}
			if err := w.retireContent(current); err != nil {
				return err
			}
		}
		if out.ID == 0 {
			id, err := w.nextID(keyNextInode)
			if err != nil {
				return err
			}
			out = types.Inode{ID: id, ParentID: t.ParentID, Name: t.Name, Type: types.TypeFile, Generation: 1}
		}
		out.ObjID, out.Chunked, out.Chunks = obj.ID, false, nil
		out.Size, out.Checksum, out.Mtime = t.Size, t.Checksum, t.Mtime
		out.Replicas = append([]uint64(nil), obj.Replicas...)
		if types.ContainsUint64(obj.Suspect, t.PrimaryID) {
			return ErrCommitFailed
		}
		out.DoneReplicas = appendUnique(append([]uint64(nil), obj.Done...), t.PrimaryID)
		out.SuspectReplicas = append([]uint64(nil), obj.Suspect...)
		out.IntegrityEpoch = obj.IntegrityEpoch
		if err := w.putInode(&out); err != nil {
			return err
		}
		if err := w.putChild(t.ParentID, t.Name, out.ID); err != nil {
			return err
		}
		return w.putOpResult(t.OpID, "small", t.Fingerprint, out, time.Now())
	})
	return out, old, hadOld, replay, err
}

func (w *txw) updateObjectIndex(in *types.Inode) error {
	before, err := getInodeTx(w.tx, in.ID)
	if err != nil && !errors.Is(err, ErrNotExist) {
		return err
	}
	if err == nil && before.ObjID != 0 && (in.Chunked || before.ObjID != in.ObjID) {
		if err := w.retireObject(before.ObjID); err != nil {
			return err
		}
	}
	if in.ObjID == 0 || in.Chunked {
		return nil
	}
	obj, err := objectTx(w.tx, in.ObjID)
	if err != nil {
		return fmt.Errorf("content object %d is not reserved: %w", in.ObjID, err)
	}
	if obj.State != objectPending && !(obj.State == objectLive && obj.FileID == in.ID) {
		return ErrObjectChanged
	}
	if obj.Size != in.Size || obj.Checksum != in.Checksum {
		return ErrObjectChanged
	}
	obj.FileID, obj.Generation, obj.State = in.ID, in.Generation, objectLive
	obj.ExpiresAt = time.Time{}
	obj.Replicas = append([]uint64(nil), in.Replicas...)
	obj.Done = append([]uint64(nil), in.DoneReplicas...)
	obj.Suspect = append([]uint64(nil), in.SuspectReplicas...)
	obj.IntegrityEpoch = in.IntegrityEpoch
	return w.putObject(obj)
}

func (w *txw) retireObject(id uint64) error {
	obj, err := objectTx(w.tx, id)
	if errors.Is(err, ErrNotExist) {
		return nil
	}
	if err != nil || obj.State == objectRetired || obj.State == objectDeleting {
		return err
	}
	d := types.ObjectIntegrity{ObjectID: obj.ID, InodeID: obj.FileID, Generation: obj.Generation, ChunkIndex: -1,
		Size: obj.Size, Checksum: obj.Checksum, ChecksumKnown: true, Replicas: obj.Replicas, Done: obj.Done, Suspect: obj.Suspect, IntegrityEpoch: obj.IntegrityEpoch}
	for _, nodeID := range obj.Replicas {
		if err := w.queueRetirement(d, nodeID, obj.FileID != 0, "retired-object", time.Now()); err != nil {
			return err
		}
	}
	obj.State, obj.ExpiresAt = objectRetired, time.Now().Add(objectRetireGrace)
	return w.putObject(obj)
}

// retireContent 把 inode 当前引用的内容对象转入退休状态。
// 分块文件的对象不在 objects 表（回收由 chunk 回收通道负责），仅 legacy 小文件有记录。
func (w *txw) retireContent(in types.Inode) error {
	if in.Chunked || in.Type != types.TypeFile {
		return nil
	}
	if in.ObjID == 0 {
		return nil // v1 旧对象无登记表，调用方按旧路径处理
	}
	return w.retireObject(in.ObjID)
}

func (s *Store) AbortSmallFile(id uint64) error {
	return s.write(func(w *txw) error {
		obj, err := objectTx(w.tx, id)
		if errors.Is(err, ErrNotExist) {
			return nil
		}
		if err != nil || obj.State != objectPending {
			return err
		}
		return w.retireObject(id)
	})
}

// ProtectedObjectIDs retains live uploads and detached published content.
func (s *Store) ProtectedObjectIDs() (map[uint64]bool, error) {
	out := make(map[uint64]bool)
	now := time.Now()
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketObjects).ForEach(func(_, v []byte) error {
			var obj ObjectRecord
			if err := json.Unmarshal(v, &obj); err != nil {
				return err
			}
			if obj.State == objectLive || obj.State == objectPending || obj.ExpiresAt.After(now) || obj.FileID != 0 {
				out[obj.ID] = true
			}
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket(bucketRetired).ForEach(func(k, v []byte) error {
			rec, err := decodeRetirementRecord(k, v)
			if err != nil {
				return err
			}
			if rec.State != RetirementConfirmed {
				out[rec.ObjectID] = true
			}
			return nil
		})
	})
	return out, err
}

// Expired registry entries become durable retirement records before losing their upload roots.
func (s *Store) SweepExpiredObjects() (int, error) {
	removed := 0
	now := time.Now()
	err := s.write(func(w *txw) error {
		var expired []ObjectRecord
		if err := w.tx.Bucket(bucketObjects).ForEach(func(_, v []byte) error {
			var obj ObjectRecord
			if err := json.Unmarshal(v, &obj); err != nil {
				return err
			}
			if (obj.State == objectPending || obj.State == objectRetired) && !obj.ExpiresAt.After(now) {
				expired = append(expired, obj)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, obj := range expired {
			d := types.ObjectIntegrity{ObjectID: obj.ID, InodeID: obj.FileID, Generation: obj.Generation, ChunkIndex: -1,
				Size: obj.Size, Checksum: obj.Checksum, ChecksumKnown: true, Replicas: obj.Replicas, Done: obj.Done, Suspect: obj.Suspect, IntegrityEpoch: obj.IntegrityEpoch}
			for _, nodeID := range obj.Replicas {
				if err := w.queueRetirement(d, nodeID, obj.FileID != 0, "expired-object", now); err != nil {
					return err
				}
			}
			if err := w.del(bcObjects, bucketObjects, u64be(obj.ID)); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}

func (s *Store) GetObject(id uint64) (ObjectRecord, error) {
	var obj ObjectRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		obj, err = objectTx(tx, id)
		return err
	})
	return obj, err
}

// MarkObjectDone resolves by physical identity; late reports never modify a newer file version.
func (s *Store) MarkObjectDone(id, nodeID uint64) error {
	return s.write(func(w *txw) error {
		obj, err := objectTx(w.tx, id)
		if err != nil {
			return err
		}
		if obj.State != objectPending && obj.State != objectLive {
			return nil
		}
		if !types.ContainsUint64(obj.Replicas, nodeID) || types.ContainsUint64(obj.Suspect, nodeID) {
			return nil
		}
		obj.Done = appendUnique(obj.Done, nodeID)
		if obj.State == objectLive {
			in, err := getInodeTx(w.tx, obj.FileID)
			if err != nil {
				return err
			}
			if in.Chunked || in.ObjID != id || in.Generation != obj.Generation || types.ContainsUint64(in.SuspectReplicas, nodeID) {
				return nil
			}
			in.DoneReplicas = appendUnique(in.DoneReplicas, nodeID)
			return w.putInode(&in)
		}
		return w.putObject(obj)
	})
}

func (s *Store) ReplaceObjectReplica(fileID, objectID, generation, oldNodeID, newNodeID uint64) error {
	return s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, fileID)
		if err != nil {
			return err
		}
		if in.Chunked || types.ObjIDFor(in) != objectID || in.Generation != generation {
			return ErrObjectChanged
		}
		if types.ContainsUint64(in.Replicas, newNodeID) {
			return ErrReplicaDup
		}
		found := false
		for i, id := range in.Replicas {
			if id == oldNodeID {
				in.Replicas[i], found = newNodeID, true
				break
			}
		}
		if !found {
			return ErrObjectChanged
		}
		done := make([]uint64, 0, len(in.DoneReplicas))
		for _, id := range in.DoneReplicas {
			if id != oldNodeID {
				done = append(done, id)
			}
		}
		in.DoneReplicas = done
		in.SuspectReplicas = withoutReplica(in.SuspectReplicas, oldNodeID)
		if err := bumpIntegrityEpoch(&in.IntegrityEpoch); err != nil {
			return err
		}
		return w.putInode(&in)
	})
}

func (s *Store) RemoveObjectDone(id, nodeID uint64) error {
	return s.write(func(w *txw) error {
		obj, err := objectTx(w.tx, id)
		if err != nil || obj.State != objectLive {
			return err
		}
		in, err := getInodeTx(w.tx, obj.FileID)
		if err != nil || in.ObjID != id {
			return err
		}
		done := make([]uint64, 0, len(in.DoneReplicas))
		for _, n := range in.DoneReplicas {
			if n != nodeID {
				done = append(done, n)
			}
		}
		in.DoneReplicas = done
		return w.putInode(&in)
	})
}
