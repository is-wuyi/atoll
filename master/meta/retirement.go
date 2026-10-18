package meta

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

const (
	RetirementHeld      = "held"
	RetirementPending   = "pending"
	RetirementAttempted = "attempted"
	RetirementConfirmed = "confirmed"
)

var (
	ErrRetirementConflict    = errors.New("object retirement conflicts with current state")
	keyRetirementInitialized = []byte("retirement_initialized_v1")
)

type RetirementRecord struct {
	ObjectID    uint64                         `json:"object_id"`
	NodeID      uint64                         `json:"node_id"`
	FenceID     string                         `json:"fence_id"`
	Expected    types.ObjectIntegrity          `json:"expected"`
	State       string                         `json:"state"`
	Reason      string                         `json:"reason"`
	CreatedAt   time.Time                      `json:"created_at"`
	Attempt     *types.ObjectRetirement        `json:"attempt,omitempty"`
	Baseline    *types.NodeInfo                `json:"baseline,omitempty"`
	NextAttempt time.Time                      `json:"next_attempt,omitempty"`
	Receipt     *types.ObjectRetirementReceipt `json:"receipt,omitempty"`
	ConfirmedAt time.Time                      `json:"confirmed_at,omitempty"`
}

func retirementKey(objectID, nodeID uint64) []byte {
	key := make([]byte, 0, 16)
	key = append(key, u64be(objectID)...)
	return append(key, u64be(nodeID)...)
}

func retirementToken(prefix string) (string, error) {
	var buf [24]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buf[:]), nil
}

func decodeRetirementRecord(key, raw []byte) (RetirementRecord, error) {
	var rec RetirementRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, err
	}
	if len(key) != 16 || !bytes.Equal(key, retirementKey(rec.ObjectID, rec.NodeID)) || rec.ObjectID == 0 || rec.NodeID == 0 ||
		rec.Expected.ObjectID != rec.ObjectID || rec.Expected.Size < 0 || !types.ValidRetirementToken(rec.FenceID) || rec.CreatedAt.IsZero() {
		return rec, ErrRetirementConflict
	}
	switch rec.State {
	case RetirementHeld, RetirementPending:
		if rec.Attempt != nil || rec.Receipt != nil {
			return rec, ErrRetirementConflict
		}
	case RetirementAttempted, RetirementConfirmed:
		if rec.Attempt == nil || rec.Attempt.Validate() != nil || rec.Attempt.ObjectID != rec.ObjectID || rec.Attempt.NodeID != rec.NodeID ||
			rec.Attempt.ExpectedSize != rec.Expected.Size || rec.Attempt.FenceID != rec.FenceID || rec.Baseline == nil || rec.Baseline.ID != rec.NodeID {
			return rec, ErrRetirementConflict
		}
		if rec.State == RetirementConfirmed && (rec.Receipt == nil || rec.Receipt.Validate() != nil || rec.Receipt.ObjectRetirement != *rec.Attempt || rec.ConfirmedAt.IsZero()) {
			return rec, ErrRetirementConflict
		}
	default:
		return rec, ErrRetirementConflict
	}
	return rec, nil
}

func retirementTx(tx *bolt.Tx, objectID, nodeID uint64) (RetirementRecord, error) {
	key := retirementKey(objectID, nodeID)
	raw := tx.Bucket(bucketRetired).Get(key)
	if raw == nil {
		return RetirementRecord{}, ErrNotExist
	}
	return decodeRetirementRecord(key, raw)
}

func putRetirement(w *txw, rec RetirementRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	key := retirementKey(rec.ObjectID, rec.NodeID)
	if _, err := decodeRetirementRecord(key, raw); err != nil {
		return err
	}
	marker := w.tx.Bucket(bucketMeta).Get(keyRetirementInitialized)
	if marker == nil {
		if err := w.put(bcMeta, bucketMeta, keyRetirementInitialized, []byte{1}); err != nil {
			return err
		}
	} else if !bytes.Equal(marker, []byte{1}) {
		return ErrRetirementConflict
	}
	return w.put(bcRetired, bucketRetired, key, raw)
}

func (w *txw) queueRetirement(expected types.ObjectIntegrity, nodeID uint64, held bool, reason string, now time.Time) error {
	if nodeID == 0 || expected.ObjectID == 0 || expected.Size < 0 || now.IsZero() {
		return ErrRetirementConflict
	}
	rec, err := retirementTx(w.tx, expected.ObjectID, nodeID)
	if err == nil {
		if rec.Expected.Size != expected.Size || rec.Expected.Checksum != expected.Checksum || rec.Expected.ChecksumKnown != expected.ChecksumKnown {
			return ErrRetirementConflict
		}
		if held && rec.State != RetirementHeld {
			return ErrRetirementConflict
		}
		return nil
	}
	if !errors.Is(err, ErrNotExist) {
		return err
	}
	fence, err := retirementToken("rf1_")
	if err != nil {
		return err
	}
	state := RetirementPending
	if held {
		state = RetirementHeld
	}
	return putRetirement(w, RetirementRecord{ObjectID: expected.ObjectID, NodeID: nodeID, FenceID: fence,
		Expected: expected, State: state, Reason: reason, CreatedAt: now})
}

func inodeObjects(in types.Inode) []types.ObjectIntegrity {
	if in.Type != types.TypeFile {
		return nil
	}
	var out []types.ObjectIntegrity
	if in.Chunked {
		for _, ch := range in.Chunks {
			if d, ok := describeInodeObject(in, types.ChunkObjID(ch, in.ID)); ok {
				out = append(out, d)
			}
		}
	} else if d, ok := describeInodeObject(in, types.ObjIDFor(in)); ok {
		out = append(out, d)
	}
	return out
}

// Dropped published content stays held until read leases and retention roots exist.
func (w *txw) retainDroppedContent(before types.Inode, after *types.Inode) error {
	remaining := map[uint64]bool{}
	if after != nil {
		for _, d := range inodeObjects(*after) {
			remaining[d.ObjectID] = true
		}
	}
	for _, d := range inodeObjects(before) {
		if remaining[d.ObjectID] {
			continue
		}
		// Adoption removes the staging inode after publishing the same physical IDs.
		referenced, err := inodeObjectReferencedTx(w.tx, d.ObjectID, before.ID)
		if err != nil {
			return err
		}
		if referenced {
			continue
		}
		for _, nodeID := range d.Replicas {
			if err := w.queueRetirement(d, nodeID, !before.Staging, "detached-content", time.Now()); err != nil {
				return err
			}
		}
	}
	return nil
}

func inodeObjectReferencedTx(tx *bolt.Tx, objectID, except uint64) (bool, error) {
	found := false
	err := tx.Bucket(bucketInodes).ForEach(func(_, raw []byte) error {
		var in types.Inode
		if err := json.Unmarshal(raw, &in); err != nil {
			return err
		}
		if in.ID != except {
			for _, d := range inodeObjects(in) {
				if d.ObjectID == objectID {
					found = true
				}
			}
		}
		return nil
	})
	return found, err
}

func retirementUnreferencedTx(tx *bolt.Tx, objectID uint64) (bool, error) {
	referenced, err := inodeObjectReferencedTx(tx, objectID, 0)
	if err != nil || referenced {
		return false, err
	}
	if err := tx.Bucket(bucketRetired).ForEach(func(key, raw []byte) error {
		rec, err := decodeRetirementRecord(key, raw)
		if err != nil {
			return err
		}
		if rec.ObjectID == objectID && rec.State == RetirementHeld {
			referenced = true
		}
		return nil
	}); err != nil {
		return false, err
	}
	if referenced {
		return false, nil
	}
	if raw := tx.Bucket(bucketObjects).Get(u64be(objectID)); raw != nil {
		var obj ObjectRecord
		if err := json.Unmarshal(raw, &obj); err != nil {
			return false, err
		}
		if obj.State == objectPending || obj.State == objectLive {
			return false, nil
		}
		if obj.State != objectRetired && obj.State != objectDeleting {
			return false, ErrRetirementConflict
		}
		if obj.FileID != 0 {
			return false, nil
		}
	}
	protected := false
	err = walkAutonomy(tx, "plan", func(raw []byte) error {
		var plan ProtectionPlan
		if err := json.Unmarshal(raw, &plan); err != nil {
			return err
		}
		if plan.Expected.ObjectID == objectID && plan.State == ProtectionPending {
			protected = true
		}
		return nil
	})
	return !protected, err
}

func (w *txw) retireAbortedWrite(rec plannedWriteRecord, now time.Time) error {
	if rec.Upload.State != types.WriteAborted {
		return ErrRetirementConflict
	}
	for _, p := range rec.Upload.Chunks {
		d := types.ObjectIntegrity{ObjectID: p.Object.ID, InodeID: rec.Upload.ID, Chunked: true, ChunkIndex: p.Index,
			Size: p.Object.StoredSize, Checksum: p.Object.Checksum, ChecksumKnown: p.Object.ChecksumKnown, Replicas: p.Layout.Nodes}
		for _, nodeID := range p.Layout.Nodes {
			if err := w.queueRetirement(d, nodeID, false, "aborted-write", now); err != nil {
				return err
			}
		}
	}
	if in, err := getInodeTx(w.tx, rec.Upload.ID); err == nil {
		if !in.Staging {
			return ErrRetirementConflict
		}
		return w.delInode(in.ID)
	} else if !errors.Is(err, ErrNotExist) {
		return err
	}
	return nil
}

// ReconcileRetirements also protects completed plans written before the retirement journal existed.
func (s *Store) ReconcileRetirements(now time.Time) error {
	if now.IsZero() {
		return ErrRetirementConflict
	}
	err := s.write(func(w *txw) error {
		c := w.tx.Bucket(bucketWrites).Cursor()
		prefix := []byte("upload/")
		var records []plannedWriteRecord
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var rec plannedWriteRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			validated, err := plannedWriteTx(w.tx, rec.Upload.ID)
			if err != nil {
				return err
			}
			records = append(records, validated)
		}
		for _, rec := range records {
			if rec.Upload.State == types.WriteAborted {
				if err := w.retireAbortedWrite(rec, now); err != nil {
					return err
				}
			}
			if rec.Upload.State == types.WriteCommitted {
				current, err := getInodeTx(w.tx, rec.Upload.Result.ID)
				if err != nil && !errors.Is(err, ErrNotExist) {
					return err
				}
				var after *types.Inode
				if err == nil {
					after = &current
				}
				if err := w.retainDroppedContent(*rec.Upload.Result, after); err != nil {
					return err
				}
			}
		}
		var protection []ProtectionPlan
		if err := walkAutonomy(w.tx, "plan", func(raw []byte) error {
			var plan ProtectionPlan
			if err := json.Unmarshal(raw, &plan); err != nil {
				return err
			}
			if plan.Expected.ObjectID == 0 || plan.Expected.Size <= 0 {
				return ErrRetirementConflict
			}
			switch plan.State {
			case ProtectionPending, ProtectionCompleted, ProtectionStale, ProtectionCancelled:
			default:
				return ErrRetirementConflict
			}
			protection = append(protection, plan)
			return nil
		}); err != nil {
			return err
		}
		for _, plan := range protection {
			referenced, err := inodeObjectReferencedTx(w.tx, plan.Expected.ObjectID, 0)
			if err != nil {
				return err
			}
			if referenced {
				continue
			}
			if plan.State == ProtectionPending {
				plan.State, plan.UpdatedAt = ProtectionStale, now
				plan.LastError = "content no longer published"
				if err := putAutonomy(w, "plan", plan.ID, plan); err != nil {
					return err
				}
			}
			nodes := append([]uint64(nil), plan.Expected.Replicas...)
			for _, target := range plan.Targets {
				if target.Done || target.Attempts > 0 {
					nodes = appendUnique(nodes, target.NodeID)
				}
			}
			for _, nodeID := range nodes {
				if err := w.queueRetirement(plan.Expected, nodeID, true, "detached-protection", now); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}

func (s *Store) ListRetirements() ([]RetirementRecord, error) {
	var out []RetirementRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRetired).ForEach(func(k, v []byte) error {
			rec, err := decodeRetirementRecord(k, v)
			if err == nil {
				out = append(out, rec)
			}
			return err
		})
	})
	return out, err
}

func (s *Store) ClaimRetirement(objectID, nodeID uint64, now time.Time, retryAfter, nodeMaxAge time.Duration) (types.ObjectRetirement, bool, error) {
	var req types.ObjectRetirement
	claimed := false
	if now.IsZero() || retryAfter <= 0 || nodeMaxAge <= 0 {
		return req, false, ErrRetirementConflict
	}
	err := s.write(func(w *txw) error {
		if err := requireWritePlanningTx(w.tx); err != nil {
			return err
		}
		rec, err := retirementTx(w.tx, objectID, nodeID)
		if err != nil {
			return err
		}
		if rec.State == RetirementHeld || rec.State == RetirementConfirmed || now.Before(rec.NextAttempt) {
			return nil
		}
		if err := liveWriteNodeTx(w.tx, nodeID, nodeMaxAge, now); err != nil {
			return err
		}
		ok, err := retirementUnreferencedTx(w.tx, objectID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrRetirementConflict
		}
		var node types.NodeInfo
		if err := json.Unmarshal(w.tx.Bucket(bucketNodes).Get(u64be(nodeID)), &node); err != nil {
			return err
		}
		attempt, err := retirementToken("ra1_")
		if err != nil {
			return err
		}
		req = types.ObjectRetirement{Version: types.RetirementVersion, ObjectID: objectID, NodeID: nodeID,
			FenceID: rec.FenceID, AttemptID: attempt, ExpectedSize: rec.Expected.Size}
		rec.Attempt, rec.Baseline = &req, &node
		rec.State, rec.NextAttempt = RetirementAttempted, now.Add(retryAfter)
		claimed = true
		return putRetirement(w, rec)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return req, claimed, err
}

func retirementConfirmedTx(tx *bolt.Tx, objectID, nodeID uint64) (bool, error) {
	rec, err := retirementTx(tx, objectID, nodeID)
	if errors.Is(err, ErrNotExist) {
		return false, nil
	}
	return err == nil && rec.State == RetirementConfirmed, err
}

func (s *Store) ConfirmRetirement(receipt types.ObjectRetirementReceipt, now time.Time, nodeMaxAge time.Duration) (bool, error) {
	if receipt.Validate() != nil || now.IsZero() {
		return false, ErrRetirementConflict
	}
	confirmed := false
	err := s.write(func(w *txw) error {
		rec, err := retirementTx(w.tx, receipt.ObjectID, receipt.NodeID)
		if err != nil {
			return err
		}
		if rec.Attempt == nil || receipt.ObjectRetirement != *rec.Attempt {
			return ErrRetirementConflict
		}
		if rec.State == RetirementConfirmed {
			if !reflect.DeepEqual(*rec.Receipt, receipt) {
				return ErrRetirementConflict
			}
			confirmed = true
			return nil
		}
		if rec.State != RetirementAttempted {
			return ErrRetirementConflict
		}
		if err := liveWriteNodeTx(w.tx, rec.NodeID, nodeMaxAge, now); err != nil {
			return err
		}
		ok, err := retirementUnreferencedTx(w.tx, rec.ObjectID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrRetirementConflict
		}
		var node types.NodeInfo
		if err := json.Unmarshal(w.tx.Bucket(bucketNodes).Get(u64be(rec.NodeID)), &node); err != nil {
			return err
		}
		// A fresh attempt proves ordering only against the unchanged captured baseline.
		baselineMatches := node.UsedBytes == rec.Baseline.UsedBytes && node.UsageFloorBytes == rec.Baseline.UsageFloorBytes && reflect.DeepEqual(node.Usage, rec.Baseline.Usage)
		oldFloor := node.UsageFloorBytes
		if err := applyNodeUsage(&node, receipt.Usage); err != nil {
			return err
		}
		if baselineMatches {
			credit := min(rec.Expected.Size, receipt.RemovedBytes)
			node.UsageFloorBytes = max(receipt.Usage.UsedBytes, max(int64(0), oldFloor-credit))
		}
		raw, err := json.Marshal(node)
		if err != nil {
			return err
		}
		if err := w.putNode(raw, node.ID); err != nil {
			return err
		}
		rec.State, rec.Receipt, rec.ConfirmedAt = RetirementConfirmed, &receipt, now
		if err := putRetirement(w, rec); err != nil {
			return err
		}
		confirmed = true
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return confirmed, err
}

func retirementRequestAllowedTx(tx *bolt.Tx, objectID, nodeID uint64, fence, bodyHash string) bool {
	rec, err := retirementTx(tx, objectID, nodeID)
	if err != nil || rec.State != RetirementAttempted || rec.FenceID != fence || rec.Attempt == nil {
		return false
	}
	raw, err := json.Marshal(rec.Attempt)
	if err != nil || BodySHA256(raw) != bodyHash {
		return false
	}
	ok, err := retirementUnreferencedTx(tx, objectID)
	return err == nil && ok
}

func (r RetirementRecord) String() string {
	return fmt.Sprintf("retirement object=%d node=%d state=%s", r.ObjectID, r.NodeID, r.State)
}
