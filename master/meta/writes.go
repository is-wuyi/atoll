package meta

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrWritePlanRequired = errors.New("planned write required")
	ErrWriteNotReady     = errors.New("write confirmations not ready")
	ErrWriteExpired      = errors.New("write plan expired")
	ErrWriteBudget       = errors.New("write capacity unavailable")
	ErrWriteNoFeasible   = errors.New("no feasible write plan")
	ErrWritePlanConflict = errors.New("write plan conflict")
	keyWriteInitialized  = []byte("write_planning_initialized_v1")
	keyWriteConfig       = []byte("config")
)

const plannedWriteTTL = 24 * time.Hour

type WriteActor struct{ UserID, SpaceID uint64 }

type plannedWriteRecord struct {
	Upload           types.WriteUpload         `json:"upload"`
	Actor            WriteActor                `json:"actor"`
	ParentID         uint64                    `json:"parent_id"`
	Name             string                    `json:"name"`
	TargetID         uint64                    `json:"target_id"`
	TargetGeneration uint64                    `json:"target_generation"`
	Begin            types.BeginWriteRequest   `json:"begin"`
	Commit           *types.CommitWriteRequest `json:"commit,omitempty"`
}

type writeConfig struct {
	Version   int       `json:"version"`
	EnabledAt time.Time `json:"enabled_at"`
}

type protectionOverride struct {
	Tier     types.ProtectionTier `json:"tier"`
	Revision uint64               `json:"revision"`
}

func writeKey(kind string, id uint64) []byte { return []byte(fmt.Sprintf("%s/%d", kind, id)) }
func writeOpKey(actor WriteActor, kind, op string) []byte {
	return []byte(fmt.Sprintf("op/%d/%d/%s/%s", actor.UserID, actor.SpaceID, kind, BodySHA256([]byte(op))))
}

func writePlanningEnabledTx(tx *bolt.Tx) (bool, error) {
	b := tx.Bucket(bucketWrites)
	marker := tx.Bucket(bucketMeta).Get(keyWriteInitialized)
	if b == nil {
		if marker != nil {
			return false, errors.New("write planning configuration missing")
		}
		return false, nil
	}
	raw := b.Get(keyWriteConfig)
	if raw == nil {
		k, _ := b.Cursor().First()
		if marker != nil || k != nil {
			return false, errors.New("write planning configuration missing from initialized database")
		}
		return false, nil
	}
	var cfg writeConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return false, err
	}
	if cfg.Version != 1 || cfg.EnabledAt.IsZero() || !bytes.Equal(marker, []byte{1}) {
		return false, errors.New("invalid write planning configuration")
	}
	return true, nil
}

func requireWritePlanningTx(tx *bolt.Tx) error {
	enabled, err := writePlanningEnabledTx(tx)
	if err != nil {
		return err
	}
	if !enabled {
		return ErrWritePlanRequired
	}
	return nil
}
func (s *Store) WritePlanningEnabled() (bool, error) {
	var enabled bool
	err := s.db.View(func(tx *bolt.Tx) error { var err error; enabled, err = writePlanningEnabledTx(tx); return err })
	return enabled, err
}
func (s *Store) EnableWritePlanning() error {
	err := s.write(func(w *txw) error {
		enabled, err := writePlanningEnabledTx(w.tx)
		if err != nil || enabled {
			return err
		}
		raw, err := json.Marshal(writeConfig{Version: 1, EnabledAt: time.Now()})
		if err != nil {
			return err
		}
		if err = w.put(bcWrites, bucketWrites, keyWriteConfig, raw); err != nil {
			return err
		}
		return w.put(bcMeta, bucketMeta, keyWriteInitialized, []byte{1})
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}

func plannedWriteTx(tx *bolt.Tx, id uint64) (plannedWriteRecord, error) {
	var rec plannedWriteRecord
	raw := tx.Bucket(bucketWrites).Get(writeKey("upload", id))
	if raw == nil {
		return rec, ErrNotExist
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, err
	}
	u := rec.Upload
	if u.ID != id || u.ID < types.StagingInodeBase || u.ID > types.MaxStagingInode || u.PlanID == "" || u.Revision != 1 || u.CreatedAt.IsZero() || !u.ExpiresAt.After(u.CreatedAt) || !u.Policy.Tier.Valid() || rec.ParentID == 0 || validateName(rec.Name) != nil {
		return rec, ErrWritePlanConflict
	}
	if u.State != types.WritePending && u.State != types.WriteCommitted && u.State != types.WriteAborted {
		return rec, ErrWritePlanConflict
	}
	if !validWriteOp(rec.Begin.OpID) || !validWriteSize(u.Size) || rec.Begin.Size != u.Size || len(u.Chunks) > types.MaxChunksPerFile {
		return rec, ErrWritePlanConflict
	}
	previous := -1
	for _, chunk := range u.Chunks {
		req := types.PlanWriteChunkRequest{WriteBinding: writeBinding(u), Index: chunk.Index, LogicalSize: chunk.Object.LogicalSize, StoredSize: chunk.Object.StoredSize, Encoding: chunk.Object.Encoding, Checksum: chunk.Object.Checksum}
		if chunk.Index <= previous || types.ValidateWriteChunkPlan(req, chunk) != nil {
			return rec, ErrWritePlanConflict
		}
		previous = chunk.Index
	}
	if u.State == types.WriteCommitted && (u.Result == nil || rec.Commit == nil || u.Result.Content == nil || u.Result.Content.ID != u.ID || types.ValidateContentManifest(*u.Result) != nil) {
		return rec, ErrWritePlanConflict
	}
	return rec, nil
}
func putPlannedWrite(w *txw, rec plannedWriteRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return w.put(bcWrites, bucketWrites, writeKey("upload", rec.Upload.ID), raw)
}
func hasPlannedWriteTx(tx *bolt.Tx, id uint64) bool {
	return tx.Bucket(bucketWrites).Get(writeKey("upload", id)) != nil
}
func rejectPlannedStagingTx(tx *bolt.Tx, in types.Inode) error {
	if in.Staging && hasPlannedWriteTx(tx, in.ID) {
		return ErrWritePlanRequired
	}
	return nil
}

func writeActorRootTx(tx *bolt.Tx, actor WriteActor, inodeID uint64, write bool) (uint64, error) {
	enabled, err := securityEnabledTx(tx)
	if err != nil {
		return 0, err
	}
	if enabled {
		if actor.UserID == 0 || actor.SpaceID == 0 {
			return 0, ErrAuthentication
		}
		space, err := authorizeSpaceTx(tx, actor.UserID, actor.SpaceID, write)
		if err != nil {
			return 0, err
		}
		if inodeID != 0 {
			if err := inodeInSpaceTx(tx, actor.SpaceID, inodeID); err != nil {
				return 0, err
			}
		}
		return space.RootID, nil
	}
	if actor.UserID != 0 || actor.SpaceID != 0 {
		return 0, ErrAuthentication
	}
	return RootID, nil
}
func authorizePlannedTx(tx *bolt.Tx, actor WriteActor, b types.WriteBinding, now time.Time, allowFinished bool) (plannedWriteRecord, error) {
	var rec plannedWriteRecord
	if err := requireWritePlanningTx(tx); err != nil {
		return rec, err
	}
	var err error
	rec, err = plannedWriteTx(tx, b.UploadID)
	if err != nil {
		return rec, err
	}
	if rec.Actor != actor {
		return rec, ErrAuthentication
	}
	if rec.Upload.PlanID != b.PlanID || rec.Upload.Revision != b.Revision {
		return rec, ErrWritePlanConflict
	}
	if _, err = writeActorRootTx(tx, actor, rec.ParentID, true); err != nil {
		return rec, err
	}
	if !allowFinished && rec.Upload.State != types.WritePending {
		return rec, ErrWritePlanConflict
	}
	if rec.Upload.State == types.WritePending && !now.Before(rec.Upload.ExpiresAt) {
		return rec, ErrWriteExpired
	}
	return rec, nil
}

func protectionTx(tx *bolt.Tx, rootID, inodeID uint64) (types.ProtectionResponse, error) {
	out := types.ProtectionResponse{InodeID: inodeID, Policy: types.EffectiveProtection{Tier: types.ProtectionNormal, SourceInodeID: rootID}}
	seen := map[uint64]bool{}
	found := false
	for depth := 0; depth < maxParentChainDepth; depth++ {
		if seen[inodeID] {
			return out, ErrOutsideSpace
		}
		seen[inodeID] = true
		in, err := getInodeTx(tx, inodeID)
		if err != nil {
			return out, err
		}
		if raw := tx.Bucket(bucketWrites).Get(writeKey("policy", inodeID)); raw != nil {
			var policy protectionOverride
			if err := json.Unmarshal(raw, &policy); err != nil {
				return out, err
			}
			if policy.Revision == 0 || (policy.Tier != "" && !policy.Tier.Valid()) {
				return out, ErrWritePlanConflict
			}
			if inodeID == out.InodeID {
				out.Override = policy.Tier
			}
			if !found && policy.Tier != "" {
				out.Policy = types.EffectiveProtection{Tier: policy.Tier, SourceInodeID: inodeID, Revision: policy.Revision}
				found = true
			}
		}
		if inodeID == rootID {
			return out, nil
		}
		if in.ParentID == 0 {
			return out, ErrOutsideSpace
		}
		inodeID = in.ParentID
	}
	return out, ErrOutsideSpace
}
func (s *Store) GetProtection(actor WriteActor, inodeID uint64) (types.ProtectionResponse, error) {
	var out types.ProtectionResponse
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := requireWritePlanningTx(tx); err != nil {
			return err
		}
		root, err := writeActorRootTx(tx, actor, inodeID, false)
		if err != nil {
			return err
		}
		out, err = protectionTx(tx, root, inodeID)
		return err
	})
	return out, err
}
func (s *Store) SetProtection(actor WriteActor, inodeID uint64, tier types.ProtectionTier, now time.Time) (types.ProtectionResponse, error) {
	var out types.ProtectionResponse
	if tier != "" && !tier.Valid() || now.IsZero() {
		return out, ErrBadPath
	}
	err := s.write(func(w *txw) error {
		if err := requireWritePlanningTx(w.tx); err != nil {
			return err
		}
		root, err := writeActorRootTx(w.tx, actor, inodeID, true)
		if err != nil {
			return err
		}
		in, err := getInodeTx(w.tx, inodeID)
		if err != nil {
			return err
		}
		if in.Staging || in.Type == types.TypeSymlink {
			return ErrNotFile
		}
		var old protectionOverride
		if raw := w.tx.Bucket(bucketWrites).Get(writeKey("policy", inodeID)); raw != nil {
			if err = json.Unmarshal(raw, &old); err != nil {
				return err
			}
			if old.Revision == 0 || old.Revision == math.MaxUint64 {
				return ErrWritePlanConflict
			}
		}
		if old.Revision == 0 || old.Tier != tier {
			raw, _ := json.Marshal(protectionOverride{Tier: tier, Revision: old.Revision + 1})
			if err = w.put(bcWrites, bucketWrites, writeKey("policy", inodeID), raw); err != nil {
				return err
			}
		}
		out, err = protectionTx(w.tx, root, inodeID)
		return err
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func validWriteOp(op string) bool {
	return len(op) > 0 && len(op) <= 256 && !strings.ContainsAny(op, " \t\r\n\x00")
}
func validWriteSize(size int64) bool {
	return types.ChunkSize > 0 && types.ChunkSize <= math.MaxInt64/types.MaxChunksPerFile && size >= -1 && size <= types.ChunkSize*types.MaxChunksPerFile
}
func writeBinding(u types.WriteUpload) types.WriteBinding {
	return types.WriteBinding{UploadID: u.ID, PlanID: u.PlanID, Revision: u.Revision}
}

func (s *Store) BeginPlannedWrite(actor WriteActor, parentID uint64, name string, req types.BeginWriteRequest, now time.Time) (types.WriteUpload, error) {
	var out types.WriteUpload
	if err := validateName(name); err != nil {
		return out, err
	}
	if !validWriteOp(req.OpID) || !validWriteSize(req.Size) || req.Path == "" || len(req.Path) > 8192 || now.IsZero() {
		return out, ErrBadPath
	}
	err := s.write(func(w *txw) error {
		if err := requireWritePlanningTx(w.tx); err != nil {
			return err
		}
		root, err := writeActorRootTx(w.tx, actor, parentID, true)
		if err != nil {
			return err
		}
		key := writeOpKey(actor, "begin", req.OpID)
		if raw := w.tx.Bucket(bucketWrites).Get(key); raw != nil {
			if len(raw) != 8 {
				return ErrWritePlanConflict
			}
			rec, err := plannedWriteTx(w.tx, beU64(raw))
			if err != nil {
				return err
			}
			if rec.Actor != actor || rec.ParentID != parentID || rec.Name != name || rec.Begin != req {
				return ErrOpConflict
			}
			if rec.Upload.State == types.WritePending && !now.Before(rec.Upload.ExpiresAt) {
				return ErrWriteExpired
			}
			if rec.Upload.State == types.WriteAborted {
				return ErrWritePlanConflict
			}
			out = rec.Upload
			return nil
		}
		parent, err := getInodeTx(w.tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		rec := plannedWriteRecord{Actor: actor, ParentID: parentID, Name: name, Begin: req}
		policyID := parentID
		if raw := w.tx.Bucket(bucketChildren).Get(childKey(parentID, name)); raw != nil {
			old, err := getInodeTx(w.tx, beU64(raw))
			if err != nil {
				return err
			}
			if !req.Overwrite || old.Type == types.TypeDir {
				return ErrExist
			}
			rec.TargetID, rec.TargetGeneration = old.ID, old.Generation
			if old.Type == types.TypeFile {
				policyID = old.ID
			}
		}
		policy, err := protectionTx(w.tx, root, policyID)
		if err != nil {
			return err
		}
		id, err := w.nextStagingID()
		if err != nil {
			return err
		}
		var token [24]byte
		if _, err = rand.Read(token[:]); err != nil {
			return err
		}
		rec.Upload = types.WriteUpload{ID: id, PlanID: "wp1_" + hex.EncodeToString(token[:]), Revision: 1, Policy: policy.Policy, Size: req.Size, State: types.WritePending, CreatedAt: now, ExpiresAt: now.Add(plannedWriteTTL)}
		in := types.Inode{ID: id, ParentID: parentID, Name: name, Type: types.TypeFile, Staging: true, Chunked: true, Mtime: now}
		if err = w.putInode(&in); err != nil {
			return err
		}
		if err = putPlannedWrite(w, rec); err != nil {
			return err
		}
		if err = w.put(bcWrites, bucketWrites, key, u64be(id)); err != nil {
			return err
		}
		out = rec.Upload
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func (s *Store) GetPlannedWrite(actor WriteActor, b types.WriteBinding, now time.Time) (types.WriteUpload, error) {
	var out types.WriteUpload
	err := s.db.View(func(tx *bolt.Tx) error {
		rec, err := authorizePlannedTx(tx, actor, b, now, true)
		out = rec.Upload
		return err
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func liveWriteNodeTx(tx *bolt.Tx, id uint64, maxAge time.Duration, now time.Time) error {
	if maxAge <= 0 {
		return ErrWritePlanConflict
	}
	var n types.NodeInfo
	raw := tx.Bucket(bucketNodes).Get(u64be(id))
	if raw == nil {
		return ErrWriteNotReady
	}
	if err := json.Unmarshal(raw, &n); err != nil {
		return err
	}
	if n.ID != id || n.LastHeartbeat.IsZero() || n.LastHeartbeat.After(now.Add(time.Second)) || now.Sub(n.LastHeartbeat) > maxAge {
		return ErrWriteNotReady
	}
	secure, err := securityEnabledTx(tx)
	if err != nil {
		return err
	}
	if secure {
		if _, err = deviceByNodeTx(tx, id); err != nil {
			return ErrWriteNotReady
		}
	}
	return nil
}

func (s *Store) ReserveWriteChunk(actor WriteActor, req types.PlanWriteChunkRequest, choice types.WriteChunkPlan, profileRevision uint64, nodeMaxAge time.Duration, now time.Time) (types.WriteChunkPlan, types.ChunkInfo, error) {
	var out types.WriteChunkPlan
	var chunk types.ChunkInfo
	if err := types.ValidateWriteChunkPlan(req, choice); err != nil {
		return out, chunk, fmt.Errorf("%w: %v", ErrWritePlanConflict, err)
	}
	err := s.write(func(w *txw) error {
		rec, err := authorizePlannedTx(w.tx, actor, req.WriteBinding, now, false)
		if err != nil {
			return err
		}
		in, err := getInodeTx(w.tx, rec.Upload.ID)
		if err != nil {
			return err
		}
		if !in.Staging || !in.Chunked || in.ParentID != rec.ParentID {
			return ErrWritePlanConflict
		}
		for _, plan := range rec.Upload.Chunks {
			if plan.Index == req.Index {
				if !reflect.DeepEqual(plan, choice) {
					return ErrWritePlanConflict
				}
				for _, c := range in.Chunks {
					if c.Index == req.Index {
						if !chunkMatchesPlan(c, plan) {
							return ErrWritePlanConflict
						}
						out, chunk = plan, c
						if plan.Transfer != nil && !now.Before(plan.Transfer.ExpiresAt) {
							return ErrWriteExpired
						}
						return nil
					}
				}
				return ErrWritePlanConflict
			}
		}
		transferEnabled, err := transferPlanningEnabledTx(w.tx)
		if err != nil || transferEnabled != (choice.Transfer != nil) {
			return ErrWritePlanConflict
		}
		if choice.Transfer != nil && (!now.Before(choice.Transfer.ExpiresAt) || choice.Transfer.ExpiresAt.After(now.Add(time.Hour))) {
			return ErrWriteExpired
		}
		if profileRevision != profileRevisionTx(w.tx) {
			return ErrWritePlanConflict
		}
		if rec.Upload.Size >= 0 {
			offset := int64(req.Index) * types.ChunkSize
			if offset >= rec.Upload.Size || req.LogicalSize != min(types.ChunkSize, rec.Upload.Size-offset) {
				return ErrChunkBadSize
			}
		}
		if err := validateWriteTransferBudgetTx(w.tx, choice, now); err != nil {
			return err
		}
		caps, err := capacitiesTx(w.tx)
		if err != nil {
			return err
		}
		free := map[uint64]int64{}
		for _, c := range caps {
			free[c.NodeID] = c.Free
		}
		for _, id := range choice.Layout.Nodes {
			if err = liveWriteNodeTx(w.tx, id, nodeMaxAge, now); err != nil {
				return err
			}
			if free[id] < req.StoredSize {
				return ErrWriteBudget
			}
		}
		chunk = types.ChunkInfo{ID: choice.Object.ID, Index: req.Index, Size: req.StoredSize, LogicalSize: req.LogicalSize, Encoding: req.Encoding, Checksum: req.Checksum, ChecksumKnown: true, Replicas: append([]uint64(nil), choice.Layout.Nodes...)}
		in.Chunks = append(in.Chunks, chunk)
		sort.Slice(in.Chunks, func(i, j int) bool { return in.Chunks[i].Index < in.Chunks[j].Index })
		rec.Upload.Chunks = append(rec.Upload.Chunks, choice)
		sort.Slice(rec.Upload.Chunks, func(i, j int) bool { return rec.Upload.Chunks[i].Index < rec.Upload.Chunks[j].Index })
		if err = putPlannedWrite(w, rec); err != nil {
			return err
		}
		if err = w.putInode(&in); err != nil {
			return err
		}
		out = choice
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, chunk, err
}

func chunkMatchesPlan(c types.ChunkInfo, p types.WriteChunkPlan) bool {
	return c.ID == p.Object.ID && c.Index == p.Index && c.Size == p.Object.StoredSize && c.LogicalSize == p.Object.LogicalSize && ChunkInfoEncodes(c, p.Object.Encoding) && c.ChecksumKnown && c.Checksum == p.Object.Checksum && reflect.DeepEqual(c.Replicas, p.Layout.Nodes)
}

// ChunkInfoEncodes 判断块表编码与 manifest 编码是否同一语义：空编码等价 plain-v1
// （旧数据），plain 下允许任一写法；新编码必须逐字相等。
func ChunkInfoEncodes(c types.ChunkInfo, encoding string) bool {
	e := c.Encoding
	if e == "" {
		e = types.PlainEncoding
	}
	return e == encoding || (encoding == types.PlainEncoding && e == types.PlainEncoding)
}

func (s *Store) CommitPlannedWrite(actor WriteActor, req types.CommitWriteRequest, nodeMaxAge time.Duration, now time.Time) (types.Inode, types.Inode, bool, error) {
	var out, old types.Inode
	replaced := false
	if !validWriteOp(req.OpID) || req.Size < 0 || !validWriteSize(req.Size) || req.ChunkCount < 0 || req.ChunkCount > types.MaxChunksPerFile {
		return out, old, false, ErrBadPath
	}
	err := s.write(func(w *txw) error {
		rec, err := authorizePlannedTx(w.tx, actor, req.WriteBinding, now, true)
		if err != nil {
			return err
		}
		key := writeOpKey(actor, "commit", req.OpID)
		if raw := w.tx.Bucket(bucketWrites).Get(key); raw != nil && (len(raw) != 8 || beU64(raw) != req.UploadID) {
			return ErrOpConflict
		}
		if rec.Upload.State == types.WriteCommitted {
			if rec.Commit == nil || *rec.Commit != req || rec.Upload.Result == nil {
				return ErrOpConflict
			}
			out = *rec.Upload.Result
			return nil
		}
		if rec.Upload.State != types.WritePending {
			return ErrWritePlanConflict
		}
		if rec.Upload.Size >= 0 && rec.Upload.Size != req.Size {
			return ErrWritePlanConflict
		}
		in, err := getInodeTx(w.tx, req.UploadID)
		if err != nil {
			return err
		}
		if !in.Staging || !in.Chunked || in.ParentID != rec.ParentID || len(in.Chunks) != req.ChunkCount || len(rec.Upload.Chunks) != req.ChunkCount {
			return ErrWritePlanConflict
		}
		content := types.ContentVersion{ID: req.UploadID, LogicalSize: req.Size}
		var total int64
		for i, p := range rec.Upload.Chunks {
			c := in.Chunks[i]
			check := types.PlanWriteChunkRequest{WriteBinding: req.WriteBinding, Index: i, LogicalSize: p.Object.LogicalSize, StoredSize: p.Object.StoredSize, Encoding: p.Object.Encoding, Checksum: p.Object.Checksum}
			if types.ValidateWriteChunkPlan(check, p) != nil || !chunkMatchesPlan(c, p) || c.Index != i {
				return ErrWritePlanConflict
			}
			if i < req.ChunkCount-1 && p.Object.LogicalSize != types.ChunkSize {
				return ErrChunkBadSize
			}
			for _, id := range p.Confirmations {
				if !types.ContainsUint64(c.Done, id) || types.ContainsUint64(c.Suspect, id) {
					return ErrWriteNotReady
				}
				if err = liveWriteNodeTx(w.tx, id, nodeMaxAge, now); err != nil {
					return err
				}
			}
			content.Extents = append(content.Extents, types.ContentExtent{Offset: total, Length: p.Object.LogicalSize, Object: p.Object})
			total, err = checkedBytesAdd(total, p.Object.LogicalSize)
			if err != nil {
				return ErrChunkBadSize
			}
		}
		if total != req.Size {
			return ErrChunkBadSize
		}
		parent, err := getInodeTx(w.tx, rec.ParentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		raw := w.tx.Bucket(bucketChildren).Get(childKey(rec.ParentID, rec.Name))
		if raw == nil {
			if rec.TargetID != 0 {
				return ErrObjectChanged
			}
		} else {
			old, err = getInodeTx(w.tx, beU64(raw))
			if err != nil {
				return err
			}
			if !rec.Begin.Overwrite || old.Type == types.TypeDir || old.ID != rec.TargetID || old.Generation != rec.TargetGeneration {
				return ErrObjectChanged
			}
			replaced = true
		}
		out = in
		out.Name = rec.Name
		out.Size = req.Size
		out.Staging = false
		out.Mtime = now
		out.Generation = 1
		out.Content = &content
		if replaced && old.Type == types.TypeFile {
			if old.Generation == math.MaxUint64 {
				return ErrObjectChanged
			}
			out.ID = old.ID
			out.Generation = old.Generation + 1
		}
		if err = w.putInode(&out); err != nil {
			return err
		}
		if out.ID != in.ID {
			if err = w.delInode(in.ID); err != nil {
				return err
			}
		}
		if replaced && old.Type != types.TypeFile {
			if err = w.delInode(old.ID); err != nil {
				return err
			}
		}
		if err = w.putChild(out.ParentID, out.Name, out.ID); err != nil {
			return err
		}
		rec.Upload.State = types.WriteCommitted
		rec.Upload.Result = &out
		rec.Commit = &req
		if err = putPlannedWrite(w, rec); err != nil {
			return err
		}
		return w.put(bcWrites, bucketWrites, key, u64be(req.UploadID))
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, old, replaced, err
}

func (s *Store) AbortPlannedWrite(actor WriteActor, b types.WriteBinding, now time.Time) error {
	err := s.write(func(w *txw) error {
		rec, err := plannedWriteTx(w.tx, b.UploadID)
		if err != nil {
			return err
		}
		if err = requireWritePlanningTx(w.tx); err != nil {
			return err
		}
		if rec.Actor != actor {
			return ErrAuthentication
		}
		if rec.Upload.PlanID != b.PlanID || rec.Upload.Revision != b.Revision {
			return ErrWritePlanConflict
		}
		if _, err = writeActorRootTx(w.tx, actor, rec.ParentID, true); err != nil {
			return err
		}
		if rec.Upload.State == types.WriteCommitted {
			return ErrWritePlanConflict
		}
		if rec.Upload.State == types.WriteAborted {
			return w.retireAbortedWrite(rec, now)
		}
		rec.Upload.State = types.WriteAborted
		if err := putPlannedWrite(w, rec); err != nil {
			return err
		}
		return w.retireAbortedWrite(rec, now)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return err
}

func (s *Store) ExpirePlannedWrites(now time.Time) (int, error) {
	count := 0
	err := s.write(func(w *txw) error {
		c := w.tx.Bucket(bucketWrites).Cursor()
		prefix := []byte("upload/")
		var expired []plannedWriteRecord
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var rec plannedWriteRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.Upload.State == types.WritePending && !now.Before(rec.Upload.ExpiresAt) {
				expired = append(expired, rec)
			}
		}
		for _, rec := range expired {
			rec.Upload.State = types.WriteAborted
			if err := putPlannedWrite(w, rec); err != nil {
				return err
			}
			if err := w.retireAbortedWrite(rec, now); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	return count, err
}

func writeReservationsTx(tx *bolt.Tx) (map[[2]uint64]int64, error) {
	out := map[[2]uint64]int64{}
	c := tx.Bucket(bucketWrites).Cursor()
	prefix := []byte("upload/")
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		var rec plannedWriteRecord
		if err := json.Unmarshal(v, &rec); err != nil {
			return nil, err
		}
		var published *types.Inode
		if rec.Upload.State == types.WriteCommitted {
			if rec.Upload.Result == nil {
				return nil, ErrWritePlanConflict
			}
			in, err := getInodeTx(tx, rec.Upload.Result.ID)
			if err == nil && in.Content != nil && in.Content.ID == rec.Upload.ID {
				published = &in
			} else if err != nil && !errors.Is(err, ErrNotExist) {
				return nil, err
			}
		} else if rec.Upload.State != types.WritePending && rec.Upload.State != types.WriteAborted {
			return nil, ErrWritePlanConflict
		}
		for _, p := range rec.Upload.Chunks {
			req := types.PlanWriteChunkRequest{WriteBinding: writeBinding(rec.Upload), Index: p.Index, LogicalSize: p.Object.LogicalSize, StoredSize: p.Object.StoredSize, Encoding: p.Object.Encoding, Checksum: p.Object.Checksum}
			if err := types.ValidateWriteChunkPlan(req, p); err != nil {
				return nil, ErrWritePlanConflict
			}
			for _, id := range p.Layout.Nodes {
				retired, err := retirementConfirmedTx(tx, p.Object.ID, id)
				if err != nil {
					return nil, err
				}
				if retired {
					continue
				}
				confirmed := false
				if published != nil {
					for _, chunk := range published.Chunks {
						if chunk.ID == p.Object.ID && types.ContainsUint64(chunk.Done, id) && !types.ContainsUint64(chunk.Suspect, id) {
							var err error
							confirmed, err = writeUsageCoveredTx(tx, p.Object.ID, id)
							if err != nil {
								return nil, err
							}
							break
						}
					}
				}
				if !confirmed {
					out[[2]uint64{p.Object.ID, id}] = p.Object.StoredSize
				}
			}
		}
	}
	return out, nil
}
