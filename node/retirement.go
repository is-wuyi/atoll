package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"atoll/pkg/access"
	"atoll/pkg/types"
)

var (
	errObjectRetired     = errors.New("object is durably retired")
	errRetirementPending = errors.New("retired object still has active writes")
)

type objectFence struct {
	Version      int    `json:"version"`
	ObjectID     uint64 `json:"object_id"`
	NodeID       uint64 `json:"node_id"`
	FenceID      string `json:"fence_id"`
	ExpectedSize int64  `json:"expected_size"`
	RemovedBytes int64  `json:"removed_bytes"`
}

func (n *Node) fencePath(id uint64) string {
	return filepath.Join(n.dataDir, "fences", fmt.Sprintf("%02x", id%256), strconv.FormatUint(id, 10))
}

func (n *Node) readFence(id uint64) (*objectFence, error) {
	path := n.fencePath(id)
	for _, dir := range []string{filepath.Join(n.dataDir, "fences"), filepath.Dir(path)} {
		st, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("invalid fence directory")
		}
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 4096 {
		return nil, errors.New("invalid fence file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("fence file changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, err
	}
	var fence objectFence
	if err := types.DecodeRetirementJSON(raw, &fence); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for _, name := range []string{"version", "object_id", "node_id", "fence_id", "expected_size", "removed_bytes"} {
		if _, ok := fields[name]; !ok {
			return nil, errors.New("incomplete object fence")
		}
	}
	if fence.Version != types.RetirementVersion || fence.ObjectID != id || fence.NodeID == 0 ||
		!types.ValidRetirementToken(fence.FenceID) || fence.ExpectedSize < 0 || fence.RemovedBytes < 0 || fence.RemovedBytes > fence.ExpectedSize {
		return nil, errors.New("invalid fence identity")
	}
	return &fence, nil
}

func (n *Node) checkObjectFence(id uint64) error {
	fence, err := n.readFence(id)
	if err != nil {
		return err
	}
	if fence != nil {
		return errObjectRetired
	}
	return nil
}

func (n *Node) persistFence(fence objectFence) error {
	path := n.fencePath(fence.ObjectID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := n.readFence(fence.ObjectID); err != nil {
		return err
	}
	raw, err := json.Marshal(fence)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-fence-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncObjectDirectories(path)
}

// The same object lock covers fence checks, writer registration and publication.
func (n *Node) beginObjectWrite(id uint64) error {
	lock := n.objectLock(id)
	lock.Lock()
	defer lock.Unlock()
	if err := n.checkObjectFence(id); err != nil {
		return err
	}
	value, _ := n.activeObjectWrites.LoadOrStore(id, 0)
	count := value.(int)
	n.activeObjectWrites.Store(id, count+1)
	return nil
}

func (n *Node) endObjectWrite(id uint64) {
	lock := n.objectLock(id)
	lock.Lock()
	defer lock.Unlock()
	value, ok := n.activeObjectWrites.Load(id)
	if !ok {
		return
	}
	count := value.(int)
	if count <= 1 {
		n.activeObjectWrites.Delete(id)
	} else {
		n.activeObjectWrites.Store(id, count-1)
	}
}

func (n *Node) retireObject(req types.ObjectRetirement) (types.ObjectRetirementReceipt, error) {
	var out types.ObjectRetirementReceipt
	if err := req.Validate(); err != nil {
		return out, err
	}
	if n.nodeID.Load() <= 0 || uint64(n.nodeID.Load()) != req.NodeID {
		return out, errors.New("retirement node identity mismatch")
	}
	lock := n.objectLock(req.ObjectID)
	lock.Lock()
	defer lock.Unlock()
	fence, err := n.readFence(req.ObjectID)
	if err != nil {
		return out, err
	}
	if fence != nil && (fence.NodeID != req.NodeID || fence.FenceID != req.FenceID || fence.ExpectedSize != req.ExpectedSize) {
		return out, errors.New("retirement fence conflict")
	}
	path := n.objectPath(req.ObjectID)
	st, statErr := os.Lstat(path)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return out, statErr
	}
	if statErr == nil && (!st.Mode().IsRegular() || st.Size() != req.ExpectedSize) {
		return out, errors.New("retirement object size or type mismatch")
	}
	if fence == nil {
		removed := int64(0)
		if statErr == nil {
			removed = st.Size()
		}
		fence = &objectFence{Version: types.RetirementVersion, ObjectID: req.ObjectID, NodeID: req.NodeID,
			FenceID: req.FenceID, ExpectedSize: req.ExpectedSize, RemovedBytes: removed}
		if err := n.persistFence(*fence); err != nil {
			return out, err
		}
	} else {
		// A previous attempt may have failed the parent sync after publishing the fence.
		if err := syncObjectDirectories(n.fencePath(req.ObjectID)); err != nil {
			return out, err
		}
	}
	if statErr == nil {
		if err := os.Remove(path); err != nil {
			return out, err
		}
		n.settleCapacity(-st.Size(), 0)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return out, err
	}
	if err := syncObjectDirectories(path); err != nil {
		return out, err
	}
	if value, ok := n.activeObjectWrites.Load(req.ObjectID); ok && value.(int) > 0 {
		return out, errRetirementPending
	}
	usage := n.usageSnapshot()
	if usage == nil {
		return out, errors.New("retirement usage unavailable")
	}
	out = types.ObjectRetirementReceipt{ObjectRetirement: req, State: types.RetirementRemoved,
		RemovedBytes: fence.RemovedBytes, Usage: *usage}
	return out, nil
}

func (n *Node) handleRetirement(w http.ResponseWriter, r *http.Request) {
	id, ok := parseObjectID(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	var req types.ObjectRetirement
	if err != nil || types.DecodeRetirementJSON(raw, &req) != nil || req.Validate() != nil || req.ObjectID != id || r.Header.Get(access.PlanHeader) != req.FenceID || r.URL.RawQuery != "" {
		httpError(w, http.StatusBadRequest, "invalid retirement request")
		return
	}
	receipt, err := n.retireObject(req)
	if errors.Is(err, errRetirementPending) {
		httpError(w, http.StatusAccepted, err.Error())
		return
	}
	if err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (n *Node) reconcileFences() error {
	root := filepath.Join(n.dataDir, "fences")
	if st, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	} else if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid fence directory")
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in fence directory")
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".tmp-fence-") {
			if err := os.Remove(path); err != nil {
				return err
			}
			return syncDir(filepath.Dir(path))
		}
		id, err := strconv.ParseUint(d.Name(), 10, 64)
		if err != nil || id == 0 || n.fencePath(id) != path {
			return errors.New("invalid fence filename")
		}
		fence, err := n.readFence(id)
		if err != nil || fence == nil {
			return errors.New("invalid persisted object fence")
		}
		if err := syncObjectDirectories(path); err != nil {
			return err
		}
		obj := n.objectPath(id)
		st, err := os.Lstat(obj)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil {
			if !st.Mode().IsRegular() || st.Size() != fence.ExpectedSize {
				return errors.New("fenced object type or size mismatch")
			}
			if err := os.Remove(obj); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(filepath.Dir(obj), 0o755); err != nil {
			return err
		}
		return syncObjectDirectories(obj)
	})
}
