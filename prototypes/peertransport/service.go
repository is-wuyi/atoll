package peertransport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Default resource budget. Object bodies are streamed with a hard per-object
// byte cap and a per-request wall-clock deadline; both are finite.
const (
	DefaultMaxObjectBytes  = 256 << 20 // 256 MiB per object/stream
	DefaultTransferTimeout = 120 * time.Second
)

// ObjectMeta is the stored object manifest entry.
type ObjectMeta struct {
	Key      string    `json:"key"`
	Size     int64     `json:"size"`
	Sha256   string    `json:"sha256"`
	StoredAt time.Time `json:"stored_at"`
}

var keyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ObjectStore is a small atomic object service used by the prototype instead
// of importing production code. It streams request bodies to a temp file and
// only atomically renames into place after the body is complete and the
// optional X-Object-Sha256 checksum matches — a failed or cancelled transfer
// can never leave a half-written visible object.
type ObjectStore struct {
	dir      string
	maxBytes int64
	timeout  time.Duration

	mu       sync.RWMutex
	manifest map[string]ObjectMeta
}

// NewObjectStore creates the store directory (0700).
func NewObjectStore(dir string, maxBytes int64, timeout time.Duration) (*ObjectStore, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxObjectBytes
	}
	if timeout <= 0 {
		timeout = DefaultTransferTimeout
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("peertransport: create object dir: %w", err)
	}
	return &ObjectStore{dir: dir, maxBytes: maxBytes, timeout: timeout, manifest: map[string]ObjectMeta{}}, nil
}

// Dir returns the object directory.
func (st *ObjectStore) Dir() string { return st.dir }

// Has reports whether key is committed.
func (st *ObjectStore) Has(key string) bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	_, ok := st.manifest[key]
	return ok
}

// Get returns the manifest entry for key.
func (st *ObjectStore) Get(key string) (ObjectMeta, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	m, ok := st.manifest[key]
	return m, ok
}

// Keys returns committed keys sorted.
func (st *ObjectStore) Keys() []string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]string, 0, len(st.manifest))
	for k := range st.manifest {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// VerifyNoPartial scans the store directory and fails if any uncommitted
// (temp) file remains — the "no half objects" invariant.
func (st *ObjectStore) VerifyNoPartial() error {
	entries, err := os.ReadDir(st.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, committed := st.Get(e.Name()); !committed {
			return fmt.Errorf("peertransport: uncommitted partial object present: %s", e.Name())
		}
	}
	return nil
}

// Handler returns the object-service HTTP handler. All routes are explicit;
// size and deadline limits are enforced per request.
func (st *ObjectStore) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /objects/{key}", st.handlePut)
	mux.HandleFunc("GET /objects/{key}", st.handleGet)
	mux.HandleFunc("GET /objects", st.handleList)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func (st *ObjectStore) handlePut(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !keyRe.MatchString(key) {
		httpError(w, http.StatusBadRequest, "invalid object key")
		return
	}
	if st.timeout > 0 {
		// Enforce the per-request wall-clock budget on the underlying
		// connection (a libp2p stream here): a stalled/trickling upload is
		// aborted after the deadline instead of blocking forever. The
		// deadline is cleared on return so HTTP keep-alive stays usable.
		rc := http.NewResponseController(w)
		if err := rc.SetReadDeadline(time.Now().Add(st.timeout)); err == nil {
			defer rc.SetReadDeadline(time.Time{})
		}
	}

	tmp, err := os.CreateTemp(st.dir, "incoming-*")
	if err != nil {
		httpError(w, http.StatusInternalServerError, "temp file: "+err.Error())
		return
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	hasher := sha256.New()
	// Read at most maxBytes+1: the +1 detects a size violation instead of
	// silently truncating.
	n, err := io.Copy(tmp, io.TeeReader(io.LimitReader(r.Body, st.maxBytes+1), hasher))
	if err != nil {
		cleanup()
		httpError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if n > st.maxBytes {
		cleanup()
		httpError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("object exceeds limit of %d bytes", st.maxBytes))
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		httpError(w, http.StatusInternalServerError, "close temp: "+err.Error())
		return
	}

	sum := hex.EncodeToString(hasher.Sum(nil))
	if want := r.Header.Get("X-Object-Sha256"); want != "" && want != sum {
		os.Remove(tmpName)
		httpError(w, http.StatusBadRequest, "sha256 mismatch: got "+sum)
		return
	}

	// Atomic commit: rename within the same directory.
	final := filepath.Join(st.dir, key)
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		httpError(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}
	meta := ObjectMeta{Key: key, Size: n, Sha256: sum, StoredAt: time.Now().UTC()}
	st.mu.Lock()
	st.manifest[key] = meta
	st.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(meta)
}

func (st *ObjectStore) handleGet(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	meta, ok := st.Get(key)
	if !ok {
		httpError(w, http.StatusNotFound, "object not found: "+key)
		return
	}
	if st.timeout > 0 {
		// Bound downloads too: a client that stops reading mid-GET would
		// otherwise pin the stream (and its fd) forever. The write deadline
		// aborts a stalled reader after the same per-request budget the
		// upload path enforces; it is cleared on return so keep-alive stays
		// usable.
		rc := http.NewResponseController(w)
		if err := rc.SetWriteDeadline(time.Now().Add(st.timeout)); err == nil {
			defer rc.SetWriteDeadline(time.Time{})
		}
	}
	f, err := os.Open(filepath.Join(st.dir, key))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httpError(w, http.StatusNotFound, "object not found: "+key)
			return
		}
		httpError(w, http.StatusInternalServerError, "open object: "+err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("X-Object-Sha256", meta.Sha256)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", meta.Size))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		// Client cancellation or connection loss; nothing to recover.
		return
	}
}

func (st *ObjectStore) handleList(w http.ResponseWriter, _ *http.Request) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]ObjectMeta, 0, len(st.manifest))
	for _, m := range st.manifest {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
