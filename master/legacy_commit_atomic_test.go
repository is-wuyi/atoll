package master

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

func TestLegacyChunkCommitRecordsReplayBeforeDurabilityFailure(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	node, err := store.RegisterNode("127.0.0.1:9443", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	staging, err := store.CreateStagingFile(meta.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AssignChunk(staging.ID, 0, 16, []uint64{node.ID}, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkChunkDone(types.ChunkID(staging.ID, 0), node.ID); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(store, time.Minute).Handler()
	var unavailable atomic.Bool
	unavailable.Store(true)
	var confirmationCalls atomic.Int32
	store.SetPostCommitHook(func(uint64, []byte) error {
		confirmationCalls.Add(1)
		if unavailable.Load() {
			return errors.New("injected durability failure")
		}
		return nil
	})
	const op = "legacy-atomic-commit"
	raw, err := json.Marshal(map[string]any{"inode_id": staging.ID, "name": "atomic.bin", "size": 16, "chunk_count": 1, "op_id": op})
	if err != nil {
		t.Fatal(err)
	}
	commit := func(body []byte) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/files/commit", bytes.NewReader(body)))
		return rec
	}
	if rec := commit(raw); rec.Code < 500 {
		t.Fatalf("durability failure must not be acknowledged: %d %s", rec.Code, rec.Body.String())
	}
	published, err := store.ResolvePath("/atomic.bin")
	if err != nil || published.Staging {
		t.Fatalf("fixture failed to reach the committed transaction: %+v %v", published, err)
	}
	opResult, ok, err := store.GetOpResult(op)
	if err != nil || !ok || opResult.Inode.ID != published.ID || opResult.Fingerprint == "" {
		t.Fatalf("published file has no atomic replay record: found=%v record=%+v err=%v", ok, opResult, err)
	}
	if rec := commit(raw); rec.Code < 500 {
		t.Fatalf("replay bypassed durability confirmation: %d %s", rec.Code, rec.Body.String())
	}
	unavailable.Store(false)
	rec := commit(raw)
	if rec.Code != http.StatusOK {
		t.Fatalf("retry must return the original committed result: %d %s", rec.Code, rec.Body.String())
	}
	var replayed types.Inode
	if err := json.Unmarshal(rec.Body.Bytes(), &replayed); err != nil || replayed.ID != published.ID || replayed.Generation != published.Generation {
		t.Fatalf("retry changed file identity/generation: %+v %v", replayed, err)
	}
	if confirmationCalls.Load() != 3 {
		t.Fatalf("each result must pass durability confirmation: %d calls", confirmationCalls.Load())
	}
	changed := bytes.Replace(raw, []byte(`"size":16`), []byte(`"size":17`), 1)
	if bytes.Equal(raw, changed) {
		t.Fatal("fixture did not change commit contents")
	}
	if rec := commit(changed); rec.Code != http.StatusConflict {
		t.Fatalf("same operation with different contents must conflict: %d %s", rec.Code, rec.Body.String())
	}
}
