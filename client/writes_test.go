package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master"
	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/types"
)

type plannedCluster struct {
	client   *Client
	store    *meta.Store
	master   *httptest.Server
	nodes    []*httptest.Server
	dataDirs []string
	mu       sync.Mutex
	paths    map[string]int
	bytes    atomic.Int64
}

func newPlannedCluster(t *testing.T, count int) *plannedCluster {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := master.NewServer(store, time.Hour)
	if err = srv.EnableWritePlanning(master.WritePlanningConfig{MaxReplicas: 4}); err != nil {
		t.Fatal(err)
	}
	cl := &plannedCluster{store: store, paths: map[string]int{}}
	handler := srv.Handler()
	cl.master = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl.mu.Lock()
		cl.paths[r.Method+" "+r.URL.Path]++
		cl.mu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(cl.master.Close)
	cl.client = New(cl.master.URL)
	for i := 0; i < count; i++ {
		dir := filepath.Join(t.TempDir(), "objects")
		n := node.New(dir, cl.master.URL, "", 1<<30)
		h := n.Handler()
		ns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
				cl.bytes.Add(r.ContentLength)
			}
			h.ServeHTTP(w, r)
		}))
		t.Cleanup(ns.Close)
		reg, err := store.RegisterNode(ns.Listener.Addr().String(), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		n.SetNodeIDForTest(reg.ID)
		if err = store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: reg.ID, FailureDomains: map[string]string{"zone": fmt.Sprint(i)}}); err != nil {
			t.Fatal(err)
		}
		cl.nodes = append(cl.nodes, ns)
		cl.dataDirs = append(cl.dataDirs, dir)
	}
	return cl
}
func (cl *plannedCluster) assertNoLegacyWrites(t *testing.T) {
	t.Helper()
	cl.mu.Lock()
	defer cl.mu.Unlock()
	for _, p := range []string{"POST /files", "POST /files/small", "POST /files/chunks", "POST /files/commit", "POST /auth/files/empty"} {
		if cl.paths[p] != 0 {
			t.Errorf("legacy bypass %s = %d", p, cl.paths[p])
		}
	}
}

func TestPlannedClientPutReadOverwriteEmpty(t *testing.T) {
	withChunkSize(t, 1024)
	cl := newPlannedCluster(t, 3)
	c := cl.client
	if _, err := c.Mkdir("/docs"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetProtection("/docs", types.ProtectionSecurity); err != nil {
		t.Fatal(err)
	}
	first, err := c.PutSmall("/docs/file", []byte("first"), 99, false)
	if err != nil {
		t.Fatal(err)
	}
	if first.Content == nil || first.Content.Extents[0].Object.Encoding != types.PlainEncoding {
		t.Fatalf("missing content model %+v", first)
	}
	data := bytes.Repeat([]byte("abc"), 900)
	if err = c.PutChunkedReaderWithMinCopies("/docs/file", int64(len(data)), bytes.NewReader(data), 99, 99, true); err != nil {
		t.Fatal(err)
	}
	second, _, err := c.Lookup("/docs/file")
	if err != nil || second.ID != first.ID || second.Generation != first.Generation+1 || second.Content.ID == first.Content.ID {
		t.Fatalf("overwrite %+v %v", second, err)
	}
	out := filepath.Join(t.TempDir(), "read")
	if err = c.Get("/docs/file", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read %v", err)
	}
	if err = c.PutReaderOverwrite("/docs/empty", 0, bytes.NewReader(nil), 99, false); err != nil {
		t.Fatal(err)
	}
	if err = c.Get("/docs/empty", out); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(out)
	if err != nil || st.Size() != 0 {
		t.Fatal("empty read")
	}
	policy, err := c.GetProtection("/docs/file")
	if err != nil || policy.Policy.Tier != types.ProtectionSecurity {
		t.Fatalf("policy %+v %v", policy, err)
	}
	if cl.bytes.Load() < int64(len(data)+5) {
		t.Fatal("payload did not go directly to nodes")
	}
	cl.assertNoLegacyWrites(t)
}

func TestPlannedClientStreamAndClosedState(t *testing.T) {
	withChunkSize(t, 512)
	cl := newPlannedCluster(t, 2)
	c := cl.client
	u, err := c.BeginStreamUpload("/stream", 99)
	if err != nil {
		t.Fatal(err)
	}
	block := bytes.Repeat([]byte("a"), 512)
	for i := 0; i < 3; i++ {
		if err = u.Push(block); err != nil {
			t.Fatal(err)
		}
	}
	if err = u.Finish([]byte("tail"), 1540); err != nil {
		t.Fatal(err)
	}
	if u.Progress() != 1540 {
		t.Fatal("progress")
	}
	if err = u.Push(block); err == nil {
		t.Fatal("push accepted after finish")
	}
	if err = u.Close(); err != nil {
		t.Fatal(err)
	}
	v, err := c.BeginStreamUpload("/aborted", 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Push(block); err != nil {
		t.Fatal(err)
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	if err = v.Finish(nil, 512); err == nil {
		t.Fatal("finish accepted after close")
	}
	if _, _, err = c.Lookup("/aborted"); err == nil {
		t.Fatal("aborted visible")
	}
	empty, err := c.BeginStreamUpload("/empty-stream", 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = empty.Finish(nil, 0); err != nil {
		t.Fatal(err)
	}
	cl.assertNoLegacyWrites(t)
}

func TestPlannedClientCapabilitiesFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr bool
		enabled bool
	}{
		{"404", 404, "", false, false}, {"405", 405, "", false, false}, {"503", 503, "{}", true, false}, {"403", 403, "{}", true, false}, {"malformed", 200, "!", true, false}, {"null", 200, "null", true, false}, {"missing", 200, "{}", true, false}, {"unknown", 200, `{"write_planning":true,"features":[]}`, true, false}, {"disabled", 200, `{"write_planning":false,"features":[]}`, false, false}, {"enabled", 200, `{"write_planning":true,"features":["write-plan-v1"]}`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
			defer srv.Close()
			c := New(srv.URL)
			enabled, err := c.WritePlanning(context.Background())
			if (err != nil) != tc.wantErr || enabled != tc.enabled {
				t.Fatalf("%v %v", enabled, err)
			}
			if err != nil && !IsPlannedWriteError(err) {
				t.Fatal("failure permits old fallback")
			}
		})
	}
}

func TestPlannedClientStickyCapabilityAndNoDowngrade(t *testing.T) {
	var enabled atomic.Bool
	enabled.Store(true)
	var legacy atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/capabilities" {
			json.NewEncoder(w).Encode(types.Capabilities{Features: []string{types.WritePlanFeature}, WritePlanning: enabled.Load()})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/files") {
			legacy.Add(1)
		}
		w.WriteHeader(503)
	}))
	defer srv.Close()
	c := New(srv.URL)
	if on, err := c.WritePlanning(context.Background()); err != nil || !on {
		t.Fatal(err)
	}
	enabled.Store(false)
	if on, err := c.WritePlanning(context.Background()); err != nil || !on {
		t.Fatal("downgrade")
	}
	_, err := c.PutSmall("/test", []byte("data"), 1, false)
	if err == nil || legacy.Load() != 0 || !IsPlannedWriteError(err) {
		t.Fatalf("fallback: %v %d", err, legacy.Load())
	}
}

func TestPlannedClientRejectsTamperedPlan(t *testing.T) {
	mutations := map[string]func(*types.PlanWriteChunkResponse){
		"wrong-object":  func(o *types.PlanWriteChunkResponse) { o.Plan.Object.ID++ },
		"wrong-size":    func(o *types.PlanWriteChunkResponse) { o.Plan.Object.StoredSize++ },
		"unknown-crc":   func(o *types.PlanWriteChunkResponse) { o.Plan.Object.ChecksumKnown = false },
		"confirm-count": func(o *types.PlanWriteChunkResponse) { o.Plan.RequiredConfirmations++ },
		"node-missing":  func(o *types.PlanWriteChunkResponse) { o.Nodes = nil },
		"bad-address":   func(o *types.PlanWriteChunkResponse) { o.Nodes[0].Addr = "evil@127.0.0.1:5/path" },
		"layout-mirror": func(o *types.PlanWriteChunkResponse) { o.Chunk.Replicas = []uint64{5} },
		"encoding":      func(o *types.PlanWriteChunkResponse) { o.Plan.Object.Encoding = "encrypted" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			cl := newPlannedCluster(t, 1)
			u, err := cl.client.beginPlannedWrite(context.Background(), "/test", 4, false, "test")
			if err != nil {
				t.Fatal(err)
			}
			req := types.PlanWriteChunkRequest{WriteBinding: plannedBinding(u), Index: 0, LogicalSize: 4, StoredSize: 4, Encoding: types.PlainEncoding, Checksum: types.CRC32C([]byte("test"))}
			var out types.PlanWriteChunkResponse
			if err = cl.client.writeJSON(context.Background(), http.MethodPost, "/writes/chunks", req, &out); err != nil {
				t.Fatal(err)
			}
			if err = validatePlannedChunk(req, out); err != nil {
				t.Fatal(err)
			}
			mutate(&out)
			if err = validatePlannedChunk(req, out); err == nil {
				t.Fatal("tampered response accepted")
			}
		})
	}
}

func TestPlannedClientLostCommitReplySameOperation(t *testing.T) {
	cl := newPlannedCluster(t, 1)
	c := cl.client
	base := c.HTTP.Transport
	var dropped atomic.Bool
	var mu sync.Mutex
	var commits []string
	c.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/writes/commit" {
			body, _ := r.GetBody()
			raw, _ := io.ReadAll(body)
			body.Close()
			mu.Lock()
			commits = append(commits, string(raw))
			mu.Unlock()
		}
		resp, err := base.RoundTrip(r)
		if r.URL.Path == "/writes/commit" && err == nil && resp.StatusCode == 200 && !dropped.Swap(true) {
			resp.Body.Close()
			return nil, io.ErrUnexpectedEOF
		}
		return resp, err
	})
	if _, err := c.PutSmall("/replay", []byte("payload"), 99, false); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(commits) < 2 || commits[0] != commits[len(commits)-1] {
		t.Fatalf("commit changed: %v", commits)
	}
	in, _, err := c.Lookup("/replay")
	if err != nil || in.Generation != 1 {
		t.Fatalf("published twice: %+v %v", in, err)
	}
	cl.assertNoLegacyWrites(t)
}

type plannedTestTransport func(*http.Request) (*http.Response, error)

func (f plannedTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPlannedClientUnavailableRequiredNodeNeverReassigns(t *testing.T) {
	cl := newPlannedCluster(t, 1)
	c := cl.client
	base := c.HTTP.Transport
	var attempted atomic.Int64
	c.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			attempted.Add(1)
			r.Body.Close()
			return &http.Response{StatusCode: 507, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"full"}`)), Request: r}, nil
		}
		return base.RoundTrip(r)
	})
	if _, err := c.PutSmall("/fail", []byte("payload"), 5, false); err == nil || !IsPlannedWriteError(err) {
		t.Fatal(err)
	}
	if attempted.Load() != 3 {
		t.Fatalf("same plan PUT attempts %d", attempted.Load())
	}
	if _, _, err := c.Lookup("/fail"); err == nil {
		t.Fatal("unconfirmed published")
	}
	cl.mu.Lock()
	begin, plan, commit := cl.paths["POST /writes"], cl.paths["POST /writes/chunks"], cl.paths["POST /writes/commit"]
	cl.mu.Unlock()
	if begin != 1 || plan != 1 || commit != 0 {
		t.Fatalf("replanned begin=%d plan=%d commit=%d", begin, plan, commit)
	}
	cl.assertNoLegacyWrites(t)
}

func TestPlannedClientReaderFailureAborts(t *testing.T) {
	cl := newPlannedCluster(t, 1)
	_, err := cl.client.putPlannedReader(context.Background(), "/short", 10, bytes.NewReader([]byte("bad")), false)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if _, _, err = cl.client.Lookup("/short"); err == nil {
		t.Fatal("short reader published")
	}
}
