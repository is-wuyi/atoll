package mount

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"atoll/client"
	"atoll/master"
	"atoll/master/meta"
	atollnode "atoll/node"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type plannedMountCluster struct {
	client     *client.Client
	mount      *Mount
	store      *meta.Store
	mu         sync.Mutex
	calls      map[string]int
	failCommit bool
}

func newPlannedMountCluster(t *testing.T) *plannedMountCluster {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := master.NewServer(store, time.Hour)
	if err = srv.EnableWritePlanning(master.WritePlanningConfig{MaxReplicas: 3}); err != nil {
		t.Fatal(err)
	}
	cl := &plannedMountCluster{store: store, calls: map[string]int{}}
	h := srv.Handler()
	ms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl.mu.Lock()
		cl.calls[r.Method+" "+r.URL.Path]++
		fail := cl.failCommit && r.URL.Path == "/writes/commit"
		cl.mu.Unlock()
		if fail {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			fmt.Fprint(w, `{"code":"write_plan_conflict","error":"injected conflict"}`)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ms.Close)
	for i := 0; i < 2; i++ {
		n := atollnode.New(filepath.Join(t.TempDir(), "data"), ms.URL, "", 1<<30)
		ns := httptest.NewServer(n.Handler())
		t.Cleanup(ns.Close)
		reg, err := store.RegisterNode(ns.Listener.Addr().String(), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		n.SetNodeIDForTest(reg.ID)
	}
	cl.client = client.New(ms.URL)
	cl.mount, err = New(cl.client, filepath.Join(t.TempDir(), "cache"), 99)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func (c *plannedMountCluster) assertPlanned(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, path := range []string{"POST /files", "POST /files/small", "POST /files/chunks", "POST /files/commit", "POST /auth/files/empty"} {
		if n := c.calls[path]; n != 0 {
			t.Errorf("legacy upload %s=%d", path, n)
		}
	}
}

func TestMountPlannedSmallStreamEmptyAndOverwrite(t *testing.T) {
	withChunkSize(t, 1024)
	cl := newPlannedMountCluster(t)
	_, raw := namespaceFS(cl.mount)
	for _, tc := range []struct {
		name   string
		size   int
		stream bool
	}{{"small", 53, false}, {"stream", 2500, true}, {"empty", 0, false}} {
		t.Run(tc.name, func(t *testing.T) {
			cl.mount.NoSmallPath = tc.stream
			f := createNamespaceFile(t, raw, tc.name)
			data := bytes.Repeat([]byte(tc.name[:1]), tc.size)
			if len(data) > 0 {
				f.write(t, data, 0)
			}
			if status := f.flush(); status != fuse.OK {
				t.Fatal(status)
			}
			if status := f.flush(); status != fuse.OK {
				t.Fatal(status)
			}
			f.release()
			verifySmallPathContent(t, cl.client, "/"+tc.name, data)
			in, _, err := cl.client.Lookup("/" + tc.name)
			if err != nil || in.Content == nil {
				t.Fatalf("content %+v %v", in, err)
			}
		})
	}
	cl.assertPlanned(t)
}

func TestMountPlannedFailureNeverStartsFreshWriteOnFlush(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			withChunkSize(t, 1024)
			cl := newPlannedMountCluster(t)
			cl.mount.NoSmallPath = stream
			_, raw := namespaceFS(cl.mount)
			cl.mu.Lock()
			cl.failCommit = true
			cl.mu.Unlock()
			f := createNamespaceFile(t, raw, "fail")
			f.write(t, bytes.Repeat([]byte("a"), 2300), 0)
			if status := f.flush(); status == fuse.OK {
				t.Fatal("conflict hidden")
			}
			cl.mu.Lock()
			before := cl.calls["POST /writes"]
			cl.failCommit = false
			cl.mu.Unlock()
			if status := f.flush(); status == fuse.OK {
				t.Fatal("later flush silently re-created write")
			}
			cl.mu.Lock()
			after := cl.calls["POST /writes"]
			cl.mu.Unlock()
			if before != 1 || after != before {
				t.Fatalf("fresh write after conflict: %d/%d", before, after)
			}
			f.release()
			if _, _, err := cl.client.Lookup("/fail"); err == nil {
				t.Fatal("conflicted file visible")
			}
			cl.assertPlanned(t)
		})
	}
}

func TestMountPlannedOutOfOrderRewritePublishesCurrentBytes(t *testing.T) {
	withChunkSize(t, 1024)
	cl := newPlannedMountCluster(t)
	cl.mount.NoSmallPath = true
	w, err := cl.mount.newWriteHandle("/edit", true)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Release(context.Background())
	w.created = true
	data := bytes.Repeat([]byte("x"), 2300)
	if _, errno := w.Write(context.Background(), data, 0); errno != 0 {
		t.Fatal(errno)
	}
	copy(data[10:], []byte("new"))
	if _, errno := w.Write(context.Background(), []byte("new"), 10); errno != 0 {
		t.Fatal(errno)
	}
	if errno := w.Flush(context.Background()); errno != 0 {
		t.Fatal(errno)
	}
	verifySmallPathContent(t, cl.client, "/edit", data)
	cl.assertPlanned(t)
}
