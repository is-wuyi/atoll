package mount

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"atoll/client"
	"atoll/master"
	"atoll/master/meta"
	atollnode "atoll/node"
	"atoll/pkg/types"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type readTestNode struct {
	id      uint64
	dataDir string
	server  *httptest.Server
	gets    atomic.Int64
}

type readTestCluster struct {
	client   *client.Client
	m        *Mount
	store    *meta.Store
	scanner  *master.Scanner
	nodes    []*readTestNode
	reported chan struct{}
}

func newReadTestCluster(t *testing.T, numNodes int) *readTestCluster {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rc := &readTestCluster{store: store, reported: make(chan struct{}, 32)}
	rc.scanner = master.NewScanner(store, time.Hour, time.Millisecond, time.Hour)
	ms := master.NewServer(store, time.Hour)
	ms.SetScanner(rc.scanner)
	handler := ms.Handler()
	masterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		if r.URL.Path == "/files/suspect" || r.URL.Path == "/files/corrupt" {
			rc.reported <- struct{}{}
		}
	}))
	t.Cleanup(masterSrv.Close)
	rc.client = client.New(masterSrv.URL)
	for i := 0; i < numNodes; i++ {
		n := &readTestNode{dataDir: t.TempDir()}
		storage := atollnode.New(n.dataDir, masterSrv.URL, "", 1<<30)
		h := storage.Handler()
		n.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/objects/") {
				n.gets.Add(1)
			}
			h.ServeHTTP(w, r)
		}))
		t.Cleanup(n.server.Close)
		info, err := store.RegisterNode(n.server.Listener.Addr().String(), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		n.id = info.ID
		storage.SetNodeIDForTest(info.ID)
		rc.nodes = append(rc.nodes, n)
	}
	rc.m, err = New(rc.client, t.TempDir(), numNodes)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

func (rc *readTestCluster) objectPath(t *testing.T, nodeID, objectID uint64) string {
	t.Helper()
	for _, n := range rc.nodes {
		if n.id == nodeID {
			return filepath.Join(n.dataDir, "objects", fmt.Sprintf("%02x", objectID%256), fmt.Sprint(objectID))
		}
	}
	t.Fatalf("unknown node %d", nodeID)
	return ""
}

func (rc *readTestCluster) waitReport(t *testing.T) {
	t.Helper()
	select {
	case <-rc.reported:
	case <-time.After(10 * time.Second):
		t.Fatal("corruption was not reported")
	}
}

func corruptDiskObject(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] ^= 0xff
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func openReadHandle(t *testing.T, m *Mount, path string) *readHandle {
	t.Helper()
	root, raw := namespaceFS(m)
	var current *fs.Inode = &root.Inode
	nodeID := uint64(1)
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		var out fuse.EntryOut
		if status := raw.Lookup(nil, &fuse.InHeader{NodeId: nodeID}, part, &out); status != fuse.OK {
			t.Fatalf("Lookup %s: %v", part, status)
		}
		current = current.GetChild(part)
		if current == nil {
			t.Fatalf("missing FUSE child %s", part)
		}
		nodeID = out.NodeId
	}
	handle, _, errno := current.Operations().(*node).Open(context.Background(), syscall.O_RDONLY)
	if errno != 0 {
		t.Fatalf("Open: %v", errno)
	}
	rh, ok := handle.(*readHandle)
	if !ok {
		t.Fatalf("expected legacy read handle, got %T", handle)
	}
	return rh
}

func readBytes(rh *readHandle, ctx context.Context, off int64, n int) ([]byte, syscall.Errno) {
	buf := make([]byte, n)
	result, errno := rh.Read(ctx, buf, off)
	if errno != 0 {
		return nil, errno
	}
	defer result.Done()
	data, status := result.Bytes(buf)
	return append([]byte(nil), data...), syscall.Errno(status)
}

func TestMountSmallReadVerifiesCRC(t *testing.T) {
	rc := newReadTestCluster(t, 1)
	data := bytes.Repeat([]byte("crc-guard-"), 100)
	in, err := rc.client.PutSmall("/file", data, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	path := rc.objectPath(t, in.Replicas[0], in.ID)
	corruptDiskObject(t, path)
	rh := openReadHandle(t, rc.m, "/file")
	if got, errno := readBytes(rh, context.Background(), 0, 5); errno != syscall.EIO || len(got) != 0 {
		t.Fatalf("bad bytes escaped verification: %x errno=%v", got, errno)
	}
	rc.waitReport(t)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a suspect report must not delete the only physical copy: %v", err)
	}
}

func TestMountSmallReadFailsOverToGoodReplica(t *testing.T) {
	rc := newReadTestCluster(t, 2)
	data := bytes.Repeat([]byte("failover-me-"), 100)
	in, err := rc.client.PutSmall("/file", data, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	waitReplica(t, rc.client, "/file", 2)
	victim := in.Replicas[0]
	badPath := rc.objectPath(t, victim, in.ID)
	corruptDiskObject(t, badPath)
	rh := openReadHandle(t, rc.m, "/file")
	// 固定先命中坏副本，不能用随机顺序或缓存命中证明故障转移。
	for i, r := range rh.cands {
		if r.ID == victim {
			rh.cands[0], rh.cands[i] = rh.cands[i], rh.cands[0]
			break
		}
	}
	for _, span := range [][2]int{{0, 5}, {5, 111}, {len(data) - 8, 20}} {
		got, errno := readBytes(rh, context.Background(), int64(span[0]), span[1])
		want := data[span[0]:min(span[0]+span[1], len(data))]
		if errno != 0 || !bytes.Equal(got, want) {
			t.Fatalf("failover read: got=%x want=%x errno=%v", got, want, errno)
		}
	}
	rc.waitReport(t)
	state, err := rc.store.GetInode(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if types.ContainsUint64(state.DoneReplicas, victim) {
		t.Fatal("suspect replica is still counted as done")
	}
	if _, err := os.Stat(badPath); err != nil {
		t.Fatalf("report deleted data instead of scheduling repair: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rc.scanner.RepairScanOnce()
		state, err = rc.store.GetInode(in.ID)
		if err == nil && len(state.DoneReplicas) == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || len(state.DoneReplicas) != 2 {
		t.Fatalf("repair did not converge: %+v %v", state, err)
	}
	for _, id := range in.Replicas {
		got, err := os.ReadFile(rc.objectPath(t, id, in.ID))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("replica %d still differs after repair: %v", id, err)
		}
	}
}

func TestMountStaleChecksumDoesNotDeleteNewVersion(t *testing.T) {
	rc := newReadTestCluster(t, 1)
	old := []byte("old-version")
	latest := []byte("new-version")
	in, err := rc.client.PutSmall("/file", old, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	rh := openReadHandle(t, rc.m, "/file")
	updated, err := rc.client.PutSmall("/file", latest, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != in.ID || updated.Generation <= in.Generation {
		t.Fatalf("test requires same object ID with a newer generation: %+v", updated)
	}
	if _, errno := readBytes(rh, context.Background(), 0, len(old)); errno == 0 {
		t.Fatal("stale checksum unexpectedly accepted the new bytes")
	}
	rc.waitReport(t)
	got, err := os.ReadFile(rc.objectPath(t, in.Replicas[0], in.ID))
	if err != nil || !bytes.Equal(got, latest) {
		t.Fatalf("stale reader damaged the new version: %q %v", got, err)
	}
	state, err := rc.store.GetInode(in.ID)
	if err != nil || !types.ContainsUint64(state.DoneReplicas, in.Replicas[0]) {
		t.Fatalf("stale report invalidated the new version: %+v %v", state, err)
	}
	fresh := openReadHandle(t, rc.m, "/file")
	if got, errno := readBytes(fresh, context.Background(), 0, len(latest)); errno != 0 || !bytes.Equal(got, latest) {
		t.Fatalf("fresh reader cannot read new version: %q %v", got, errno)
	}
}

func TestReadHandleConcurrentReads(t *testing.T) {
	for _, cache := range []bool{true, false} {
		t.Run(fmt.Sprintf("cache=%t", cache), func(t *testing.T) {
			data := bytes.Repeat([]byte("parallel-"), 200)
			var requests atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.ServeContent(w, r, "file", time.Time{}, bytes.NewReader(data))
			}))
			t.Cleanup(srv.Close)
			crc := uint32(0)
			if cache {
				crc = types.CRC32C(data)
			}
			rh := &readHandle{ino: 2, size: int64(len(data)), checksum: crc,
				cands: []client.Replica{{ID: 2, Addr: srv.Listener.Addr().String(), Done: true}},
				http: srv.Client(), scheme: "http"}
			start := make(chan struct{})
			var wg sync.WaitGroup
			for g := 0; g < 8; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					<-start
					for i := 0; i < 20; i++ {
						off := (g*73 + i*17) % (len(data) - 128)
						got, errno := readBytes(rh, context.Background(), int64(off), 128)
						if errno != 0 || !bytes.Equal(got, data[off:off+128]) {
							t.Errorf("concurrent read differs: errno=%v", errno)
							return
						}
					}
				}(g)
			}
			close(start)
			wg.Wait()
			if cache && requests.Load() != 1 {
				t.Errorf("cache miss was not coalesced: %d GETs", requests.Load())
			}
		})
	}
}

func TestReadHandleSmallBoundaries(t *testing.T) {
	data := []byte("abcdef")
	var requests atomic.Int64
	var broken atomic.Bool
	broken.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if broken.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	rh := &readHandle{ino: 2, size: int64(len(data)), checksum: types.CRC32C(data),
		cands: []client.Replica{{ID: 2, Addr: srv.Listener.Addr().String()}}, http: srv.Client(), scheme: "http"}
	if _, errno := readBytes(rh, context.Background(), -1, 1); errno != syscall.EINVAL {
		t.Fatalf("negative offset: %v", errno)
	}
	for _, span := range [][2]int{{0, 0}, {len(data), 10}} {
		got, errno := readBytes(rh, context.Background(), int64(span[0]), span[1])
		if errno != 0 || len(got) != 0 {
			t.Fatalf("empty read: %q %v", got, errno)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("empty/EOF reads made HTTP requests")
	}
	if _, errno := readBytes(rh, context.Background(), 0, 2); errno == 0 {
		t.Fatal("unavailable source accepted")
	}
	broken.Store(false)
	got, errno := readBytes(rh, context.Background(), 4, 10)
	if errno != 0 || string(got) != "ef" {
		t.Fatalf("failure poisoned the cache or EOF slice is wrong: %q %v", got, errno)
	}
	got[0] = 'x'
	if got, errno := readBytes(rh, context.Background(), 4, 2); errno != 0 || string(got) != "ef" {
		t.Fatalf("caller modified shared cache: %q %v", got, errno)
	}
}

func TestReadHandleRejectsBadLength(t *testing.T) {
	for _, body := range []string{"abc", "abcdefextra"} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
			t.Cleanup(srv.Close)
			rh := &readHandle{ino: 2, size: 6, checksum: types.CRC32C([]byte("abcdef")),
				cands: []client.Replica{{ID: 2, Addr: srv.Listener.Addr().String()}}, http: srv.Client(), scheme: "http"}
			if _, errno := readBytes(rh, context.Background(), 0, 2); errno != syscall.EIO {
				t.Fatalf("invalid object length accepted: %v", errno)
			}
		})
	}
}

func TestStatfsAliveOnly(t *testing.T) {
	rc := newReadTestCluster(t, 3)
	root := rc.m.Root().(*node)
	capacity := func() fuse.StatfsOut {
		var out fuse.StatfsOut
		if errno := root.Statfs(context.Background(), &out); errno != 0 {
			t.Fatal(errno)
		}
		return out
	}
	full := capacity()
	if full.Blocks != 3*(1<<30)/4096 {
		t.Fatalf("wrong initial physical capacity: %+v", full)
	}
	if err := rc.store.SetNodeHeartbeatAt(rc.nodes[0].id, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// 保留两秒缓存契约，通过回退缓存时间测试过期，不靠 sleep。
	if cached := capacity(); cached.Blocks != full.Blocks {
		t.Fatalf("fresh cache unexpectedly changed: %+v", cached)
	}
	rc.m.statfsMu.Lock()
	rc.m.statfsAt = time.Now().Add(-time.Hour)
	rc.m.statfsMu.Unlock()
	if after := capacity(); after.Blocks != 2*(1<<30)/4096 {
		t.Fatalf("dead node still counted: %+v", after)
	}
	for _, n := range rc.nodes {
		if err := rc.store.SetNodeHeartbeatAt(n.id, time.Now().Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	rc.m.statfsMu.Lock()
	rc.m.statfsAt = time.Time{}
	rc.m.statfsMu.Unlock()
	if empty := capacity(); empty.Blocks != 0 || empty.Bavail != 0 {
		t.Fatalf("all-offline cluster advertised space: %+v", empty)
	}
}

func TestStatfsDoesNotInventCapacity(t *testing.T) {
	var healthy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode([]map[string]any{{"total_bytes": 4096, "used_bytes": 8192, "alive": true}})
	}))
	t.Cleanup(srv.Close)
	m, err := New(client.New(srv.URL), t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	root := m.Root().(*node)
	var out fuse.StatfsOut
	if errno := root.Statfs(context.Background(), &out); errno != syscall.EIO {
		t.Fatalf("failed metadata call advertised capacity: %+v errno=%v", out, errno)
	}
	healthy.Store(true)
	if errno := root.Statfs(context.Background(), &out); errno != 0 || out.Bavail != 0 || out.Bfree != 0 {
		t.Fatalf("overfull node reported free space: %+v errno=%v", out, errno)
	}
}
