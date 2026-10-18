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
	"reflect"
	"strconv"
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
	if in.ObjID == 0 {
		t.Fatalf("small 新上传应有显式 ObjID: %+v", in)
	}
	path := rc.objectPath(t, in.Replicas[0], types.ObjIDFor(in))
	corruptDiskObject(t, path)
	rh := openReadHandle(t, rc.m, "/file")
	if rh.objID != in.ObjID || rh.ino != in.ID {
		t.Fatalf("Open 应快照 objID=%d 且保持逻辑 FileID ino=%d: got objID=%d ino=%d",
			in.ObjID, in.ID, rh.objID, rh.ino)
	}
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
	badPath := rc.objectPath(t, victim, types.ObjIDFor(in))
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
		got, err := os.ReadFile(rc.objectPath(t, id, types.ObjIDFor(in)))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("replica %d still differs after repair: %v", id, err)
		}
	}
}

// TestMountStaleChecksumDoesNotDeleteNewVersion 旧版本读者不得伤害新版本（v2-4b）：
// 覆盖写保留 FileID/Generation 递进，内容切换到新的不复用 ObjID；旧对象延迟回收。
// 旧句柄按打开时快照的旧 ObjID 寻址：旧对象尚在则读到旧内容（CRC 匹配，属允许的
// “回收窗口内旧 fd 可读”），已回收则 404 失败——两条路都不能伤到新版本。
// 旧版本 suspect 不依赖旧 fd 产生 CRC 冲突（新语义下通常不会），故显式重放旧版本的
// suspect 报文验证：master 按版本三元组精确匹配，旧快照上报既不撤销新版本副本、
// 也不删除任何对象。
func TestMountStaleChecksumDoesNotDeleteNewVersion(t *testing.T) {
	rc := newReadTestCluster(t, 1)
	old := []byte("old-version")
	latest := []byte("new-version")
	in, err := rc.client.PutSmall("/file", old, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	rh := openReadHandle(t, rc.m, "/file")
	if rh.objID != types.ObjIDFor(in) || rh.ino != in.ID {
		t.Fatalf("Open 应快照 objID=%d、ino 保持 FileID=%d: got objID=%d ino=%d",
			types.ObjIDFor(in), in.ID, rh.objID, rh.ino)
	}
	updated, err := rc.client.PutSmall("/file", latest, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != in.ID || updated.Generation <= in.Generation {
		t.Fatalf("覆盖写应保留 FileID 且 Generation 递进: %+v", updated)
	}
	if updated.ObjID == in.ObjID {
		t.Fatalf("覆盖写应切换到新 ObjID: %+v", updated)
	}

	// 安全断言 1：旧句柄永远读不到新版本字节。旧对象还在 → 读回旧内容；
	// 已被异步回收 → EIO。等待回收收敛后再读，同时容忍窗口内读到旧内容。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(rc.objectPath(t, in.Replicas[0], in.ObjID)); os.IsNotExist(err) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, errno := readBytes(rh, context.Background(), 0, len(old))
	if errno == 0 && !bytes.Equal(got, old) {
		t.Fatalf("stale handle observed new-version bytes: %q", got)
	}
	if errno != 0 && errno != syscall.EIO {
		t.Fatalf("stale read: unexpected errno %v", errno)
	}

	// 安全断言 2：显式重放旧版本 suspect（不靠旧 fd 的 CRC 冲突）——
	// 服务端按 (FileID, generation, size, checksum) 与当前版本精确匹配，
	// 旧快照上报必须被忽略：新版本 Done 副本不被撤销、磁盘对象不被删除。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	staleReport := types.Inode{ID: in.ID, Size: in.Size, Checksum: in.Checksum, Generation: in.Generation}
	if err := rc.client.ReportSuspect(ctx, staleReport, in.Replicas[0]); err != nil {
		t.Fatalf("ReportSuspect: %v", err)
	}
	state, err := rc.store.GetInode(in.ID)
	if err != nil || !types.ContainsUint64(state.DoneReplicas, in.Replicas[0]) {
		t.Fatalf("stale report invalidated the new version: %+v %v", state, err)
	}
	disk, err := os.ReadFile(rc.objectPath(t, updated.Replicas[0], updated.ObjID))
	if err != nil || !bytes.Equal(disk, latest) {
		t.Fatalf("stale reader damaged the new version: %q %v", disk, err)
	}

	// 安全断言 3：新读者按新 ObjID 读到新内容。
	fresh := openReadHandle(t, rc.m, "/file")
	if got, errno := readBytes(fresh, context.Background(), 0, len(latest)); errno != 0 || !bytes.Equal(got, latest) {
		t.Fatalf("fresh reader cannot read new version: %q %v", got, errno)
	}
}

// TestReadHandlePhysicalReadsUseObjID 物理寻址与身份分离的单元测试：
// objID 非零时请求打 /objects/<objID>（ino 仅用于 suspect 上报）；
// objID=0 兼容直接构造句柄的既有测试/旧数据——回退按旧约定 ino 寻址。
func TestReadHandlePhysicalReadsUseObjID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ino      uint64
		objID    uint64
		wantHits []uint64
	}{
		{name: "explicit_objid", ino: 100, objID: 500, wantHits: []uint64{500}},
		{name: "legacy_fallback", ino: 100, objID: 0, wantHits: []uint64{100}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("addressed-by-objid")
			var mu sync.Mutex
			var hits []uint64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				hits = append(hits, parseObjectIDForTest(r.URL.Path))
				mu.Unlock()
				w.Write(data)
			}))
			t.Cleanup(srv.Close)
			rh := &readHandle{ino: tc.ino, objID: tc.objID, size: int64(len(data)),
				checksum: types.CRC32C(data),
				cands:    []client.Replica{{ID: 2, Addr: srv.Listener.Addr().String(), Done: true}},
				http:     srv.Client(), scheme: "http"}
			got, errno := readBytes(rh, context.Background(), 0, len(data))
			if errno != 0 || !bytes.Equal(got, data) {
				t.Fatalf("read: %q %v", got, errno)
			}
			mu.Lock()
			defer mu.Unlock()
			if !reflect.DeepEqual(hits, tc.wantHits) {
				t.Fatalf("physical reads hit %v, want %v", hits, tc.wantHits)
			}
		})
	}
}

// parseObjectIDForTest 从 /objects/<id> 路径提取对象 ID（测试辅助）。
func parseObjectIDForTest(path string) uint64 {
	const prefix = "/objects/"
	if !strings.HasPrefix(path, prefix) {
		return 0
	}
	id, _ := strconv.ParseUint(strings.TrimPrefix(path, prefix), 10, 64)
	return id
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
				http:  srv.Client(), scheme: "http"}
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

// TestReadHandleSharesMountCache 同一 Mount 的两个句柄读同一小对象：整对象校验读取
// 合并为 1 次 GET（Mount 级缓存跨句柄共享，而非句柄私有 retained 副本）。
func TestReadHandleSharesMountCache(t *testing.T) {
	data := []byte("shared-verified-object")
	var gets atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/objects/500" {
			gets.Add(1)
		}
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	masterSrv := httptest.NewServer(http.NotFoundHandler()) // 成功路径不触 master
	t.Cleanup(masterSrv.Close)
	m, err := New(client.New(masterSrv.URL), t.TempDir(), 1)
	if err != nil {
		t.Fatalf("mount.New: %v", err)
	}
	mk := func() *readHandle {
		return &readHandle{ino: 2, objID: 500, size: int64(len(data)), checksum: types.CRC32C(data),
			generation: 1, cands: []client.Replica{{ID: 2, Addr: srv.Listener.Addr().String(), Done: true}},
			http: srv.Client(), scheme: "http", m: m}
	}
	for i, rh := range []*readHandle{mk(), mk()} {
		got, errno := readBytes(rh, context.Background(), 0, len(data))
		if errno != 0 || !bytes.Equal(got, data) {
			t.Fatalf("rh%d read: %q %v", i, got, errno)
		}
	}
	if gets.Load() != 1 {
		t.Fatalf("跨句柄未共享缓存: %d GETs", gets.Load())
	}
}

// TestReadHandleLargeLegacyUsesStrictRange 超过 ChunkSize 的 legacy 整对象即使有
// checksum 也走严格 Range（整块校验需缓冲整对象，会突破在飞内存界）；Range 响应
// Content-Range 逐字节匹配时照常服务。
func TestReadHandleLargeLegacyUsesStrictRange(t *testing.T) {
	total := types.ChunkSize + 1
	var wholeGET atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			wholeGET.Add(1)
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-1/%d", total))
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte("ab"))
	}))
	t.Cleanup(srv.Close)
	// checksum 非 0：若误走整块校验会先发整对象 GET 并因长度不符失败。
	rh := &readHandle{ino: 2, size: total, checksum: 12345,
		cands: []client.Replica{{ID: 2, Addr: srv.Listener.Addr().String(), Done: true}},
		http:  srv.Client(), scheme: "http"}
	got, errno := readBytes(rh, context.Background(), 0, 2)
	if errno != 0 || string(got) != "ab" {
		t.Fatalf("大 legacy 对象 Range 读: %q %v", got, errno)
	}
	if wholeGET.Load() != 0 {
		t.Fatalf("大 legacy 对象不应整对象 GET: %d 次", wholeGET.Load())
	}
}

// TestReadHandleSuspectRotation 小路径（readRange，checksum=0 不缓存）同句柄连续读：
// suspect 副本殿后兜底、不参与轮转；健康失败轮到 suspect 成功后，下一次仍先试健康。
func TestReadHandleSuspectRotation(t *testing.T) {
	var healthyGets, suspectGets atomic.Int64
	var healthyBroken atomic.Bool
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthyGets.Add(1)
		if healthyBroken.Load() {
			http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Write([]byte("abcdef"))
	}))
	t.Cleanup(healthy.Close)
	suspect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suspectGets.Add(1)
		w.Write([]byte("abcdef"))
	}))
	t.Cleanup(suspect.Close)
	rh := &readHandle{ino: 2, objID: 500, size: 6, checksum: 0, // 未知 checksum：严格 Range、不缓存
		cands:    []client.Replica{{ID: 2, Addr: healthy.Listener.Addr().String(), Done: true}},
		suspects: []client.Replica{{ID: 1, Addr: suspect.Listener.Addr().String()}},
		http:     healthy.Client(), scheme: "http"}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if got, errno := readBytes(rh, ctx, 0, 6); errno != 0 || string(got) != "abcdef" {
			t.Fatalf("读 %d: %q %v", i, got, errno)
		}
	}
	if n := suspectGets.Load(); n != 0 {
		t.Fatalf("suspect 副本被轮转首选: %d 次", n)
	}
	healthyBroken.Store(true) // 健康段全败 → suspect 兜底成功
	if got, errno := readBytes(rh, ctx, 0, 6); errno != 0 || string(got) != "abcdef" {
		t.Fatalf("兜底读: %q %v", got, errno)
	}
	healthyBroken.Store(false) // 下一次必须先回健康段
	if got, errno := readBytes(rh, ctx, 0, 6); errno != 0 || string(got) != "abcdef" {
		t.Fatalf("回归健康读: %q %v", got, errno)
	}
	if n := suspectGets.Load(); n != 1 {
		t.Fatalf("suspect 兜底后仍被轮转首选: %d 次", n)
	}
	if n := healthyGets.Load(); n != 5 {
		t.Fatalf("健康副本应始终先试: %d 次", n)
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
		if r.URL.Path == "/capabilities" {
			json.NewEncoder(w).Encode(types.Capabilities{WritePlanning: false})
			return
		}
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
