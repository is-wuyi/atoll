package mount

// 分块读完整性（阶段 A chunked 部分）测试。
//
// 覆盖：
//   - 带块 checksum 的读取必须整块校验（长度恰为 c.Size 且 CRC32C 匹配）后才把字节
//     交给 FUSE；CRC/长度不符 → 上报 suspect（POST /files/chunks/suspect）并轮换副本；
//   - 绝不回退旧 /files/corrupt 删除通道（唯一坏副本不得被删）；
//   - legacy 无 checksum 块保持 Range 读取，但严格校验 Content-Range / 长度，
//     200 仅当 start==0 且请求覆盖完整块；
//   - per-Mount 共享有界整块缓存（字节预算可注入）+ 跨句柄 singleflight；
//   - ctx 取消传到 HTTP 与等待、负偏移/空 dest/越界无 panic。
//
// master 端 /files/chunks/suspect 的 tuple CAS 语义属主 agent 批次：此处用假 master
// （记录报文）与真集群（统计端点命中）两侧验证客户端行为。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
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
)

// ---- 假 master / 假节点 ----

// chunkSuspectBody 是 /files/chunks/suspect 的请求报文（与 client 实现字段一致）。
type chunkSuspectBody struct {
	InodeID    uint64 `json:"inode_id"`
	Generation uint64 `json:"generation"`
	ChunkIndex int    `json:"chunk_index"`
	ObjectID   uint64 `json:"object_id"`
	NodeID     uint64 `json:"node_id"`
	Size       int64  `json:"size"`
	Checksum   uint32 `json:"checksum"`
}

// suspectRecorder 假 master：记录 suspect 报文并统计旧 /files/corrupt 删除通道命中。
type suspectRecorder struct {
	mu      sync.Mutex
	bodies  []chunkSuspectBody
	corrupt int
	srv     *httptest.Server
}

func newSuspectRecorder(t *testing.T) *suspectRecorder {
	t.Helper()
	rec := &suspectRecorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("/files/chunks/suspect", func(w http.ResponseWriter, r *http.Request) {
		var b chunkSuspectBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Errorf("decode suspect body: %v", err)
		}
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, b)
		rec.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/files/corrupt" {
			rec.mu.Lock()
			rec.corrupt++
			rec.mu.Unlock()
		}
		http.Error(w, "not implemented in fake master", http.StatusNotFound)
	})
	rec.srv = httptest.NewServer(mux)
	t.Cleanup(rec.srv.Close)
	return rec
}

func (rec *suspectRecorder) snapshot() ([]chunkSuspectBody, int) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]chunkSuspectBody(nil), rec.bodies...), rec.corrupt
}

// waitSuspectBodies 轮询直到 suspect 报文数达到 want（上报是异步 goroutine）。
func (rec *suspectRecorder) waitSuspectBodies(t *testing.T, want int) []chunkSuspectBody {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		bodies, _ := rec.snapshot()
		if len(bodies) >= want {
			return bodies
		}
		time.Sleep(20 * time.Millisecond)
	}
	bodies, _ := rec.snapshot()
	t.Fatalf("等待 suspect 上报超时: got %d want %d", len(bodies), want)
	return nil
}

// assertNoSuspect 断言窗口期内既无 suspect 上报也无旧删除通道调用。
func assertNoSuspect(t *testing.T, rec *suspectRecorder) {
	t.Helper()
	time.Sleep(500 * time.Millisecond)
	bodies, corrupt := rec.snapshot()
	if len(bodies) != 0 || corrupt != 0 {
		t.Fatalf("不应有上报: suspect=%d corrupt=%d", len(bodies), corrupt)
	}
}

// countingNode 假存储节点：按对象 ID 返回固定内容并记录整对象 GET 次数。
type countingNode struct {
	srv  *httptest.Server
	mu   sync.Mutex
	gets map[uint64]int
}

func newCountingNode(t *testing.T, bodies map[uint64][]byte) *countingNode {
	t.Helper()
	cn := &countingNode{gets: map[uint64]int{}}
	cn.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := parseObjectIDForTest(r.URL.Path)
		if r.Method == http.MethodGet && id != 0 {
			cn.mu.Lock()
			cn.gets[id]++
			cn.mu.Unlock()
		}
		if b, ok := bodies[id]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(cn.srv.Close)
	return cn
}

func (cn *countingNode) getCount(id uint64) int {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return cn.gets[id]
}

// ---- 测试辅助 ----

// readChunkBytes 经 chunkedReadHandle.Read 读取并返回拷贝（模仿 FUSE 侧消费）。
func readChunkBytes(ctx context.Context, h *chunkedReadHandle, off int64, n int) ([]byte, syscall.Errno) {
	buf := make([]byte, n)
	res, errno := h.Read(ctx, buf, off)
	if errno != 0 {
		return nil, errno
	}
	data, status := res.Bytes(buf)
	if status != 0 {
		return nil, syscall.Errno(status)
	}
	return append([]byte(nil), data...), 0
}

// newUnitChunkHandle 构造直连假节点的 chunkedReadHandle（m 指向假 master 的 Mount）。
func newUnitChunkHandle(t *testing.T, masterURL string, ino, gen uint64, size int64,
	chunks []types.ChunkInfo, addr map[uint64]string) *chunkedReadHandle {
	t.Helper()
	m, err := New(client.New(masterURL), t.TempDir(), 1)
	if err != nil {
		t.Fatalf("mount.New: %v", err)
	}
	return chunkHandleOn(m, ino, gen, size, chunks, addr)
}

// chunkHandleOn 在给定 Mount 上构造直连假节点的 chunkedReadHandle
// （同一 Mount 的句柄共享 chunkCache / chunkVerifySem）。
func chunkHandleOn(m *Mount, ino, gen uint64, size int64,
	chunks []types.ChunkInfo, addr map[uint64]string) *chunkedReadHandle {
	return &chunkedReadHandle{
		ino: ino, size: size, generation: gen,
		chunks: chunks, addr: addr, next: map[int]int{},
		http: http.DefaultClient, scheme: "http", m: m,
	}
}

// ---- 带校验块的整块校验路径 ----

func TestChunkReadVerifiedPath(t *testing.T) {
	good := []byte("0123456789abcdef")
	crc := types.CRC32C(good)
	for _, tc := range []struct {
		name        string
		body        []byte // 节点实际返回的字节
		wantErr     syscall.Errno
		wantBytes   []byte
		wantReports int
	}{
		{"ok", good, 0, good, 0},
		{"bitflip", []byte("0123456789abcdeX"), syscall.EIO, nil, 1},
		{"short_response", good[:13], syscall.EIO, nil, 1},
		{"extra_bytes", append(append([]byte{}, good...), []byte("xxxxx")...), syscall.EIO, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newSuspectRecorder(t)
			node := newCountingNode(t, map[uint64][]byte{4242: tc.body})
			chunk := types.ChunkInfo{Index: 0, ID: 4242, Size: 16, Checksum: crc,
				Replicas: []uint64{9}, Done: []uint64{9}}
			h := newUnitChunkHandle(t, rec.srv.URL, 77, 3, 16,
				[]types.ChunkInfo{chunk}, map[uint64]string{9: node.srv.Listener.Addr().String()})

			got, errno := readChunkBytes(context.Background(), h, 0, 16)
			if errno != tc.wantErr {
				t.Fatalf("errno = %v, want %v", errno, tc.wantErr)
			}
			if tc.wantErr == 0 {
				if !bytes.Equal(got, tc.wantBytes) {
					t.Fatalf("bytes = %q, want %q", got, tc.wantBytes)
				}
			} else if len(got) != 0 {
				t.Fatalf("坏字节逃过校验: %x", got)
			}
			if tc.wantReports > 0 {
				bodies := rec.waitSuspectBodies(t, tc.wantReports)
				b := bodies[0]
				if b.InodeID != 77 || b.Generation != 3 || b.ChunkIndex != 0 ||
					b.ObjectID != 4242 || b.NodeID != 9 || b.Size != 16 || b.Checksum != crc {
					t.Fatalf("suspect 报文字段不符: %+v (crc=%d)", b, crc)
				}
			} else {
				assertNoSuspect(t, rec)
			}
			if _, corrupt := rec.snapshot(); corrupt != 0 {
				t.Fatal("校验路径调用了旧 /files/corrupt 删除通道")
			}
		})
	}
}

// ---- singleflight 与 per-Mount 共享缓存 ----

func TestChunkReadConcurrentFirstReadSingleflight(t *testing.T) {
	good := bytes.Repeat([]byte("S"), 4096)
	crc := types.CRC32C(good)
	var gets atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		time.Sleep(50 * time.Millisecond) // 拉宽并发窗口
		w.Write(good)
	}))
	t.Cleanup(srv.Close)
	rec := newSuspectRecorder(t)
	chunk := types.ChunkInfo{Index: 0, ID: 9000, Size: 4096, Checksum: crc, Replicas: []uint64{5}}
	h := newUnitChunkHandle(t, rec.srv.URL, 7, 1, 4096,
		[]types.ChunkInfo{chunk}, map[uint64]string{5: srv.Listener.Addr().String()})

	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start
			off := int64(g * 128)
			got, errno := readChunkBytes(context.Background(), h, off, 128)
			if errno != 0 || !bytes.Equal(got, good[off:off+128]) {
				t.Errorf("并发读 g=%d: errno=%v", g, errno)
			}
		}(g)
	}
	close(start)
	wg.Wait()
	if gets.Load() != 1 {
		t.Fatalf("并发首读未合并: %d GETs", gets.Load())
	}
}

// TestChunkCacheSharedBudgetAcrossHandles 缓存预算是 per-Mount 总预算：
// 两个句柄读同一块共享一次 GET；注入小预算后总驻留字节恒不超预算且 LRU 淘汰。
func TestChunkCacheSharedBudgetAcrossHandles(t *testing.T) {
	chunksData := map[uint64][]byte{
		1000: []byte("AAAAAAAA"),
		1001: []byte("BBBBBBBB"),
		1002: []byte("CCCCCCCC"),
	}
	rec := newSuspectRecorder(t)
	node := newCountingNode(t, chunksData)
	mkChunk := func(idx int, id uint64) types.ChunkInfo {
		return types.ChunkInfo{Index: idx, ID: id, Size: 8,
			Checksum: types.CRC32C(chunksData[id]), Replicas: []uint64{9}}
	}
	chunks := []types.ChunkInfo{mkChunk(0, 1000), mkChunk(1, 1001), mkChunk(2, 1002)}
	addr := map[uint64]string{9: node.srv.Listener.Addr().String()}

	h1 := newUnitChunkHandle(t, rec.srv.URL, 7, 1, 24, chunks, addr)
	h2 := chunkHandleOn(h1.m, 7, 1, 24, chunks, addr) // 同一 Mount：共享缓存预算

	// 句柄 1 首读块 0 → 1 次 GET；句柄 2 读同一块 → 命中共享缓存，无新 GET。
	if got, errno := readChunkBytes(context.Background(), h1, 0, 8); errno != 0 || string(got) != "AAAAAAAA" {
		t.Fatalf("h1 read: %q %v", got, errno)
	}
	if got, errno := readChunkBytes(context.Background(), h2, 0, 8); errno != 0 || string(got) != "AAAAAAAA" {
		t.Fatalf("h2 read: %q %v", got, errno)
	}
	if n := node.getCount(1000); n != 1 {
		t.Fatalf("跨句柄未共享缓存: %d GETs", n)
	}

	// 注入预算 = 18（校验缓冲实分配 size+1，按 cap 计费每块 9）：3 块轮流读必然
	// 淘汰，总驻留不超预算。
	cc := h1.m.chunkCache
	cc.mu.Lock()
	cc.maxBytes = 18
	cc.mu.Unlock()
	evict := func(off int64, want string, id uint64) {
		t.Helper()
		got, errno := readChunkBytes(context.Background(), h1, off, 8)
		if errno != 0 || string(got) != want {
			t.Fatalf("read(off=%d): %q %v", off, got, errno)
		}
	}
	evict(0, "AAAAAAAA", 1000)
	evict(8, "BBBBBBBB", 1001)
	evict(0, "AAAAAAAA", 1000) // 命中
	if n := node.getCount(1000); n != 1 {
		t.Fatalf("块 0 应命中缓存: %d GETs", n)
	}
	evict(16, "CCCCCCCC", 1002) // 挤掉 LRU（块 1）
	evict(0, "AAAAAAAA", 1000)  // 仍命中
	evict(8, "BBBBBBBB", 1001)  // 已被挤掉 → 重新 GET
	if n := node.getCount(1001); n != 2 {
		t.Fatalf("块 1 应被淘汰后重取: %d GETs", n)
	}
	cc.mu.Lock()
	resident, entries := cc.curBytes, len(cc.entries)
	cc.mu.Unlock()
	if resident > 18 || entries != 2 {
		t.Fatalf("缓存超预算驻留: %d bytes / %d entries", resident, entries)
	}

	// 全文件读（跨 3 块）内容正确。
	if got, errno := readChunkBytes(context.Background(), h1, 0, 24); errno != 0 || string(got) != "AAAAAAAABBBBBBBBCCCCCCCC" {
		t.Fatalf("全文件读: %q %v", got, errno)
	}
}

// TestChunkCacheKeyBindsSizeAndObj 缓存键绑定 objID+size+CRC：任一不同即不互通，
// 元数据不一致的句柄命中不了他人校验过的条目（各自重新验证）。
func TestChunkCacheKeyBindsSizeAndObj(t *testing.T) {
	cc := newMountChunkCache(1 << 20)
	key := chunkCacheKey{obj: 1, size: 8, crc: 42}
	fetch := func(context.Context) ([]byte, syscall.Errno) {
		return []byte("AAAAAAAA"), 0
	}
	if data, errno := cc.load(context.Background(), key, fetch); errno != 0 || string(data) != "AAAAAAAA" {
		t.Fatalf("首次加载: %q %v", data, errno)
	}
	for _, other := range []chunkCacheKey{
		{obj: 1, size: 16, crc: 42}, // 同 objID 不同 size
		{obj: 2, size: 8, crc: 42},  // 不同 objID
		{obj: 1, size: 8, crc: 43},  // 不同 CRC
	} {
		calls := 0
		counting := func(context.Context) ([]byte, syscall.Errno) { calls++; return nil, 0 }
		if _, errno := cc.load(context.Background(), other, counting); errno != 0 || calls != 1 {
			t.Fatalf("异键不应命中缓存: %+v calls=%d errno=%v", other, calls, errno)
		}
	}
	calls := 0
	counting := func(context.Context) ([]byte, syscall.Errno) { calls++; return nil, 0 }
	cc.load(context.Background(), key, counting)
	if calls != 0 {
		t.Fatal("精确键应命中缓存")
	}
}

// TestChunkReadDemotesSuspectReplicas master 标记 Suspect 的副本不再首选：健康副本
// 在位时绝不访问可疑副本；全部可疑时仍兜底读取（内容照常整块校验）。
func TestChunkReadDemotesSuspectReplicas(t *testing.T) {
	good := bytes.Repeat([]byte("P"), 16)
	crc := types.CRC32C(good)
	rec := newSuspectRecorder(t)
	node9 := newCountingNode(t, map[uint64][]byte{700: good, 701: good})
	node8 := newCountingNode(t, map[uint64][]byte{700: good})
	addr := map[uint64]string{
		9: node9.srv.Listener.Addr().String(),
		8: node8.srv.Listener.Addr().String(),
	}
	chunk := types.ChunkInfo{Index: 0, ID: 700, Size: 16, Checksum: crc,
		Replicas: []uint64{9, 8}, Done: []uint64{9, 8}, Suspect: []uint64{9}}

	h := newUnitChunkHandle(t, rec.srv.URL, 7, 1, 16, []types.ChunkInfo{chunk}, addr)
	got, errno := readChunkBytes(context.Background(), h, 0, 16)
	if errno != 0 || !bytes.Equal(got, good) {
		t.Fatalf("suspect 降级读: %q %v", got, errno)
	}
	if n := node9.getCount(700); n != 0 {
		t.Fatalf("Suspect 副本仍被首选访问: %d GETs", n)
	}
	if n := node8.getCount(700); n != 1 {
		t.Fatalf("健康副本应被选中: %d GETs", n)
	}
	assertNoSuspect(t, rec) // 读 suspect 副本未发生=无误报

	// 全部副本 Suspect：仍兜底读取（拒绝意味着文件不可读，而标记可能只是误报）。
	chunk2 := types.ChunkInfo{Index: 0, ID: 701, Size: 16, Checksum: crc,
		Replicas: []uint64{9}, Done: []uint64{9}, Suspect: []uint64{9}}
	h2 := chunkHandleOn(h.m, 7, 1, 16, []types.ChunkInfo{chunk2}, addr)
	if got, errno := readChunkBytes(context.Background(), h2, 0, 16); errno != 0 || !bytes.Equal(got, good) {
		t.Fatalf("全 suspect 兜底读: %q %v", got, errno)
	}
	if n := node9.getCount(701); n != 1 {
		t.Fatalf("全 suspect 应仍可读: %d GETs", n)
	}
}

// TestChunkReadRejectsBadChunkSizes 块表坏元数据（0/负/超 ChunkSize/溢出源）必须在
// 任何 GET / make(c.Size+1) 之前拒绝——否则按 c.Size 无限分配。以 0 GET 证明。
func TestChunkReadRejectsBadChunkSizes(t *testing.T) {
	rec := newSuspectRecorder(t)
	node := newCountingNode(t, map[uint64][]byte{800: []byte("data")})
	for _, size := range []int64{0, -1, types.ChunkSize + 1, math.MaxInt64} {
		chunk := types.ChunkInfo{Index: 0, ID: 800, Size: size, Checksum: 123,
			Replicas: []uint64{9}, Done: []uint64{9}}
		h := chunkHandleOn(nodeMustMount(t, rec.srv.URL), 7, 1, 16,
			[]types.ChunkInfo{chunk}, map[uint64]string{9: node.srv.Listener.Addr().String()})
		if got, errno := readChunkBytes(context.Background(), h, 0, 8); errno != syscall.EIO || len(got) != 0 {
			t.Fatalf("Size=%d 应 EIO 无字节: %q %v", size, got, errno)
		}
		if n := node.getCount(800); n != 0 {
			t.Fatalf("Size=%d 在 GET 前未被拒绝: %d GETs", size, n)
		}
	}
}

// nodeMustMount 构造一个可复用的 Mount（块表防御测试用）。
func nodeMustMount(t *testing.T, masterURL string) *Mount {
	t.Helper()
	m, err := New(client.New(masterURL), t.TempDir(), 1)
	if err != nil {
		t.Fatalf("mount.New: %v", err)
	}
	return m
}

// TestChunkReadRotationKeepsSuspectLast next 轮转只在健康段内：跨多次 cache miss，
// suspect 副本永不因轮转被首选；健康副本失败轮到 suspect 成功后，下一次仍先试健康。
func TestChunkReadRotationKeepsSuspectLast(t *testing.T) {
	good := bytes.Repeat([]byte("R"), 16)
	crc := types.CRC32C(good)
	rec := newSuspectRecorder(t)
	var healthyBad atomic.Bool // 健康节点首次返回坏内容，之后转好
	var healthyGets, suspectGets atomic.Int64
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthyGets.Add(1)
		if healthyBad.Swap(false) { // 只坏第一次
			w.Write(bytes.Repeat([]byte("X"), 16))
			return
		}
		w.Write(good)
	}))
	t.Cleanup(healthy.Close)
	suspect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suspectGets.Add(1)
		w.Write(good)
	}))
	t.Cleanup(suspect.Close)
	addr := map[uint64]string{
		8: healthy.Listener.Addr().String(),
		9: suspect.Listener.Addr().String(),
	}
	chunk := types.ChunkInfo{Index: 0, ID: 900, Size: 16, Checksum: crc,
		Replicas: []uint64{8, 9}, Done: []uint64{8, 9}, Suspect: []uint64{9}}
	m := nodeMustMount(t, rec.srv.URL)
	m.chunkCache.mu.Lock()
	m.chunkCache.maxBytes = 0 // 每次读都 cache miss，放大轮转暴露面
	m.chunkCache.mu.Unlock()
	h := chunkHandleOn(m, 7, 1, 16, []types.ChunkInfo{chunk}, addr)

	// 读 1：健康 8 返回坏内容 → 上报 → suspect 9 兜底成功（suspectGets=1）。
	healthyBad.Store(true)
	if got, errno := readChunkBytes(context.Background(), h, 0, 16); errno != 0 || !bytes.Equal(got, good) {
		t.Fatalf("failover 读: %q %v", got, errno)
	}
	// 读 2/3：必须先试健康 8（已转好）成功，suspect 不再被访问。
	for i := 2; i <= 3; i++ {
		if got, errno := readChunkBytes(context.Background(), h, 0, 16); errno != 0 || !bytes.Equal(got, good) {
			t.Fatalf("读 %d: %q %v", i, got, errno)
		}
	}
	if n := suspectGets.Load(); n != 1 {
		t.Fatalf("suspect 兜底后仍被轮转首选: %d 次", n)
	}
	if n := healthyGets.Load(); n != 3 { // 读1坏 + 读2好 + 读3好；读1的 suspect 兜底成功
		t.Fatalf("健康副本应始终先试: %d 次", n)
	}
}

// TestChunkVerifyTimeoutScaling 整块校验 GET 超时按字节数缩放：30s 基线 + 每 512KiB
// 1s，封顶 150s——64MiB 整取不得沿用 30s 全程超时被慢链路反复误杀。
func TestChunkVerifyTimeoutScaling(t *testing.T) {
	cases := []struct {
		size int64
		want time.Duration
	}{
		{0, 30 * time.Second},
		{512 * 1024, 31 * time.Second},
		{32 << 20, 94 * time.Second},
		{64 << 20, 150 * time.Second}, // 30+128 → 封顶
		{1 << 40, 150 * time.Second},
	}
	for _, tc := range cases {
		if got := chunkVerifyTimeout(tc.size); got != tc.want {
			t.Fatalf("chunkVerifyTimeout(%d) = %v, want %v", tc.size, got, tc.want)
		}
	}
}

// TestChunkReadSlowStreamDeadline 缩放 deadline 到期（stub 100ms）→ 读快速失败且
// 不上报 suspect（慢链路不等于损坏）；取消同义。注入 stub 避免睡满真实超时。
func TestChunkReadSlowStreamDeadline(t *testing.T) {
	orig := chunkVerifyTimeoutFn
	chunkVerifyTimeoutFn = func(int64) time.Duration { return 100 * time.Millisecond }
	t.Cleanup(func() { chunkVerifyTimeoutFn = orig })

	good := bytes.Repeat([]byte("D"), 16)
	crc := types.CRC32C(good)
	rec := newSuspectRecorder(t)
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(good[:8]) // 头已出、身体拖过 deadline：模拟慢链路
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
		w.Write(good[8:])
	}))
	t.Cleanup(func() { close(release); slow.Close() })
	h := newUnitChunkHandle(t, rec.srv.URL, 7, 1, 16,
		[]types.ChunkInfo{{Index: 0, ID: 950, Size: 16, Checksum: crc, Replicas: []uint64{9}}},
		map[uint64]string{9: slow.Listener.Addr().String()})

	if _, errno := readChunkBytes(context.Background(), h, 0, 16); errno != syscall.EIO {
		t.Fatalf("所有副本均超时应 EIO: %v", errno)
	}
	assertNoSuspect(t, rec)

	// 恢复真实超时前，先验证同 stub 下取消路径：ctx 取消 → EINTR，亦不误报。
	h2 := chunkHandleOn(h.m, 7, 1, 16,
		[]types.ChunkInfo{{Index: 0, ID: 951, Size: 16, Checksum: crc, Replicas: []uint64{9}}},
		map[uint64]string{9: slow.Listener.Addr().String()})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, errno := readChunkBytes(ctx, h2, 0, 16); errno != syscall.EINTR {
		t.Fatalf("ctx 取消应 EINTR: %v", errno)
	}
	assertNoSuspect(t, rec)
}

// ---- legacy（checksum==0）严格 Range 路径 ----

func TestChunkReadLegacyStrictRange(t *testing.T) {
	body := []byte("0123456789abcdef") // 16 字节；块表未记录 checksum（0）

	serveCorrectRange := func(crTotal int64, bodyN int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var s, e int
			if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &s, &e); err != nil {
				http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
				return
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", s, e, crTotal))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(body[s:min(s+bodyN, len(body))])
		}
	}
	cases := []struct {
		name        string
		serve       http.HandlerFunc
		off         int64
		n           int
		wantErr     syscall.Errno
		wantBytes   []byte
		wantReports int
	}{
		{"206_exact", serveCorrectRange(16, 8), 4, 8, 0, []byte("456789ab"), 0},
		{"200_whole_ok", func(w http.ResponseWriter, r *http.Request) { w.Write(body) }, 0, 16, 0, body, 0},
		{"200_offset_rejected", func(w http.ResponseWriter, r *http.Request) { w.Write(body) }, 4, 8, syscall.EIO, nil, 0},
		{"206_wrong_total", serveCorrectRange(15, 16), 4, 8, syscall.EIO, nil, 0},
		{"206_short_body", serveCorrectRange(16, 4), 4, 8, syscall.EIO, nil, 1},
		{"200_extra_body", func(w http.ResponseWriter, r *http.Request) {
			w.Write(append(append([]byte{}, body...), []byte("xxxxx")...))
		}, 0, 16, syscall.EIO, nil, 1},
		{"416_rejected", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusRequestedRangeNotSatisfiable)
		}, 4, 8, syscall.EIO, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := newSuspectRecorder(t)
			srv := httptest.NewServer(tc.serve)
			t.Cleanup(srv.Close)
			chunk := types.ChunkInfo{Index: 0, ID: 5000, Size: 16, Replicas: []uint64{9}}
			h := newUnitChunkHandle(t, rec.srv.URL, 88, 2, 16,
				[]types.ChunkInfo{chunk}, map[uint64]string{9: srv.Listener.Addr().String()})

			got, errno := readChunkBytes(context.Background(), h, tc.off, tc.n)
			if errno != tc.wantErr {
				t.Fatalf("errno = %v, want %v", errno, tc.wantErr)
			}
			if tc.wantErr == 0 {
				if !bytes.Equal(got, tc.wantBytes) {
					t.Fatalf("bytes = %q, want %q", got, tc.wantBytes)
				}
			} else if len(got) != 0 {
				t.Fatalf("拒绝的响应仍有字节外泄: %x", got)
			}
			if tc.wantReports > 0 {
				bodies := rec.waitSuspectBodies(t, tc.wantReports)
				if bodies[0].NodeID != 9 || bodies[0].Size != 16 || bodies[0].Checksum != 0 {
					t.Fatalf("suspect 报文字段不符: %+v", bodies[0])
				}
			} else {
				assertNoSuspect(t, rec)
			}
		})
	}
}

// TestChunkReadChecksumKnownZero 显式 ChecksumKnown 的 CRC=0 块走整块校验路径而非
// legacy Range：整对象 GET（无 Range 头）。正例用 GF2 线性解得的 CRC32C 恰为 0 的
// 内容（0xab,0x9b,0xe0,0x9b）证明 known 的 0 是真校验值而非"跳过"；负例内容 CRC
// 不符 → EIO + suspect 且报文 Checksum 字段为 0。
func TestChunkReadChecksumKnownZero(t *testing.T) {
	rec := newSuspectRecorder(t)
	crcZero := []byte{0xab, 0x9b, 0xe0, 0x9b} // CRC32C(Castagnoli) == 0
	var rangeSeen atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			rangeSeen.Store(true)
		}
		w.Write(bytes.Repeat([]byte("K"), 16)) // 16 字节且 CRC32C ≠ 0
	}))
	t.Cleanup(srv.Close)
	addr := map[uint64]string{9: srv.Listener.Addr().String()}
	h := newUnitChunkHandle(t, rec.srv.URL, 66, 1, 16,
		[]types.ChunkInfo{{Index: 0, ID: 6000, Size: 16, Checksum: 0, ChecksumKnown: true,
			Replicas: []uint64{9}}}, addr)

	if got, errno := readChunkBytes(context.Background(), h, 0, 16); errno != syscall.EIO || len(got) != 0 {
		t.Fatalf("CRC=0(known) 内容不符应整块校验拒绝: %q %v", got, errno)
	}
	if rangeSeen.Load() {
		t.Fatal("known CRC=0 应走整块 GET，而非 legacy Range")
	}
	bodies := rec.waitSuspectBodies(t, 1)
	if bodies[0].NodeID != 9 || bodies[0].Size != 16 || bodies[0].Checksum != 0 || bodies[0].ObjectID != 6000 {
		t.Fatalf("suspect 报文字段不符: %+v", bodies[0])
	}

	// 正例：内容 CRC32C 恰为 0 且块表记录 Checksum=0+known → 整块校验通过。
	zAddr := crcZeroSrv(t, crcZero)
	h2 := chunkHandleOn(h.m, 66, 1, 4,
		[]types.ChunkInfo{{Index: 0, ID: 6001, Size: 4, Checksum: 0, ChecksumKnown: true,
			Replicas: []uint64{9}}}, map[uint64]string{9: zAddr})
	if got, errno := readChunkBytes(context.Background(), h2, 0, 4); errno != 0 || !bytes.Equal(got, crcZero) {
		t.Fatalf("CRC=0(known) 内容相符应通过整块校验: %q %v", got, errno)
	}
}

// crcZeroSrv 返回固定字节的整对象 GET 服务（记录 Range 是否出现）。
func crcZeroSrv(t *testing.T, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// ---- suspect 上报：去重、generation 快照、不触碰删除通道 ----

func TestChunkSuspectReportDedupAndGeneration(t *testing.T) {
	rec := newSuspectRecorder(t)
	good := bytes.Repeat([]byte("G"), 16)
	crc := types.CRC32C(good)
	chunk := types.ChunkInfo{Index: 1, ID: 4242, Size: 16, Checksum: crc,
		Replicas: []uint64{9, 8}, Done: []uint64{9}}
	badNode := newCountingNode(t, map[uint64][]byte{4242: []byte("CORRUPTED-CORRUPT")})
	goodNode := newCountingNode(t, map[uint64][]byte{4242: good})
	addr := map[uint64]string{
		9: badNode.srv.Listener.Addr().String(),
		8: goodNode.srv.Listener.Addr().String(),
	}
	mk := func(gen uint64) *chunkedReadHandle {
		return newUnitChunkHandle(t, rec.srv.URL, 77, gen, 16, []types.ChunkInfo{chunk}, addr)
	}

	// 首读：候选固定 [9(done), 8]，9 CRC 坏 → 上报 → 8 兜底，坏字节不出 FUSE。
	h := mk(3)
	got, errno := readChunkBytes(context.Background(), h, 0, 16)
	if errno != 0 || !bytes.Equal(got, good) {
		t.Fatalf("failover read: %q %v", got, errno)
	}
	bodies := rec.waitSuspectBodies(t, 1)
	b := bodies[0]
	if b.InodeID != 77 || b.Generation != 3 || b.ChunkIndex != 1 || b.ObjectID != 4242 ||
		b.NodeID != 9 || b.Size != 16 || b.Checksum != crc {
		t.Fatalf("suspect 报文字段不符: %+v", b)
	}

	// 同句柄再次命中坏副本 → (node,obj) 去重，仍只 1 条。
	h.next[1] = 0 // 强制重新先访问坏节点
	if got, errno := readChunkBytes(context.Background(), h, 0, 16); errno != 0 || !bytes.Equal(got, good) {
		t.Fatalf("second read: %q %v", got, errno)
	}
	time.Sleep(500 * time.Millisecond)
	if bodies, corrupt := rec.snapshot(); len(bodies) != 1 || corrupt != 0 {
		t.Fatalf("重复上报未去重或误触删除通道: %d bodies, %d corrupt", len(bodies), corrupt)
	}

	// 不同 generation 的另一句柄独立上报：旧版本读者不影响新版本读者，
	// 上报按 (FileID, generation, chunk, objID, size, checksum) 完整 tuple 走。
	h2 := mk(9)
	if got, errno := readChunkBytes(context.Background(), h2, 0, 16); errno != 0 || !bytes.Equal(got, good) {
		t.Fatalf("gen9 read: %q %v", got, errno)
	}
	bodies = rec.waitSuspectBodies(t, 2)
	var gen3, gen9 bool
	for _, b := range bodies {
		switch {
		case b.Generation == 3 && b.NodeID == 9:
			gen3 = true
		case b.Generation == 9 && b.NodeID == 9:
			gen9 = true
		}
	}
	if !gen3 || !gen9 {
		t.Fatalf("generation 快照未随句柄保留: %+v", bodies)
	}
}

// ---- 边界：负偏移 / 空 dest / EOF / 越界 / 负 size，全程无 panic ----

func TestChunkReadRejectsBadOffsets(t *testing.T) {
	good := []byte("0123456789abcdef")
	crc := types.CRC32C(good)
	node := newCountingNode(t, map[uint64][]byte{4242: good})
	chunk := types.ChunkInfo{Index: 0, ID: 4242, Size: 16, Checksum: crc, Replicas: []uint64{9}}
	h := newUnitChunkHandle(t, newSuspectRecorder(t).srv.URL, 7, 1, 16,
		[]types.ChunkInfo{chunk}, map[uint64]string{9: node.srv.Listener.Addr().String()})
	ctx := context.Background()

	if _, errno := readChunkBytes(ctx, h, -1, 4); errno != syscall.EINVAL {
		t.Fatalf("负偏移: %v", errno)
	}
	for _, off := range []int64{16, 17, 100, math.MaxInt64} {
		got, errno := readChunkBytes(ctx, h, off, 4)
		if errno != 0 || len(got) != 0 {
			t.Fatalf("off=%d 应为空 EOF 读: %q %v", off, got, errno)
		}
	}
	if got, errno := readChunkBytes(ctx, h, 0, 0); errno != 0 || len(got) != 0 {
		t.Fatalf("空 dest: %q %v", got, errno)
	}
	if node.getCount(4242) != 0 {
		t.Fatal("无效读发出了 HTTP 请求")
	}

	// 超长 dest 截断到文件尾（count = size-off）。
	if got, errno := readChunkBytes(ctx, h, 10, 100); errno != 0 || string(got) != "abcdef" {
		t.Fatalf("尾读: %q %v", got, errno)
	}
	// 负 size（元数据损坏）→ EINVAL，不 panic。
	h.size = -1
	if _, errno := readChunkBytes(ctx, h, 0, 4); errno != syscall.EINVAL {
		t.Fatalf("负 size: %v", errno)
	}
}

// ---- 取消语义：ctx 取消传到 HTTP 与等待者，semaphore 许可归还 ----

func TestChunkReadCancelDoesNotBlock(t *testing.T) {
	good := bytes.Repeat([]byte("C"), 32)
	crc := types.CRC32C(good)
	chunk := func(id uint64) types.ChunkInfo {
		return types.ChunkInfo{Index: 0, ID: id, Size: 32, Checksum: crc, Replicas: []uint64{9}}
	}
	newBlocked := func(release chan struct{}) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-release
			w.Write(good)
		}))
		return srv
	}
	rec := newSuspectRecorder(t)
	release1 := make(chan struct{})
	blocked1 := newBlocked(release1)
	t.Cleanup(func() { close(release1); blocked1.Close() })

	h := newUnitChunkHandle(t, rec.srv.URL, 7, 1, 32,
		[]types.ChunkInfo{chunk(111)}, map[uint64]string{9: blocked1.Listener.Addr().String()})
	h.m.chunkVerifySem = make(chan struct{}, 1) // 容量 1：验证取消后许可归还

	// 领导者取消：挂住的请求随 ctx 取消返回 EINTR，不阻塞到 HTTP 超时。
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	done := make(chan syscall.Errno, 1)
	go func() {
		_, errno := readChunkBytes(ctx, h, 0, 8)
		done <- errno
	}()
	select {
	case errno := <-done:
		if errno != syscall.EINTR {
			t.Fatalf("取消读应 EINTR: %v", errno)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("取消后读未返回")
	}
	cancel()

	// 许可归还验证：换好节点再读应立即成功（若泄漏会阻塞至 HTTP 超时）。
	// h2 与 h 同一 Mount，天然共享容量 1 的 semaphore。
	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(good) }))
	t.Cleanup(goodSrv.Close)
	h2 := chunkHandleOn(h.m, 7, 1, 32,
		[]types.ChunkInfo{chunk(222)}, map[uint64]string{9: goodSrv.Listener.Addr().String()})
	done2 := make(chan syscall.Errno, 1)
	go func() {
		_, errno := readChunkBytes(context.Background(), h2, 0, 8)
		done2 <- errno
	}()
	select {
	case errno := <-done2:
		if errno != 0 {
			t.Fatalf("取消后许可未归还: %v", errno)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("semaphore 许可泄漏：好节点读取被阻塞")
	}

	// 等待者取消：领导者挂在坏节点，等待者 ctx 超时 → EINTR 快速返回，领导者不受影响。
	release2 := make(chan struct{})
	var unblock2 sync.Once
	blocked2 := newBlocked(release2)
	t.Cleanup(func() {
		unblock2.Do(func() { close(release2) })
		blocked2.Close()
	})
	h3 := chunkHandleOn(h.m, 7, 1, 32,
		[]types.ChunkInfo{chunk(333)}, map[uint64]string{9: blocked2.Listener.Addr().String()})
	leaderDone := make(chan []byte, 1)
	go func() {
		got, errno := readChunkBytes(context.Background(), h3, 0, 32)
		if errno == 0 {
			leaderDone <- got
		}
		close(leaderDone)
	}()
	time.Sleep(100 * time.Millisecond) // 让领导者先成队
	wctx, wcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, werrno := readChunkBytes(wctx, h3, 8, 8)
	wcancel()
	if werrno != syscall.EINTR {
		t.Fatalf("等待者取消应 EINTR: %v", werrno)
	}
	unblock2.Do(func() { close(release2) }) // 先释放领导者再等结果，否则与清理互等
	if got := <-leaderDone; got == nil || !bytes.Equal(got, good) {
		t.Fatalf("领导者等待者取消后读回不符: %q", got)
	}
}

// ---- 真实集群端到端：位翻转故障转移 / 唯一坏副本不删 ----

// integrityCluster 真实 1 master + N node 集群：统计 suspect 端点命中与旧删除通道命中，
// 保留各节点 dataDir 以便直接破坏磁盘对象。
type integrityCluster struct {
	client      *client.Client
	m           *Mount
	store       *meta.Store
	addrs       map[uint64]string
	dataDirs    map[uint64]string
	suspectHits atomic.Int64
	corruptHits atomic.Int64
}

func newIntegrityCluster(t *testing.T, numNodes int) *integrityCluster {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	inner := master.NewServer(store, time.Hour).Handler()
	ic := &integrityCluster{store: store, addrs: map[uint64]string{}, dataDirs: map[uint64]string{}}
	masterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/files/chunks/suspect":
			ic.suspectHits.Add(1)
		case "/files/corrupt":
			ic.corruptHits.Add(1)
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(masterSrv.Close)
	for i := 0; i < numNodes; i++ {
		dataDir := filepath.Join(t.TempDir(), fmt.Sprintf("node%d", i))
		n := atollnode.New(dataDir, masterSrv.URL, "", 1<<30)
		nodeSrv := httptest.NewServer(n.Handler())
		t.Cleanup(nodeSrv.Close)
		body := fmt.Sprintf(`{"addr": %q, "total_bytes": 1073741824}`, nodeSrv.Listener.Addr().String())
		resp, err := http.Post(masterSrv.URL+"/nodes/register", "application/json", strings.NewReader(body))
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("node 注册失败: %v status=%d", err, resp.StatusCode)
		}
		var reg struct {
			ID uint64 `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
			t.Fatalf("解析注册响应: %v", err)
		}
		resp.Body.Close()
		n.SetNodeIDForTest(reg.ID)
		ic.addrs[reg.ID] = nodeSrv.Listener.Addr().String()
		ic.dataDirs[reg.ID] = dataDir
	}
	c := client.New(masterSrv.URL)
	m, err := New(c, filepath.Join(t.TempDir(), "cache"), numNodes)
	if err != nil {
		t.Fatalf("mount.New: %v", err)
	}
	ic.client, ic.m = c, m
	return ic
}

func (ic *integrityCluster) chunkDiskPath(t *testing.T, nodeID, chunkID uint64) string {
	t.Helper()
	dir, ok := ic.dataDirs[nodeID]
	if !ok {
		t.Fatalf("unknown node %d", nodeID)
	}
	return filepath.Join(dir, "objects", fmt.Sprintf("%02x", chunkID%256), fmt.Sprint(chunkID))
}

func (ic *integrityCluster) waitSuspectAtLeast(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ic.suspectHits.Load() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("suspect 上报未到达: got %d want %d", ic.suspectHits.Load(), want)
}

// putChunk 拉起 staging 文件的单块（真实 master 块表 + 真实节点对象），可只标部分副本 Done。
func (ic *integrityCluster) putChunk(t *testing.T, dirID uint64, name string, data []byte,
	replicas, done []uint64) types.ChunkInfo {
	t.Helper()
	st, err := ic.store.CreateStagingFile(dirID)
	if err != nil {
		t.Fatalf("CreateStagingFile: %v", err)
	}
	ci, err := ic.store.AssignChunk(st.ID, 0, int64(len(data)), replicas, types.CRC32C(data))
	if err != nil {
		t.Fatalf("AssignChunk: %v", err)
	}
	for _, id := range replicas {
		putChunkObject(t, ic.addrs[id], types.ChunkID(st.ID, 0), data)
	}
	for _, id := range done {
		if err := ic.store.MarkChunkDone(types.ChunkID(st.ID, 0), id); err != nil {
			t.Fatalf("MarkChunkDone: %v", err)
		}
	}
	if _, _, _, err := ic.store.CommitStagingFile(st.ID, name, int64(len(data))); err != nil {
		t.Fatalf("CommitStagingFile: %v", err)
	}
	return ci
}

func (ic *integrityCluster) openChunkHandle(t *testing.T, path string) *chunkedReadHandle {
	t.Helper()
	in, reps, err := ic.client.Lookup(path)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !in.Chunked || len(in.Chunks) == 0 {
		t.Fatalf("应为 chunked inode: %+v", in)
	}
	addr := make(map[uint64]string)
	for _, r := range reps {
		addr[r.ID] = r.Addr
	}
	return &chunkedReadHandle{
		ino: in.ID, size: in.Size, generation: in.Generation,
		chunks: in.Chunks, addr: addr, next: map[int]int{},
		http: http.DefaultClient, scheme: "http", m: ic.m,
	}
}

// TestChunkIntegrityRealClusterFailover 唯一副本位翻转 → 换副本读到好字节，
// suspect 上报只走 /files/chunks/suspect，不触碰 /files/corrupt，坏对象不被删除。
func TestChunkIntegrityRealClusterFailover(t *testing.T) {
	ic := newIntegrityCluster(t, 2)
	ids := make([]uint64, 0, 2)
	for id := range ic.addrs {
		ids = append(ids, id)
	}
	if ids[1] < ids[0] {
		ids[0], ids[1] = ids[1], ids[0]
	}
	A, B := ids[0], ids[1]

	dir, err := ic.client.Mkdir("/docs")
	if err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	good := []byte("integrity-failover-payload-32b!!")
	// Done=[A]：候选固定 [A, B]；数据双副本都在。
	ic.putChunk(t, dir.ID, "failover.bin", good, []uint64{A, B}, []uint64{A})

	h := ic.openChunkHandle(t, "/docs/failover.bin")
	chunkID := types.ChunkObjID(h.chunks[0], h.ino)
	corruptDiskObject(t, ic.chunkDiskPath(t, A, chunkID))

	got, errno := readChunkBytes(context.Background(), h, 0, len(good))
	if errno != 0 || !bytes.Equal(got, good) {
		t.Fatalf("failover 读回不符（坏字节外泄？）: %q %v", got, errno)
	}
	ic.waitSuspectAtLeast(t, 1)
	if ic.corruptHits.Load() != 0 {
		t.Fatal("触发了旧 /files/corrupt 删除通道")
	}
	if _, err := os.Stat(ic.chunkDiskPath(t, A, chunkID)); err != nil {
		t.Fatalf("suspect 上报不得删除坏副本对象: %v", err)
	}
}

// TestChunkIntegrityRealClusterUniqueCorruptNotDeleted 唯一副本损坏：读 EIO、
// 坏字节不出 FUSE、上报 suspect、对象保留待修复（绝不删除唯一物理副本）。
func TestChunkIntegrityRealClusterUniqueCorruptNotDeleted(t *testing.T) {
	ic := newIntegrityCluster(t, 1)
	var nodeID uint64
	for id := range ic.addrs {
		nodeID = id
	}
	dir, err := ic.client.Mkdir("/docs")
	if err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	good := []byte("unique-replica-must-survive")
	ic.putChunk(t, dir.ID, "unique.bin", good, []uint64{nodeID}, []uint64{nodeID})

	h := ic.openChunkHandle(t, "/docs/unique.bin")
	chunkID := types.ChunkObjID(h.chunks[0], h.ino)
	corruptDiskObject(t, ic.chunkDiskPath(t, nodeID, chunkID))

	got, errno := readChunkBytes(context.Background(), h, 0, len(good))
	if errno != syscall.EIO || len(got) != 0 {
		t.Fatalf("唯一坏副本应 EIO 且无坏字节: %q %v", got, errno)
	}
	ic.waitSuspectAtLeast(t, 1)
	if ic.corruptHits.Load() != 0 {
		t.Fatal("触发了旧 /files/corrupt 删除通道")
	}
	if _, err := os.Stat(ic.chunkDiskPath(t, nodeID, chunkID)); err != nil {
		t.Fatalf("唯一物理副本被删除: %v", err)
	}
}
