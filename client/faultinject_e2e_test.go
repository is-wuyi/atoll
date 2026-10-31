package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
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

// ---- WAN 抖动故障注入档 ----
// 本项目主打多地存储融合，跨公网延迟/丢包/节点卡死是常态而非边界。这里在
// 节点 HTTP handler 上注入确定性故障（固定延迟、PUT 卡死），验证系统在慢网下
// 仍正确/不永久挂起。超时用 SetPutTimeout 注入小值以便秒级跑完。

// 首个 PUT 选出故障节点；该节点直到下一个文件开始前都拒绝 PUT。
// 用屏障注入失败，避免健康节点刷盘耗时决定测试结果。
type putGate struct {
	mu       sync.Mutex
	armed    bool
	fail     chan struct{}
	arrived  chan struct{}
	bad      uint64
	arrivals int
}

func newPutGate() *putGate { return &putGate{} }

func (g *putGate) arm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.armed = true
	g.fail = make(chan struct{})
	g.arrived = make(chan struct{}, 1)
	g.bad = 0
}

// 保留关闭的通道，使故障节点的后续 PUT 仍失败。
func (g *putGate) trigger() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail == nil {
		return
	}
	select {
	case <-g.fail:
	default:
		close(g.fail)
	}
}

func (g *putGate) waitArrived() chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.arrived
}

func (g *putGate) onArrive(nodeID uint64) chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.armed && g.bad == 0 {
		return nil
	}
	if g.bad == 0 {
		g.armed = false
		g.bad = nodeID
		g.arrivals++
		select {
		case g.arrived <- struct{}{}:
		default:
		}
		return g.fail
	}
	if nodeID == g.bad {
		g.arrivals++
		return g.fail
	}
	return nil
}

func (g *putGate) stats() (arrivals int, bad uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.arrivals, g.bad
}

// 直接检查 exclude，避免靠随机重选到故障节点才能发现回归。
type chunkAssignLog struct {
	mu   sync.Mutex
	reqs []struct {
		Reassign bool
		Exclude  []uint64
	}
}

func (l *chunkAssignLog) add(reassign bool, exclude []uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, struct {
		Reassign bool
		Exclude  []uint64
	}{reassign, exclude})
}

func (l *chunkAssignLog) reassigns() []struct {
	Reassign bool
	Exclude  []uint64
} {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []struct {
		Reassign bool
		Exclude  []uint64
	}
	for _, r := range l.reqs {
		if r.Reassign {
			out = append(out, r)
		}
	}
	return out
}

// faultOpts 描述对单个节点注入的故障。
type faultOpts struct {
	latency    time.Duration  // 每个请求前固定延迟（模拟 RTT）
	stallPut   time.Duration  // 对 PUT /objects 额外卡住这么久（模拟"连得上但传不动"）
	stallGet   time.Duration  // 对 GET /objects 额外卡住这么久（模拟读路径节点卡死）
	healthzCnt *int64         // 非 nil 时统计 /healthz 被探测的次数（验证探测缓存）
	putGate    *putGate       // 非 nil 时参与全局在途 PUT 屏障（见 putGate）
	nodeID     *atomic.Uint64 // fixture 填充的节点注册 ID（handler 读，须 atomic）
}

// faultHandler 包装节点 Handler 注入故障；/healthz 永远快速正常，
// 使 master 探测认为节点"可达"——正是"能连上却传不动"的真实故障形态。
func faultHandler(inner http.Handler, f faultOpts) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			if f.healthzCnt != nil {
				atomic.AddInt64(f.healthzCnt, 1)
			}
			inner.ServeHTTP(w, r)
			return
		}
		// 在途屏障：bad 节点的 PUT 挂起至 trigger/ctx，随后真实中止连接
		//（panic(http.ErrAbortHandler) 是 net/http 的静默连接终止，不假报状态）。
		if f.putGate != nil && r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			if failCh := f.putGate.onArrive(f.nodeID.Load()); failCh != nil {
				select {
				case <-r.Context().Done(): // 客户端可取消 ctx 到期兜底
				case <-failCh: // 测试确定性触发
				}
				panic(http.ErrAbortHandler)
			}
		}
		// 卡死/延迟都尊重请求取消：客户端 context 超时断连时 handler 立即返回，
		// 避免 httptest.Server.Close() 在 t.Cleanup 里干等整段 stall。
		sleep := func(d time.Duration) bool {
			if d <= 0 {
				return true
			}
			select {
			case <-time.After(d):
				return true
			case <-r.Context().Done():
				return false
			}
		}
		if !sleep(f.latency) {
			return
		}
		if f.stallPut > 0 && r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			if !sleep(f.stallPut) {
				return
			}
		}
		if f.stallGet > 0 && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/objects/") {
			if !sleep(f.stallGet) {
				return
			}
		}
		inner.ServeHTTP(w, r)
	})
}

// faultCluster 携带 fixture 句柄：节点注册 ID 供排除断言，chunk 请求日志供
// exclude 断言。
type faultCluster struct {
	*Client
	nodeIDs []uint64
	chunks  *chunkAssignLog
}

// newFaultClusterState 起 1 master + N node，第 i 个节点套用 faults[i]，全部注册。
// master 包一层录制中间件：POST /files/chunks 请求体（reassign/exclude）入账。
func newFaultClusterState(t *testing.T, numNodes int, faults map[int]faultOpts) *faultCluster {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	chunks := &chunkAssignLog{}
	masterHandler := master.NewServer(store, time.Hour).Handler()
	masterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/files/chunks" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body.Close()
			var rec struct {
				Reassign bool     `json:"reassign"`
				Exclude  []uint64 `json:"exclude"`
			}
			_ = json.Unmarshal(body, &rec)
			chunks.add(rec.Reassign, rec.Exclude)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		masterHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { masterSrv.Close() })

	fc := &faultCluster{chunks: chunks}
	for i := 0; i < numNodes; i++ {
		n := node.New(filepath.Join(t.TempDir(), "data"), masterSrv.URL, "", 1<<30)
		idSlot := new(atomic.Uint64)
		f := faults[i]
		f.nodeID = idSlot
		h := faultHandler(n.Handler(), f)
		nodeSrv := httptest.NewServer(h)
		t.Cleanup(func() { nodeSrv.Close() })
		resp, err := postRaw(masterSrv.URL+"/nodes/register",
			fmt.Sprintf(`{"addr": %q, "total_bytes": 1073741824}`, nodeSrv.Listener.Addr().String()))
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("node %d 注册失败: %v", i, err)
		}
		var reg struct {
			ID uint64 `json:"id"`
		}
		if err := decodeBody(resp.Body, &reg); err != nil {
			t.Fatalf("解码注册: %v", err)
		}
		resp.Body.Close()
		idSlot.Store(reg.ID)
		n.SetNodeIDForTest(reg.ID)
		fc.nodeIDs = append(fc.nodeIDs, reg.ID)
	}
	fc.Client = New(masterSrv.URL)
	return fc
}

// newFaultCluster 起 1 master + N node，第 i 个节点套用 faults[i]（缺省无故障）。
func newFaultCluster(t *testing.T, numNodes int, faults map[int]faultOpts) *Client {
	return newFaultClusterState(t, numNodes, faults).Client
}

// PLACEHOLDER_TESTS

// 延迟容忍：每个节点每请求 +150ms（模拟跨地域 RTT），多块上传+下载仍逐字节正确。
func TestFaultLatencyStillCorrect(t *testing.T) {
	withChunkSize(t, 1024) // 1KB 块 → 造多块
	c := newFaultCluster(t, 3, map[int]faultOpts{
		0: {latency: 150 * time.Millisecond},
		1: {latency: 150 * time.Millisecond},
		2: {latency: 150 * time.Millisecond},
	})
	if _, err := c.Mkdir("/w"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := make([]byte, 3500) // 3×1024 + 428 → 4 块
	rand.New(rand.NewSource(1)).Read(content)
	dir := t.TempDir()
	src := filepath.Join(dir, "in.bin")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.PutChunked(src, "/w/lat.bin", 2); err != nil {
		t.Fatalf("延迟下多块上传失败: %v", err)
	}
	out := filepath.Join(dir, "out.bin")
	if err := c.Get("/w/lat.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatalf("延迟下读回不符: %d vs %d", len(got), len(content))
	}
}

// 节点卡死不得永久挂起：唯一节点 PUT 卡死 30s，PUT 超时注入 400ms →
// 上传必须在数秒内有界失败（换节点 3 轮后放弃），而不是无限挂起拖死调用方。
// 这正是之前 Finder「设备已消失」的底层机理（无超时 PUT → close 永久阻塞）。
func TestFaultStalledNodeBoundedFailure(t *testing.T) {
	withChunkSize(t, 1024)
	c := newFaultCluster(t, 1, map[int]faultOpts{
		0: {stallPut: 3 * time.Second},
	})
	c.SetPutTimeout(400 * time.Millisecond)
	if _, err := c.Mkdir("/w"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := make([]byte, 2000)
	rand.New(rand.NewSource(2)).Read(content)
	src := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := c.PutChunked(src, "/w/stall.bin", 1)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("唯一节点卡死时上传应失败，而非成功")
	}
	if elapsed > 8*time.Second {
		t.Fatalf("上传应有界失败（3 轮×400ms 量级），实际耗时 %v——退化成挂起了", elapsed)
	}
}

// 故障由屏障触发，健康节点使用默认超时；短超时不能区分 WAN 卡死与慢刷盘。
func TestFaultStalledNodeReassignsToHealthy(t *testing.T) {
	withChunkSize(t, 1<<20) // 大块 → 单块文件，一次 PUT 决策
	gate := newPutGate()
	fc := newFaultClusterState(t, 3, map[int]faultOpts{
		0: {putGate: gate},
		1: {putGate: gate},
		2: {putGate: gate},
	})
	// LIFO：cleanup 先 trigger（放行可能仍挂起的屏障请求），再关服务器——
	// 失败路径不会让 httptest.Server.Close 干等 hold。
	t.Cleanup(gate.trigger)
	c := fc.Client
	if _, err := c.Mkdir("/w"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := make([]byte, 4096)
	rand.New(rand.NewSource(3)).Read(content)
	src := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	const files = 8
	for i := 0; i < files; i++ {
		remote := fmt.Sprintf("/w/r%d.bin", i)
		gate.arm()
		putDone := make(chan error, 1)
		go func() { putDone <- c.PutChunked(src, remote, 1) }()
		select {
		case <-gate.waitArrived(): // 屏障：请求已在目标 handler 在途
		case err := <-putDone:
			t.Fatalf("PUT 在屏障触发前就结束（fixture 失真）: err=%v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("PUT 未到达目标节点——屏障未触发")
		}
		gate.trigger() // 在途确定性失败（真实连接中止，非超时竞速）
		select {
		case err := <-putDone:
			if err != nil {
				t.Fatalf("有健康节点时第 %d 个文件仍失败: %v", i, err)
			}
		case <-time.After(90 * time.Second):
			t.Fatalf("第 %d 个文件在屏障失败后未恢复（疑似挂起）", i)
		}
		_, bad := gate.stats()
		// 排除断言（确定性）：恢复（reassign）请求必须排除被拦节点。
		reassigns := fc.chunks.reassigns()
		if len(reassigns) != i+1 {
			t.Fatalf("第 %d 个文件后 reassign 应恰好 %d 次，got %d", i, i+1, len(reassigns))
		}
		if !containsUint64(reassigns[i].Exclude, bad) {
			t.Fatalf("r%d 恢复请求 exclude 应包含被拦节点 %d: %+v", i, bad, reassigns[i].Exclude)
		}
		// 屏障拦截数（确定性）：bad 节点被排除后不应再有第二次拦截。
		arrivals, _ := gate.stats()
		if arrivals != i+1 {
			t.Fatalf("第 %d 个文件后屏障拦截应恰好 %d 次，got %d（失败节点被复选）", i, i+1, arrivals)
		}
		in, _, err := c.Lookup(remote)
		if err != nil {
			t.Fatalf("Lookup r%d: %v", i, err)
		}
		// chunked 副本断言直接查块表：primary 不落在 bad 节点且已 Done
		//（chunked 的 Lookup reps 可能为空，块表才是权威）。
		if len(in.Chunks) != 1 {
			t.Fatalf("r%d 应恰好 1 块，got %d", i, len(in.Chunks))
		}
		ch := in.Chunks[0]
		if len(ch.Replicas) != 1 || ch.Replicas[0] == bad || !types.ContainsUint64(ch.Done, ch.Replicas[0]) || types.ContainsUint64(ch.Done, bad) {
			t.Fatalf("r%d 块 primary 不应落在被拦节点 %d 且须 Done: replicas=%v done=%v", i, bad, ch.Replicas, ch.Done)
		}
		out := filepath.Join(t.TempDir(), fmt.Sprintf("o%d", i))
		if err := c.Get(remote, out); err != nil {
			t.Fatalf("Get r%d: %v", i, err)
		}
		got, _ := os.ReadFile(out)
		if !bytes.Equal(got, content) {
			t.Fatalf("r%d 读回不符", i)
		}
	}
}

func containsUint64(list []uint64, v uint64) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// 探测缓存：连传一批小文件时，master 对节点 /healthz 的探测次数应远小于文件数
// （靠短 TTL 缓存），否则每文件都串行重探每节点会把 folder 拷贝拖垮。
func TestProbeCacheBoundsHealthzCalls(t *testing.T) {
	withChunkSize(t, 1<<20) // 大块 → 每个小文件单块单次分配
	var h0, h1 int64
	c := newFaultCluster(t, 2, map[int]faultOpts{
		0: {healthzCnt: &h0},
		1: {healthzCnt: &h1},
	})
	if _, err := c.Mkdir("/w"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := make([]byte, 4096)
	rand.New(rand.NewSource(9)).Read(content)
	src := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	const nFiles = 20
	for i := 0; i < nFiles; i++ {
		if err := c.PutChunked(src, fmt.Sprintf("/w/s%d.bin", i), 2); err != nil {
			t.Fatalf("第 %d 个文件上传失败: %v", i, err)
		}
	}
	total := atomic.LoadInt64(&h0) + atomic.LoadInt64(&h1)
	// 无缓存时 ≈ nFiles×2=40 次；有 3s 缓存时这批快速上传只探几次。放宽到 nFiles 以内
	// 就足以证明"不随文件数线性爆炸"。
	if total > nFiles {
		t.Fatalf("探测次数 %d 过高（应被缓存压到远小于 %d×2）——缓存没生效", total, nFiles)
	}
}

// 读路径：节点收了 GET 连接后卡住，Get 必须有界失败而非永久挂起。
// 回归：此前对象 GET 用无超时的 c.HTTP.Get，卡死节点让 FUSE 读永不返回。
func TestFaultStalledGetBoundedFailure(t *testing.T) {
	withChunkSize(t, 1<<20)
	c := newFaultCluster(t, 1, map[int]faultOpts{
		0: {stallGet: 5 * time.Second},
	})
	if _, err := c.Mkdir("/w"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := make([]byte, 4096)
	rand.New(rand.NewSource(7)).Read(content)
	src := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.PutChunked(src, "/w/g.bin", 1); err != nil { // PUT 不受 stallGet 影响
		t.Fatalf("上传失败: %v", err)
	}
	c.SetPutTimeout(500 * time.Millisecond) // 让 GET 的 ioTimeout=500ms
	out := filepath.Join(t.TempDir(), "out.bin")
	start := time.Now()
	err := c.Get("/w/g.bin", out)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("唯一副本 GET 卡死时读取应失败，而非成功")
	}
	if elapsed > 4*time.Second {
		t.Fatalf("读取应有界失败（~500ms 量级），实际 %v——退化成挂起了", elapsed)
	}
}
