package client

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/master"
	"atoll/master/meta"
	"atoll/node"
)

// ---- WAN 抖动故障注入档 ----
// 本项目主打多地存储融合，跨公网延迟/丢包/节点卡死是常态而非边界。这里在
// 节点 HTTP handler 上注入确定性故障（固定延迟、PUT 卡死），验证系统在慢网下
// 仍正确/不永久挂起。超时用 SetPutTimeout 注入小值以便秒级跑完。

// faultOpts 描述对单个节点注入的故障。
type faultOpts struct {
	latency  time.Duration // 每个请求前固定延迟（模拟 RTT）
	stallPut time.Duration // 对 PUT /objects 额外卡住这么久（模拟"连得上但传不动"）
}

// faultHandler 包装节点 Handler 注入故障；/healthz 永远快速正常，
// 使 master 探测认为节点"可达"——正是"能连上却传不动"的真实故障形态。
func faultHandler(inner http.Handler, f faultOpts) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			inner.ServeHTTP(w, r)
			return
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
		inner.ServeHTTP(w, r)
	})
}

// newFaultCluster 起 1 master + N node，第 i 个节点套用 faults[i]（缺省无故障）。
func newFaultCluster(t *testing.T, numNodes int, faults map[int]faultOpts) *Client {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	masterSrv := httptest.NewServer(master.NewServer(store, time.Hour).Handler())
	t.Cleanup(func() { masterSrv.Close() })

	for i := 0; i < numNodes; i++ {
		n := node.New(filepath.Join(t.TempDir(), "data"), masterSrv.URL, "", 1<<30)
		h := faultHandler(n.Handler(), faults[i])
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
		n.SetNodeIDForTest(reg.ID)
	}
	return New(masterSrv.URL)
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

// 卡死节点旁有健康节点时应确定性自愈：节点0 PUT 卡死、节点1/2 健康，PUT 超时 400ms。
// reassign 排除刚卡死的节点后必落到健康节点——每个文件都应成功、内容一致。
// （靠"reassign 排除失败节点"才能确定性通过，否则随机重选可能再撞坏节点而 flaky。）
func TestFaultStalledNodeReassignsToHealthy(t *testing.T) {
	withChunkSize(t, 1<<20) // 大块 → 单块文件，一次 PUT 决策
	c := newFaultCluster(t, 3, map[int]faultOpts{
		0: {stallPut: 3 * time.Second},
	})
	c.SetPutTimeout(400 * time.Millisecond)
	if _, err := c.Mkdir("/w"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := make([]byte, 4096)
	rand.New(rand.NewSource(3)).Read(content)
	src := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		remote := fmt.Sprintf("/w/r%d.bin", i)
		if err := c.PutChunked(src, remote, 1); err != nil {
			t.Fatalf("有健康节点时第 %d 个文件仍失败: %v", i, err)
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

