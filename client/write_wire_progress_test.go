package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/master"
	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/types"
)

const (
	wireReportInterval = 250 * time.Millisecond
	wireIdleWindow     = 2 * time.Second
	wireReceiveChunk   = 32
	wireReceivePause   = 200 * time.Millisecond
	wirePayloadSize    = 512
)

type wireProgressCluster struct {
	client  *Client
	store   *meta.Store
	master  *httptest.Server
	nodes   []*httptest.Server
	nodeIDs []uint64
}

func newWireProgressCluster(t *testing.T, count, maxReplicas int, wrap func(i int, next http.Handler) http.Handler) *wireProgressCluster {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := master.NewServer(store, time.Hour)
	if err := srv.EnableWritePlanning(master.WritePlanningConfig{MaxReplicas: maxReplicas}); err != nil {
		t.Fatal(err)
	}
	cl := &wireProgressCluster{store: store}
	cl.master = httptest.NewServer(srv.Handler())
	t.Cleanup(cl.master.Close)
	cl.client = New(cl.master.URL)
	for i := 0; i < count; i++ {
		n := node.New(filepath.Join(t.TempDir(), fmt.Sprintf("wire-node-%d", i)), cl.master.URL, "", 1<<30)
		n.SetWriteProgressIntervalForTest(wireReportInterval)
		h := n.Handler()
		if wrap != nil {
			h = wrap(i, h)
		}
		ns := httptest.NewServer(h)
		t.Cleanup(ns.Close)
		reg, err := store.RegisterNode(ns.Listener.Addr().String(), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		n.SetNodeIDForTest(reg.ID)
		if err := store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: reg.ID, FailureDomains: map[string]string{"zone": fmt.Sprint(i)}}); err != nil {
			t.Fatal(err)
		}
		cl.nodes = append(cl.nodes, ns)
		cl.nodeIDs = append(cl.nodeIDs, reg.ID)
	}
	return cl
}

// wireProgressRecorder 记录客户端可观察行为：PUT 计数（按节点地址）、
// recover 请求、计划响应里的目标节点。
type wireProgressRecorder struct {
	mu       sync.Mutex
	slow     map[string]bool // 节点地址 → 慢收/卡死
	slowIDs  []uint64
	puts     map[string]int
	recovers []types.RecoverWriteChunkRequest
	plan     types.WriteChunkPlan
}

// transport 只记录、不节流：PUT 原样转发（慢收在节点 handler），recover 与
// /writes/chunks 读取后回填 body 原样转发。
func (w *wireProgressRecorder) transport(base http.RoundTripper) plannedTestTransport {
	return plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == "/writes/chunks" {
			resp, err := base.RoundTrip(r)
			if err == nil && resp.StatusCode == http.StatusOK {
				raw, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if readErr != nil {
					return nil, readErr
				}
				var out types.PlanWriteChunkResponse
				if err := json.Unmarshal(raw, &out); err != nil {
					return nil, err
				}
				w.mu.Lock()
				w.plan = out.Plan
				addresses := map[uint64]string{}
				for _, n := range out.Nodes {
					addresses[n.ID] = n.Addr
				}
				target := addresses[out.Plan.Confirmations[0]]
				w.slow[target] = true
				for _, n := range out.Nodes {
					if n.Addr == target {
						w.slowIDs = append(w.slowIDs, n.ID)
					}
				}
				w.mu.Unlock()
				resp.Body = io.NopCloser(bytes.NewReader(raw))
			}
			return resp, err
		}
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			w.mu.Lock()
			w.puts[r.Host]++
			w.mu.Unlock()
			return base.RoundTrip(r)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/writes/chunks/recover" {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			var rr types.RecoverWriteChunkRequest
			_ = json.Unmarshal(raw, &rr)
			w.mu.Lock()
			w.recovers = append(w.recovers, rr)
			w.mu.Unlock()
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		return base.RoundTrip(r)
	})
}

func (w *wireProgressRecorder) recoverCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.recovers)
}

func (w *wireProgressRecorder) putCount(addr string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.puts[addr]
}

func (w *wireProgressRecorder) totalPuts() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := 0
	for _, n := range w.puts {
		total += n
	}
	return total
}

func (w *wireProgressRecorder) firstRecover() (types.RecoverWriteChunkRequest, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.recovers) == 0 {
		return types.RecoverWriteChunkRequest{}, false
	}
	return w.recovers[0], true
}

func (w *wireProgressRecorder) firstSlowID() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.slowIDs) == 0 {
		return 0
	}
	return w.slowIDs[0]
}

// wireReceiveSpan 记录节点侧慢收的时间跨度与字节数（覆盖守卫用）。
type wireReceiveSpan struct {
	mu    sync.Mutex
	start time.Time
	end   time.Time
	bytes int64
	set   bool
}

func (s *wireReceiveSpan) record(start, end time.Time, n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.start, s.end, s.bytes, s.set = start, end, n, true
}

func (s *wireReceiveSpan) get() (start, end time.Time, n int64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.start, s.end, s.bytes, s.set
}

// 客户端不节流；节点直接读取慢速包装的原始 Body，才能让进度统计覆盖真实接收。
type wireSlowBody struct {
	io.ReadCloser
	started time.Time
	span    *wireReceiveSpan
	bytes   int64
}

func (b *wireSlowBody) Read(p []byte) (int, error) {
	if len(p) > wireReceiveChunk {
		p = p[:wireReceiveChunk]
	}
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.bytes += int64(n)
		time.Sleep(wireReceivePause)
	}
	return n, err
}

func wireSlowReceiveWrap(rec *wireProgressRecorder, span *wireReceiveSpan) func(i int, next http.Handler) http.Handler {
	return func(i int, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/objects/") {
				next.ServeHTTP(w, r)
				return
			}
			rec.mu.Lock()
			slow := rec.slow[r.Host]
			rec.mu.Unlock()
			if !slow {
				next.ServeHTTP(w, r)
				return
			}
			body := &wireSlowBody{ReadCloser: r.Body, started: time.Now(), span: span}
			r.Body = body
			next.ServeHTTP(w, r)
			span.record(body.started, time.Now(), body.bytes)
		})
	}
}

func TestWriteWireProgressSlowNodeReceiveNotKilled(t *testing.T) {
	rec := &wireProgressRecorder{slow: map[string]bool{}, puts: map[string]int{}}
	var span wireReceiveSpan
	cl := newWireProgressCluster(t, 2, 1, wireSlowReceiveWrap(rec, &span))
	c := cl.client
	if _, err := c.SetProtection("/", types.ProtectionNormal); err != nil {
		t.Fatal(err)
	}
	c.SetPutTimeout(wireIdleWindow)
	base := c.HTTP.Transport
	c.HTTP.Transport = rec.transport(base)

	data := bytes.Repeat([]byte("w"), wirePayloadSize)
	if err := c.PutChunkedReader("/wire-slow", int64(len(data)), bytes.NewReader(data), 1); err != nil {
		t.Fatalf("slow-but-progressing upload failed: %v", err)
	}

	// 覆盖守卫：节点接收时长必须严格大于客户端空闲窗口 —— 旧本地 timer
	// 必然先到期，本用例才真正覆盖 “窗口到期时 wire 消费仍在继续”。
	start, end, n, ok := span.get()
	if !ok {
		t.Fatal("slow node never received the payload")
	}
	receiveSpan := end.Sub(start)
	if receiveSpan <= wireIdleWindow {
		t.Fatalf("fixture too fast to cover the claim: node receive %s <= client idle %s", receiveSpan, wireIdleWindow)
	}
	if n != wirePayloadSize {
		t.Fatalf("slow node received %d/%d bytes", n, len(data))
	}

	// 健康节点不得被排除：零 recover。
	if got := rec.recoverCount(); got != 0 {
		t.Fatalf("healthy progressing node was excluded: %d recover request(s)", got)
	}
	// 恰好一次 PUT 成功：无放弃、无重试。
	slowID := rec.firstSlowID()
	if total := rec.totalPuts(); total != 1 {
		t.Fatalf("expected exactly one PUT, got %d (%v)", total, rec.puts)
	}

	in, _, err := c.Lookup("/wire-slow")
	if err != nil || len(in.Chunks) != 1 {
		t.Fatalf("lookup: %v", err)
	}
	if !types.ContainsUint64(in.Chunks[0].Replicas, slowID) {
		t.Fatalf("healthy node was dropped from the layout: %v", in.Chunks[0].Replicas)
	}
	out := filepath.Join(t.TempDir(), "out")
	if err := c.Get("/wire-slow", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read-back mismatch: %v", err)
	}
}

// TestWriteWireProgressStuckNodeBoundedAndSwitches 覆盖另一侧契约：节点完全
// 卡死（一个字节都不收、也无任何进度上报）时，客户端必须有界放弃、报告该
// 节点、换目标完成。修复（等待期消费节点进度）不得把卡死节点变成无限等待。
func TestWriteWireProgressStuckNodeBoundedAndSwitches(t *testing.T) {
	rec := &wireProgressRecorder{slow: map[string]bool{}, puts: map[string]int{}}
	// 释放阀：net/http 只有在 handler 读完 body 后才启动后台断连探测，本
	// handler 故意不读 body，客户端断连后 r.Context() 也不会取消 —— 必须用
	// 测试侧通道保证 handler 返回。注册必须在 fixture 之后（Cleanup LIFO，
	// 先于 ns.Close 释放，否则清理挂死）。
	release := make(chan struct{})
	cl := newWireProgressCluster(t, 3, 1, func(i int, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
				rec.mu.Lock()
				stuck := rec.slow[r.Host]
				rec.mu.Unlock()
				if stuck {
					// 完全卡死：不读任何字节，直到客户端放弃连接。
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	t.Cleanup(func() { close(release) })
	c := cl.client
	if _, err := c.SetProtection("/", types.ProtectionNormal); err != nil {
		t.Fatal(err)
	}
	c.SetPutTimeout(400 * time.Millisecond)
	base := c.HTTP.Transport
	c.HTTP.Transport = rec.transport(base)

	data := bytes.Repeat([]byte("k"), wirePayloadSize)
	started := time.Now()
	if err := c.PutChunkedReader("/wire-stuck", int64(len(data)), bytes.NewReader(data), 1); err != nil {
		t.Fatalf("stuck node did not switch targets: %v", err)
	}
	elapsed := time.Since(started)
	// 有界护栏：精确的每尝试上界属 PUT 等待设计空间，这里只排除无限挂起。
	if elapsed > 2*time.Minute {
		t.Fatalf("stuck-node failure was not bounded: %s", elapsed)
	}

	rr, ok := rec.firstRecover()
	if !ok {
		t.Fatal("no recovery was requested for the stuck node")
	}
	stuckID := rec.firstSlowID()
	if !types.ContainsUint64(rr.FailedNodes, stuckID) {
		t.Fatalf("recover did not report the stuck node: %v", rr.FailedNodes)
	}
	in, _, err := c.Lookup("/wire-stuck")
	if err != nil || len(in.Chunks) != 1 {
		t.Fatalf("lookup: %v", err)
	}
	if types.ContainsUint64(in.Chunks[0].Replicas, stuckID) {
		t.Fatalf("stuck node was not excluded: %v", in.Chunks[0].Replicas)
	}
	out := filepath.Join(t.TempDir(), "out")
	if err := c.Get("/wire-stuck", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read-back mismatch: %v", err)
	}
	t.Logf("stuck node bounded: recover reported %v, total %s", rr.FailedNodes, elapsed)
}
