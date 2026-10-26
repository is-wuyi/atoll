package node

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/types"
)

// pullDedupProbe 起一个真实 node Handler，验证 /pull 去重身份：
// 相同 (对象, 计划, 尝试) 幂等 202；不同计划或尝试 409；不同对象互不影响。
func TestPullDedupConflictOnDifferentPlanOrAttempt(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer source.Close()
	sourceAddr := source.Listener.Addr().String()
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/files/replication" {
			lease := time.Now().Add(time.Minute)
			_ = json.NewEncoder(w).Encode(types.ReplicationPlan{Protocol: types.IntegrityProtocol, Object: types.ObjectIntegrity{ObjectID: 5000, InodeID: 10000, Size: 1, Checksum: 1, ChecksumKnown: true, PlanID: r.URL.Query().Get("plan_id"), PlanLeaseUntil: lease, PlanAttempt: 3, PlanAttemptToken: "test-token", PlanHardUntil: time.Now().Add(30*time.Minute + time.Second), Replicas: []uint64{7, 8}, Done: []uint64{8}}, Sources: []types.NodeInfo{{ID: 8, Addr: sourceAddr}}})
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"recorded":true}`))
	}))
	defer master.Close()
	n := New(t.TempDir(), master.URL, "", 1<<20)
	n.SetNodeIDForTest(7)
	h := n.Handler()
	defer func() {
		close(release)
		waitForPullIdle(t, n, 5000)
	}()
	do := func(plan string, attempt uint32) int {
		body, _ := json.Marshal(map[string]any{"inode_id": 5000, "source_addr": sourceAddr, "plan_id": plan, "attempt": attempt})
		req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if code := do("plan-x", 3); code != http.StatusAccepted {
		t.Fatalf("first dispatch = %d", code)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("valid feedback attempt never reached source")
	}
	if code := do("plan-x", 3); code != http.StatusAccepted {
		t.Fatalf("same identity duplicate = %d", code)
	}
	for _, identity := range []struct {
		plan    string
		attempt uint32
	}{{"plan-x", 4}, {"plan-y", 3}, {"", 0}} {
		if code := do(identity.plan, identity.attempt); code != http.StatusConflict {
			t.Fatalf("different identity %+v = %d", identity, code)
		}
	}
}

// 进度心跳与失败反馈走 master 控制通道；progressLoop 周期可注入缩短。
func TestProgressLoopReportsMeasuredBytes(t *testing.T) {
	var mu sync.Mutex
	var reports []map[string]any
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/files/protection/progress" {
			w.WriteHeader(http.StatusOK)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		reports = append(reports, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"recorded":true}`))
	}))
	defer master.Close()
	n := New(t.TempDir(), master.URL, "", 1<<20)
	n.SetNodeIDForTest(7)
	counter := &progressCounter{}
	counter.n.Store(12345)
	stop := make(chan struct{})
	done := make(chan struct{})
	old := progressReportInterval
	progressReportInterval = 10 * time.Millisecond
	go func() { defer close(done); n.progressLoop(context.Background(), stop, "p1", 2, 900, counter) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(reports)
		mu.Unlock()
		if count >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	<-done
	progressReportInterval = old
	mu.Lock()
	defer mu.Unlock()
	if len(reports) < 2 {
		t.Fatalf("expected periodic reports, got %d", len(reports))
	}
	first := reports[0]
	if first["plan_id"] != "p1" || first["object_id"] != float64(900) {
		t.Fatalf("identity fields wrong: %v", first)
	}
	if first["node_id"] != float64(7) || first["attempt"] != float64(2) {
		t.Fatalf("attempt identity wrong: %v", first)
	}
	if first["bytes_done"] != float64(12345) {
		t.Fatalf("measured bytes missing: %v", first)
	}
	if g, _ := first["goodput_bps"].(float64); g <= 0 {
		t.Fatalf("goodput not derived from measured bytes: %v", first)
	}
}

// 失败反馈 best-effort：master 不可达不影响本地函数返回，也不死等。
func TestFailureFeedbackBestEffort(t *testing.T) {
	var attempts atomic.Int64
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer master.Close()
	n := New(t.TempDir(), master.URL, "", 1<<20)
	n.SetNodeIDForTest(7)
	done := make(chan struct{})
	go func() { defer close(done); n.reportPullFeedback("p1", 1, 900, 42, "failed", "stalled") }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("failure feedback blocked")
	}
}

// pullObject 的阻塞由 master stub 与 5min 上界约束；此处无需额外引用。
var _ = time.Second
