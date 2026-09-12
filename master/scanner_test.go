package master

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/types"
)

func newTestScanner(t *testing.T, nodeMaxAge time.Duration) (*Scanner, *meta.Store) {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	s := NewScanner(store, nodeMaxAge, time.Hour, time.Hour) // repair/gc 不关心
	return s, store
}

// captureLogs 捕获 log 输出到 buffer。
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// TestDeathMonitorNewDeath 测试 alive→dead 转换记日志。
// nodeMaxAge 取 500ms 而非更小值：并行测试高负载下 goroutine 调度延迟
// 可能超过小阈值，导致心跳与扫描之间的间隔被误判过期（曾引发 flaky）。
func TestDeathMonitorNewDeath(t *testing.T) {
	s, store := newTestScanner(t, 500*time.Millisecond)
	buf := captureLogs(t)

	// 注册节点，刷新心跳使其 alive。
	n, _ := store.RegisterNode("n1:9421", 100)
	store.Heartbeat(n.ID, 0)

	// 首次扫描：节点 alive，prevAlive 被记录。
	s.deathMonitorOnce()

	// 等待心跳过期。
	time.Sleep(600 * time.Millisecond)

	// 第二次扫描：节点变 dead，应记日志。
	s.deathMonitorOnce()
	logs := buf.String()
	if !strings.Contains(logs, "判定死亡") {
		t.Fatalf("应输出 '判定死亡' 日志, got: %s", logs)
	}
}

// TestDeathMonitorRejoin 测试 dead→alive 转换记日志。
func TestDeathMonitorRejoin(t *testing.T) {
	s, store := newTestScanner(t, 500*time.Millisecond)
	buf := captureLogs(t)

	// 注册节点但不刷新心跳。RegisterNode 会写入 LastHeartbeat=now，
	// 必须等待超过 nodeMaxAge 后首扫才判 dead（否则 prevAlive 含该节点，无状态转换）。
	n, _ := store.RegisterNode("n1:9421", 100)
	time.Sleep(600 * time.Millisecond)
	s.deathMonitorOnce() // prevAlive={}

	// 刷新心跳，使其恢复 alive。
	store.Heartbeat(n.ID, 0)
	s.deathMonitorOnce()
	logs := buf.String()
	if !strings.Contains(logs, "心跳恢复") {
		t.Fatalf("应输出 '心跳恢复' 日志, got: %s", logs)
	}
}

// TestDeathMonitorNoRepeat 测试持续 dead 状态不重复记日志。
func TestDeathMonitorNoRepeat(t *testing.T) {
	s, store := newTestScanner(t, 500*time.Millisecond)
	buf := captureLogs(t)

	store.RegisterNode("n1:9421", 100)
	s.deathMonitorOnce() // 首扫记下 prevAlive
	time.Sleep(600 * time.Millisecond)
	s.deathMonitorOnce() // 第一次判定死亡
	before := buf.Len()
	s.deathMonitorOnce() // 持续 dead，不应再记日志
	after := buf.Len()
	if after != before {
		t.Fatalf("持续 dead 不应重复记日志, before=%d after=%d", before, after)
	}
}

// ---- planRepairs 单测 ----

// mkNodes 构造节点列表：ids 中的节点心跳新鲜（alive），其余心跳过期（dead）。
func mkNodes(aliveIDs []uint64, allIDs []uint64) []types.NodeInfo {
	aliveSet := make(map[uint64]bool, len(aliveIDs))
	for _, id := range aliveIDs {
		aliveSet[id] = true
	}
	nodes := make([]types.NodeInfo, 0, len(allIDs))
	for _, id := range allIDs {
		hb := time.Now().Add(-time.Hour) // 默认 dead
		if aliveSet[id] {
			hb = time.Now()
		}
		nodes = append(nodes, types.NodeInfo{
			ID:            id,
			Addr:          fmt.Sprintf("n%d:9421", id),
			TotalBytes:    1 << 30,
			UsedBytes:     0,
			LastHeartbeat: hb,
		})
	}
	return nodes
}

// TestPlanRepairsAllHealthy 全部健康时无需修复。
func TestPlanRepairsAllHealthy(t *testing.T) {
	inode := types.Inode{
		Replicas:     []uint64{1, 2, 3},
		DoneReplicas: []uint64{1, 2, 3},
		Size:         100,
	}
	nodes := mkNodes([]uint64{1, 2, 3}, []uint64{1, 2, 3})
	tasks := planRepairs(inode, nodes, 30*time.Second)
	if len(tasks) != 0 {
		t.Fatalf("全部健康应返回 0 个任务, got %d", len(tasks))
	}
}

// TestPlanRepairsDeadSlot dead 槽应产出 replaceDead 任务。
func TestPlanRepairsDeadSlot(t *testing.T) {
	inode := types.Inode{
		Replicas:     []uint64{1, 2, 3},
		DoneReplicas: []uint64{1, 2},
		Size:         100,
	}
	// 节点 3 dead，节点 4 为候选。
	nodes := mkNodes([]uint64{1, 2, 4}, []uint64{1, 2, 3, 4})
	tasks := planRepairs(inode, nodes, 30*time.Second)
	if len(tasks) != 1 {
		t.Fatalf("应有 1 个任务, got %d", len(tasks))
	}
	if tasks[0].Action != repairReplaceDead {
		t.Fatalf("动作应为 repairReplaceDead, got %d", tasks[0].Action)
	}
	if tasks[0].OldNodeID != 3 {
		t.Fatalf("OldNodeID 应为 3, got %d", tasks[0].OldNodeID)
	}
	if tasks[0].NewNodeID != 4 {
		t.Fatalf("NewNodeID 应为 4, got %d", tasks[0].NewNodeID)
	}
}

// TestPlanRepairsAliveNotDone alive 未 Done 应产出 triggerPull 任务。
func TestPlanRepairsAliveNotDone(t *testing.T) {
	inode := types.Inode{
		Replicas:     []uint64{1, 2, 3},
		DoneReplicas: []uint64{1, 2},
		Size:         100,
	}
	// 节点 3 alive 但未 Done
	nodes := mkNodes([]uint64{1, 2, 3}, []uint64{1, 2, 3})
	tasks := planRepairs(inode, nodes, 30*time.Second)
	if len(tasks) != 1 {
		t.Fatalf("应有 1 个任务, got %d", len(tasks))
	}
	if tasks[0].Action != repairTriggerPull {
		t.Fatalf("动作应为 repairTriggerPull, got %d", tasks[0].Action)
	}
	if tasks[0].TargetAddr != "n3:9421" {
		t.Fatalf("TargetAddr 应为 n3:9421, got %q", tasks[0].TargetAddr)
	}
}

// TestPlanRepairsNoSource 无可用源时应跳过。
func TestPlanRepairsNoSource(t *testing.T) {
	inode := types.Inode{
		Replicas:     []uint64{1, 2},
		DoneReplicas: []uint64{1},
		Size:         100,
	}
	// 两个节点都 dead
	nodes := mkNodes(nil, []uint64{1, 2})
	tasks := planRepairs(inode, nodes, 30*time.Second)
	if len(tasks) != 2 {
		t.Fatalf("应有 2 个任务, got %d", len(tasks))
	}
	for _, tk := range tasks {
		if tk.Action != repairSkipNoSource {
			t.Fatalf("动作应为 repairSkipNoSource, got %d", tk.Action)
		}
	}
}

// TestPlanRepairsNoTarget 无合格新目标时应跳过（dead 节点保留在 Replicas）。
func TestPlanRepairsNoTarget(t *testing.T) {
	inode := types.Inode{
		Replicas:     []uint64{1, 2},
		DoneReplicas: []uint64{1},
		Size:         1 << 30, // 1GB，超出剩余容量
	}
	// 节点 2 dead，只有节点 1 alive（已在 Replicas 中，无其他候选）
	nodes := mkNodes([]uint64{1}, []uint64{1, 2})
	tasks := planRepairs(inode, nodes, 30*time.Second)
	if len(tasks) != 1 {
		t.Fatalf("应有 1 个任务, got %d", len(tasks))
	}
	if tasks[0].Action != repairSkipNoTarget {
		t.Fatalf("动作应为 repairSkipNoTarget, got %d", tasks[0].Action)
	}
	if tasks[0].OldNodeID != 2 {
		t.Fatalf("dead 节点应保留在记录中, OldNodeID=%d", tasks[0].OldNodeID)
	}
}

// ---- findOrphans 单测 ----

// TestFindOrphans 孤儿对象识别。
func TestFindOrphans(t *testing.T) {
	objects := []ObjectEntry{
		{ID: 1, Size: 100},
		{ID: 2, Size: 200},
		{ID: 99, Size: 300}, // 孤儿
		{ID: 100, Size: 400}, // 孤儿
	}
	validIDs := map[uint64]bool{1: true, 2: true}
	orphans := findOrphans(objects, validIDs)
	if len(orphans) != 2 {
		t.Fatalf("应有 2 个孤儿, got %d", len(orphans))
	}
	ids := map[uint64]bool{}
	for _, o := range orphans {
		ids[o.ID] = true
	}
	if !ids[99] || !ids[100] {
		t.Fatalf("孤儿 ID 应包含 99 和 100, got %v", ids)
	}
}

// TestFindOrphansEmpty 无孤儿时返回 nil。
func TestFindOrphansEmpty(t *testing.T) {
	objects := []ObjectEntry{
		{ID: 1, Size: 100},
		{ID: 2, Size: 200},
	}
	validIDs := map[uint64]bool{1: true, 2: true}
	orphans := findOrphans(objects, validIDs)
	if len(orphans) != 0 {
		t.Fatalf("应无孤儿, got %d", len(orphans))
	}
}

// TestFindOrphansNormalObjectsNotAffected 正常对象不被误判（额外副本场景）。
func TestFindOrphansNormalObjectsNotAffected(t *testing.T) {
	// 额外副本（节点被替换后旧副本仍存在）不应被 GC。
	objects := []ObjectEntry{
		{ID: 1, Size: 100},
		{ID: 2, Size: 200}, // 文件 2 在元数据中存在（额外副本）
	}
	validIDs := map[uint64]bool{1: true, 2: true}
	orphans := findOrphans(objects, validIDs)
	if len(orphans) != 0 {
		t.Fatalf("额外副本不应被 GC, got %d 个孤儿", len(orphans))
	}
}

// ---- 修复退避单测 ----

// TestRepairBackoffRampsUp 修复连续未收敛时退避窗口倍增，收敛后清零。
func TestRepairBackoffRampsUp(t *testing.T) {
	s, _ := newTestScanner(t, time.Hour) // repairIntv = time.Hour
	s.bumpRepairBackoff(42)
	s.mu.Lock()
	first := s.nextAttempt[42].Sub(time.Now())
	s.mu.Unlock()
	if first < 30*time.Minute || first > time.Hour {
		t.Fatalf("第一次退避应 ≈ 1x repairIntv, got %v", first)
	}
	s.bumpRepairBackoff(42)
	s.mu.Lock()
	second := s.nextAttempt[42].Sub(time.Now())
	streak := s.failStreak[42]
	s.mu.Unlock()
	if streak != 2 {
		t.Fatalf("failStreak = %d, want 2", streak)
	}
	if second < time.Hour || second > 2*time.Hour+time.Minute {
		t.Fatalf("第二次退避应 ≈ 2x repairIntv, got %v", second)
	}
	// 模拟收敛：扫描循环里 len(tasks)==0 时直接清零。
	s.mu.Lock()
	delete(s.failStreak, 42)
	delete(s.nextAttempt, 42)
	s.mu.Unlock()
	s.bumpRepairBackoff(42)
	s.mu.Lock()
	afterReset := s.nextAttempt[42].Sub(time.Now())
	streak = s.failStreak[42]
	s.mu.Unlock()
	if streak != 1 || afterReset > time.Hour {
		t.Fatalf("收敛清零后应重新从 1x 开始, streak=%d next=%v", streak, afterReset)
	}
}

// TestRepairBackoffCapsAt40x 退避倍数封顶 40x。
func TestRepairBackoffCapsAt40x(t *testing.T) {
	s, _ := newTestScanner(t, time.Hour)
	s.mu.Lock()
	s.failStreak[7] = 50 // 远超上限
	s.mu.Unlock()
	s.bumpRepairBackoff(7)
	s.mu.Lock()
	next := s.nextAttempt[7].Sub(time.Now())
	s.mu.Unlock()
	if next > 41*time.Hour {
		t.Fatalf("退避应封顶 40x, got %v", next)
	}
}

// TestProbeSource404 源对象 404 时 probeSource 返回 false；存在/网络错误返回 true。
func TestProbeSource404(t *testing.T) {
	// 源节点：写入对象 1，没有对象 2。
	_, ts := newTestNodeForMaster(t)
	putObjectForMaster(t, ts.URL, 1)

	s, _ := newTestScanner(t, time.Hour)
	if !s.probeSource(ts.Listener.Addr().String(), 1) {
		t.Fatal("对象存在时应返回 true")
	}
	if s.probeSource(ts.Listener.Addr().String(), 2) {
		t.Fatal("对象 404 时应返回 false")
	}
	// 不存在的地址（网络错误）应保持乐观返回 true。
	if !s.probeSource("127.0.0.1:1", 1) {
		t.Fatal("网络错误时应返回 true")
	}
}

// ---- 测试辅助 ----

// newTestNodeForMaster 在 master 包内启动一个最小存储节点 HTTP 服务。
func newTestNodeForMaster(t *testing.T) (*node.Node, *httptest.Server) {
	t.Helper()
	n := node.New(t.TempDir(), "http://master.invalid", "127.0.0.1:19000", 1<<30)
	ts := httptest.NewServer(n.Handler())
	t.Cleanup(func() { ts.Close() })
	return n, ts
}

// putObjectForMaster 向测试节点 PUT 一个对象。
func putObjectForMaster(t *testing.T, baseURL string, id uint64) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/objects/%d", baseURL, id), strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT 状态码 = %d", resp.StatusCode)
	}
}
