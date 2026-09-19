package master

import (
	"bytes"
	"encoding/json"
	"errors"
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

// ---- 批次 C：块级修复 / GC 两轮确认 / staging TTL ----

// TestChunkRepairReplaceDead 分块文件一块的主副本 dead → ReplaceChunkReplica + pull（chunkID）。
func TestChunkRepairReplaceDead(t *testing.T) {
	_, store := newTestScanner(t, time.Hour)

	// 注册 3 个节点：1,2 alive；3 注册后心跳过期（dead）。
	for i := 1; i <= 2; i++ {
		n, _ := store.RegisterNode(fmt.Sprintf("n%d:9421", i), 1<<30)
		_ = n
	}
	n3, _ := store.RegisterNode("n3:9421", 1<<30)

	// 建一个已提交的分块文件：chunk0 副本 [1,3]，Done [1]。
	st, _ := store.CreateStagingFile(1)
	store.AssignChunk(st.ID, 0, 100, []uint64{1, n3.ID})
	store.MarkChunkDone(types.ChunkID(st.ID, 0), 1)
	store.CommitStagingFile(st.ID, "f.bin", 100)

	// 验证块任务复用 planRepairs（伪 inode）：dead 槽产出 replaceDead。
	chunkID := types.ChunkID(st.ID, 0)
	in, _ := store.GetInode(st.ID)
	nodes := mkNodes([]uint64{1, 2}, []uint64{1, 2, n3.ID})
	pseudo := types.Inode{
		ID:           chunkID,
		Replicas:     in.Chunks[0].Replicas,
		DoneReplicas: in.Chunks[0].Done,
		Size:         100,
	}
	tasks := planRepairs(pseudo, nodes, time.Hour)
	if len(tasks) != 1 || tasks[0].Action != repairReplaceDead {
		t.Fatalf("应产出 1 个 replaceDead 任务, got %+v", tasks)
	}
	if tasks[0].OldNodeID != n3.ID {
		t.Fatalf("OldNodeID 应为 dead 节点 %d, got %d", n3.ID, tasks[0].OldNodeID)
	}
}

// TestGCConfirmTwoRounds GC 两轮确认：第一轮 execute 不删，第二轮才删。
func TestGCConfirmTwoRounds(t *testing.T) {
	s, store := newTestScanner(t, time.Hour)

	// 源节点上放一个孤儿对象（不在任何元数据中）。
	_, nTS := newTestNodeForMaster(t)
	nInfo, _ := store.RegisterNode(nTS.Listener.Addr().String(), 1<<30)
	store.Heartbeat(nInfo.ID, 0)
	putObjectForMaster(t, nTS.URL, 99999)

	// 第一轮 execute：报告孤儿但不删（上轮快照为空）。
	reports, err := s.RunGC(true)
	if err != nil {
		t.Fatalf("GC 第一轮: %v", err)
	}
	found := false
	for _, r := range reports {
		for _, o := range r.Orphans {
			if o.ID == 99999 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("第一轮应报告孤儿")
	}
	// 第二轮 execute：上轮见过 → 删除。
	_, err = s.RunGC(true)
	if err != nil {
		t.Fatalf("GC 第二轮: %v", err)
	}
	// 验证删除：对象清单里不再有 99999。
	resp, err := http.Get(nTS.URL + "/admin/objects")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var objects []ObjectEntry
	json.NewDecoder(resp.Body).Decode(&objects)
	for _, o := range objects {
		if o.ID == 99999 {
			t.Fatal("两轮确认后孤儿应被删除")
		}
	}
}

// TestSweepStagingExpiredTTL 超 TTL 的 staging 被回收，未超时保留。
func TestSweepStagingExpiredTTL(t *testing.T) {
	s, store := newTestScanner(t, time.Hour)
	s.stagingTTL = 100 * time.Millisecond

	// old：mtime 超过 TTL 的 staging。
	old, _ := store.CreateStagingFile(1)
	store.AssignChunk(old.ID, 0, 10, []uint64{7})
	// 把 mtime 改老：meta 层没有 API，用直接改 TTL 的方式 —— 等待 TTL 过期。
	// 留足余量（TTL 的数倍）：-race + 并行满载下 50ms 边距会偶发不足。
	time.Sleep(400 * time.Millisecond)

	// fresh：刚建的 staging。
	fresh, _ := store.CreateStagingFile(1)

	s.sweepStaging()

	if _, err := store.GetInode(old.ID); !errors.Is(err, meta.ErrNotExist) {
		t.Fatalf("超时 staging 应被回收: %v", err)
	}
	if _, err := store.GetInode(fresh.ID); err != nil {
		t.Fatalf("未超时 staging 不应被回收: %v", err)
	}
}

// TestGCKeepStagingChunk staging 未提交的块不算孤儿（防上传竞态误删）。
func TestGCKeepStagingChunk(t *testing.T) {
	s, store := newTestScanner(t, time.Hour)

	nNode, nTS := newTestNodeForMaster(t)
	nInfo, _ := store.RegisterNode(nTS.Listener.Addr().String(), 1<<30)
	store.Heartbeat(nInfo.ID, 0)

	// staging inode 分配一块并真实落盘（模拟上传中）。
	st, _ := store.CreateStagingFile(1)
	store.AssignChunk(st.ID, 0, 10, []uint64{nInfo.ID})
	putObjectForMaster(t, nTS.URL, types.ChunkID(st.ID, 0))

	// GC dry-run：staging 的块在 validIDs 中，不是孤儿。
	reports, err := s.RunGC(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reports {
		for _, o := range r.Orphans {
			if o.ID == types.ChunkID(st.ID, 0) {
				t.Fatal("staging 未提交的块不应被判孤儿")
			}
		}
	}
	_ = nNode
}

// TestDegradedChunkWarnAfterThreshold 改进项2：已 commit 的块降级（单副本）
// 持续超阈值 → WARN 一次；不重复刷。
func TestDegradedChunkWarnAfterThreshold(t *testing.T) {
	s, store := newTestScanner(t, time.Hour)
	s.degradedWarnDur = 0 // 阈值清零：第一次发现即触发（首次只记时刻，第二次告警）
	buf := captureLogs(t)

	// 节点 1、2 alive；块副本 [1,2]，Done 只有 1 → 降级。
	for i := 1; i <= 2; i++ {
		n, _ := store.RegisterNode(fmt.Sprintf("n%d:9421", i), 1<<30)
		_ = n
		store.Heartbeat(uint64(i), 0)
	}
	st, _ := store.CreateStagingFile(1)
	store.AssignChunk(st.ID, 0, 100, []uint64{1, 2})
	store.MarkChunkDone(types.ChunkID(st.ID, 0), 1)
	store.CommitStagingFile(st.ID, "f.bin", 100)

	in, _ := store.GetInode(st.ID)
	nodes := mkNodes([]uint64{1, 2}, []uint64{1, 2})
	now := time.Now()
	s.trackDegradedChunk(in, in.Chunks[0], types.ChunkID(st.ID, 0), nodes, now)         // 首次：记时刻
	s.trackDegradedChunk(in, in.Chunks[0], types.ChunkID(st.ID, 0), nodes, now.Add(time.Minute)) // 告警
	s.trackDegradedChunk(in, in.Chunks[0], types.ChunkID(st.ID, 0), nodes, now.Add(2*time.Minute)) // 不重复

	logs := buf.String()
	if strings.Count(logs, "WARN: inode") != 1 {
		t.Fatalf("应恰好 1 次 WARN, got: %s", logs)
	}
	if !strings.Contains(logs, "降级已持续") {
		t.Fatalf("WARN 文案应含降级描述, got: %s", logs)
	}
}

// TestDegradedChunkRecoverClearsState 改进项2：恢复满副本 → 解除日志 + 状态清零（再降级重新计时）。
func TestDegradedChunkRecoverClearsState(t *testing.T) {
	s, store := newTestScanner(t, time.Hour)
	s.degradedWarnDur = 0
	buf := captureLogs(t)

	for i := 1; i <= 2; i++ {
		store.RegisterNode(fmt.Sprintf("n%d:9421", i), 1<<30)
		store.Heartbeat(uint64(i), 0)
	}
	st, _ := store.CreateStagingFile(1)
	store.AssignChunk(st.ID, 0, 100, []uint64{1, 2})
	store.MarkChunkDone(types.ChunkID(st.ID, 0), 1)
	store.CommitStagingFile(st.ID, "f.bin", 100)

	in, _ := store.GetInode(st.ID)
	chunkID := types.ChunkID(st.ID, 0)
	nodes := mkNodes([]uint64{1, 2}, []uint64{1, 2})
	now := time.Now()
	s.trackDegradedChunk(in, in.Chunks[0], chunkID, nodes, now)
	s.trackDegradedChunk(in, in.Chunks[0], chunkID, nodes, now.Add(time.Second)) // WARN

	// 从副本补齐 → 恢复日志 + 清状态。
	in, _ = store.GetInode(st.ID)
	// 直接改内存里的 Done 模拟补齐（meta 无该 API，构造新 ChunkInfo）。
	in.Chunks[0].Done = []uint64{1, 2}
	s.trackDegradedChunk(in, in.Chunks[0], chunkID, nodes, now.Add(2*time.Second))
	logs := buf.String()
	if !strings.Contains(logs, "WARN-解除") {
		t.Fatalf("恢复应输出 WARN-解除, got: %s", logs)
	}

	// 再降级：从头计时（degradedSince 已清），首次只记时刻不告警。
	in.Chunks[0].Done = []uint64{1}
	buf.Reset()
	s.trackDegradedChunk(in, in.Chunks[0], chunkID, nodes, now.Add(3*time.Second))
	if strings.Contains(buf.String(), "WARN: inode") {
		t.Fatalf("再降级首次不应立即告警（应重新计时）, got: %s", buf.String())
	}
	s.trackDegradedChunk(in, in.Chunks[0], chunkID, nodes, now.Add(5*time.Second))
	if !strings.Contains(buf.String(), "WARN: inode") {
		t.Fatalf("再降级超阈值应再次告警, got: %s", buf.String())
	}
}

// TestDegradedChunkIgnoreStaging 改进项2：staging 文件降级不告警（从副本在路上是正常态）。
func TestDegradedChunkIgnoreStaging(t *testing.T) {
	s, store := newTestScanner(t, time.Hour)
	s.degradedWarnDur = 0
	buf := captureLogs(t)

	store.RegisterNode("n1:9421", 1<<30)
	store.Heartbeat(1, 0)
	st, _ := store.CreateStagingFile(1) // 不 commit：保持 staging
	store.AssignChunk(st.ID, 0, 100, []uint64{1, 2})
	store.MarkChunkDone(types.ChunkID(st.ID, 0), 1)

	in, _ := store.GetInode(st.ID)
	nodes := mkNodes([]uint64{1, 2}, []uint64{1, 2})
	now := time.Now()
	s.trackDegradedChunk(in, in.Chunks[0], types.ChunkID(st.ID, 0), nodes, now)
	s.trackDegradedChunk(in, in.Chunks[0], types.ChunkID(st.ID, 0), nodes, now.Add(time.Minute))
	if strings.Contains(buf.String(), "WARN: inode") {
		t.Fatalf("staging 降级不应告警, got: %s", buf.String())
	}
}
