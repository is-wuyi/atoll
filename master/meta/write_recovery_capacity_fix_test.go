package meta

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"atoll/pkg/types"
)

// 恢复容量与完成副本保护的回归测试。
// 覆盖两类缺陷：
//  1. 规划快照对旧布局节点按节点总 Reserved 盲目抵回，且基于截断后 Free 累加，
//     令超额提交节点的未完成副本看起来可容纳新副本（伪容量）；事务侧对旧布局
//     节点完全没有预算校验。
//  2. removed 节点被迫进入 Recovery.Excluded 后，Done 保护 guard 的豁免条件被
//     同一集合满足，规划窗口内新完成的副本被静默丢弃并进入回收。

func recoveryCapacityFixStore(t *testing.T) (*Store, []uint64) {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	var nodes []uint64
	for i := 0; i < 5; i++ {
		n, err := s.RegisterNode(fmt.Sprintf("127.0.0.1:%d", 59200+i), 1024)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, n.ID)
	}
	return s, nodes
}

// lateDoneChoice 构造一个把 layout 整体替换为 layout/confirm 的恢复选择，
// 被移出的节点自动进入 Recovery.Excluded（累计排除语义不变）。
func lateDoneChoice(u types.WriteUpload, old types.WriteChunkPlan, failed uint64, layout, confirm []uint64) (types.RecoverWriteChunkRequest, types.WriteChunkPlan) {
	req := types.RecoverWriteChunkRequest{WriteBinding: writeBinding(u), Index: old.Index, ExpectedEpoch: old.Layout.Epoch, OpID: "recover-late", FailedNodes: []uint64{failed}}
	p := old
	p.Layout.Nodes = append([]uint64(nil), layout...)
	p.Confirmations = append([]uint64(nil), confirm...)
	p.RequiredConfirmations = len(confirm)
	p.Layout.Epoch++
	removed := make([]uint64, 0, len(old.Layout.Nodes))
	for _, id := range old.Layout.Nodes {
		if !types.ContainsUint64(p.Layout.Nodes, id) {
			removed = append(removed, id)
		}
	}
	excluded := recoveryExcluded(old, req.FailedNodes)
	for _, id := range removed {
		excluded = appendUnique(excluded, id)
	}
	sort.Slice(excluded, func(i, j int) bool { return excluded[i] < excluded[j] })
	p.Recovery = &types.WriteRecovery{Epoch: p.Layout.Epoch, Attempts: old.Recovery.Attempts + 1, HardUntil: old.Recovery.HardUntil,
		Excluded: excluded, OperationID: req.OpID, RequestHash: RecoveryRequestHash(req), FailedNodes: req.FailedNodes}
	return req, p
}

func backdateHeartbeatTest(t *testing.T, s *Store, nodeID uint64, age time.Duration) {
	t.Helper()
	err := s.write(func(w *txw) error {
		raw := w.tx.Bucket(bucketNodes).Get(u64be(nodeID))
		if raw == nil {
			return ErrNotExist
		}
		var n types.NodeInfo
		if err := json.Unmarshal(raw, &n); err != nil {
			return err
		}
		n.LastHeartbeat = time.Now().Add(-age)
		updated, err := json.Marshal(n)
		if err != nil {
			return err
		}
		return w.putNode(updated, nodeID)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// 快照侧：未完成旧副本在超额提交节点上不得靠截断后的伪余量通过调度闸门；
// 已完成副本始终可保留（不重复计费）；新节点余量原样保留。
func TestRecoveryPlanningCapacityDistinguishesReplicaStates(t *testing.T) {
	s, nodes := recoveryCapacityFixStore(t)
	_, before := recoveryFixture(t, s, nodes)
	confirmWriteTest(t, s, before.Object.ID, nodes[0])
	if err := s.Heartbeat(nodes[1], 1000); err != nil {
		t.Fatal(err)
	}
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	done := []uint64{nodes[0]}
	out, err := s.RecoveryPlanningCapacity(snap.Capacity, before.Object.ID, before.Layout.Nodes, done, before.Object.StoredSize)
	if err != nil {
		t.Fatal(err)
	}
	byNode := map[uint64]NodeCapacity{}
	for _, c := range out {
		byNode[c.NodeID] = c
	}
	// 旧布局未完成副本：节点超额提交（未截断余量 1024-1000-64 = -40），
	// 不得按节点总 Reserved 盲目抵回出 64 的伪余量。
	if got := byNode[nodes[1]].Free; got >= before.Object.StoredSize {
		t.Fatalf("overcommitted unfinished replica presented %d free, must gate re-selection", got)
	}
	// 旧布局已完成副本：无需新写入空间，始终可保留。
	if got := byNode[nodes[0]].Free; got < before.Object.StoredSize {
		t.Fatalf("completed replica presented %d free, retention must stay feasible", got)
	}
	// 新目标节点：真实余量不被恢复语义修改。
	if got, want := byNode[nodes[2]].Free, int64(1024); got != want {
		t.Fatalf("fresh node free %d, want %d", got, want)
	}
}

// 事务侧：保留在布局里的未完成旧副本，其预留必须有真实（未截断）余量支撑。
func TestRecoverWriteChunkRejectsOvercommittedRetainedReplica(t *testing.T) {
	s, nodes := recoveryCapacityFixStore(t)
	u, before := recoveryFixture(t, s, nodes)
	req, choice := recoveredChoice(u, before, nodes[1], nodes[2])
	if err := s.Heartbeat(nodes[0], 1000); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.RecoverWriteChunk(WriteActor{}, req, before, choice, 0, time.Hour, time.Now())
	if !errors.Is(err, ErrWriteBudget) {
		t.Fatalf("overcommitted retained replica accepted: %v", err)
	}
	current, err := s.GetPlannedWrite(WriteActor{}, writeBinding(u), time.Now())
	if err != nil || !sameRecoveryPlan(current.Chunks[0], before) {
		t.Fatalf("failed recovery changed live plan: %+v %v", current, err)
	}
	if retired, _ := s.ListRetirements(); len(retired) != 0 {
		t.Fatal("failed recovery leaked retirement")
	}
}

// 已完成副本保留不受容量双重计费影响（防过度收紧）。
func TestRecoverWriteChunkRetainsDoneReplicaWithoutFreshCapacity(t *testing.T) {
	s, nodes := recoveryCapacityFixStore(t)
	u, before := recoveryFixture(t, s, nodes)
	confirmWriteTest(t, s, before.Object.ID, nodes[0])
	if err := s.Heartbeat(nodes[0], 1000); err != nil {
		t.Fatal(err)
	}
	req, choice := recoveredChoice(u, before, nodes[1], nodes[2])
	out, chunk, err := s.RecoverWriteChunk(WriteActor{}, req, before, choice, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(chunk.Done, nodes[:1]) {
		t.Fatalf("completed replica lost: %+v", chunk)
	}
	if out.Layout.Epoch != 2 {
		t.Fatalf("unexpected epoch: %+v", out)
	}
	retired, err := s.ListRetirements()
	if err != nil || len(retired) != 1 || retired[0].NodeID != nodes[1] || retired[0].Reason != "write-reassigned" {
		t.Fatalf("detached replica not journaled: %+v %v", retired, err)
	}
}

// 规划窗口内新完成的副本不能因 removed⊆Excluded 被静默丢弃：要求重新规划。
func TestRecoverWriteChunkRejectsDroppingLateDone(t *testing.T) {
	s, nodes := recoveryCapacityFixStore(t)
	u, before := recoveryFixture(t, s, nodes)
	req, choice := lateDoneChoice(u, before, nodes[0], nodes[2:4], nodes[2:4])
	// 规划快照之后、事务提交之前，nodes[1] 完成副本（late Done）。
	confirmWriteTest(t, s, before.Object.ID, nodes[1])
	_, _, err := s.RecoverWriteChunk(WriteActor{}, req, before, choice, 0, time.Hour, time.Now())
	if !errors.Is(err, ErrWriteRecoveryRetry) {
		t.Fatalf("late done replica silently dropped: %v", err)
	}
	if errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("snapshot change misreported as identity conflict: %v", err)
	}
	current, err := s.GetPlannedWrite(WriteActor{}, writeBinding(u), time.Now())
	if err != nil || !sameRecoveryPlan(current.Chunks[0], before) {
		t.Fatalf("failed recovery changed live plan: %+v %v", current, err)
	}
	if retired, _ := s.ListRetirements(); len(retired) != 0 {
		t.Fatal("failed recovery leaked retirement")
	}
	// 以同一 epoch 重新发起、布局保留新完成副本：应当成功且不丢 Done。
	req2 := req
	choice2 := before
	choice2.Layout.Nodes = []uint64{nodes[1], nodes[2], nodes[3]}
	choice2.Confirmations = []uint64{nodes[1], nodes[2]}
	choice2.RequiredConfirmations = 2
	choice2.Layout.Epoch = 2
	choice2.Recovery = &types.WriteRecovery{Epoch: 2, Attempts: 1, HardUntil: before.Recovery.HardUntil,
		Excluded: recoveryExcluded(before, req2.FailedNodes), OperationID: req2.OpID, RequestHash: RecoveryRequestHash(req2), FailedNodes: req2.FailedNodes}
	out, chunk, err := s.RecoverWriteChunk(WriteActor{}, req2, before, choice2, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(chunk.Done, nodes[1:2]) {
		t.Fatalf("re-planned recovery lost the late done replica: %+v", chunk)
	}
	if out.Layout.Epoch != 2 {
		t.Fatalf("unexpected epoch: %+v", out)
	}
	retired, err := s.ListRetirements()
	if err != nil || len(retired) != 1 || retired[0].NodeID != nodes[0] {
		t.Fatalf("declared failed node not journaled: %+v %v", retired, err)
	}
}

// 客户端申报失败的已完成副本允许丢弃，并逐节点进入回收。
func TestRecoverWriteChunkAllowsDroppingDeclaredFailedDone(t *testing.T) {
	s, nodes := recoveryCapacityFixStore(t)
	u, before := recoveryFixture(t, s, nodes)
	confirmWriteTest(t, s, before.Object.ID, nodes[0], nodes[1])
	req, choice := recoveredChoice(u, before, nodes[1], nodes[2])
	out, chunk, err := s.RecoverWriteChunk(WriteActor{}, req, before, choice, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(chunk.Done, nodes[:1]) {
		t.Fatalf("unexpected done set: %+v", chunk)
	}
	if out.Layout.Epoch != 2 {
		t.Fatalf("unexpected epoch: %+v", out)
	}
	retired, err := s.ListRetirements()
	if err != nil || len(retired) != 1 || retired[0].NodeID != nodes[1] || retired[0].Reason != "write-reassigned" {
		t.Fatalf("declared failed replica not journaled: %+v %v", retired, err)
	}
}

// 已死亡节点上的已完成副本允许直接丢弃（回收等待节点回归）。
func TestRecoverWriteChunkAllowsDroppingDeadDoneReplica(t *testing.T) {
	s, nodes := recoveryCapacityFixStore(t)
	u, before := recoveryFixture(t, s, nodes)
	confirmWriteTest(t, s, before.Object.ID, nodes[0], nodes[1])
	req, choice := lateDoneChoice(u, before, nodes[0], nodes[2:4], nodes[2:4])
	backdateHeartbeatTest(t, s, nodes[1], 2*time.Hour)
	out, chunk, err := s.RecoverWriteChunk(WriteActor{}, req, before, choice, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(chunk.Done) != 0 {
		t.Fatalf("dead replica done set not dropped: %+v", chunk)
	}
	if out.Layout.Epoch != 2 {
		t.Fatalf("unexpected epoch: %+v", out)
	}
	retired, err := s.ListRetirements()
	if err != nil || len(retired) != 2 {
		t.Fatalf("every removed node must be journaled: %+v %v", retired, err)
	}
}

// 身份冲突仍报告 ErrWritePlanConflict，不被新的重试语义吞掉。
func TestRecoverWriteChunkStillRejectsIdentityConflicts(t *testing.T) {
	s, nodes := recoveryCapacityFixStore(t)
	u, before := recoveryFixture(t, s, nodes)
	req, choice := recoveredChoice(u, before, nodes[1], nodes[2])
	stale := before
	stale.RequiredConfirmations = 1
	_, _, err := s.RecoverWriteChunk(WriteActor{}, req, stale, choice, 0, time.Hour, time.Now())
	if !errors.Is(err, ErrWritePlanConflict) || errors.Is(err, ErrWriteRecoveryRetry) {
		t.Fatalf("identity conflict misclassified: %v", err)
	}
}

// 纯函数：恢复容量视图的三类节点语义与新旧差异。
func TestApplyRecoveryPlanningCapacityViews(t *testing.T) {
	size := int64(50)
	capacity := []NodeCapacity{
		{NodeID: 1, Capacity: 100, Accounted: 10, Reserved: 0, Headroom: 5, Free: 85},
		{NodeID: 2, Capacity: 100, Accounted: 60, Reserved: 50, Headroom: 0, Free: 0},
		{NodeID: 3, Capacity: 100, Accounted: 30, Reserved: 50, Headroom: 0, Free: 20},
		{NodeID: 4, Capacity: 100, Accounted: 30, Reserved: 50, Headroom: 0, Free: 20},
		{NodeID: 5, Capacity: 100, Accounted: 60, Reserved: 50, Headroom: 0, Free: 0},
		{NodeID: 6, Capacity: 100, Accounted: 30, Reserved: 50, Headroom: 0, Free: 20},
		{NodeID: 7, Capacity: 60, Accounted: 0, Reserved: 50, Headroom: 0, Free: 10},
	}
	oldNodes := []uint64{2, 3, 4, 5, 6, 7}
	done := map[uint64]bool{2: true, 3: true, 7: true}
	credit := map[uint64]int64{2: 50, 3: 50, 4: 50, 5: 50, 7: 50}
	out := applyRecoveryPlanningCapacity(capacity, oldNodes, done, credit, size)
	byNode := map[uint64]NodeCapacity{}
	for _, c := range out {
		byNode[c.NodeID] = c
	}
	if got := byNode[1].Free; got != 85 {
		t.Fatalf("fresh node free %d, want unchanged 85", got)
	}
	// 已完成且双重计费（未截断余量 -10）：抵回后恰好可保留。
	if got := byNode[2].Free; got != 50 {
		t.Fatalf("done overcounted free %d, want 50", got)
	}
	// 已完成且余量充足：真实余量 + 抵回。
	if got := byNode[3].Free; got != 70 {
		t.Fatalf("done healthy free %d, want 70", got)
	}
	// 未完成且余量支撑预留：可重选，闸门等价于未截断余量 >= 0。
	if got := byNode[4].Free; got != 70 {
		t.Fatalf("unfinished backed free %d, want 70", got)
	}
	// 未完成且超额提交：不得抵回出伪余量。
	if got := byNode[5].Free; got >= size {
		t.Fatalf("unfinished overcommitted free %d, must gate re-selection", got)
	}
	// 未完成且无预留（异常状态）：视同新目标，按真实余量。
	if got := byNode[6].Free; got != 20 {
		t.Fatalf("unfinished unreserved free %d, want 20", got)
	}
	// 抵回不超过节点容量。
	if got := byNode[7].Free; got != 60 {
		t.Fatalf("capped free %d, want 60", got)
	}
	// 输入切片不被修改。
	if capacity[3].Free != 20 {
		t.Fatalf("input capacity mutated: %+v", capacity[3])
	}
}
