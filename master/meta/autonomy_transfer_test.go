package meta

// autonomy_transfer_test.go —— 多源块调度：claim 事务内绑定已校验源与每流速率。
// 契约：源资格 = 已校验副本 ∧ 心跳窗口（无窗口时至少上报过一次心跳）；选择 = 完成成本
// (流数+1)×字节/实际流速 最小、平局最小 ID；分配 = min(目标下行份额, 源上行份额, 天花板)
// 按「活跃+排队」均分且同一实际流速双侧入账；速率是否声明由目标侧决定，未配置持久化 0；
// 挑不到源不占租约、绑定不多计容量；票据侧只认绑定源，遗留未绑定目标按轮转放行。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"atoll/pkg/types"
)

// trfWorld 构造 5 节点世界：ids[:2] 是某若干对象的已校验副本，ids[2] 是目标，
// ids[3:] 是空闲节点。所有节点都写 profile，因此 profile revision 在 reserve 前稳定。
func trfWorld(t *testing.T, objects int, size int64, up, down uint64) (*Store, []uint64, []types.ObjectIntegrity) {
	t.Helper()
	s := newTestStore(t)
	ids := protectionNodes(t, s, 5, 1<<30)
	var objs []types.ObjectIntegrity
	used := map[uint64]int64{}
	for i := 0; i < objects; i++ {
		d := protectionFixture(t, s, fmt.Sprintf("trf-block-%d", i), ids[:2], size)
		for _, holder := range ids[:2] {
			// 同一节点持有多块时 usage 序列必须单调，receipt 才不会被当作旧值忽略。
			used[holder] += size
			u := types.NodeUsage{Epoch: fmt.Sprintf("epoch-%d", holder),
				Sequence: uint64(used[holder] / size), UsedBytes: used[holder]}
			if ok, err := s.MarkVerifiedObjectDoneWithUsage(d, holder, &u); err != nil || !ok {
				t.Fatalf("done receipt holder %d object %d: ok=%v err=%v", holder, i, ok, err)
			}
		}
		objs = append(objs, d)
	}
	for i, id := range ids {
		if err := s.SetNodePlacementProfile(NodePlacementProfile{NodeID: id,
			FailureDomains: map[string]string{"site": fmt.Sprintf("site-%d", i)},
			HeadroomBytes:  0, UploadBPS: up, DownloadBPS: down, MaxTransferConcurrency: 4}); err != nil {
			t.Fatalf("profile %d: %v", id, err)
		}
	}
	return s, ids, objs
}

func trfRevision(t *testing.T, s *Store) uint64 {
	t.Helper()
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snap.ProfileRevision
}

func trfReserve(t *testing.T, s *Store, id string, d types.ObjectIntegrity, target uint64) ProtectionPlan {
	t.Helper()
	req := protectionReq(id, d, target)
	req.ProfileRevision = trfRevision(t, s)
	plan, err := s.ReserveProtection(req, time.Now())
	if err != nil {
		t.Fatalf("reserve %s: %v", id, err)
	}
	return plan
}

func trfClaim(t *testing.T, s *Store, planID string, at time.Time, budget ProtectionExecutionBudget) *ProtectionTarget {
	t.Helper()
	_, target, err := s.ClaimProtectionTarget(planID, at, 30*time.Second, budget)
	if err != nil {
		t.Fatalf("claim %s: %v", planID, err)
	}
	return target
}

func trfReservations(t *testing.T, s *Store) map[[2]uint64]int64 {
	t.Helper()
	var out map[[2]uint64]int64
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		out, err = capacityReservationsTx(tx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// trfAddr 复刻 protectionNodes 的地址命名，用于核对绑定的地址字段。
func trfAddr(index int) string { return string(rune('a'+index)) + ":9421" }

func TestTransferBindingPersistsThroughSnapshotAndWAL(t *testing.T) {
	s, ids, objs := trfWorld(t, 1, 1000, 1000, 1000)
	plan := trfReserve(t, s, "trf-wal", objs[0], ids[2])
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20,
		MaxSourceConcurrent: 4, MaxTargetConcurrent: 4, MaxSourceUploadBPS: 1000, MaxTargetDownloadBPS: 1000}
	now := time.Now()
	target := trfClaim(t, s, plan.ID, now, budget)
	if target == nil {
		t.Fatal("claim returned no target")
	}
	if target.SourceID != ids[0] || target.SourceAddr != trfAddr(0) {
		t.Fatalf("binding = (%d,%s), want (%d,%s)", target.SourceID, target.SourceAddr, ids[0], trfAddr(0))
	}
	if target.UploadBPS != 1000 || target.DownloadBPS != 1000 {
		t.Fatalf("allocation = (%d,%d), want (1000,1000)", target.UploadBPS, target.DownloadBPS)
	}
	expiry := target.NextAttempt

	var buf bytes.Buffer
	if _, err := s.Snapshot(&buf); err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreFromReader(filepath.Join(t.TempDir(), "restore.db"), bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	base, err := restored.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	frames, err := s.FramesSince(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatal(err)
	}
	// 计划记录里的绑定必须随 WAL 帧落库，而不是只在内存里。
	got, err := restored.ProtectionPlan(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 1 || got.Targets[0].SourceID != ids[0] || got.Targets[0].SourceAddr != trfAddr(0) ||
		got.Targets[0].UploadBPS != 1000 || got.Targets[0].DownloadBPS != 1000 || got.Targets[0].Attempts != 1 {
		t.Fatalf("restored plan lost the binding: %+v", got.Targets)
	}
	transfer, err := restored.ProtectionTransfer(plan.ID, objs[0].ObjectID, ids[2])
	if err != nil {
		t.Fatal(err)
	}
	if transfer == nil {
		t.Fatal("restored ProtectionTransfer returned nil for a bound target")
	}
	if transfer.SourceID != ids[0] || transfer.TargetID != ids[2] || transfer.UploadBPS != 1000 ||
		transfer.DownloadBPS != 1000 || !transfer.ExpiresAt.Equal(expiry) {
		t.Fatalf("restored transfer = %+v, want source=%d target=%d (1000,1000) expires=%v",
			transfer, ids[0], ids[2], expiry)
	}
}

// 同一目标的多个块分摊同一份下行预算（份额按「活跃+排队」均分），按完成成本
// 分散到两个源；总占用不越过任何一侧声明预算。
func TestTransferDistributesDistinctBlocksAcrossSources(t *testing.T) {
	s, ids, objs := trfWorld(t, 3, 1000, 1000, 2000)
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20,
		MaxSourceConcurrent: 0, MaxTargetConcurrent: 0, MaxSourceUploadBPS: 1000, MaxTargetDownloadBPS: 1000}
	now := time.Now()
	var chosen []uint64
	var upSum, downSum uint64
	for i := range objs {
		plan := trfReserve(t, s, fmt.Sprintf("trf-spread-%d", i), objs[i], ids[2])
		target := trfClaim(t, s, plan.ID, now, budget)
		if target == nil {
			t.Fatalf("block %d got no source", i)
		}
		chosen = append(chosen, target.SourceID)
		if target.UploadBPS == 0 || target.UploadBPS != target.DownloadBPS {
			t.Fatalf("block %d allocation = (%d,%d), want the same positive flow on both sides",
				i, target.UploadBPS, target.DownloadBPS)
		}
		if target.UploadBPS > 1000 {
			t.Fatalf("block %d flow %d exceeds the per-flow ceiling 1000", i, target.UploadBPS)
		}
		upSum += target.UploadBPS
		downSum += target.DownloadBPS
	}
	if chosen[0] != ids[0] {
		t.Fatalf("first block picked source %d, want %d (least cost, ID tie-break)", chosen[0], ids[0])
	}
	if !types.ContainsUint64(chosen, ids[1]) {
		t.Fatalf("blocks all stuck on one source: %v", chosen)
	}
	// 两个源各声明 1000 B/s 上行，目标声明 2000 B/s 下行：总占用不得越过任何一侧。
	if upSum > 2*1000 || downSum > 2000 {
		t.Fatalf("total allocation (%d up, %d down) exceeds the declared budgets", upSum, downSum)
	}
	// 三个计划各占一个目标槽位；绑定不新增任何容量预留键。
	if reserved := trfReservations(t, s); len(reserved) != 3 {
		t.Fatalf("reservations = %+v, want 3 target slots", reserved)
	}
}

// 每源并发上限按该源当前持有的租约数共享统计：A 满不再选 A，B 满后本轮无源。
func TestTransferHeldSourceConcurrencyCapIsShared(t *testing.T) {
	s, ids, objs := trfWorld(t, 3, 1000, 1000, 4000)
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20,
		MaxSourceConcurrent: 1, MaxTargetConcurrent: 0, MaxSourceUploadBPS: 0, MaxTargetDownloadBPS: 0}
	now := time.Now()
	var chosen []uint64
	for i := range objs {
		plan := trfReserve(t, s, fmt.Sprintf("trf-cap-%d", i), objs[i], ids[2])
		target := trfClaim(t, s, plan.ID, now, budget)
		if i < 2 {
			if target == nil {
				t.Fatalf("block %d got no source", i)
			}
			chosen = append(chosen, target.SourceID)
		} else if target != nil {
			t.Fatalf("block %d claimed source %d after both sources hit the shared cap", i, target.SourceID)
		}
	}
	if chosen[0] != ids[0] || chosen[1] != ids[1] {
		t.Fatalf("source order = %v, want [%d %d]", chosen, ids[0], ids[1])
	}
	// 上限已满是「本轮无源」，不是把租约领走后失败：未派工的块 Attempts 必须仍为 0。
	plan, err := s.ProtectionPlan("trf-cap-2")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Targets[0].Attempts != 0 || plan.Targets[0].SourceID != 0 {
		t.Fatalf("blocked block took a lease: %+v", plan.Targets[0])
	}
}

// 绑定源死亡后，下一轮 claim 换一个活的已校验源；旧租约的速率随窗口过期自然释放。
func TestTransferReassignsToLiveVerifiedSourceAfterFailure(t *testing.T) {
	s, ids, objs := trfWorld(t, 1, 1000, 1000, 1000)
	plan := trfReserve(t, s, "trf-reassign", objs[0], ids[2])
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20,
		MaxSourceConcurrent: 0, MaxTargetConcurrent: 0, MaxSourceUploadBPS: 0, MaxTargetDownloadBPS: 0}
	now := time.Now()
	first := trfClaim(t, s, plan.ID, now, budget)
	if first == nil || first.SourceID != ids[0] {
		t.Fatalf("first claim binding = %+v, want source %d", first, ids[0])
	}
	if err := s.RecordProtectionError(plan.ID, ids[2], "source unreachable"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeHeartbeatAt(ids[0], now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	retry := trfClaim(t, s, plan.ID, now.Add(30*time.Second), budget)
	if retry == nil {
		t.Fatal("retry produced no target after the bound source died")
	}
	if retry.SourceID != ids[1] || retry.SourceAddr != trfAddr(1) {
		t.Fatalf("retry binding = (%d,%s), want (%d,%s)", retry.SourceID, retry.SourceAddr, ids[1], trfAddr(1))
	}
	if retry.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", retry.Attempts)
	}
}

// 绑定只写计划记录：源侧字节已在预留里（它是当前副本），不新增任何容量预留键。
func TestTransferBindingDoesNotDoubleChargeCapacity(t *testing.T) {
	s, ids, objs := trfWorld(t, 1, 1000, 1000, 1000)
	trfReserve(t, s, "trf-capacity", objs[0], ids[2])
	before := trfReservations(t, s)
	key := [2]uint64{objs[0].ObjectID, ids[2]}
	if before[key] != 1000 {
		t.Fatalf("target slot not reserved: %+v", before)
	}
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20,
		MaxSourceConcurrent: 0, MaxTargetConcurrent: 0, MaxSourceUploadBPS: 1000, MaxTargetDownloadBPS: 1000}
	target := trfClaim(t, s, "trf-capacity", time.Now(), budget)
	if target == nil {
		t.Fatal("claim returned no target")
	}
	after := trfReservations(t, s)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("claiming changed capacity reservations: before=%+v after=%+v", before, after)
	}
	if _, charged := after[[2]uint64{objs[0].ObjectID, target.SourceID}]; charged {
		t.Fatalf("binding charged the source node: %+v", after)
	}
	if before[[2]uint64{objs[0].ObjectID, ids[0]}] != 0 {
		t.Fatalf("held source already double-charged before the binding: %+v", before)
	}
}

// 天花板只截断每次分配，不淘汰源：4 个块全部绑定成功且两个源都被用到。
func TestTransferCeilingCapsPerFlowWithoutRejectingSource(t *testing.T) {
	s, ids, objs := trfWorld(t, 4, 1000, 10000, 10000)
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20,
		MaxSourceConcurrent: 0, MaxTargetConcurrent: 0, MaxSourceUploadBPS: 1000, MaxTargetDownloadBPS: 1000}
	now := time.Now()
	seen := map[uint64]bool{}
	for i := range objs {
		plan := trfReserve(t, s, fmt.Sprintf("trf-ceiling-%d", i), objs[i], ids[2])
		target := trfClaim(t, s, plan.ID, now, budget)
		if target == nil {
			t.Fatalf("block %d rejected despite a 10000 B/s declaration and a 1000 B/s ceiling", i)
		}
		if target.UploadBPS != 1000 || target.DownloadBPS != 1000 {
			t.Fatalf("block %d allocation = (%d,%d), want the ceiling (1000,1000)",
				i, target.UploadBPS, target.DownloadBPS)
		}
		seen[target.SourceID] = true
	}
	if !seen[ids[0]] || !seen[ids[1]] {
		t.Fatalf("sources used = %v, want both %v", seen, ids[:2])
	}
}

// 已分配速率必须被记账：3000 B/s 按「活跃+排队」槽位均分，首块不独占，两侧之和
// 不超过声明预算。计划先全部预留再派工（真实 controller→dispatch 时序）。
func TestTransferAllocationTracksHeldStreams(t *testing.T) {
	s, ids, objs := trfWorld(t, 3, 1000, 3000, 3000)
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20,
		MaxSourceConcurrent: 0, MaxTargetConcurrent: 0, MaxSourceUploadBPS: 0, MaxTargetDownloadBPS: 0}
	var plans []ProtectionPlan
	for i := range objs[:2] {
		plans = append(plans, trfReserve(t, s, fmt.Sprintf("trf-held-%d", i), objs[i], ids[2]))
	}
	now := time.Now()
	var uploads, downloads []uint64
	for i, plan := range plans {
		target := trfClaim(t, s, plan.ID, now, budget)
		if target == nil {
			t.Fatalf("block %d got no source", i)
		}
		uploads = append(uploads, target.UploadBPS)
		downloads = append(downloads, target.DownloadBPS)
	}
	// 首块：2 个槽位（自己 + 一个排队块）→ 3000/2 = 1500，绝不独占 3000。
	// 第二块：剩余 1500/2 = 750，源侧同样的份额分摊把它截到同一值。
	if uploads[0] != 1500 || uploads[1] != 750 {
		t.Fatalf("upload allocations = %v, want [1500 750]", uploads)
	}
	if downloads[0] != 1500 || downloads[1] != 750 {
		t.Fatalf("download allocations = %v, want [1500 750]", downloads)
	}
	if sum := uploads[0] + uploads[1]; sum > 3000 {
		t.Fatalf("total uploads %d exceed the declared 3000 B/s budget", sum)
	}
	if sum := downloads[0] + downloads[1]; sum > 3000 {
		t.Fatalf("total downloads %d exceed the declared 3000 B/s budget", sum)
	}
	third := trfClaim(t, s, "trf-held-0", now, budget) // 同一计划仍在租约内，不能再领
	if third != nil {
		t.Fatalf("lease taken twice: %+v", third)
	}
}

// 票据侧绑定校验：绑定目标只认绑定源；升级前未绑定目标（SourceID==0）按遗留轮转放行；
// 无 plan_id 放行；租约过期/发送方不是认领者/计划不存在拒绝。遗留调用（不传预算）
// 仍然绑定源——绑定是安全要求与预算无关；显式空预算拒绝。
func TestProtectionSourceMatchesTx(t *testing.T) {
	s, ids, objs := trfWorld(t, 4, 1000, 1000, 1000)
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20,
		MaxSourceConcurrent: 0, MaxTargetConcurrent: 0, MaxSourceUploadBPS: 0, MaxTargetDownloadBPS: 0}
	now := time.Now()
	// 先全部预留再派工（与规划器→派工的真实时序一致），排队块才会进入份额分母。
	bound := trfReserve(t, s, "trf-match-bound", objs[0], ids[2])
	empty := trfReserve(t, s, "trf-match-empty", objs[1], ids[2])
	legacy := trfReserve(t, s, "trf-match-legacy", objs[2], ids[2])
	unbound := trfReserve(t, s, "trf-match-unbound", objs[3], ids[2])
	if target := trfClaim(t, s, bound.ID, now, budget); target == nil || target.SourceID == 0 {
		t.Fatalf("setup binding failed: %+v", target)
	}
	// 显式传空预算必须拒绝：0 不是「不限制」。
	if target := trfClaim(t, s, empty.ID, now, ProtectionExecutionBudget{}); target != nil {
		t.Fatalf("empty budget must not claim: %+v", target)
	}
	// 遗留调用不传预算：仍然绑定源（只是没有全局闸与天花板）。
	_, legacyTarget, err := s.ClaimProtectionTarget(legacy.ID, now, 30*time.Second)
	if err != nil || legacyTarget == nil || legacyTarget.SourceID == 0 || legacyTarget.SourceAddr == "" {
		t.Fatalf("legacy claim must still bind a source: target=%+v err=%v", legacyTarget, err)
	}
	// 注入一条升级前的遗留记录：目标已领租约但从未绑定源。新 claim 总会写绑定，
	// 这种记录只可能来自旧版本数据，必须按遗留行为放行而不是误伤。
	if err := s.write(func(w *txw) error {
		p, err := planTx(w.tx, unbound.ID)
		if err != nil {
			return err
		}
		p.Targets[0].SourceID = 0
		p.Targets[0].SourceAddr = ""
		p.Targets[0].UploadBPS = 0
		p.Targets[0].DownloadBPS = 0
		p.Targets[0].Attempts = 1
		p.Targets[0].NextAttempt = now.Add(30 * time.Second)
		return putAutonomy(w, "plan", p.ID, p)
	}); err != nil {
		t.Fatal(err)
	}
	check := func(planID string, sender, audience uint64, at time.Time) (bool, error) {
		var ok bool
		var err error
		err = s.db.View(func(tx *bolt.Tx) error {
			ok, err = protectionSourceMatchesTx(tx, planID, sender, audience, at)
			return err
		})
		return ok, err
	}
	for _, tc := range []struct {
		planID   string
		sender   uint64
		audience uint64
		at       time.Time
		want     bool
		wantErr  bool
	}{
		{planID: bound.ID, sender: ids[2], audience: ids[0], at: now.Add(time.Second), want: true},
		{planID: bound.ID, sender: ids[2], audience: ids[1], at: now.Add(time.Second), want: false},
		{planID: bound.ID, sender: ids[3], audience: ids[0], at: now.Add(time.Second), want: false},
		{planID: bound.ID, sender: ids[2], audience: ids[0], at: now.Add(31 * time.Second), want: false},
		{planID: "trf-match-unknown", sender: ids[2], audience: ids[0], at: now.Add(time.Second), want: false},
		{planID: "", sender: ids[2], audience: ids[0], at: now.Add(time.Second), want: true},
		{planID: legacy.ID, sender: ids[2], audience: legacyTarget.SourceID, at: now.Add(time.Second), want: true},
		{planID: legacy.ID, sender: ids[2], audience: ids[0], at: now.Add(time.Second),
			want: legacyTarget.SourceID == ids[0]},
		{planID: unbound.ID, sender: ids[2], audience: ids[0], at: now.Add(time.Second), want: true},
		{planID: unbound.ID, sender: ids[2], audience: ids[3], at: now.Add(time.Second), want: true},
		{planID: empty.ID, sender: ids[2], audience: ids[0], at: now.Add(time.Second), want: false},
	} {
		ok, err := check(tc.planID, tc.sender, tc.audience, tc.at)
		if tc.wantErr != (err != nil) || ok != tc.want {
			t.Fatalf("match(plan=%q sender=%d audience=%d) = (%v,%v), want (%v,%v)",
				tc.planID, tc.sender, tc.audience, ok, err, tc.want, tc.wantErr)
		}
	}
}

// 描述符取绑定的契约：未绑定返回 (nil,nil)；pending 要求租约窗口有效；completed 的
// 绑定作为历史事实返回（NextAttempt 已清零）；地址漂移、identity 代际推进、过期租约都拒绝。
func TestProtectionTransferContract(t *testing.T) {
	s, ids, objs := trfWorld(t, 5, 1000, 1000, 1000)
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20,
		MaxSourceConcurrent: 0, MaxTargetConcurrent: 0, MaxSourceUploadBPS: 0, MaxTargetDownloadBPS: 0}
	now := time.Now()

	// 先全部预留再派工（真实 planner→dispatch 时序）。
	unbound := trfReserve(t, s, "trf-unbound", objs[0], ids[2])
	bound := trfReserve(t, s, "trf-bound", objs[1], ids[2])
	completed := trfReserve(t, s, "trf-completed", objs[2], ids[2])
	shortLease := trfReserve(t, s, "trf-shortlease", objs[3], ids[2])
	drift := trfReserve(t, s, "trf-drift", objs[4], ids[2])

	if trfClaim(t, s, unbound.ID, now, ProtectionExecutionBudget{}) != nil {
		t.Fatal("empty budget must not claim")
	}
	transfer, err := s.ProtectionTransfer(unbound.ID, objs[0].ObjectID, ids[2])
	if err != nil || transfer != nil {
		t.Fatalf("unbound target: transfer=%+v err=%v, want (nil,nil)", transfer, err)
	}

	boundTarget := trfClaim(t, s, bound.ID, now, budget)
	if boundTarget == nil {
		t.Fatal("claim failed")
	}
	if transfer, err = s.ProtectionTransfer(bound.ID, objs[1].ObjectID, ids[2]); err != nil || transfer == nil {
		t.Fatalf("bound target: %+v %v", transfer, err)
	}
	// completed：真实回执路径（descriptor 携带 plan_id）→ 计划完成 → 绑定仍可取回。
	completedTarget := trfClaim(t, s, completed.ID, now, budget)
	if completedTarget == nil {
		t.Fatal("completed claim failed")
	}
	desc, err := s.ProtectionDescriptor(completed.ID, objs[2].ObjectID, ids[2])
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	u := types.NodeUsage{Epoch: fmt.Sprintf("epoch-%d", ids[2]), Sequence: 1, UsedBytes: 1000}
	if ok, err := s.MarkVerifiedObjectDoneWithUsage(desc, ids[2], &u); err != nil || !ok {
		t.Fatalf("completed receipt: ok=%v err=%v", ok, err)
	}
	donePlan, err := s.ProtectionPlan(completed.ID)
	if err != nil || donePlan.State != ProtectionCompleted {
		t.Fatalf("plan state = %s err=%v, want completed", donePlan.State, err)
	}
	if transfer, err = s.ProtectionTransfer(completed.ID, objs[2].ObjectID, ids[2]); err != nil || transfer == nil {
		t.Fatalf("completed binding: %+v %v", transfer, err)
	}

	if _, err = s.ProtectionTransfer(bound.ID, objs[1].ObjectID, ids[3]); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("wrong target: %v", err)
	}
	if _, err = s.ProtectionTransfer(bound.ID, objs[0].ObjectID, ids[2]); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("wrong object: %v", err)
	}
	if _, err = s.ProtectionTransfer("trf-missing", objs[0].ObjectID, ids[2]); !errors.Is(err, ErrNotExist) {
		t.Fatalf("missing plan: %v", err)
	}
	// 内容代际推进后旧绑定必须失效：给副本打上 suspect 会推进 integrity epoch。
	if _, err = s.MarkPhysicalObjectSuspect(bound.Expected, ids[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ProtectionTransfer(bound.ID, objs[1].ObjectID, ids[2]); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("stale binding still served after an epoch bump: %v", err)
	}
	// pending 的租约窗口过期后描述符失效（极短 retryAfter 的独立租约）。
	if _, st, err := s.ClaimProtectionTarget(shortLease.ID, now, time.Millisecond, budget); err != nil || st == nil {
		t.Fatalf("short lease claim: %+v %v", st, err)
	}
	if _, err = s.ProtectionTransfer(shortLease.ID, objs[3].ObjectID, ids[2]); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("expired lease still served: %v", err)
	}
	// 源的当前地址漂移（节点换地址）→ pending 与 completed 都拒绝。
	driftTarget := trfClaim(t, s, drift.ID, now, budget)
	if driftTarget == nil {
		t.Fatal("drift claim failed")
	}
	driftAddr(t, s, driftTarget.SourceID)
	if _, err = s.ProtectionTransfer(drift.ID, objs[4].ObjectID, ids[2]); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("pending binding served after source addr drift: %v", err)
	}
	driftAddr(t, s, completedTarget.SourceID)
	if _, err = s.ProtectionTransfer(completed.ID, objs[2].ObjectID, ids[2]); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("completed binding served after source addr drift: %v", err)
	}
}

// driftAddr 直接改写节点元数据里的当前地址，模拟节点换端口/换地址。
func driftAddr(t *testing.T, s *Store, nodeID uint64) {
	t.Helper()
	if err := s.db.Update(func(tx *bolt.Tx) error {
		var n types.NodeInfo
		if err := json.Unmarshal(tx.Bucket(bucketNodes).Get(u64be(nodeID)), &n); err != nil {
			return err
		}
		n.Addr = fmt.Sprintf("drifted-%d:1", nodeID)
		raw, err := json.Marshal(n)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketNodes).Put(u64be(nodeID), raw)
	}); err != nil {
		t.Fatalf("drift addr node %d: %v", nodeID, err)
	}
}

// 目标没有可用 profile 时保持遗留的不声明速率路径（0 = 未分配，不是无限），
// 绑定仍然完成；profile 速率与并发字段有上限校验。
func TestTransferRefusesAbsentAndInvalidProfiles(t *testing.T) {
	s := newTestStore(t)
	ids := protectionNodes(t, s, 4, 1<<30)
	for i := range []int{0, 1, 2} { // ids[3] 不写有效 profile
		if err := s.SetNodePlacementProfile(NodePlacementProfile{NodeID: ids[i],
			FailureDomains: map[string]string{"site": fmt.Sprintf("site-%d", i)},
			UploadBPS:      1000, DownloadBPS: 1000, MaxTransferConcurrency: 4}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		up, down uint64
		slots    int
	}{
		{0, 1000, 0},
		{1000, 0, 0},
		{0, 0, 0},
		{1, 1, 33},
	} {
		if err := s.SetNodePlacementProfile(NodePlacementProfile{NodeID: ids[3],
			FailureDomains: map[string]string{"site": "site-3"},
			UploadBPS:      tc.up, DownloadBPS: tc.down, MaxTransferConcurrency: tc.slots}); tc.slots > 32 && err == nil {
			t.Fatalf("profile with %d transfer slots accepted", tc.slots)
		}
	}
	// ids[3] 的最后有效 profile 是全 0（未配置速率）：目标未配置时不得声明速率，
	// 也不得因此拒绝绑定——0 保留遗留的不限速执行路径。
	d := protectionFixture(t, s, "trf-noprofile", ids[:2], 1000)
	for _, holder := range ids[:2] {
		u := types.NodeUsage{Epoch: fmt.Sprintf("epoch-%d", holder), Sequence: 1, UsedBytes: 1000}
		if ok, err := s.MarkVerifiedObjectDoneWithUsage(d, holder, &u); err != nil || !ok {
			t.Fatalf("done receipt: %v %v", ok, err)
		}
	}
	plan := trfReserve(t, s, "trf-noprofile-plan", d, ids[3])
	target := trfClaim(t, s, plan.ID, time.Now(), ProtectionExecutionBudget{
		MaxConcurrent: 4, MaxBytes: 1 << 20})
	if target == nil {
		t.Fatal("unconfigured profiles must not block the legacy bounded path")
	}
	if target.SourceID != ids[0] || target.UploadBPS != 0 || target.DownloadBPS != 0 {
		t.Fatalf("binding = %+v, want source %d with zero (unthrottled) allocation", target, ids[0])
	}
}

// 租约窗口过期后占用归还、目标回到排队集合，claim 重新成功——过期租约绝不永久占用预算。
func TestProtectionLeaseLoadExcludesExpiredLeases(t *testing.T) {
	s, ids, objs := trfWorld(t, 2, 1000, 2, 2)
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20}
	now := time.Now()
	first := trfReserve(t, s, "trf-expiry-0", objs[0], ids[2])
	second := trfReserve(t, s, "trf-expiry-1", objs[1], ids[2])
	if target := trfClaim(t, s, first.ID, now, budget); target == nil || target.DownloadBPS == 0 {
		t.Fatalf("first claim failed: %+v", target)
	}
	if target := trfClaim(t, s, second.ID, now, budget); target != nil {
		t.Fatalf("second claim succeeded while the first lease still held the whole declared budget: %+v", target)
	}
	if target := trfClaim(t, s, second.ID, now.Add(31*time.Second), budget); target == nil || target.SourceID == 0 || target.DownloadBPS == 0 {
		t.Fatalf("expired lease did not release the budget: %+v", target)
	}
}

// TestTransferJSONRoundTrip 绑定的新字段必须能被旧读法忽略、新读法完整取回。
func TestTransferJSONRoundTrip(t *testing.T) {
	in := ProtectionPlan{ID: "x", Targets: []ProtectionTarget{{NodeID: 3, Addr: "c:1", SourceID: 1,
		SourceAddr: "a:1", UploadBPS: 1000, DownloadBPS: 2000, Attempts: 2}}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out ProtectionPlan
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Targets[0].SourceID != 1 || out.Targets[0].SourceAddr != "a:1" || out.Targets[0].UploadBPS != 1000 ||
		out.Targets[0].DownloadBPS != 2000 {
		t.Fatalf("binding lost in JSON round trip: %+v", out.Targets[0])
	}
	// 旧计划记录（无绑定字段）反序列化后必须是零值，走遗留路径。
	var legacy ProtectionPlan
	if err := json.Unmarshal([]byte(`{"id":"old","targets":[{"node_id":3,"addr":"c:1"}]}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Targets[0].SourceID != 0 || legacy.Targets[0].UploadBPS != 0 {
		t.Fatalf("legacy record must deserialize as unbound: %+v", legacy.Targets[0])
	}
}
