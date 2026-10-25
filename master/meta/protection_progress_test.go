package meta

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// feedbackFixture 建一个带已校验源对象的存储并预留单目标计划。
func feedbackFixture(t *testing.T) (*Store, ProtectionPlan, uint64, uint64) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "feedback.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var ids []uint64
	for i := 0; i < 3; i++ {
		node, err := s.RegisterNode(string(rune('a'+i))+":9421", 1000)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Heartbeat(node.ID, 0); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, node.ID)
	}
	d := protectionFixture(t, s, "feedback-src", ids[:2], 100)
	for _, id := range ids[:2] {
		if ok, err := s.MarkVerifiedObjectDone(d, id); err != nil || !ok {
			t.Fatalf("source confirm %d: %v %v", id, ok, err)
		}
	}
	d, err = s.ObjectIntegrity(d.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.ReserveProtection(ProtectionRequest{ID: "fb-plan", Expected: d, Targets: ids[2:], MaxBytes: d.Size, NodeMaxAge: time.Hour, ProfileRevision: snap.ProfileRevision, Reason: "feedback test"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s, plan, ids[0], ids[2]
}

func TestAttemptTokenRegeneratesAndProgressMonotonic(t *testing.T) {
	s, plan, _, target := feedbackFixture(t)
	now := time.Now()
	_, first, err := s.ClaimProtectionTarget(plan.ID, now, time.Minute)
	if err != nil || first == nil || first.AttemptToken == "" {
		t.Fatalf("first claim: %+v %v", first, err)
	}
	report := ProtectionProgressReport{PlanID: plan.ID, ObjectID: plan.Expected.ObjectID, NodeID: target, Attempt: first.Attempts, BytesDone: 40, GoodputBPS: 10, Now: now.Add(time.Second)}
	if _, err := s.RecordProtectionProgress(report, ProtectionRenewPolicy{}); err != nil {
		t.Fatal(err)
	}
	// 回退被拒。
	report.BytesDone = 30
	if _, err := s.RecordProtectionProgress(report, ProtectionRenewPolicy{}); !errors.Is(err, ErrProtectionProgress) {
		t.Fatalf("regressed bytes accepted: %v", err)
	}
	// 超过对象大小被拒。
	report.BytesDone = plan.Expected.Size + 1
	if _, err := s.RecordProtectionProgress(report, ProtectionRenewPolicy{}); !errors.Is(err, ErrProtectionProgress) {
		t.Fatalf("oversized bytes accepted: %v", err)
	}
	// 旧 attempt 的报告被拒：claim 重生成 token 且 Attempts++。
	_, second, err := s.ClaimProtectionTarget(plan.ID, now.Add(2*time.Minute), time.Minute)
	if err != nil || second == nil || second.AttemptToken == first.AttemptToken || second.Attempts != first.Attempts+1 {
		t.Fatalf("second claim: %+v %v", second, err)
	}
	stale := ProtectionProgressReport{PlanID: plan.ID, ObjectID: plan.Expected.ObjectID, NodeID: target, Attempt: first.Attempts, BytesDone: 50, Now: now.Add(3 * time.Minute)}
	if _, err := s.RecordProtectionProgress(stale, ProtectionRenewPolicy{}); !errors.Is(err, ErrProtectionProgress) {
		t.Fatalf("stale attempt progress accepted: %v", err)
	}
	// 新 attempt 的进度从零重新开始（上一尝试的字节不属于本尝试）。
	fresh := ProtectionProgressReport{PlanID: plan.ID, ObjectID: plan.Expected.ObjectID, NodeID: target, Attempt: second.Attempts, BytesDone: 5, Now: now.Add(3 * time.Minute)}
	if _, err := s.RecordProtectionProgress(fresh, ProtectionRenewPolicy{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ProtectionPlan(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	// claim 重置反馈字段：新尝试 ProgressBytes 从 5 起、GoodputBPS 清零。
	if got.Targets[0].ProgressBytes != 5 || got.Targets[0].GoodputBPS != 0 {
		t.Fatalf("progress state: %+v", got.Targets[0])
	}
}

func TestProgressRenewalBoundedAndKeepsReservation(t *testing.T) {
	s, plan, _, target := feedbackFixture(t)
	now := time.Now()
	_, first, err := s.ClaimProtectionTarget(plan.ID, now, time.Minute)
	if err != nil || first == nil {
		t.Fatalf("claim: %+v %v", first, err)
	}
	before, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	var reservedBefore int64 = -1
	for _, c := range before.Capacity {
		if c.NodeID == target {
			reservedBefore = c.Reserved
		}
	}
	if reservedBefore <= 0 {
		t.Fatal("fixture has no reservation to protect")
	}
	report := ProtectionProgressReport{PlanID: plan.ID, ObjectID: plan.Expected.ObjectID, NodeID: target, Attempt: first.Attempts,
		BytesDone: 10, GoodputBPS: 1, Now: now.Add(time.Second)}
	renew := ProtectionRenewPolicy{Window: time.Minute, MaxRenewals: 2, MaxTotalLease: 90 * time.Second}
	// goodput=1B/s，剩余 90B 需 90s > 剩余租约 → 续租。
	renewed, err := s.RecordProtectionProgress(report, renew)
	if err != nil || !renewed {
		t.Fatalf("first renewal: renewed=%v err=%v", renewed, err)
	}
	got, _ := s.ProtectionPlan(plan.ID)
	if got.Targets[0].Renewals != 1 || !got.Targets[0].NextAttempt.After(first.NextAttempt) {
		t.Fatalf("renewal state: %+v", got.Targets[0])
	}
	// 次数上限 2：第二次进度仍可续（Renewals 1→2），第三次不再续。
	report.BytesDone, report.Now = 20, now.Add(3*time.Second)
	if renewed, err = s.RecordProtectionProgress(report, renew); err != nil || !renewed {
		t.Fatalf("second renewal: renewed=%v err=%v", renewed, err)
	}
	report.BytesDone, report.Now = 30, now.Add(4*time.Second)
	if renewed, err = s.RecordProtectionProgress(report, renew); err != nil || renewed {
		t.Fatalf("renewal beyond cap: renewed=%v err=%v", renewed, err)
	}
	got2, _ := s.ProtectionPlan(plan.ID)
	if got2.Targets[0].Renewals != 2 {
		t.Fatalf("renewal count: %+v", got2.Targets[0])
	}
	// 预留不被续租释放。
	after, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range after.Capacity {
		if c.NodeID == target && c.Reserved != reservedBefore {
			t.Fatalf("renewal changed reservation: %d -> %d", reservedBefore, c.Reserved)
		}
	}
}

func TestProgressFailureConvergesLeaseWithoutFakeDone(t *testing.T) {
	s, plan, _, target := feedbackFixture(t)
	now := time.Now()
	_, first, err := s.ClaimProtectionTarget(plan.ID, now, time.Minute)
	if err != nil || first == nil {
		t.Fatalf("claim: %+v %v", first, err)
	}
	report := ProtectionProgressReport{PlanID: plan.ID, ObjectID: plan.Expected.ObjectID, NodeID: target, Attempt: first.Attempts,
		BytesDone: 25, FailureKind: "failed", Message: "source stalled", Now: now.Add(2 * time.Second)}
	if _, err := s.RecordProtectionProgress(report, ProtectionRenewPolicy{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ProtectionPlan(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	tt := got.Targets[0]
	if tt.Done || tt.FailureKind != "failed" || tt.LastError != "source stalled" || tt.NextAttempt.After(report.Now) {
		t.Fatalf("failure state: %+v", tt)
	}
	// 失败后对象未被发布、目标不在 Done 集合。
	d, err := s.ObjectIntegrity(plan.Expected.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if ContainsID(d.Done, target) || ContainsID(d.Replicas, target) && !ContainsID(d.Done, target) && d.IntegrityEpoch != plan.Expected.IntegrityEpoch {
		t.Fatalf("failure leaked publication: %+v", d)
	}
	// 失败报告自身类别必须合法。
	report.FailureKind = "exploded"
	if _, err := s.RecordProtectionProgress(report, ProtectionRenewPolicy{}); !errors.Is(err, ErrProtectionProgress) {
		t.Fatalf("invalid failure kind accepted: %v", err)
	}
	// 非 feedback 计划（token 空）的报告被拒。
	if err := s.write(func(w *txw) error {
		p, err := planTx(w.tx, plan.ID)
		if err != nil {
			return err
		}
		p.Targets[0].AttemptToken = ""
		return putAutonomy(w, "plan", p.ID, p)
	}); err != nil {
		t.Fatal(err)
	}
	report.FailureKind = ""
	report.Attempt = got.Targets[0].Attempts
	if _, err := s.RecordProtectionProgress(report, ProtectionRenewPolicy{}); !errors.Is(err, ErrProtectionProgress) {
		t.Fatalf("legacy plan progress accepted: %v", err)
	}
}

func ContainsID(ids []uint64, id uint64) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
