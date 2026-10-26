package meta

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/types"
)

func feedbackFixture(t *testing.T) (*Store, ProtectionPlan, uint64, uint64) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "feedback.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.EnableProtectionFeedback(); err != nil {
		t.Fatal(err)
	}
	var ids []uint64
	for i := 0; i < 3; i++ {
		node, err := s.RegisterNode(string(rune('a'+i))+":9421", 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Heartbeat(node.ID, 0); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, node.ID)
	}
	d := protectionFixture(t, s, "feedback-src", ids[:2], 1000)
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

func feedbackReport(plan ProtectionPlan, target ProtectionTarget, bytesDone int64, now time.Time) ProtectionProgressReport {
	return ProtectionProgressReport{PlanID: plan.ID, ObjectID: plan.Expected.ObjectID, Generation: plan.Expected.Generation, IntegrityEpoch: plan.Expected.IntegrityEpoch, NodeID: target.NodeID, Attempt: target.Attempts, AttemptToken: target.AttemptToken, BytesDone: bytesDone, Now: now}
}

func TestAttemptTokenRegeneratesAndProgressMonotonic(t *testing.T) {
	s, plan, _, _ := feedbackFixture(t)
	now := time.Now()
	_, first, err := s.ClaimProtectionTarget(plan.ID, now, time.Minute)
	if err != nil || first == nil || first.AttemptToken == "" {
		t.Fatalf("first claim: %+v %v", first, err)
	}
	report := feedbackReport(plan, *first, 40, now.Add(time.Second))
	if _, err := s.RecordProtectionProgress(report, ProtectionRenewPolicy{}); err != nil {
		t.Fatal(err)
	}
	for _, bytesDone := range []int64{-1, 30, plan.Expected.Size + 1} {
		report.BytesDone = bytesDone
		if _, err := s.RecordProtectionProgress(report, ProtectionRenewPolicy{}); !errors.Is(err, ErrProtectionProgress) {
			t.Fatalf("invalid bytes %d accepted: %v", bytesDone, err)
		}
	}
	_, second, err := s.ClaimProtectionTarget(plan.ID, now.Add(2*time.Minute), time.Minute)
	if err != nil || second == nil || second.AttemptToken == first.AttemptToken || second.Attempts != first.Attempts+1 {
		t.Fatalf("second claim: %+v %v", second, err)
	}
	if second.ProgressBytes != 0 || second.GoodputBPS != 0 {
		t.Fatalf("claim retained old progress: %+v", second)
	}
	stale := feedbackReport(plan, *first, 50, now.Add(2*time.Minute+time.Second))
	if _, err := s.RecordProtectionProgress(stale, ProtectionRenewPolicy{}); !errors.Is(err, ErrProtectionProgress) {
		t.Fatalf("stale attempt accepted: %v", err)
	}
	fresh := feedbackReport(plan, *second, 5, now.Add(2*time.Minute+time.Second))
	fresh.GoodputBPS = 1 << 40
	if _, err := s.RecordProtectionProgress(fresh, ProtectionRenewPolicy{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ProtectionPlan(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Targets[0].ProgressBytes != 5 || got.Targets[0].GoodputBPS != 5 {
		t.Fatalf("measurement trusted caller instead of master clock: %+v", got.Targets[0])
	}
}

func TestProgressRenewalBoundedAndKeepsReservation(t *testing.T) {
	s, plan, _, targetID := feedbackFixture(t)
	now := time.Now()
	_, first, err := s.ClaimProtectionTarget(plan.ID, now, time.Minute)
	if err != nil || first == nil {
		t.Fatalf("claim: %+v %v", first, err)
	}
	before := trfReservations(t, s)
	renew := ProtectionRenewPolicy{Window: time.Minute, MaxRenewals: 2, MaxTotalLease: 20 * time.Minute}
	report := feedbackReport(plan, *first, 15, now.Add(15*time.Second))
	if renewed, err := s.RecordProtectionProgress(report, renew); err != nil || renewed {
		t.Fatalf("early heartbeat spent renewal: %v %v", renewed, err)
	}
	report.BytesDone, report.Now = 45, now.Add(45*time.Second)
	if renewed, err := s.RecordProtectionProgress(report, renew); err != nil || !renewed {
		t.Fatalf("near-expiry progress not renewed: %v %v", renewed, err)
	}
	report.BytesDone, report.Now = 90, now.Add(90*time.Second)
	if renewed, err := s.RecordProtectionProgress(report, renew); err != nil || !renewed {
		t.Fatalf("second renewal: %v %v", renewed, err)
	}
	report.BytesDone, report.Now = 135, now.Add(135*time.Second)
	if renewed, err := s.RecordProtectionProgress(report, renew); err != nil || renewed {
		t.Fatalf("renewal cap: %v %v", renewed, err)
	}
	got, err := s.ProtectionPlan(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Targets[0].Renewals != 2 || !got.Targets[0].NextAttempt.Equal(now.Add(150*time.Second)) {
		t.Fatalf("renewal state: %+v", got.Targets[0])
	}
	after := trfReservations(t, s)
	key := [2]uint64{plan.Expected.ObjectID, targetID}
	if before[key] != plan.Expected.Size || after[key] != before[key] {
		t.Fatalf("reservation changed: before=%v after=%v", before, after)
	}
	if got.Targets[0].Done || got.State != ProtectionPending || got.Targets[0].SourceID != first.SourceID || got.Targets[0].Attempts != first.Attempts || got.Targets[0].AttemptToken != first.AttemptToken {
		t.Fatalf("renewal mutated binding/publication: %+v", got)
	}
}

func TestProgressFailureConvergesLeaseWithoutFakeDone(t *testing.T) {
	s, plan, _, targetID := feedbackFixture(t)
	now := time.Now()
	_, first, err := s.ClaimProtectionTarget(plan.ID, now, time.Minute)
	if err != nil || first == nil {
		t.Fatalf("claim: %+v %v", first, err)
	}
	report := feedbackReport(plan, *first, 25, now.Add(2*time.Second))
	report.FailureKind, report.Message = "failed", "source stalled"
	if _, err := s.RecordProtectionProgress(report, ProtectionRenewPolicy{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ProtectionPlan(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	tt := got.Targets[0]
	if tt.Done || tt.FailureKind != "failed" || tt.LastError != "source stalled" || !tt.NextAttempt.Equal(report.Now) || tt.ProgressBytes != 25 {
		t.Fatalf("failure state: %+v", tt)
	}
	d, err := s.ObjectIntegrity(plan.Expected.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if types.ContainsUint64(d.Done, targetID) || types.ContainsUint64(d.Replicas, targetID) || d.IntegrityEpoch != plan.Expected.IntegrityEpoch {
		t.Fatalf("failure leaked publication: %+v", d)
	}
	report.FailureKind = "exploded"
	if _, err := s.RecordProtectionProgress(report, ProtectionRenewPolicy{}); !errors.Is(err, ErrProtectionProgress) {
		t.Fatalf("invalid failure accepted: %v", err)
	}
}

func TestProgressRejectsForgedIdentityAndExpiredRenewal(t *testing.T) {
	s, plan, _, _ := feedbackFixture(t)
	now := time.Now()
	_, first, err := s.ClaimProtectionTarget(plan.ID, now, time.Minute)
	if err != nil || first == nil {
		t.Fatal(err)
	}
	base := feedbackReport(plan, *first, 50, now.Add(50*time.Second))
	for _, mutate := range []func(*ProtectionProgressReport){
		func(r *ProtectionProgressReport) { r.AttemptToken = "forged" },
		func(r *ProtectionProgressReport) { r.AttemptToken = "" },
		func(r *ProtectionProgressReport) { r.Generation++ },
		func(r *ProtectionProgressReport) { r.IntegrityEpoch++ },
		func(r *ProtectionProgressReport) { r.Attempt++ },
		func(r *ProtectionProgressReport) { r.NodeID++ },
	} {
		r := base
		mutate(&r)
		if _, err := s.RecordProtectionProgress(r, ProtectionRenewPolicy{}); !errors.Is(err, ErrProtectionProgress) {
			t.Fatalf("forged report accepted: %+v %v", r, err)
		}
	}
	base.Now = now.Add(time.Minute)
	result, err := s.RecordProtectionProgressResult(base, ProtectionRenewPolicy{Window: time.Minute, MaxRenewals: 8})
	if err != nil || result.Recorded || result.Renewed || result.Action != "defer" {
		t.Fatalf("expired lease revived: %+v %v", result, err)
	}
	got, err := s.ProtectionPlan(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Targets[0].ProgressBytes != 0 || got.Targets[0].Renewals != 0 || !got.Targets[0].NextAttempt.Equal(first.NextAttempt) {
		t.Fatalf("expired report mutated target: %+v", got.Targets[0])
	}
}

func TestProtectionFeedbackCapabilitySnapshotAndWAL(t *testing.T) {
	s := newTestStore(t)
	var snapshot bytes.Buffer
	if _, err := s.Snapshot(&snapshot); err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreFromReader(filepath.Join(t.TempDir(), "feedback-restored.db"), bytes.NewReader(snapshot.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	seq, err := restored.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableProtectionFeedback(); err != nil {
		t.Fatal(err)
	}
	frames, err := s.FramesSince(seq)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatal(err)
	}
	if enabled, err := restored.ProtectionFeedbackEnabled(); err != nil || !enabled {
		t.Fatalf("capability lost in WAL: %v %v", enabled, err)
	}
}
