package meta

import (
	"fmt"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestFeedbackSiblingCompletionDoesNotInvalidateInFlightProgress(t *testing.T) {
	s, ids, objects := trfWorld(t, 1, 1000, 1000, 1000)
	if err := s.EnableProtectionFeedback(); err != nil {
		t.Fatal(err)
	}
	d, err := s.ObjectIntegrity(objects[0].ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	req := protectionReq("siblings", d, ids[2])
	req.Targets = []uint64{ids[2], ids[3]}
	req.ProfileRevision = trfRevision(t, s)
	req.MaxBytes = 2 * d.Size
	plan, err := s.ReserveProtection(req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 2 * d.Size}
	first := trfClaim(t, s, plan.ID, now, budget)
	second := trfClaim(t, s, plan.ID, now, budget)
	if first == nil || second == nil {
		t.Fatal("two targets were not claimed")
	}
	firstDesc, err := s.ProtectionDescriptor(plan.ID, d.ObjectID, first.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	secondDesc, err := s.ProtectionDescriptor(plan.ID, d.ObjectID, second.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.MarkVerifiedObjectDoneWithUsage(firstDesc, first.NodeID, &types.NodeUsage{Epoch: fmt.Sprint(first.NodeID), Sequence: 1, UsedBytes: d.Size}); err != nil || !ok {
		t.Fatalf("first completion: %v %v", ok, err)
	}
	report := feedbackReport(plan, *second, 24, now.Add(24*time.Second))
	report.IntegrityEpoch = secondDesc.IntegrityEpoch
	result, err := s.RecordProtectionProgressResult(report, ProtectionRenewPolicy{Window: time.Minute, MaxRenewals: 4})
	if err != nil || !result.Recorded || !result.Renewed {
		t.Fatalf("sibling invalidated progress: %+v %v", result, err)
	}
	fresh, err := s.ProtectionDescriptor(plan.ID, d.ObjectID, second.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.IntegrityEpoch <= secondDesc.IntegrityEpoch || fresh.PlanAttemptToken != secondDesc.PlanAttemptToken {
		t.Fatalf("refreshed descriptor: %+v", fresh)
	}
	if ok, err := s.MarkVerifiedObjectDoneWithUsage(fresh, second.NodeID, &types.NodeUsage{Epoch: fmt.Sprint(second.NodeID), Sequence: 1, UsedBytes: d.Size}); err != nil || !ok {
		t.Fatalf("second completion: %v %v", ok, err)
	}
	final, err := s.ProtectionPlan(plan.ID)
	if err != nil || final.State != ProtectionCompleted {
		t.Fatalf("multi-target plan incomplete: %+v %v", final, err)
	}
}

func TestFeedbackTerminalFailureBackoffIsBoundedAndIdempotent(t *testing.T) {
	s, plan, _, _ := feedbackFixture(t)
	now := time.Now()
	_, first, err := s.ClaimProtectionTarget(plan.ID, now, time.Minute)
	if err != nil || first == nil {
		t.Fatal(err)
	}
	r := feedbackReport(plan, *first, 10, now.Add(time.Minute))
	r.FailureKind = "failed"
	result, err := s.RecordProtectionProgressResult(r, ProtectionRenewPolicy{})
	if err != nil || !result.Recorded {
		t.Fatalf("terminal feedback at expired lease lost: %+v %v", result, err)
	}
	got, _ := s.ProtectionPlan(plan.ID)
	retry := got.Targets[0].RetryAt
	if !retry.Equal(r.Now.Add(5 * time.Second)) {
		t.Fatalf("retry backoff=%v", retry)
	}
	if _, target, err := s.ClaimProtectionTarget(plan.ID, r.Now.Add(time.Second), time.Minute); err != nil || target != nil {
		t.Fatalf("ignored retry backoff: %+v %v", target, err)
	}
	r.Now = r.Now.Add(time.Second)
	if _, err := s.RecordProtectionProgressResult(r, ProtectionRenewPolicy{}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ProtectionPlan(plan.ID)
	if !got.Targets[0].RetryAt.Equal(retry) {
		t.Fatal("duplicate terminal report extended backoff")
	}
	for attempt := uint32(1); attempt < 100; attempt++ {
		if delay := protectionFailureBackoff(attempt); delay < 5*time.Second || delay > 5*time.Minute {
			t.Fatalf("unbounded delay=%v", delay)
		}
	}
}
