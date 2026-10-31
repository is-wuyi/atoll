package meta

import (
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestProtectionRenewalCoversNextProgressRoundTrip(t *testing.T) {
	s, plan, _, targetID := feedbackFixture(t)
	now := time.Now()
	_, first, err := s.ClaimProtectionTarget(plan.ID, now, 25*time.Second, ProtectionExecutionBudget{MaxConcurrent: 2, MaxBytes: plan.Expected.Size, MaxTotalLease: 3 * time.Minute})
	if err != nil || first == nil {
		t.Fatalf("claim: %+v %v", first, err)
	}
	renew := ProtectionRenewPolicy{Window: 30 * time.Second, MaxRenewals: 4, MaxTotalLease: 3 * time.Minute}
	one, err := s.RecordProtectionProgressResult(feedbackReport(plan, *first, 330, now.Add(15*time.Second)), renew)
	if err != nil || !one.Renewed {
		t.Fatalf("first progress did not renew: %+v %v", one, err)
	}
	two, err := s.RecordProtectionProgressResult(feedbackReport(plan, *first, 660, now.Add(30*time.Second)), renew)
	if err != nil || !two.Renewed || two.LeaseUntil.Sub(now.Add(30*time.Second)) < types.ProtectionProgressInterval+types.ProtectionProgressTimeout {
		t.Fatalf("next report could arrive after the old lease: %+v %v", two, err)
	}
	three, err := s.RecordProtectionProgressResult(feedbackReport(plan, *first, 1000, now.Add(45*time.Second)), renew)
	if err != nil || !three.Recorded || three.LeaseUntil.Sub(now.Add(45*time.Second)) < types.ProtectionProgressTimeout {
		t.Fatalf("final bytes have no time for verification/receipt: %+v %v", three, err)
	}
	got, err := s.ProtectionPlan(plan.ID)
	if err != nil || got.State != ProtectionPending || got.Targets[0].Done || got.Targets[0].Attempts != 1 || got.Targets[0].AttemptToken != first.AttemptToken || !got.Targets[0].HardUntil.Equal(first.HardUntil) {
		t.Fatalf("renewal changed confirmation or identity: %+v %v", got, err)
	}
	if amount := trfReservations(t, s)[[2]uint64{plan.Expected.ObjectID, targetID}]; amount != plan.Expected.Size {
		t.Fatalf("progress released storage reservation: %d", amount)
	}
	duplicate, err := s.RecordProtectionProgressResult(feedbackReport(plan, *first, 1000, now.Add(55*time.Second)), renew)
	if err != nil || duplicate.Renewed || !duplicate.LeaseUntil.Equal(three.LeaseUntil) {
		t.Fatalf("duplicate completed bytes renewed again: %+v %v", duplicate, err)
	}
}
