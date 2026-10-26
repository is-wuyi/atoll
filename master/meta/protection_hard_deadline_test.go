package meta

import (
	"testing"
	"time"
)

func TestFeedbackPersistedHardDeadlineIgnoresLaterPolicyReconfiguration(t *testing.T) {
	s, plan, _, _ := feedbackFixture(t)
	now := time.Now()
	_, target, err := s.ClaimProtectionTarget(plan.ID, now, 2*time.Minute)
	if err != nil || target == nil {
		t.Fatal(err)
	}
	r := feedbackReport(plan, *target, 30, now.Add(30*time.Second))
	result, err := s.RecordProtectionProgressResult(r, ProtectionRenewPolicy{Window: time.Minute, MaxRenewals: 4, MaxTotalLease: time.Minute})
	if err != nil || !result.Recorded || !result.HardUntil.Equal(target.HardUntil) {
		t.Fatalf("later policy changed attempt hard deadline: %+v %v", result, err)
	}
}
