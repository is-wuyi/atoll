package meta

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"atoll/internal/scheduler"
)

func TestFeedbackClaimUsesMeasuredGoodputWithoutChangingBudget(t *testing.T) {
	s, ids, objects := trfWorld(t, 1, 1000, 1000, 1000)
	if err := s.EnableProtectionFeedback(); err != nil {
		t.Fatal(err)
	}
	plan := trfReserve(t, s, "measured-selection", objects[0], ids[2])
	now := time.Now()
	links := []scheduler.LinkObservation{
		{From: fmt.Sprint(ids[0]), To: fmt.Sprint(ids[2]), Path: scheduler.TransferHTTP, Available: true, ThroughputBPS: 50, Confidence: 1, ObservedAt: now, ValidUntil: now.Add(30 * time.Second)},
		{From: fmt.Sprint(ids[1]), To: fmt.Sprint(ids[2]), Path: scheduler.TransferHTTP, Available: true, ThroughputBPS: 500, Confidence: 1, ObservedAt: now, ValidUntil: now.Add(30 * time.Second)},
	}
	before := trfReservations(t, s)
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20, Links: links, Path: scheduler.TransferHTTP}
	first := trfClaim(t, s, plan.ID, now, budget)
	if first == nil || first.SourceID != ids[1] || first.UploadBPS != 1000 || first.DownloadBPS != 1000 || first.AttemptToken == "" {
		t.Fatalf("real measurement not used or hard budget rewritten: %+v", first)
	}
	after := trfReservations(t, s)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("source selection changed capacity: %v %v", before, after)
	}
	// A failed observation only excludes that direction while it remains fresh.
	links[1].Available = false
	second := trfClaim(t, s, plan.ID, now.Add(30*time.Second), budget)
	if second == nil || second.SourceID != ids[0] || second.Attempts != 2 || second.AttemptToken == first.AttemptToken {
		t.Fatalf("expired observation was trusted or attempt unchanged: %+v", second)
	}
}

func TestFeedbackClaimExcludesFreshFailedSource(t *testing.T) {
	s, ids, objects := trfWorld(t, 1, 1000, 1000, 1000)
	if err := s.EnableProtectionFeedback(); err != nil {
		t.Fatal(err)
	}
	plan := trfReserve(t, s, "failed-selection", objects[0], ids[2])
	now := time.Now()
	budget := ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20, Links: []scheduler.LinkObservation{{From: fmt.Sprint(ids[0]), To: fmt.Sprint(ids[2]), Path: scheduler.TransferHTTP, Available: false, Confidence: 1, ObservedAt: now, ValidUntil: now.Add(30 * time.Second)}}}
	first := trfClaim(t, s, plan.ID, now, budget)
	if first == nil || first.SourceID != ids[1] {
		t.Fatalf("failed source selected: %+v", first)
	}
}

func TestFeedbackGateOffPreservesLegacyPlanFence(t *testing.T) {
	s, ids, objects := trfWorld(t, 1, 1000, 1000, 1000)
	plan := trfReserve(t, s, "legacy-before-gate", objects[0], ids[2])
	if err := s.EnableProtectionFeedback(); err != nil {
		t.Fatal(err)
	}
	target := trfClaim(t, s, plan.ID, time.Now(), ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1 << 20})
	if target == nil || target.AttemptToken != "" || !target.HardUntil.IsZero() {
		t.Fatalf("legacy plan silently upgraded: %+v", target)
	}
	d, transfer, err := s.ProtectionPlanSnapshot(plan.ID, objects[0].ObjectID, ids[2])
	if err != nil || transfer == nil || d.PlanAttempt != 0 || d.PlanAttemptToken != "" || transfer.PlanAttempt != 0 {
		t.Fatalf("legacy wire changed: %+v %+v %v", d, transfer, err)
	}
	bad := d
	bad.PlanLeaseUntil = d.PlanLeaseUntil.Add(time.Second)
	if ok, err := s.MarkVerifiedObjectDone(bad, ids[2]); err != nil || ok {
		t.Fatalf("legacy lease fence lost: %v %v", ok, err)
	}
	if _, err := s.RecordProtectionProgress(feedbackReport(plan, *target, 1, time.Now()), ProtectionRenewPolicy{}); !errors.Is(err, ErrProtectionProgress) {
		t.Fatalf("legacy feedback accepted: %v", err)
	}
}
