package types

import (
	"testing"
	"time"
)

func pathRecoveryPlanFixture() (PlanWriteChunkRequest, WriteChunkPlan) {
	req, plan := recoveryPlanFixture()
	hardUntil := plan.Recovery.HardUntil
	plan.Layout.Epoch = 2
	plan.Recovery = &WriteRecovery{Epoch: 2, Attempts: 1, HardUntil: hardUntil, OperationID: "recover-path", RequestHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", AvoidPaths: []string{"direct"}}
	plan.Transfer = &WriteTransferPlan{UploadTargets: []uint64{1}, ExpiresAt: hardUntil, Legs: []WriteTransferLeg{{ToNodeID: 1, Path: "circuit", BPS: 1}, {FromNodeID: 1, ToNodeID: 2, Path: "circuit", BPS: 1}}}
	return req, plan
}

func TestWritePathRecoveryValidation(t *testing.T) {
	req, original := pathRecoveryPlanFixture()
	if err := ValidateWriteChunkPlan(req, original); err != nil {
		t.Fatalf("valid path recovery rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		edit func(*WriteChunkPlan)
	}{
		{"initial-avoid", func(p *WriteChunkPlan) { p.Layout.Epoch = 1; p.Recovery.Epoch = 1; p.Recovery.Attempts = 0 }},
		{"unknown-path", func(p *WriteChunkPlan) { p.Recovery.AvoidPaths = []string{"circuit"} }},
		{"duplicate-path", func(p *WriteChunkPlan) { p.Recovery.AvoidPaths = []string{"direct", "direct"} }},
		{"failed-and-path", func(p *WriteChunkPlan) { p.Recovery.Excluded = []uint64{3}; p.Recovery.FailedNodes = []uint64{3} }},
		{"empty-recovery-cause", func(p *WriteChunkPlan) { p.Recovery.AvoidPaths = nil }},
		{"avoided-leg", func(p *WriteChunkPlan) { p.Transfer.Legs[1].Path = "direct" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := original
			r := *original.Recovery
			r.Excluded = append([]uint64(nil), original.Recovery.Excluded...)
			r.FailedNodes = append([]uint64(nil), original.Recovery.FailedNodes...)
			r.AvoidPaths = append([]string(nil), original.Recovery.AvoidPaths...)
			plan.Recovery = &r
			transfer := *original.Transfer
			transfer.Legs = append([]WriteTransferLeg(nil), original.Transfer.Legs...)
			plan.Transfer = &transfer
			test.edit(&plan)
			if err := ValidateWriteChunkPlan(req, plan); err == nil {
				t.Fatal("invalid path recovery accepted")
			}
		})
	}
	for _, paths := range [][]string{nil, {}, {"direct"}} {
		if !ValidRecoveryAvoidPaths(paths) {
			t.Fatalf("valid avoid set rejected: %v", paths)
		}
	}
	for _, paths := range [][]string{{"circuit"}, {"direct", "direct"}, {"direct", "circuit"}, {""}} {
		if ValidRecoveryAvoidPaths(paths) {
			t.Fatalf("invalid avoid set accepted: %v", paths)
		}
	}
}

func TestSameUint64Set(t *testing.T) {
	if !SameUint64Set([]uint64{2, 1}, []uint64{1, 2}) || !SameUint64Set(nil, []uint64{}) {
		t.Fatal("equivalent recovery membership differs")
	}
	if SameUint64Set([]uint64{1, 2}, []uint64{1, 3}) || SameUint64Set([]uint64{1}, []uint64{1, 2}) {
		t.Fatal("different recovery membership matched")
	}
}

func TestPathRecoveryDeadlineGeometry(t *testing.T) {
	req, plan := pathRecoveryPlanFixture()
	plan.Transfer.ExpiresAt = plan.Recovery.HardUntil.Add(time.Nanosecond)
	if err := ValidateWriteChunkPlan(req, plan); err == nil {
		t.Fatal("path recovery exceeded the original hard deadline")
	}
}
