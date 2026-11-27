package client

import (
	"testing"
	"time"

	"atoll/pkg/types"
)

func slowPathProgressForTest(now time.Time) writePathProgress {
	return writePathProgress{count: 3, first: writePathProgressSample{attempt: 1, bytes: 1, at: now.Add(-40 * time.Millisecond)}, last: writePathProgressSample{attempt: 1, bytes: 3, at: now}}
}

func TestShouldRecoverDirectPath(t *testing.T) {
	now := time.Now()
	idle := 80 * time.Millisecond
	ioTimeout := 80 * time.Millisecond
	hardUntil := now.Add(time.Second)
	for _, test := range []struct {
		name       string
		storedSize int64
		now        time.Time
		hardUntil  time.Time
		edit       func(*writePathProgress)
		want       bool
	}{
		{"slow-progress", 1024, now, hardUntil, func(*writePathProgress) {}, true},
		{"fewer-than-three-samples", 1024, now, hardUntil, func(p *writePathProgress) { p.count = 2 }, false},
		{"short-window", 1024, now, hardUntil, func(p *writePathProgress) { p.first.at = now.Add(-30 * time.Millisecond) }, false},
		{"no-distinct-bytes", 1024, now, hardUntil, func(p *writePathProgress) { p.last.bytes = p.first.bytes }, false},
		{"fast-enough", 16, now, hardUntil, func(*writePathProgress) {}, false},
		{"full-payload-not-done", 3, now, hardUntil, func(*writePathProgress) {}, false},
		{"stale-sample", 1024, now.Add(41 * time.Millisecond), hardUntil, func(*writePathProgress) {}, false},
		{"insufficient-hard-until", 1024, now, now.Add(39 * time.Millisecond), func(*writePathProgress) {}, false},
		{"future-sample", 1024, now.Add(-time.Millisecond), hardUntil, func(*writePathProgress) {}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := slowPathProgressForTest(now)
			test.edit(&p)
			if got := shouldRecoverDirectPath(p, test.storedSize, test.now, test.hardUntil, idle, ioTimeout); got != test.want {
				t.Fatalf("shouldRecoverDirectPath=%v want %v; progress=%+v", got, test.want, p)
			}
		})
	}
}

func TestWritePathProgressResetsAndIgnoresRepeatedSamples(t *testing.T) {
	now := time.Now()
	p := slowPathProgressForTest(now)
	p.add(writePathProgressSample{attempt: 1, bytes: 3, at: now.Add(time.Millisecond)}, 80*time.Millisecond)
	if p.count != 3 || p.last.bytes != 3 {
		t.Fatalf("repeated target progress became a new sample: %+v", p)
	}
	p.add(writePathProgressSample{attempt: 2, bytes: 1, at: now.Add(2 * time.Millisecond)}, 80*time.Millisecond)
	if p.count != 1 || p.first.attempt != 2 || p.last.attempt != 2 {
		t.Fatalf("new attempt inherited stale rate samples: %+v", p)
	}
	p.add(writePathProgressSample{attempt: 2, bytes: 2, at: now.Add(3 * time.Millisecond)}, 80*time.Millisecond)
	p.add(writePathProgressSample{attempt: 2, bytes: 3, at: now.Add(2 * time.Millisecond)}, 80*time.Millisecond)
	if p.count != 1 || p.last.bytes != 3 || !p.last.at.Equal(now.Add(2*time.Millisecond)) {
		t.Fatalf("time regression did not reset the window: %+v", p)
	}
}

func recoveredPathPlanPairForTest() (types.WriteChunkPlan, types.WriteChunkPlan, types.RecoverWriteChunkRequest) {
	hardUntil := time.Now().Add(time.Minute)
	old := types.WriteChunkPlan{Layout: types.ReplicaLayout{Epoch: 1, Nodes: []uint64{1, 2}}, Confirmations: []uint64{1, 2}, RequiredConfirmations: 2, Recovery: &types.WriteRecovery{Epoch: 1, HardUntil: hardUntil}, Transfer: &types.WriteTransferPlan{UploadTargets: []uint64{1}, ExpiresAt: hardUntil, Legs: []types.WriteTransferLeg{{ToNodeID: 1, Path: "direct", BPS: 1}, {FromNodeID: 1, ToNodeID: 2, Path: "direct", BPS: 1}}}}
	next := old
	next.Layout.Nodes = append([]uint64(nil), old.Layout.Nodes...)
	next.Confirmations = append([]uint64(nil), old.Confirmations...)
	next.Layout.Epoch = 2
	transfer := *old.Transfer
	transfer.Legs = append([]types.WriteTransferLeg(nil), old.Transfer.Legs...)
	for i := range transfer.Legs {
		transfer.Legs[i].Path = "circuit"
	}
	next.Transfer = &transfer
	req := types.RecoverWriteChunkRequest{ExpectedEpoch: 1, OpID: "recover-path", AvoidPaths: []string{"direct"}}
	next.Recovery = &types.WriteRecovery{Epoch: 2, Attempts: 1, HardUntil: hardUntil, OperationID: req.OpID, AvoidPaths: []string{"direct"}}
	return old, next, req
}

func TestValidateRecoveredWritePlanPathOnly(t *testing.T) {
	old, next, req := recoveredPathPlanPairForTest()
	if err := validateRecoveredWritePlan(old, next, req, true); err != nil {
		t.Fatalf("valid path recovery rejected: %v", err)
	}
	for _, test := range []struct {
		name         string
		pathRecovery bool
		editRequest  func(*types.RecoverWriteChunkRequest)
		edit         func(*types.WriteChunkPlan)
	}{
		{"feature-absent", false, func(*types.RecoverWriteChunkRequest) {}, func(*types.WriteChunkPlan) {}},
		{"replace-layout", true, func(*types.RecoverWriteChunkRequest) {}, func(p *types.WriteChunkPlan) { p.Layout.Nodes[1] = 3; p.Confirmations[1] = 3 }},
		{"drop-confirmation", true, func(*types.RecoverWriteChunkRequest) {}, func(p *types.WriteChunkPlan) { p.Confirmations = p.Confirmations[:1]; p.RequiredConfirmations = 1 }},
		{"new-exclusion", true, func(*types.RecoverWriteChunkRequest) {}, func(p *types.WriteChunkPlan) { p.Recovery.Excluded = []uint64{3} }},
		{"avoided-leg", true, func(*types.RecoverWriteChunkRequest) {}, func(p *types.WriteChunkPlan) { p.Transfer.Legs[0].Path = "direct" }},
		{"missing-recovery", true, func(*types.RecoverWriteChunkRequest) {}, func(p *types.WriteChunkPlan) { p.Recovery = nil }},
		{"changed-avoid", true, func(*types.RecoverWriteChunkRequest) {}, func(p *types.WriteChunkPlan) { p.Recovery.AvoidPaths = nil }},
		{"unexpected-failed-node", true, func(*types.RecoverWriteChunkRequest) {}, func(p *types.WriteChunkPlan) { p.Recovery.FailedNodes = []uint64{2}; p.Recovery.Excluded = []uint64{2} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, bad, request := recoveredPathPlanPairForTest()
			test.editRequest(&request)
			test.edit(&bad)
			if err := validateRecoveredWritePlan(old, bad, request, test.pathRecovery); err == nil {
				t.Fatal("tampered path recovery accepted")
			}
		})
	}
}

func TestValidateRecoveredWritePlanLegacyFailureSet(t *testing.T) {
	old, next, req := recoveredPathPlanPairForTest()
	req.AvoidPaths = nil
	req.FailedNodes = []uint64{2}
	next.Layout.Nodes[1] = 3
	next.Confirmations[1] = 3
	next.Recovery.AvoidPaths = nil
	next.Recovery.FailedNodes = []uint64{2}
	next.Recovery.Excluded = []uint64{2}
	if err := validateRecoveredWritePlan(old, next, req, true); err != nil {
		t.Fatalf("legacy failed-node recovery changed behavior: %v", err)
	}
	bad := next
	bad.Recovery = &types.WriteRecovery{}
	if err := validateRecoveredWritePlan(old, bad, req, true); err == nil {
		t.Fatal("invalid legacy recovery accepted")
	}
}
