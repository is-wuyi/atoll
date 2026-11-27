package meta

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"atoll/pkg/types"
)

func legacyRecoveryRequestHashForTest(req types.RecoverWriteChunkRequest) string {
	identity := struct {
		types.WriteBinding
		Index         int      `json:"index"`
		ExpectedEpoch uint64   `json:"expected_epoch"`
		OpID          string   `json:"op_id"`
		FailedNodes   []uint64 `json:"failed_nodes"`
	}{WriteBinding: req.WriteBinding, Index: req.Index, ExpectedEpoch: req.ExpectedEpoch, OpID: req.OpID, FailedNodes: append([]uint64(nil), req.FailedNodes...)}
	sort.Slice(identity.FailedNodes, func(i, j int) bool { return identity.FailedNodes[i] < identity.FailedNodes[j] })
	raw, _ := json.Marshal(identity)
	return BodySHA256(raw)
}

func TestPathRecoveryRequestHashCompatibility(t *testing.T) {
	req := types.RecoverWriteChunkRequest{WriteBinding: types.WriteBinding{UploadID: types.StagingInodeBase + 9, PlanID: "legacy-plan", Revision: 1}, Index: 2, ExpectedEpoch: 3, OpID: "same-operation", FailedNodes: []uint64{8, 4}}
	if got, want := RecoveryRequestHash(req), legacyRecoveryRequestHashForTest(req); got != want {
		t.Fatalf("legacy hash changed: got %s want %s", got, want)
	}
	empty := req
	empty.AvoidPaths = []string{}
	if RecoveryRequestHash(empty) != RecoveryRequestHash(req) {
		t.Fatal("nil and empty avoid paths changed legacy identity")
	}
	path := req
	path.FailedNodes = nil
	path.AvoidPaths = []string{"direct"}
	if RecoveryRequestHash(path) == RecoveryRequestHash(req) {
		t.Fatal("path-only recovery reused a failed-node request identity")
	}
	emptyFailed := path
	emptyFailed.FailedNodes = []uint64{}
	if RecoveryRequestHash(emptyFailed) != RecoveryRequestHash(path) {
		t.Fatal("nil and empty failed nodes changed path-only identity")
	}
}

func TestPathRecoveryRequestValidationMatrix(t *testing.T) {
	base := types.RecoverWriteChunkRequest{WriteBinding: types.WriteBinding{UploadID: types.StagingInodeBase + 1, PlanID: "plan", Revision: 1}, ExpectedEpoch: 1, OpID: "operation", AvoidPaths: []string{"direct"}}
	for _, test := range []struct {
		name  string
		edit  func(*types.RecoverWriteChunkRequest)
		valid bool
	}{
		{"direct", func(*types.RecoverWriteChunkRequest) {}, true},
		{"empty-failed-normalizes", func(r *types.RecoverWriteChunkRequest) { r.FailedNodes = []uint64{} }, true},
		{"unknown", func(r *types.RecoverWriteChunkRequest) { r.AvoidPaths = []string{"circuit"} }, false},
		{"duplicate", func(r *types.RecoverWriteChunkRequest) { r.AvoidPaths = []string{"direct", "direct"} }, false},
		{"failed-and-path", func(r *types.RecoverWriteChunkRequest) { r.FailedNodes = []uint64{1} }, false},
		{"no-cause", func(r *types.RecoverWriteChunkRequest) { r.AvoidPaths = nil }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := base
			req.FailedNodes = append([]uint64(nil), base.FailedNodes...)
			req.AvoidPaths = append([]string(nil), base.AvoidPaths...)
			test.edit(&req)
			if got := validRecoveryRequest(req); got != test.valid {
				t.Fatalf("validRecoveryRequest=%v want %v", got, test.valid)
			}
		})
	}
}

func pathRecoveryMetaFixture(t *testing.T) (*Store, []uint64, types.WriteUpload, types.WriteChunkPlan, types.RecoverWriteChunkRequest, types.WriteChunkPlan, uint64, time.Time) {
	t.Helper()
	s, nodes, _ := completedTransferStore(t)
	data := make([]byte, 64)
	u := beginWriteTest(t, s, RootID, "path-only", int64(len(data)), false)
	now := time.Now()
	geometry, old := writeChoice(u, 0, data, nodes[:2], nodes[:2])
	hardUntil := now.Add(10 * time.Minute)
	old.Recovery = &types.WriteRecovery{Epoch: 1, HardUntil: hardUntil}
	old.Transfer = &types.WriteTransferPlan{UploadTargets: []uint64{nodes[0]}, ExpiresAt: hardUntil, Legs: []types.WriteTransferLeg{{ToNodeID: nodes[0], Path: "direct", BPS: 100}, {FromNodeID: nodes[0], ToNodeID: nodes[1], Path: "direct", BPS: 100}}}
	snapshot, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	old, _, err = s.ReserveWriteChunk(WriteActor{}, geometry, old, snapshot.ProfileRevision, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	req := types.RecoverWriteChunkRequest{WriteBinding: writeBinding(u), ExpectedEpoch: old.Layout.Epoch, OpID: "avoid-direct", AvoidPaths: []string{"direct"}}
	choice := old
	choice.Layout.Nodes = append([]uint64(nil), old.Layout.Nodes...)
	choice.Confirmations = append([]uint64(nil), old.Confirmations...)
	choice.Layout.Epoch++
	transfer := *old.Transfer
	transfer.Legs = append([]types.WriteTransferLeg(nil), old.Transfer.Legs...)
	for i := range transfer.Legs {
		transfer.Legs[i].Path = "circuit"
	}
	choice.Transfer = &transfer
	choice.Recovery = &types.WriteRecovery{Epoch: choice.Layout.Epoch, Attempts: old.Recovery.Attempts + 1, HardUntil: old.Recovery.HardUntil, OperationID: req.OpID, RequestHash: RecoveryRequestHash(req), AvoidPaths: append([]string(nil), req.AvoidPaths...)}
	return s, nodes, u, old, req, choice, snapshot.ProfileRevision, now
}

func TestPathRecoveryPreservesExactLayoutWithoutRetirement(t *testing.T) {
	s, _, u, old, req, choice, revision, now := pathRecoveryMetaFixture(t)
	out, chunk, err := s.RecoverWriteChunk(WriteActor{}, req, old, choice, revision, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if !types.SameUint64Set(out.Layout.Nodes, old.Layout.Nodes) || !types.SameUint64Set(out.Confirmations, old.Confirmations) || out.RequiredConfirmations != old.RequiredConfirmations || !reflect.DeepEqual(out.Recovery.AvoidPaths, []string{"direct"}) || len(out.Recovery.Excluded) != 0 || chunk.WriteEpoch != 2 {
		t.Fatalf("path recovery changed accepted write state: old=%+v new=%+v chunk=%+v", old, out, chunk)
	}
	for _, leg := range out.Transfer.Legs {
		if leg.Path != "circuit" {
			t.Fatalf("avoided path survived: %+v", leg)
		}
	}
	if retired, err := s.ListRetirements(); err != nil || len(retired) != 0 {
		t.Fatalf("path-only recovery queued retirement: %+v %v", retired, err)
	}
	replay := req
	replay.FailedNodes = []uint64{}
	replayed, _, err := s.RecoverWriteChunk(WriteActor{}, replay, old, choice, revision, time.Hour, now)
	if err != nil || !sameRecoveryPlan(replayed, out) {
		t.Fatalf("empty/nil replay normalization failed: %+v %v", replayed, err)
	}
	current, err := s.GetPlannedWrite(WriteActor{}, writeBinding(u), now)
	if err != nil || current.Chunks[0].Layout.Epoch != 2 {
		t.Fatalf("persisted path recovery missing: %+v %v", current, err)
	}
}

func TestPathRecoveryRejectsLayoutAndConfirmationTampering(t *testing.T) {
	s, nodes, u, old, req, choice, revision, now := pathRecoveryMetaFixture(t)
	for _, test := range []struct {
		name string
		edit func(*types.WriteChunkPlan)
	}{
		{"replace-node", func(p *types.WriteChunkPlan) { p.Layout.Nodes[1] = nodes[2]; p.Confirmations[1] = nodes[2] }},
		{"drop-confirmation", func(p *types.WriteChunkPlan) { p.Confirmations = p.Confirmations[:1]; p.RequiredConfirmations = 1 }},
		{"new-exclusion", func(p *types.WriteChunkPlan) { p.Recovery.Excluded = []uint64{nodes[2]} }},
		{"avoided-leg", func(p *types.WriteChunkPlan) { p.Transfer.Legs[0].Path = "direct" }},
		{"nil-recovery", func(p *types.WriteChunkPlan) { p.Recovery = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := choice
			bad.Layout.Nodes = append([]uint64(nil), choice.Layout.Nodes...)
			bad.Confirmations = append([]uint64(nil), choice.Confirmations...)
			if choice.Recovery != nil {
				r := *choice.Recovery
				r.Excluded = append([]uint64(nil), choice.Recovery.Excluded...)
				r.AvoidPaths = append([]string(nil), choice.Recovery.AvoidPaths...)
				bad.Recovery = &r
			}
			transfer := *choice.Transfer
			transfer.Legs = append([]types.WriteTransferLeg(nil), choice.Transfer.Legs...)
			bad.Transfer = &transfer
			test.edit(&bad)
			if _, _, err := s.RecoverWriteChunk(WriteActor{}, req, old, bad, revision, time.Hour, now); !errors.Is(err, ErrWritePlanConflict) {
				t.Fatalf("tampered path recovery accepted: %v", err)
			}
		})
	}
	current, err := s.GetPlannedWrite(WriteActor{}, writeBinding(u), now)
	if err != nil || current.Chunks[0].Layout.Epoch != old.Layout.Epoch || current.Chunks[0].Recovery.Attempts != old.Recovery.Attempts {
		t.Fatalf("rejected recovery consumed an attempt: %+v %v", current, err)
	}
	if retired, _ := s.ListRetirements(); len(retired) != 0 {
		t.Fatalf("rejected recovery queued retirement: %+v", retired)
	}
}
