package meta

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"atoll/pkg/types"
)

func recoveryFixture(t *testing.T, s *Store, nodes []uint64) (types.WriteUpload, types.WriteChunkPlan) {
	t.Helper()
	u := beginWriteTest(t, s, RootID, "recover-upload", 64, false)
	req, p := writeChoice(u, 0, make([]byte, 64), nodes[:2], nodes[:2])
	p.Recovery = &types.WriteRecovery{Epoch: 1, HardUntil: time.Now().Add(10 * time.Minute)}
	p, _, err := s.ReserveWriteChunk(WriteActor{}, req, p, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return u, p
}

func recoveredChoice(u types.WriteUpload, old types.WriteChunkPlan, failed, replacement uint64) (types.RecoverWriteChunkRequest, types.WriteChunkPlan) {
	req := types.RecoverWriteChunkRequest{WriteBinding: writeBinding(u), Index: old.Index, ExpectedEpoch: old.Layout.Epoch, OpID: "recover-one", FailedNodes: []uint64{failed}}
	p := old
	p.Layout.Nodes = append([]uint64(nil), old.Layout.Nodes...)
	p.Confirmations = append([]uint64(nil), old.Confirmations...)
	for i, id := range p.Layout.Nodes {
		if id == failed {
			p.Layout.Nodes[i] = replacement
		}
	}
	for i, id := range p.Confirmations {
		if id == failed {
			p.Confirmations[i] = replacement
		}
	}
	p.Layout.Epoch++
	p.Recovery = &types.WriteRecovery{Epoch: p.Layout.Epoch, Attempts: old.Recovery.Attempts + 1, HardUntil: old.Recovery.HardUntil, Excluded: recoveryExcluded(old, req.FailedNodes), OperationID: req.OpID, RequestHash: RecoveryRequestHash(req), FailedNodes: req.FailedNodes}
	return req, p
}

func TestWriteRecoveryPreservesDoneAndChargesDetachedReplica(t *testing.T) {
	s, nodes := writeTestStore(t)
	u, before := recoveryFixture(t, s, nodes)
	confirmWriteTest(t, s, before.Object.ID, nodes[0])
	req, choice := recoveredChoice(u, before, nodes[1], nodes[2])
	out, chunk, err := s.RecoverWriteChunk(WriteActor{}, req, before, choice, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if out.Layout.Epoch != 2 || !reflect.DeepEqual(chunk.Done, nodes[:1]) || types.ContainsUint64(chunk.Replicas, nodes[1]) || !types.ContainsUint64(chunk.Replicas, nodes[2]) {
		t.Fatalf("recovery did not preserve completed work: %+v %+v", out, chunk)
	}
	for _, id := range nodes {
		c := capacityFor(t, s, id)
		if c.Reserved != 64 || c.Free != 960 {
			t.Fatalf("node %d lost or duplicated reservation: %+v", id, c)
		}
	}
	replayed, current, err := s.RecoverWriteChunk(WriteActor{}, req, before, choice, 0, time.Hour, time.Now())
	if err != nil || !sameRecoveryPlan(replayed, out) || !reflect.DeepEqual(current, chunk) {
		t.Fatalf("lost-response replay changed plan: %+v %+v %v", replayed, current, err)
	}
	wrong := req
	wrong.FailedNodes = nodes[:1]
	if _, _, err := s.RecoverWriteChunk(WriteActor{}, wrong, before, choice, 0, time.Hour, time.Now()); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("same operation accepted changed request: %v", err)
	}
	if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(u, 64, 1), time.Hour, time.Now()); !errors.Is(err, ErrWriteNotReady) {
		t.Fatalf("unconfirmed replacement published: %v", err)
	}
	confirmWriteTest(t, s, out.Object.ID, nodes[2])
	if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(u, 64, 1), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	records, err := s.ListRetirements()
	if err != nil || len(records) != 1 || records[0].NodeID != nodes[1] || records[0].Reason != "write-reassigned" {
		t.Fatalf("detached replica not journaled: %+v %v", records, err)
	}
	if _, claimed, err := s.ClaimRetirement(out.Object.ID, nodes[1], time.Now(), time.Minute, time.Hour); err != nil || !claimed {
		t.Fatalf("detached replica cannot retire while live copies remain: %v %v", claimed, err)
	}
}

func TestWriteRecoveryWALReplayAndLateReceipt(t *testing.T) {
	s, nodes := writeTestStore(t)
	u, old := recoveryFixture(t, s, nodes)
	confirmWriteTest(t, s, old.Object.ID, nodes[0])
	oldDescriptor, err := s.ObjectIntegrity(old.Object.ID)
	if err != nil {
		t.Fatal(err)
	}
	req, choice := recoveredChoice(u, old, nodes[1], nodes[2])
	if _, _, err := s.RecoverWriteChunk(WriteActor{}, req, old, choice, 0, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if marked, err := s.MarkVerifiedObjectDone(oldDescriptor, nodes[2]); err != nil || marked {
		t.Fatalf("late old-epoch receipt accepted: marked=%v err=%v", marked, err)
	}
	frames, err := s.FramesSince(0)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Open(filepath.Join(t.TempDir(), "restored.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatal(err)
	}
	out, chunk, err := restored.RecoverWriteChunk(WriteActor{}, req, old, choice, 0, time.Hour, time.Now())
	if err != nil || out.Layout.Epoch != 2 || chunk.WriteEpoch != 2 || !reflect.DeepEqual(chunk.Done, nodes[:1]) {
		t.Fatalf("recovery did not replay: %+v %+v %v", out, chunk, err)
	}
	for _, id := range nodes {
		if got := capacityFor(t, restored, id); got.Reserved != 64 {
			t.Fatalf("restored capacity node %d: %+v", id, got)
		}
	}
}

func TestWriteRecoveryJournalsEveryRemovedNode(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	var nodes []uint64
	for i := 0; i < 5; i++ {
		n, err := s.RegisterNode("127.0.0.1:"+fmt.Sprint(59100+i), 1024)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, n.ID)
	}
	u := beginWriteTest(t, s, RootID, "removed-nodes", 64, false)
	req, old := writeChoice(u, 0, make([]byte, 64), nodes[:3], nodes[:2])
	old.Recovery = &types.WriteRecovery{Epoch: 1, HardUntil: time.Now().Add(time.Minute)}
	old, _, err := s.ReserveWriteChunk(WriteActor{}, req, old, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recoverReq := types.RecoverWriteChunkRequest{WriteBinding: writeBinding(u), Index: 0, ExpectedEpoch: 1, OpID: "replace-layout", FailedNodes: []uint64{nodes[0]}}
	choice := old
	choice.Layout.Nodes = []uint64{nodes[2], nodes[3], nodes[4]}
	choice.Confirmations = []uint64{nodes[2], nodes[3]}
	choice.Layout.Epoch = 2
	choice.Recovery = &types.WriteRecovery{Epoch: 2, Attempts: 1, HardUntil: old.Recovery.HardUntil, Excluded: []uint64{nodes[0]}, FailedNodes: recoverReq.FailedNodes, OperationID: recoverReq.OpID, RequestHash: RecoveryRequestHash(recoverReq)}
	if _, _, err := s.RecoverWriteChunk(WriteActor{}, recoverReq, old, choice, 0, time.Hour, time.Now()); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("unaccounted removed node accepted: %v", err)
	}
	choice.Recovery.Excluded = []uint64{nodes[0], nodes[1]}
	if _, _, err := s.RecoverWriteChunk(WriteActor{}, recoverReq, old, choice, 0, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	retired, err := s.ListRetirements()
	if err != nil || len(retired) != 2 || retired[0].NodeID != nodes[0] || retired[1].NodeID != nodes[1] {
		t.Fatalf("removed node not journaled: %+v %v", retired, err)
	}
}

func TestWriteRecoveryRejectsCapacityLossAndStaleEpoch(t *testing.T) {
	s, nodes := writeTestStore(t)
	u, before := recoveryFixture(t, s, nodes)
	req, choice := recoveredChoice(u, before, nodes[1], nodes[2])
	if err := s.Heartbeat(nodes[2], 1000); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RecoverWriteChunk(WriteActor{}, req, before, choice, 0, time.Hour, time.Now()); !errors.Is(err, ErrWriteBudget) {
		t.Fatalf("capacity oversold: %v", err)
	}
	current, err := s.GetPlannedWrite(WriteActor{}, writeBinding(u), time.Now())
	if err != nil || !sameRecoveryPlan(current.Chunks[0], before) {
		t.Fatalf("failed recovery changed live plan: %+v %v", current, err)
	}
	if retired, _ := s.ListRetirements(); len(retired) != 0 {
		t.Fatal("failed recovery leaked retirement")
	}
	bad := choice
	bad.Confirmations = bad.Confirmations[:1]
	bad.RequiredConfirmations = 1
	if _, _, err := s.RecoverWriteChunk(WriteActor{}, req, before, bad, 0, time.Hour, time.Now()); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("recovery weakened confirmation floor: %v", err)
	}
	req.ExpectedEpoch++
	if _, _, _, _, err := s.RecoverableWriteChunk(WriteActor{}, req, time.Now()); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("unowned epoch accepted: %v", err)
	}
}
