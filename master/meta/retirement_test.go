package meta

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/types"
)

// retirementRecords returns the durable retirement journal, failing the test on
// any decode error so corrupted records cannot masquerade as an empty journal.
func retirementRecords(t *testing.T, s *Store) []RetirementRecord {
	t.Helper()
	recs, err := s.ListRetirements()
	if err != nil {
		t.Fatalf("ListRetirements: %v", err)
	}
	return recs
}

func retirementReceiptFor(t *testing.T, req types.ObjectRetirement, removed int64, usage types.NodeUsage) types.ObjectRetirementReceipt {
	t.Helper()
	r := types.ObjectRetirementReceipt{
		ObjectRetirement: req,
		State:            types.RetirementRemoved,
		RemovedBytes:     removed,
		Usage:            usage,
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("invalid test receipt: %v", err)
	}
	return r
}

// setUsageFloorBaseline establishes a cross-epoch sample so UsageFloorBytes
// equals used. A single first sample cannot set the floor: there is no prior
// epoch to compare against.
func setUsageFloorBaseline(t *testing.T, s *Store, nodeID uint64, epoch string, sequence uint64, used int64) {
	t.Helper()
	heartbeatUsage(t, s, nodeID, types.NodeUsage{Epoch: epoch + "-prior", Sequence: 1, UsedBytes: used})
	heartbeatUsage(t, s, nodeID, types.NodeUsage{Epoch: epoch, Sequence: sequence, UsedBytes: used})
	n, err := s.GetNode(nodeID)
	if err != nil {
		t.Fatalf("GetNode(%d): %v", nodeID, err)
	}
	if n.UsedBytes != used || n.UsageFloorBytes != used {
		t.Fatalf("usage baseline node %d = used %d floor %d, want %d/%d", nodeID, n.UsedBytes, n.UsageFloorBytes, used, used)
	}
}

// reserveAndAbort exercises the production abort path: the staged inode must
// disappear while the independent pair reservations stay charged.
func reserveAndAbort(t *testing.T, s *Store, u types.WriteUpload, size int64, nodes []uint64) types.WriteChunkPlan {
	t.Helper()
	p := reserveWriteTest(t, s, u, make([]byte, size), nodes, nodes)
	if err := s.AbortPlannedWrite(WriteActor{}, writeBinding(u), time.Now()); err != nil {
		t.Fatalf("AbortPlannedWrite: %v", err)
	}
	return p
}

func TestRetirementAbortDeletesStagingAndReleasesOnlyOnExactReceipt(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	const size int64 = 150

	u := beginWriteTest(t, s, RootID, "abort", size, false)
	p := reserveAndAbort(t, s, u, size, []uint64{node})

	if _, err := s.GetInode(u.ID); !errors.Is(err, ErrNotExist) {
		t.Fatalf("staging inode survived abort: %v", err)
	}
	recs := retirementRecords(t, s)
	if len(recs) != 1 {
		t.Fatalf("retirements = %+v, want one pending record", recs)
	}
	if rec := recs[0]; rec.ObjectID != p.Object.ID || rec.NodeID != node || rec.State != RetirementPending || rec.Expected.Size != size {
		t.Fatalf("retirement = %+v, want pending object %d node %d size %d", rec, p.Object.ID, node, size)
	}
	if c := capacityFor(t, s, node); c.Reserved != size {
		t.Fatalf("abort released reservation: %+v", c)
	}

	now := time.Now()
	req, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("ClaimRetirement: claimed=%v err=%v", claimed, err)
	}
	if req.ObjectID != p.Object.ID || req.NodeID != node || req.ExpectedSize != size {
		t.Fatalf("claim = %+v", req)
	}

	// A receipt for a different attempt must never release bytes.
	stale := retirementReceiptFor(t, req, size, types.NodeUsage{Epoch: "e1", Sequence: 1, UsedBytes: 0})
	stale.AttemptID = "ra1_000000000000000000000000000000000000000000000000"
	if ok, err := s.ConfirmRetirement(stale, now, time.Hour); ok || !errors.Is(err, ErrRetirementConflict) {
		t.Fatalf("stale attempt accepted: ok=%v err=%v", ok, err)
	}
	if c := capacityFor(t, s, node); c.Reserved != size {
		t.Fatalf("rejected receipt released reservation: %+v", c)
	}

	// An impossible removed_bytes value must be rejected by receipt validation.
	invalid := types.ObjectRetirementReceipt{
		ObjectRetirement: req,
		State:            types.RetirementRemoved,
		RemovedBytes:     size + 1,
		Usage:            types.NodeUsage{Epoch: "e1", Sequence: 1, UsedBytes: 0},
	}
	if ok, err := s.ConfirmRetirement(invalid, now, time.Hour); ok || !errors.Is(err, ErrRetirementConflict) {
		t.Fatalf("invalid receipt accepted: ok=%v err=%v", ok, err)
	}
	if c := capacityFor(t, s, node); c.Reserved != size {
		t.Fatalf("invalid receipt released reservation: %+v", c)
	}

	receipt := retirementReceiptFor(t, req, size, types.NodeUsage{Epoch: "e1", Sequence: 1, UsedBytes: 0})
	ok, err := s.ConfirmRetirement(receipt, now, time.Hour)
	if err != nil || !ok {
		t.Fatalf("ConfirmRetirement: ok=%v err=%v", ok, err)
	}
	if c := capacityFor(t, s, node); c.Reserved != 0 {
		t.Fatalf("confirmed pair still reserved: %+v", c)
	}
	if recs = retirementRecords(t, s); len(recs) != 1 || recs[0].State != RetirementConfirmed || recs[0].Receipt == nil {
		t.Fatalf("tombstone = %+v", recs)
	}
}

func TestRetirementAbsenceReleasesPairWithoutFloorCredit(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	const size int64 = 150

	setUsageFloorBaseline(t, s, node, "e1", 5, 200)
	u := beginWriteTest(t, s, RootID, "absent", size, false)
	p := reserveAndAbort(t, s, u, size, []uint64{node})
	if c := capacityFor(t, s, node); c.Reserved != size {
		t.Fatalf("pre-claim reservation: %+v", c)
	}

	now := time.Now()
	req, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("ClaimRetirement: claimed=%v err=%v", claimed, err)
	}
	// removed_bytes=0 means the node found nothing; the pair reservation may go
	// away, but the observed usage floor must not be credited as if bytes left.
	receipt := retirementReceiptFor(t, req, 0, types.NodeUsage{Epoch: "e2", Sequence: 1, UsedBytes: 150})
	ok, err := s.ConfirmRetirement(receipt, now, time.Hour)
	if err != nil || !ok {
		t.Fatalf("ConfirmRetirement: ok=%v err=%v", ok, err)
	}

	n, err := s.GetNode(node)
	if err != nil {
		t.Fatal(err)
	}
	if n.UsedBytes != 150 || n.UsageFloorBytes != 200 {
		t.Fatalf("absence debited floor: used=%d floor=%d, want 150/200", n.UsedBytes, n.UsageFloorBytes)
	}
	c := capacityFor(t, s, node)
	if c.Reserved != 0 {
		t.Fatalf("pair reservation survived confirmation: %+v", c)
	}
	if c.Accounted != 200 {
		t.Fatalf("floor lost on absence receipt: %+v", c)
	}
}

func TestRetirementDuplicateConfirmationDoesNotDoubleDebitFloor(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	const size int64 = 150

	u := beginWriteTest(t, s, RootID, "duplicate", size, false)
	p := reserveAndAbort(t, s, u, size, []uint64{node})
	setUsageFloorBaseline(t, s, node, "e1", 5, 950)

	now := time.Now()
	req, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("ClaimRetirement: claimed=%v err=%v", claimed, err)
	}
	receipt := retirementReceiptFor(t, req, size, types.NodeUsage{Epoch: "e2", Sequence: 1, UsedBytes: 800})
	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); err != nil || !ok {
		t.Fatalf("first ConfirmRetirement: ok=%v err=%v", ok, err)
	}
	if n, err := s.GetNode(node); err != nil || n.UsageFloorBytes != 800 || n.UsedBytes != 800 {
		t.Fatalf("first confirmation node=%+v err=%v, want used/floor 800", n, err)
	}

	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); err != nil || !ok {
		t.Fatalf("replayed ConfirmRetirement: ok=%v err=%v", ok, err)
	}
	if n, _ := s.GetNode(node); n.UsageFloorBytes != 800 || n.UsedBytes != 800 {
		t.Fatalf("duplicate confirmation double-debited: used=%d floor=%d", n.UsedBytes, n.UsageFloorBytes)
	}

	changed := receipt
	changed.RemovedBytes = size - 50
	if ok, err := s.ConfirmRetirement(changed, now, time.Hour); ok || !errors.Is(err, ErrRetirementConflict) {
		t.Fatalf("different receipt for tombstone accepted: ok=%v err=%v", ok, err)
	}
	if n, _ := s.GetNode(node); n.UsageFloorBytes != 800 {
		t.Fatalf("conflicting receipt changed floor: %d", n.UsageFloorBytes)
	}
	recs := retirementRecords(t, s)
	if len(recs) != 1 || recs[0].State != RetirementConfirmed || recs[0].Receipt == nil || *recs[0].Receipt != receipt {
		t.Fatalf("tombstone = %+v", recs)
	}
}

func TestRetirementDurableReplayDoesNotDuplicate(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	const size int64 = 150

	setUsageFloorBaseline(t, s, node, "e1", 5, 200)
	u := beginWriteTest(t, s, RootID, "durable", size, false)
	p := reserveAndAbort(t, s, u, size, []uint64{node})

	now := time.Now()
	failure := errors.New("synchronous WAL prefix unavailable")
	s.SetPostCommitHook(func(uint64, []byte) error { return failure })
	defer s.SetPostCommitHook(nil)

	req, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour)
	if !errors.Is(err, failure) || !claimed {
		t.Fatalf("first ClaimRetirement: claimed=%v err=%v", claimed, err)
	}
	again, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour)
	if !errors.Is(err, failure) || claimed || again != (types.ObjectRetirement{}) {
		t.Fatalf("replayed ClaimRetirement created an attempt: claimed=%v req=%+v err=%v", claimed, again, err)
	}
	recs := retirementRecords(t, s)
	if len(recs) != 1 || recs[0].State != RetirementAttempted || recs[0].Attempt == nil || recs[0].Attempt.AttemptID != req.AttemptID {
		t.Fatalf("claim journal = %+v", recs)
	}

	s.SetPostCommitHook(nil)
	if _, claimed, err = s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour); err != nil || claimed {
		t.Fatalf("durable replay: claimed=%v err=%v", claimed, err)
	}

	receipt := retirementReceiptFor(t, req, 100, types.NodeUsage{Epoch: "e2", Sequence: 1, UsedBytes: 100})
	s.SetPostCommitHook(func(uint64, []byte) error { return failure })
	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); !errors.Is(err, failure) || !ok {
		t.Fatalf("first ConfirmRetirement: ok=%v err=%v", ok, err)
	}
	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); !errors.Is(err, failure) || !ok {
		t.Fatalf("replayed ConfirmRetirement bypassed durability: ok=%v err=%v", ok, err)
	}

	s.SetPostCommitHook(nil)
	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); err != nil || !ok {
		t.Fatalf("durable confirm replay: ok=%v err=%v", ok, err)
	}
	n, err := s.GetNode(node)
	if err != nil {
		t.Fatal(err)
	}
	if n.UsedBytes != 100 || n.UsageFloorBytes != 100 {
		t.Fatalf("replay double-debited floor: used=%d floor=%d, want 100/100", n.UsedBytes, n.UsageFloorBytes)
	}
	recs = retirementRecords(t, s)
	if len(recs) != 1 || recs[0].State != RetirementConfirmed {
		t.Fatalf("confirm journal = %+v", recs)
	}
}

func TestRetirementFreshAttemptRejectsStaleAck(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	const size int64 = 150

	u := beginWriteTest(t, s, RootID, "fresh", size, false)
	p := reserveAndAbort(t, s, u, size, []uint64{node})
	setUsageFloorBaseline(t, s, node, "e1", 5, 950)

	t0 := time.Now()
	oldReq, claimed, err := s.ClaimRetirement(p.Object.ID, node, t0, time.Second, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("first claim: claimed=%v err=%v", claimed, err)
	}
	freshReq, claimed, err := s.ClaimRetirement(p.Object.ID, node, t0.Add(2*time.Second), time.Second, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("fresh claim: claimed=%v err=%v", claimed, err)
	}
	if freshReq.AttemptID == oldReq.AttemptID {
		t.Fatal("fresh attempt reused the old attempt ID")
	}

	stale := retirementReceiptFor(t, oldReq, size, types.NodeUsage{Epoch: "e2", Sequence: 1, UsedBytes: 800})
	if ok, err := s.ConfirmRetirement(stale, t0.Add(2*time.Second), time.Hour); ok || !errors.Is(err, ErrRetirementConflict) {
		t.Fatalf("stale ack accepted: ok=%v err=%v", ok, err)
	}
	if n, _ := s.GetNode(node); n.UsedBytes != 950 || n.UsageFloorBytes != 950 {
		t.Fatalf("stale ack changed accounting: used=%d floor=%d", n.UsedBytes, n.UsageFloorBytes)
	}

	fresh := retirementReceiptFor(t, freshReq, size, types.NodeUsage{Epoch: "e2", Sequence: 1, UsedBytes: 800})
	if ok, err := s.ConfirmRetirement(fresh, t0.Add(2*time.Second), time.Hour); err != nil || !ok {
		t.Fatalf("fresh ack rejected: ok=%v err=%v", ok, err)
	}
	if n, _ := s.GetNode(node); n.UsedBytes != 800 || n.UsageFloorBytes != 800 {
		t.Fatalf("fresh ack accounting: used=%d floor=%d, want 800/800", n.UsedBytes, n.UsageFloorBytes)
	}
}

func TestRetirementOfflineNodeRejected(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	const size int64 = 150

	u := beginWriteTest(t, s, RootID, "offline", size, false)
	p := reserveAndAbort(t, s, u, size, []uint64{node})

	now := time.Now()
	if err := s.SetNodeHeartbeatAt(node, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour); !errors.Is(err, ErrWriteNotReady) || claimed {
		t.Fatalf("offline claim: claimed=%v err=%v", claimed, err)
	}
	recs := retirementRecords(t, s)
	if len(recs) != 1 || recs[0].State != RetirementPending || recs[0].Attempt != nil {
		t.Fatalf("offline claim mutated journal: %+v", recs)
	}

	if err := s.SetNodeHeartbeatAt(node, now); err != nil {
		t.Fatal(err)
	}
	req, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("online claim: claimed=%v err=%v", claimed, err)
	}
	receipt := retirementReceiptFor(t, req, size, types.NodeUsage{Epoch: "e1", Sequence: 1, UsedBytes: 0})

	if err := s.SetNodeHeartbeatAt(node, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); ok || !errors.Is(err, ErrWriteNotReady) {
		t.Fatalf("offline confirm: ok=%v err=%v", ok, err)
	}
	if recs = retirementRecords(t, s); len(recs) != 1 || recs[0].State != RetirementAttempted {
		t.Fatalf("offline confirm mutated journal: %+v", recs)
	}

	if err := s.SetNodeHeartbeatAt(node, now); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); err != nil || !ok {
		t.Fatalf("online confirm: ok=%v err=%v", ok, err)
	}
}

func TestRetirementPublishedHeldAndAdoption(t *testing.T) {
	s, nodes := writeTestStore(t)
	data := []byte("held")
	const size int64 = 4

	first := beginWriteTest(t, s, RootID, "heldfile", size, false)
	oldPlan := reserveWriteTest(t, s, first, data, nodes[:2], nodes[:2])
	confirmWriteTest(t, s, oldPlan.Object.ID, nodes[:2]...)
	if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(first, size, 1), time.Hour, time.Now()); err != nil {
		t.Fatalf("first commit: %v", err)
	}

	second := beginWriteTest(t, s, RootID, "heldfile", size, true)
	newPlan := reserveWriteTest(t, s, second, data, nodes[:2], nodes[:2])
	confirmWriteTest(t, s, newPlan.Object.ID, nodes[:2]...)
	if _, _, replaced, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(second, size, 1), time.Hour, time.Now()); err != nil || !replaced {
		t.Fatalf("overwrite commit: replaced=%v err=%v", replaced, err)
	}

	recs := retirementRecords(t, s)
	if len(recs) != 2 {
		t.Fatalf("retirements = %+v, want two held records for the dropped published chunk", recs)
	}
	for _, rec := range recs {
		if rec.ObjectID != oldPlan.Object.ID || rec.State != RetirementHeld {
			t.Fatalf("retirement = %+v, want held object %d", rec, oldPlan.Object.ID)
		}
	}

	if _, claimed, err := s.ClaimRetirement(oldPlan.Object.ID, nodes[0], time.Now(), time.Minute, time.Hour); err != nil || claimed {
		t.Fatalf("held content claimable: claimed=%v err=%v", claimed, err)
	}
	// The staging inode deleted by adoption references the same physical IDs as
	// the published inode, so the adopted chunk must not be held.
	if _, claimed, err := s.ClaimRetirement(newPlan.Object.ID, nodes[0], time.Now(), time.Minute, time.Hour); !errors.Is(err, ErrNotExist) || claimed {
		t.Fatalf("adopted chunk was queued for retirement: claimed=%v err=%v", claimed, err)
	}
}

func TestRetirementExpiryIdempotentAndNoBindingReuse(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	now := time.Now()
	const size int64 = 3
	const opID = "expire-op"

	u, err := s.BeginPlannedWrite(WriteActor{}, RootID, "expired", types.BeginWriteRequest{Path: "/expired", Size: size, OpID: opID}, now)
	if err != nil {
		t.Fatalf("BeginPlannedWrite: %v", err)
	}
	p := reserveWriteTest(t, s, u, []byte("abc"), []uint64{node}, []uint64{node})
	expiry := now.Add(25 * time.Hour)

	if count, err := s.ExpirePlannedWrites(expiry); err != nil || count != 1 {
		t.Fatalf("first expiry: count=%d err=%v", count, err)
	}
	if count, err := s.ExpirePlannedWrites(expiry); err != nil || count != 0 {
		t.Fatalf("second expiry was not idempotent: count=%d err=%v", count, err)
	}
	if _, err := s.GetInode(u.ID); !errors.Is(err, ErrNotExist) {
		t.Fatalf("staging inode survived expiry: %v", err)
	}
	recs := retirementRecords(t, s)
	if len(recs) != 1 || recs[0].ObjectID != p.Object.ID || recs[0].State != RetirementPending {
		t.Fatalf("expiry journal = %+v", recs)
	}

	req, choice := writeChoice(u, 0, []byte("abc"), []uint64{node}, []uint64{node})
	if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(u, size, 1), time.Hour, expiry); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("expired binding committed: %v", err)
	}
	if _, _, err := s.ReserveWriteChunk(WriteActor{}, req, choice, 0, time.Hour, expiry); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("expired binding reserved: %v", err)
	}
	if _, err := s.BeginPlannedWrite(WriteActor{}, RootID, "expired", types.BeginWriteRequest{Path: "/expired", Size: size, OpID: opID}, expiry); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("aborted begin op reused: %v", err)
	}

	next, err := s.BeginPlannedWrite(WriteActor{}, RootID, "expired", types.BeginWriteRequest{Path: "/expired", Size: size, OpID: opID + "-next"}, expiry)
	if err != nil {
		t.Fatalf("new begin op: %v", err)
	}
	if next.ID == u.ID || next.PlanID == u.PlanID {
		t.Fatalf("staging identity reused: old=%d/%s new=%d/%s", u.ID, u.PlanID, next.ID, next.PlanID)
	}
	if recs = retirementRecords(t, s); len(recs) != 1 {
		t.Fatalf("second expiry duplicated retirements: %+v", recs)
	}
	if c := capacityFor(t, s, node); c.Reserved != size {
		t.Fatalf("expired pair reservation released before receipt: %+v", c)
	}
}

func TestRetirementWALRestoreKeepsJournalAndTombstone(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	const size int64 = 150

	u := beginWriteTest(t, s, RootID, "wal", size, false)
	p := reserveAndAbort(t, s, u, size, []uint64{node})
	setUsageFloorBaseline(t, s, node, "e1", 5, 950)

	now := time.Now()
	req, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("ClaimRetirement: claimed=%v err=%v", claimed, err)
	}
	receipt := retirementReceiptFor(t, req, size, types.NodeUsage{Epoch: "e2", Sequence: 1, UsedBytes: 800})
	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); err != nil || !ok {
		t.Fatalf("ConfirmRetirement: ok=%v err=%v", ok, err)
	}

	// Keep an unrelated in-flight write reservation beside the retired pair.
	adjacent := beginWriteTest(t, s, RootID, "adjacent", 100, false)
	_ = reserveWriteTest(t, s, adjacent, make([]byte, 100), []uint64{node}, []uint64{node})

	frames, err := s.FramesSince(0)
	if err != nil {
		t.Fatalf("FramesSince: %v", err)
	}
	restored, err := Open(filepath.Join(t.TempDir(), "restored.db"))
	if err != nil {
		t.Fatalf("Open restored: %v", err)
	}
	defer restored.Close()
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatalf("ApplyFrames: %v", err)
	}

	recs := retirementRecords(t, restored)
	if len(recs) != 1 || recs[0].State != RetirementConfirmed || recs[0].Receipt == nil || *recs[0].Receipt != receipt {
		t.Fatalf("restored journal = %+v", recs)
	}
	n, err := restored.GetNode(node)
	if err != nil {
		t.Fatalf("restored node: %v", err)
	}
	if n.UsedBytes != 800 || n.UsageFloorBytes != 800 {
		t.Fatalf("restored node used=%d floor=%d, want 800/800", n.UsedBytes, n.UsageFloorBytes)
	}
	c := capacityFor(t, restored, node)
	if c.Reserved != 100 {
		t.Fatalf("restored reservation lost: %+v", c)
	}
	if c.Accounted != 800 {
		t.Fatalf("restored confirmed pair still accounted: %+v", c)
	}
	if ok, err := restored.ConfirmRetirement(receipt, now, time.Hour); err != nil || !ok {
		t.Fatalf("restored tombstone replay: ok=%v err=%v", ok, err)
	}
	if n, _ := restored.GetNode(node); n.UsageFloorBytes != 800 {
		t.Fatalf("restored replay double-debited floor: %d", n.UsageFloorBytes)
	}
}

func TestRetirementCrossEpochFloorKeepsAdjacentReservation(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	const size int64 = 150

	u := beginWriteTest(t, s, RootID, "cross", size, false)
	p := reserveAndAbort(t, s, u, size, []uint64{node})

	adjacent := beginWriteTest(t, s, RootID, "beside", 100, false)
	_ = reserveWriteTest(t, s, adjacent, make([]byte, 100), []uint64{node}, []uint64{node})
	setUsageFloorBaseline(t, s, node, "e1", 5, 950)
	if c := capacityFor(t, s, node); c.Reserved != size+100 {
		t.Fatalf("pre-confirm reservations: %+v", c)
	}

	now := time.Now()
	req, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("ClaimRetirement: claimed=%v err=%v", claimed, err)
	}
	receipt := retirementReceiptFor(t, req, size, types.NodeUsage{Epoch: "e2", Sequence: 1, UsedBytes: 800})
	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); err != nil || !ok {
		t.Fatalf("ConfirmRetirement: ok=%v err=%v", ok, err)
	}

	n, err := s.GetNode(node)
	if err != nil {
		t.Fatal(err)
	}
	if n.UsedBytes != 800 || n.UsageFloorBytes != 800 {
		t.Fatalf("cross-epoch credit = used %d floor %d, want 800/800", n.UsedBytes, n.UsageFloorBytes)
	}
	c := capacityFor(t, s, node)
	if c.Reserved != 100 {
		t.Fatalf("adjacent reservation lost: %+v", c)
	}
	if c.Accounted != 800 || c.Free != 124 {
		t.Fatalf("capacity after confirmed retirement: %+v, want accounted=800 reserved=100 free=124", c)
	}
}

func TestRetirementUsageChangeKeepsHistoricalFloor(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	const size int64 = 150

	u := beginWriteTest(t, s, RootID, "changed", size, false)
	p := reserveAndAbort(t, s, u, size, []uint64{node})
	setUsageFloorBaseline(t, s, node, "e1", 5, 950)

	now := time.Now()
	req, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("ClaimRetirement: claimed=%v err=%v", claimed, err)
	}
	// A newer heartbeat during the attempt invalidates the captured baseline.
	heartbeatUsage(t, s, node, types.NodeUsage{Epoch: "e1", Sequence: 6, UsedBytes: 900})

	receipt := retirementReceiptFor(t, req, size, types.NodeUsage{Epoch: "e1", Sequence: 7, UsedBytes: 800})
	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); err != nil || !ok {
		t.Fatalf("ConfirmRetirement: ok=%v err=%v", ok, err)
	}
	n, err := s.GetNode(node)
	if err != nil {
		t.Fatal(err)
	}
	if n.UsedBytes != 800 {
		t.Fatalf("usage not applied: %d", n.UsedBytes)
	}
	if n.UsageFloorBytes != 950 {
		t.Fatalf("unaligned baseline credited floor: %d, want conservative 950", n.UsageFloorBytes)
	}
	if c := capacityFor(t, s, node); c.Accounted != 950 {
		t.Fatalf("one low heartbeat cleared history: %+v", c)
	}
}

func TestRetirementOldEpochSampleDoesNotResurrectPair(t *testing.T) {
	s, nodes := writeTestStore(t)
	node := nodes[0]
	const size int64 = 150

	u := beginWriteTest(t, s, RootID, "oldepoch", size, false)
	p := reserveAndAbort(t, s, u, size, []uint64{node})
	setUsageFloorBaseline(t, s, node, "e1", 5, 950)

	now := time.Now()
	req, claimed, err := s.ClaimRetirement(p.Object.ID, node, now, time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("ClaimRetirement: claimed=%v err=%v", claimed, err)
	}
	receipt := retirementReceiptFor(t, req, size, types.NodeUsage{Epoch: "e2", Sequence: 1, UsedBytes: 800})
	if ok, err := s.ConfirmRetirement(receipt, now, time.Hour); err != nil || !ok {
		t.Fatalf("ConfirmRetirement: ok=%v err=%v", ok, err)
	}

	// A late sample from the previous epoch cannot order itself after the
	// confirmed receipt; it must not lower the floor or re-charge the pair.
	heartbeatUsage(t, s, node, types.NodeUsage{Epoch: "e1", Sequence: 1, UsedBytes: 100})
	n, err := s.GetNode(node)
	if err != nil {
		t.Fatal(err)
	}
	if n.UsedBytes != 100 || n.UsageFloorBytes != 800 {
		t.Fatalf("old epoch undercut history: used=%d floor=%d, want 100/800", n.UsedBytes, n.UsageFloorBytes)
	}
	c := capacityFor(t, s, node)
	if c.Reserved != 0 {
		t.Fatalf("old epoch resurrected pair reservation: %+v", c)
	}
	if c.Accounted != 800 {
		t.Fatalf("old epoch undercounted history: %+v", c)
	}
}
