package meta

// Transaction-sequencing audit regressions for the autonomy (protection plan)
// subsystem. This file is owned by the auditor; the implementation files are
// owned by the main agent. Tests here intentionally re-verify contract
// invariants independently of autonomy_test.go.

import (
	"bytes"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"atoll/pkg/types"
)

// auditStore opens an isolated store (same shape as newTestStore, kept local
// to this file to avoid touching shared helpers).
func auditStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func auditNodes(t *testing.T, s *Store, n int, capacity int64) []uint64 {
	t.Helper()
	var ids []uint64
	for i := 0; i < n; i++ {
		node, err := s.RegisterNode(string(rune('A'+i))+":9421", capacity)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, node.ID)
	}
	return ids
}

func auditFile(t *testing.T, s *Store, name string, replicas []uint64, size int64, checksum uint32) types.ObjectIntegrity {
	t.Helper()
	obj, _, err := s.PrepareSmallFile(SmallFileTarget{ParentID: RootID, Name: name, Size: size,
		Checksum: checksum, Replicas: replicas, PrimaryID: replicas[0], Mtime: time.Now(), Overwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := s.CommitSmallFile(obj.ID); err != nil {
		t.Fatal(err)
	}
	d, err := s.ObjectIntegrity(obj.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func auditReq(id string, d types.ObjectIntegrity, targets ...uint64) ProtectionRequest {
	return ProtectionRequest{ID: id, Expected: d, Targets: targets, MaxBytes: 1 << 20, NodeMaxAge: time.Hour, Reason: "audit"}
}

// auditClaimedDesc claims the target and returns a live descriptor.
func auditClaimedDesc(t *testing.T, s *Store, planID string, d types.ObjectIntegrity, nodeID uint64) types.ObjectIntegrity {
	t.Helper()
	_, target, err := s.ClaimProtectionTarget(planID, time.Now(), time.Minute)
	if err != nil || target == nil {
		t.Fatalf("claim: %+v %v", target, err)
	}
	desc, err := s.ProtectionDescriptor(planID, d.ObjectID, nodeID)
	if err != nil {
		t.Fatalf("descriptor after claim: %v", err)
	}
	return desc
}

func auditReserve(t *testing.T, s *Store, req ProtectionRequest) ProtectionPlan {
	t.Helper()
	p, err := s.ReserveProtection(req, time.Now())
	if err != nil {
		t.Fatalf("reserve %s: %v", req.ID, err)
	}
	return p
}

// ---------------------------------------------------------------------------
// A receipt for one plan must not mark a different plan's/object's target.
// ---------------------------------------------------------------------------

func TestAuditReceiptBoundToPlanObject(t *testing.T) {
	s := auditStore(t)
	ids := auditNodes(t, s, 4, 1000)
	fileA := auditFile(t, s, "alpha", ids[:1], 10, 111)
	fileB := auditFile(t, s, "beta", ids[:1], 10, 222)
	planA := auditReserve(t, s, auditReq("plan-a", fileA, ids[1]))
	planB := auditReserve(t, s, auditReq("plan-b", fileB, ids[2]))

	descA := auditClaimedDesc(t, s, planA.ID, fileA, ids[1])
	descB := auditClaimedDesc(t, s, planB.ID, fileB, ids[2])

	// Cross-plan object: receipt carries plan A's PlanID but describes object B.
	cross := descB
	cross.PlanID = planA.ID
	if ok, err := s.MarkVerifiedObjectDone(cross, ids[1]); ok || err != nil {
		t.Fatalf("cross-object receipt accepted: %v %v", ok, err)
	}
	// And the symmetric direction (plan B id, object A body, B's node).
	cross2 := descA
	cross2.PlanID = planB.ID
	if ok, err := s.MarkVerifiedObjectDone(cross2, ids[2]); ok || err != nil {
		t.Fatalf("cross-object receipt accepted (2): %v %v", ok, err)
	}
	// Neither object gained replicas from the forged receipts.
	integA, _ := s.ObjectIntegrity(fileA.ObjectID)
	integB, _ := s.ObjectIntegrity(fileB.ObjectID)
	if len(integA.Replicas) != 1 || len(integB.Replicas) != 1 {
		t.Fatalf("forged receipt mutated replicas: A=%v B=%v", integA.Replicas, integB.Replicas)
	}
	// Neither plan's target became done.
	gotA, _ := s.ProtectionPlan(planA.ID)
	gotB, _ := s.ProtectionPlan(planB.ID)
	if gotA.Targets[0].Done || gotB.Targets[0].Done {
		t.Fatalf("forged receipt advanced plan: A=%v B=%v", gotA.Targets, gotB.Targets)
	}
	// But the genuine receipts still work.
	if ok, err := s.MarkVerifiedObjectDone(descA, ids[1]); !ok || err != nil {
		t.Fatalf("genuine receipt A rejected: %v %v", ok, err)
	}
	if ok, err := s.MarkVerifiedObjectDone(descB, ids[2]); !ok || err != nil {
		t.Fatalf("genuine receipt B rejected: %v %v", ok, err)
	}
	integA, _ = s.ObjectIntegrity(fileA.ObjectID)
	integB, _ = s.ObjectIntegrity(fileB.ObjectID)
	if !types.ContainsUint64(integA.Replicas, ids[1]) || !types.ContainsUint64(integB.Replicas, ids[2]) {
		t.Fatalf("genuine receipt did not publish: A=%v B=%v", integA.Replicas, integB.Replicas)
	}
}

// A receipt from an old integrity epoch must not flip Done back on a target
// whose object has since moved on (suspect/replace or content overwrite).
func TestAuditOldEpochReceiptCannotRestoreDone(t *testing.T) {
	s := auditStore(t)
	ids := auditNodes(t, s, 3, 1000)
	d := auditFile(t, s, "epoch", ids[:1], 10, 333)
	plan := auditReserve(t, s, auditReq("epoch-plan", d, ids[1]))
	desc := auditClaimedDesc(t, s, plan.ID, d, ids[1])
	if ok, err := s.MarkVerifiedObjectDone(desc, ids[1]); !ok || err != nil {
		t.Fatalf("initial receipt: %v %v", ok, err)
	}
	// The new replica is later reported suspect: content verification is
	// withdrawn and the integrity epoch advances.
	if _, err := s.MarkPhysicalObjectSuspect(desc, ids[1]); err != nil {
		t.Fatal(err)
	}
	after, _ := s.ObjectIntegrity(d.ObjectID)
	if !types.ContainsUint64(after.Suspect, ids[1]) {
		t.Fatalf("suspect not recorded: %+v", after)
	}
	// Replaying the old receipt (stale epoch) must not clear suspect or
	// re-mark done.
	if ok, err := s.MarkVerifiedObjectDone(desc, ids[1]); ok || err != nil {
		t.Fatalf("stale-epoch receipt restored done: %v %v", ok, err)
	}
	final, _ := s.ObjectIntegrity(d.ObjectID)
	if !types.ContainsUint64(final.Suspect, ids[1]) || types.ContainsUint64(final.Done, ids[1]) {
		t.Fatalf("stale receipt cleared suspect/done: %+v", final)
	}
}

// Descriptor authorization requires a persisted claim; reserve->desc->cancel
// must not be able to authorize a transfer that the reservation no longer
// covers.
func TestAuditDescriptorRequiresPersistedClaim(t *testing.T) {
	s := auditStore(t)
	ids := auditNodes(t, s, 3, 1000)
	d := auditFile(t, s, "gated", ids[:1], 10, 444)
	plan := auditReserve(t, s, auditReq("gated-plan", d, ids[1]))
	// Before any claim the descriptor must be refused...
	if _, err := s.ProtectionDescriptor(plan.ID, d.ObjectID, ids[1]); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("unclaimed descriptor allowed: %v", err)
	}
	// ...even after the plan is cancelled (no claim ever persisted).
	if err := s.CancelProtection(plan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProtectionDescriptor(plan.ID, d.ObjectID, ids[1]); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("cancelled descriptor allowed: %v", err)
	}
	current, _ := s.ObjectIntegrity(d.ObjectID)
	if types.ContainsUint64(current.Replicas, ids[1]) {
		t.Fatal("cancelled plan published replica")
	}
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snap.Capacity {
		if c.NodeID == ids[1] && c.Reserved != 0 {
			t.Fatalf("unstarted cancelled plan kept reservation: %+v", c)
		}
	}
}

// Profile revision is a publication fence: once profiles move, descriptors,
// claims and receipts from the old revision must stop making progress.
func TestAuditProfileRevisionFencesPlans(t *testing.T) {
	s := auditStore(t)
	ids := auditNodes(t, s, 3, 1000)
	d := auditFile(t, s, "fence", ids[:1], 10, 555)
	plan := auditReserve(t, s, auditReq("fence-plan", d, ids[1]))
	if err := s.SetNodePlacementProfile(NodePlacementProfile{NodeID: ids[1], HeadroomBytes: 50}); err != nil {
		t.Fatal(err)
	}
	// Claim must refuse (and ideally mark stale) under the new revision.
	p, target, err := s.ClaimProtectionTarget(plan.ID, time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("claim after profile change: %v", err)
	}
	if target != nil {
		t.Fatalf("claim dispatched under new profile revision: %+v", target)
	}
	if p.State != ProtectionStale {
		t.Fatalf("plan not fenced by profile revision: %+v", p)
	}
	// Descriptor must refuse for any target of the fenced plan.
	if _, err := s.ProtectionDescriptor(plan.ID, d.ObjectID, ids[1]); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("descriptor after fence: %v", err)
	}
	// A pre-fence receipt (fresh lease but old revision) must not publish.
	// Re-derive a receipt shape that would otherwise be valid and check it
	// cannot mutate metadata after the fence.
	forged := d
	forged.PlanID = plan.ID
	forged.PlanLeaseUntil = time.Now().Add(time.Minute)
	if ok, err := s.MarkVerifiedObjectDone(forged, ids[1]); ok || err != nil {
		t.Fatalf("receipt crossed profile fence: %v %v", ok, err)
	}
	current, _ := s.ObjectIntegrity(d.ObjectID)
	if types.ContainsUint64(current.Replicas, ids[1]) {
		t.Fatalf("fenced receipt published replica: %+v", current)
	}
}

// Cancel keeps the reservation for attempted (uncertain) targets but releases
// unstarted ones; a lease window prevents same-target re-dispatch, and a
// receipt carrying a mismatched lease is rejected.
func TestAuditCancelKeepsAttemptedReservationAndClaimLeases(t *testing.T) {
	s := auditStore(t)
	ids := auditNodes(t, s, 3, 1000)
	d := auditFile(t, s, "lease", ids[:1], 10, 666)
	plan := auditReserve(t, s, auditReq("lease-plan", d, ids[1]))

	// First claim dispatches the target and opens a lease window.
	_, t1, err := s.ClaimProtectionTarget(plan.ID, time.Now(), time.Minute)
	if err != nil || t1 == nil {
		t.Fatalf("first claim: %+v %v", t1, err)
	}
	// An immediate re-claim must not re-dispatch the same target inside the
	// lease window (single-target plan: nothing else to hand out).
	_, again, err := s.ClaimProtectionTarget(plan.ID, time.Now().Add(time.Second), time.Minute)
	if err != nil {
		t.Fatalf("re-claim inside lease: %v", err)
	}
	if again != nil {
		t.Fatalf("target re-dispatched inside lease window: %+v", again)
	}
	// A receipt with a mismatched lease must be rejected.
	desc, err := s.ProtectionDescriptor(plan.ID, d.ObjectID, t1.NodeID)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	wrongLease := desc
	wrongLease.PlanLeaseUntil = desc.PlanLeaseUntil.Add(time.Second)
	if ok, err := s.MarkVerifiedObjectDone(wrongLease, t1.NodeID); ok || err != nil {
		t.Fatalf("mismatched lease receipt accepted: %v %v", ok, err)
	}
	// Cancel after an attempt: bytes may exist on the node, reservation stays.
	if err := s.CancelProtection(plan.ID); err != nil {
		t.Fatal(err)
	}
	snap, _ := s.AutonomySnapshot()
	reservedAttempted := int64(-1)
	for _, c := range snap.Capacity {
		if c.NodeID == ids[1] {
			reservedAttempted = c.Reserved
		}
	}
	if reservedAttempted != 10 {
		t.Fatalf("attempted target lost reservation after cancel: %d", reservedAttempted)
	}

	// A distinct plan that was never claimed must release its reservation on
	// cancel: no attempt means no bytes were ever written.
	d2 := auditFile(t, s, "unstarted", ids[:1], 10, 667)
	plan2 := auditReserve(t, s, auditReq("unstarted-plan", d2, ids[2]))
	if err := s.CancelProtection(plan2.ID); err != nil {
		t.Fatal(err)
	}
	snap, _ = s.AutonomySnapshot()
	reservedUnstarted := int64(-1)
	for _, c := range snap.Capacity {
		if c.NodeID == ids[2] {
			reservedUnstarted = c.Reserved
		}
	}
	if reservedUnstarted != 0 {
		t.Fatalf("unstarted target kept reservation after cancel: %d", reservedUnstarted)
	}
}

// Plan state (including claims) survives snapshot + WAL frame replay, and
// unknown bucket codes in WAL frames are rejected rather than skipped.
func TestAuditWALReplayOfPlanLifecycle(t *testing.T) {
	s := auditStore(t)
	ids := auditNodes(t, s, 3, 1000)
	d := auditFile(t, s, "wal", ids[:1], 10, 777)
	plan := auditReserve(t, s, auditReq("wal-plan", d, ids[1]))

	var snap bytes.Buffer
	if _, err := s.Snapshot(&snap); err != nil {
		t.Fatal(err)
	}
	if _, target, err := s.ClaimProtectionTarget(plan.ID, time.Now(), time.Minute); err != nil || target == nil {
		t.Fatalf("claim before snapshot replay: %v", err)
	}
	desc, err := s.ProtectionDescriptor(plan.ID, d.ObjectID, ids[1])
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.MarkVerifiedObjectDone(desc, ids[1]); !ok || err != nil {
		t.Fatalf("receipt before replay: %v %v", ok, err)
	}
	restored, err := RestoreFromReader(filepath.Join(t.TempDir(), "restore-wal.db"), bytes.NewReader(snap.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	base, _ := restored.WALSeq()
	frames, err := s.FramesSince(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatalf("replay plan lifecycle frames: %v", err)
	}
	got, err := restored.ProtectionPlan(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != ProtectionCompleted || len(got.Targets) != 1 || !got.Targets[0].Done {
		t.Fatalf("plan lifecycle lost in WAL replay: %+v", got)
	}
	cur, err := restored.ObjectIntegrity(d.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if !types.ContainsUint64(cur.Replicas, ids[1]) || !types.ContainsUint64(cur.Done, ids[1]) {
		t.Fatalf("replica publication lost in replay: %+v", cur)
	}
	// Unknown bucket code must abort the whole replay, not be skipped.
	bad := Frame{Seq: mustWALSeq(t, restored) + 1, Muts: []mutation{{Bucket: 0xFE, Key: []byte("k"), Value: []byte("v")}}}
	if err := restored.ApplyFrames([]Frame{bad}); err == nil {
		t.Fatal("unknown bucket code accepted in replay")
	}
}

func mustWALSeq(t *testing.T, s *Store) uint64 {
	t.Helper()
	seq, err := s.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	return seq
}

// Reserve, descriptor and receipt paths must not silently bypass durability
// when the post-commit hook fails.
func TestAuditDurabilityOfPlanTransitions(t *testing.T) {
	s := auditStore(t)
	ids := auditNodes(t, s, 3, 1000)
	d := auditFile(t, s, "dur", ids[:1], 10, 888)
	req := auditReq("dur-plan", d, ids[1])
	s.SetPostCommitHook(func(uint64, []byte) error { return errors.New("backup unavailable") })
	if _, err := s.ReserveProtection(req, time.Now()); err == nil {
		t.Fatal("reserve bypassed durability")
	}
	s.SetPostCommitHook(nil)
	auditReserve(t, s, req)
	_, target, err := s.ClaimProtectionTarget(req.ID, time.Now(), time.Minute)
	if err != nil || target == nil {
		t.Fatalf("claim: %v", err)
	}
	s.SetPostCommitHook(func(uint64, []byte) error { return errors.New("backup unavailable") })
	if _, err := s.ProtectionDescriptor(req.ID, d.ObjectID, target.NodeID); err == nil {
		t.Fatal("descriptor bypassed durability")
	}
	desc := d
	desc.PlanID = req.ID
	desc.PlanLeaseUntil = target.NextAttempt
	if _, err := s.MarkVerifiedObjectDone(desc, target.NodeID); err == nil {
		t.Fatal("receipt bypassed durability")
	}
	if err := s.CancelProtection("no-such-plan"); err == nil {
		t.Fatal("cancel of unknown plan must fail")
	}
	s.SetPostCommitHook(nil)
}

// The global execution budget is a transactional gate: with MaxConcurrent=1,
// two goroutines claiming different plans for the same slot must yield
// exactly one claim; the loser must get a nil target and no attempts bump.
func TestAuditExecutionBudgetGatesConcurrentClaims(t *testing.T) {
	s := auditStore(t)
	ids := auditNodes(t, s, 4, 1000)
	a := auditFile(t, s, "budget-a", ids[:1], 10, 3333)
	b := auditFile(t, s, "budget-b", ids[:1], 10, 4444)
	planA := auditReserve(t, s, auditReq("budget-plan-a", a, ids[1]))
	planB := auditReserve(t, s, auditReq("budget-plan-b", b, ids[2]))

	var mu sync.Mutex
	var claimed []string
	var wg sync.WaitGroup
	for _, plan := range []ProtectionPlan{planA, planB} {
		wg.Add(1)
		go func(plan ProtectionPlan) {
			defer wg.Done()
			_, target, err := s.ClaimProtectionTarget(plan.ID, time.Now(), time.Minute,
				ProtectionExecutionBudget{MaxConcurrent: 1, MaxBytes: 1 << 20})
			if err != nil {
				t.Errorf("claim %s: %v", plan.ID, err)
				return
			}
			if target != nil {
				mu.Lock()
				claimed = append(claimed, plan.ID)
				mu.Unlock()
			}
		}(plan)
	}
	wg.Wait()
	if len(claimed) != 1 {
		t.Fatalf("budget allowed %d concurrent claims, want 1: %v", len(claimed), claimed)
	}
	// The unclaimed plan must be untouched (attempts still 0), not stale.
	for _, plan := range []ProtectionPlan{planA, planB} {
		got, err := s.ProtectionPlan(plan.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != ProtectionPending {
			t.Fatalf("unbudgeted claim mutated plan state: %+v", got)
		}
	}
	// Bytes dimension: a budget smaller than the object size must refuse.
	_, target, err := s.ClaimProtectionTarget(planA.ID, time.Now().Add(2*time.Minute), time.Minute,
		ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: 1})
	if err != nil || target != nil {
		t.Fatalf("bytes budget not enforced: %+v %v", target, err)
	}
	// After the lease on the winner expires, the loser may claim.
	claimedID := claimed[0]
	other := planA.ID
	if other == claimedID {
		other = planB.ID
	}
	_, target, err = s.ClaimProtectionTarget(other, time.Now().Add(2*time.Minute), time.Minute,
		ProtectionExecutionBudget{MaxConcurrent: 1, MaxBytes: 1 << 20})
	if err != nil || target == nil {
		t.Fatalf("claim after lease expiry: %+v %v", target, err)
	}
}

// Concurrent reserves against a tight budget must not oversell, and the
// one-active-plan-per-object rule must hold under concurrency.
func TestAuditConcurrentReserveIsolation(t *testing.T) {
	s := auditStore(t)
	ids := auditNodes(t, s, 2, 10)
	a := auditFile(t, s, "iso-a", ids[:1], 6, 1111)
	b := auditFile(t, s, "iso-b", ids[:1], 6, 2222)
	var wg sync.WaitGroup
	results := make(chan error, 4)
	for i, d := range []types.ObjectIntegrity{a, b, a, b} {
		wg.Add(1)
		go func(i int, d types.ObjectIntegrity) {
			defer wg.Done()
			_, err := s.ReserveProtection(auditReq(string(rune('p'+i)), d, ids[1]), time.Now())
			results <- err
		}(i, d)
	}
	wg.Wait()
	close(results)
	ok, conflict, budget := 0, 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrProtectionConflict):
			conflict++ // one-active-plan-per-object loser
		case errors.Is(err, ErrProtectionBudget):
			budget++ // capacity loser
		default:
			t.Fatalf("unexpected reserve error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("one-active-plan/budget violated: ok=%d conflict=%d budget=%d", ok, conflict, budget)
	}
	// The winner must be fully formed.
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Plans) != 1 {
		t.Fatalf("plan count after race: %d", len(snap.Plans))
	}
	if snap.Plans[0].Targets[0].NodeID != ids[1] {
		t.Fatalf("plan target corrupted under race: %+v", snap.Plans[0].Targets)
	}
}
