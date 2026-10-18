package meta

import (
	"bytes"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"atoll/pkg/types"
)

func protectionFixture(t *testing.T, s *Store, name string, replicas []uint64, size int64) types.ObjectIntegrity {
	t.Helper()
	obj, _, err := s.PrepareSmallFile(SmallFileTarget{ParentID: RootID, Name: name, Size: size,
		Checksum: 123, Replicas: replicas, PrimaryID: replicas[0], Mtime: time.Now(), Overwrite: true})
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

func protectionNodes(t *testing.T, s *Store, n int, capacity int64) []uint64 {
	t.Helper()
	var ids []uint64
	for i := 0; i < n; i++ {
		node, err := s.RegisterNode(string(rune('a'+i))+":9421", capacity)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, node.ID)
	}
	return ids
}

func protectionReq(id string, d types.ObjectIntegrity, targets ...uint64) ProtectionRequest {
	return ProtectionRequest{ID: id, Expected: d, Targets: targets, MaxBytes: 1 << 20, NodeMaxAge: time.Hour, Reason: "test"}
}

func TestProtectionReservationPublishesOnlyVerifiedAdditions(t *testing.T) {
	s := newTestStore(t)
	ids := protectionNodes(t, s, 3, 100)
	d := protectionFixture(t, s, "file", ids[:1], 10)
	p, err := s.ReserveProtection(protectionReq("add", d, ids[1], ids[2]), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := s.ObjectIntegrity(d.ObjectID)
	if len(before.Replicas) != 1 {
		t.Fatalf("reservation published unverified targets: %+v", before)
	}
	snapshot, _ := s.AutonomySnapshot()
	for _, c := range snapshot.Capacity {
		if c.NodeID == ids[1] && (c.Reserved != 10 || c.Free != 90) {
			t.Fatalf("reservation missing: %+v", c)
		}
	}
	for i, id := range ids[1:] {
		if _, target, err := s.ClaimProtectionTarget(p.ID, time.Now(), time.Minute); err != nil || target == nil || target.NodeID != id {
			t.Fatalf("claim target: %+v %v", target, err)
		}
		desc, err := s.ProtectionDescriptor(p.ID, d.ObjectID, id)
		if err != nil {
			t.Fatal(err)
		}
		if desc.PlanID != p.ID || !types.ContainsUint64(desc.Replicas, id) {
			t.Fatalf("provisional membership missing: %+v", desc)
		}
		wrong := desc
		wrong.Checksum++
		if ok, err := s.MarkVerifiedObjectDone(wrong, id); ok || err != nil {
			t.Fatalf("bad contents accepted: %v %v", ok, err)
		}
		if ok, err := s.MarkVerifiedObjectDone(desc, id); !ok || err != nil {
			t.Fatalf("valid receipt: %v %v", ok, err)
		}
		if ok, err := s.MarkVerifiedObjectDone(desc, id); !ok || err != nil {
			t.Fatalf("lost-ack replay: %v %v", ok, err)
		}
		current, _ := s.ObjectIntegrity(d.ObjectID)
		if len(current.Replicas) != i+2 || current.Replicas[0] != ids[0] || current.Generation != d.Generation {
			t.Fatalf("not strictly additive: %+v", current)
		}
	}
	final, _ := s.ProtectionPlan(p.ID)
	if final.State != ProtectionCompleted {
		t.Fatalf("plan not complete: %+v", final)
	}
	snapshot, _ = s.AutonomySnapshot()
	for _, c := range snapshot.Capacity {
		if c.Reserved != 0 {
			t.Fatalf("completed reservation leaked: %+v", c)
		}
	}
}

func TestProtectionBudgetConcurrentReservations(t *testing.T) {
	s := newTestStore(t)
	ids := protectionNodes(t, s, 2, 10)
	a := protectionFixture(t, s, "a", ids[:1], 6)
	b := protectionFixture(t, s, "b", ids[:1], 6)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, d := range []types.ObjectIntegrity{a, b} {
		wg.Add(1)
		go func(i int, d types.ObjectIntegrity) {
			defer wg.Done()
			_, err := s.ReserveProtection(protectionReq(string(rune('a'+i)), d, ids[1]), time.Now())
			results <- err
		}(i, d)
	}
	wg.Wait()
	close(results)
	ok, budget := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if errors.Is(err, ErrProtectionBudget) {
			budget++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || budget != 1 {
		t.Fatalf("capacity oversold: accepted=%d budgetErrors=%d", ok, budget)
	}
}

func TestProtectionStaleAndCancelDoNotReleaseUncertainBytes(t *testing.T) {
	s := newTestStore(t)
	ids := protectionNodes(t, s, 2, 100)
	d := protectionFixture(t, s, "file", ids[:1], 10)
	p, err := s.ReserveProtection(protectionReq("old", d, ids[1]), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, target, err := s.ClaimProtectionTarget(p.ID, time.Now(), time.Minute); err != nil || target == nil {
		t.Fatalf("claim: %+v %v", target, err)
	}
	desc, err := s.ProtectionDescriptor(p.ID, d.ObjectID, ids[1])
	if err != nil {
		t.Fatal(err)
	}
	newVersion := protectionFixture(t, s, "file", ids[:1], 11)
	if ok, err := s.MarkVerifiedObjectDone(desc, ids[1]); ok || err != nil {
		t.Fatalf("old receipt accepted: %v %v", ok, err)
	}
	p, target, err := s.ClaimProtectionTarget(p.ID, time.Now(), time.Minute)
	if err != nil || target != nil || p.State != ProtectionStale {
		t.Fatalf("stale plan continued: %+v %+v %v", p, target, err)
	}
	snapshot, _ := s.AutonomySnapshot()
	for _, c := range snapshot.Capacity {
		if c.NodeID == ids[1] && c.Reserved != 10 {
			t.Fatalf("uncertain in-flight bytes released: %+v", c)
		}
	}
	current, _ := s.ObjectIntegrity(newVersion.ObjectID)
	if len(current.Replicas) != 1 {
		t.Fatal("old plan touched new generation")
	}
	p2, err := s.ReserveProtection(protectionReq("unstarted", current, ids[1]), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CancelProtection(p2.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = s.AutonomySnapshot()
	for _, c := range snapshot.Capacity {
		if c.NodeID == ids[1] && c.Reserved != 10 {
			t.Fatalf("unstarted cancelled plan kept extra reservation: %+v", c)
		}
	}
}

func TestProtectionPlanReplayAndRestore(t *testing.T) {
	s := newTestStore(t)
	ids := protectionNodes(t, s, 2, 100)
	d := protectionFixture(t, s, "file", ids[:1], 10)
	req := protectionReq("restart", d, ids[1])
	p, err := s.ReserveProtection(req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveProtection(req, time.Now()); err != nil {
		t.Fatalf("idempotent reserve: %v", err)
	}
	bad := req
	bad.Expected.Checksum++
	if _, err := s.ReserveProtection(bad, time.Now()); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("plan ID reused: %v", err)
	}
	if _, err := s.ReserveProtection(protectionReq("duplicate", d, ids[1]), time.Now()); !errors.Is(err, ErrProtectionConflict) {
		t.Fatalf("multiple active plans: %v", err)
	}
	if err := s.RecordNodeSample(ids[0], NodeSample{At: time.Now(), Online: true, TotalBytes: 100, UsedBytes: 10, RTTMillis: 2}); err != nil {
		t.Fatal(err)
	}
	var snap bytes.Buffer
	if _, err := s.Snapshot(&snap); err != nil {
		t.Fatal(err)
	}
	_, target, err := s.ClaimProtectionTarget(p.ID, time.Now(), time.Minute)
	if err != nil || target == nil {
		t.Fatalf("claim: %+v %v", target, err)
	}
	restored, err := RestoreFromReader(filepath.Join(t.TempDir(), "restore.db"), bytes.NewReader(snap.Bytes()))
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
		t.Fatal(err)
	}
	got, err := restored.ProtectionPlan(p.ID)
	if err != nil || got.Targets[0].Attempts != 1 {
		t.Fatalf("WAL lost claim: %+v %v", got, err)
	}
	view, err := restored.AutonomySnapshot()
	if err != nil || len(view.Observations) != 1 {
		t.Fatalf("snapshot lost observation: %+v %v", view, err)
	}
	desc, err := restored.ProtectionDescriptor(p.ID, d.ObjectID, ids[1])
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := restored.MarkVerifiedObjectDone(desc, ids[1]); !ok || err != nil {
		t.Fatalf("resumed receipt: %v %v", ok, err)
	}
}

func TestProtectionReserveAndReceiptRespectDurability(t *testing.T) {
	s := newTestStore(t)
	ids := protectionNodes(t, s, 2, 100)
	d := protectionFixture(t, s, "file", ids[:1], 10)
	req := protectionReq("durable", d, ids[1])
	s.SetPostCommitHook(func(uint64, []byte) error { return errors.New("backup unavailable") })
	defer s.SetPostCommitHook(nil)
	for i := 0; i < 2; i++ {
		if _, err := s.ReserveProtection(req, time.Now()); err == nil {
			t.Fatal("reservation replay bypassed durability")
		}
	}
	s.SetPostCommitHook(nil)
	p, err := s.ReserveProtection(req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, target, err := s.ClaimProtectionTarget(p.ID, time.Now(), time.Minute); err != nil || target == nil {
		t.Fatalf("claim: %+v %v", target, err)
	}
	desc, err := s.ProtectionDescriptor(p.ID, d.ObjectID, ids[1])
	if err != nil {
		t.Fatal(err)
	}
	s.SetPostCommitHook(func(uint64, []byte) error { return errors.New("backup unavailable") })
	for i := 0; i < 2; i++ {
		if _, err := s.MarkVerifiedObjectDone(desc, ids[1]); err == nil {
			t.Fatal("verified replay bypassed durability")
		}
	}
}
