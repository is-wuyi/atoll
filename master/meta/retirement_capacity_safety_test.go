package meta

import (
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestRetirementDelayedReceiptKeepsNewAutonomyBytesCharged(t *testing.T) {
	s, nodes := writeTestStore(t)
	target := nodes[0]
	heartbeatUsage(t, s, target, types.NodeUsage{Epoch: "first", Sequence: 1, UsedBytes: 800})
	u := beginWriteTest(t, s, RootID, "aborted-upload", 150, false)
	p := reserveWriteTest(t, s, u, make([]byte, 150), []uint64{target}, []uint64{target})
	newObject := protectionFixture(t, s, "new-autonomous-file", nodes[1:2], 50)
	plan, err := s.ReserveProtection(protectionReq("new-copy", newObject, target), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.ObjectIntegrity(p.Object.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored := types.NodeUsage{Epoch: "first", Sequence: 2, UsedBytes: 950}
	if ok, err := s.MarkVerifiedObjectDoneWithUsage(d, target, &stored); err != nil || !ok {
		t.Fatalf("stored upload receipt: %v %v", ok, err)
	}
	if err := s.AbortPlannedWrite(WriteActor{}, writeBinding(u), time.Now()); err != nil {
		t.Fatal(err)
	}
	heartbeatUsage(t, s, target, types.NodeUsage{Epoch: "second", Sequence: 1, UsedBytes: 950})
	req, claimed, err := s.ClaimRetirement(p.Object.ID, target, time.Now(), time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	// Deletion sampled 800 bytes; its response arrives after another object was stored.
	retired := types.ObjectRetirementReceipt{ObjectRetirement: req, State: types.RetirementRemoved, RemovedBytes: 150,
		Usage: types.NodeUsage{Epoch: "second", Sequence: 2, UsedBytes: 800}}
	if _, claimed, err := s.ClaimProtectionTarget(plan.ID, time.Now(), time.Minute); err != nil || claimed == nil {
		t.Fatalf("claim new copy: %+v %v", claimed, err)
	}
	descriptor, err := s.ProtectionDescriptor(plan.ID, newObject.ObjectID, target)
	if err != nil {
		t.Fatal(err)
	}
	newUsage := types.NodeUsage{Epoch: "second", Sequence: 3, UsedBytes: 850}
	if ok, err := s.MarkVerifiedObjectDoneWithUsage(descriptor, target, &newUsage); err != nil || !ok {
		t.Fatalf("new autonomous copy: %v %v", ok, err)
	}
	if ok, err := s.ConfirmRetirement(retired, time.Now(), time.Hour); err != nil || !ok {
		t.Fatalf("delayed retirement: %v %v", ok, err)
	}
	capacity := capacityFor(t, s, target)
	if capacity.Accounted+capacity.Reserved < 850 || capacity.Free > 174 {
		t.Fatalf("new copy disappeared from accounting: %+v; actual used=850, free=174", capacity)
	}
}
