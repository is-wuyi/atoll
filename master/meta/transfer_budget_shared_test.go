package meta

import (
	"errors"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestWriteAndProtectionShareDirectionalRateBudget(t *testing.T) {
	s := newTestStore(t)
	ids := protectionNodes(t, s, 3, 1<<20)
	for _, id := range ids {
		if err := s.SetNodePlacementProfile(NodePlacementProfile{NodeID: id, UploadBPS: 1000, DownloadBPS: 1000, MaxTransferConcurrency: 2}); err != nil {
			t.Fatal(err)
		}
	}
	d := protectionFixture(t, s, "existing", ids[:2], 100)
	for _, id := range ids[:2] {
		if ok, err := s.MarkVerifiedObjectDone(d, id); err != nil || !ok {
			t.Fatalf("source confirmation %v %v", ok, err)
		}
	}
	d, err := s.ObjectIntegrity(d.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.ReserveProtection(ProtectionRequest{ID: "shared-rate", Expected: d, Targets: ids[2:], MaxBytes: d.Size, NodeMaxAge: time.Hour, ProfileRevision: snapshot.ProfileRevision}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, target, err := s.ClaimProtectionTarget(p.ID, time.Now(), time.Minute, ProtectionExecutionBudget{MaxConcurrent: 2, MaxBytes: d.Size})
	if err != nil || target == nil || target.DownloadBPS != 1000 {
		t.Fatalf("protection binding %+v %v", target, err)
	}
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableTransferPlanning(); err != nil {
		t.Fatal(err)
	}
	u := beginWriteTest(t, s, RootID, "new", 4, false)
	req, choice := writeChoice(u, 0, []byte("data"), ids[2:], ids[2:])
	choice.Transfer = &types.WriteTransferPlan{UploadTargets: ids[2:], ExpiresAt: time.Now().Add(time.Minute), Legs: []types.WriteTransferLeg{{ToNodeID: ids[2], Path: "http", BPS: 1}}}
	if _, _, err := s.ReserveWriteChunk(WriteActor{}, req, choice, snapshot.ProfileRevision, time.Hour, time.Now()); !errors.Is(err, ErrWriteBudget) {
		t.Fatalf("write ignored protection download reservation: %v", err)
	}
	desc, err := s.ProtectionDescriptor(p.ID, d.ObjectID, ids[2])
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.MarkVerifiedObjectDone(desc, ids[2]); err != nil || !ok {
		t.Fatalf("complete protection %v %v", ok, err)
	}
	if _, _, err := s.ReserveWriteChunk(WriteActor{}, req, choice, snapshot.ProfileRevision, time.Hour, time.Now()); err != nil {
		t.Fatalf("finished protection held download rate: %v", err)
	}
}
