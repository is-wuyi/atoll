package meta

import (
	"errors"
	"testing"
	"time"
)

func TestStaleClaimReplayRechecksDurability(t *testing.T) {
	s := newTestStore(t)
	ids := protectionNodes(t, s, 2, 100)
	d := protectionFixture(t, s, "file", ids[:1], 10)
	p, err := s.ReserveProtection(protectionReq("stale-durability", d, ids[1]), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodePlacementProfile(NodePlacementProfile{NodeID: ids[1], HeadroomBytes: 1}); err != nil {
		t.Fatal(err)
	}
	s.SetPostCommitHook(func(uint64, []byte) error { return errors.New("durability unavailable") })
	defer s.SetPostCommitHook(nil)
	for attempt := 0; attempt < 2; attempt++ {
		_, target, err := s.ClaimProtectionTarget(p.ID, time.Now(), time.Minute)
		if target != nil || err == nil {
			t.Fatalf("stale claim attempt %d bypassed durability confirmation", attempt)
		}
	}
	s.SetPostCommitHook(nil)
	got, target, err := s.ClaimProtectionTarget(p.ID, time.Now(), time.Minute)
	if err != nil || target != nil || got.State != ProtectionStale {
		t.Fatalf("recovered stale claim: %+v %+v %v", got, target, err)
	}
}
