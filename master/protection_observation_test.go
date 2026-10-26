package master

import (
	"testing"
	"time"

	"atoll/internal/scheduler"
	"atoll/pkg/types"
)

func TestProtectionMeasuredObservationSurvivesHealthProbe(t *testing.T) {
	srv, store, _, target := progressFixture(t)
	aut, err := NewAutonomy(store, time.Hour, AutonomyConfig{Mode: AutonomyAdd, ProtectionFeedback: true})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetAutonomy(aut)
	now := time.Now()
	obs := types.TransferObservation{FromNodeID: target.SourceID, ToNodeID: target.NodeID, Path: scheduler.TransferHTTP, Available: true, ThroughputBPS: 1024, ObservedAt: now}
	if err := srv.RecordTransferObservation(obs, now); err != nil {
		t.Fatal(err)
	}
	obs.ThroughputBPS = 0
	obs.ObservedAt = now.Add(time.Second)
	if err := srv.RecordTransferObservation(obs, obs.ObservedAt); err != nil {
		t.Fatal(err)
	}
	links := srv.transferObservationsAt(obs.ObservedAt)
	if len(links) != 1 || links[0].ThroughputBPS != 1024 || !links[0].ObservedAt.Equal(now) {
		t.Fatalf("health probe erased or prolonged payload observation: %+v", links)
	}
	obs.Available = false
	obs.ObservedAt = now.Add(2 * time.Second)
	if err := srv.RecordTransferObservation(obs, obs.ObservedAt); err != nil {
		t.Fatal(err)
	}
	obs.Available = true
	obs.ObservedAt = now.Add(3 * time.Second)
	if err := srv.RecordTransferObservation(obs, obs.ObservedAt); err != nil {
		t.Fatal(err)
	}
	links = srv.transferObservationsAt(obs.ObservedAt)
	if len(links) != 1 || links[0].Available {
		t.Fatalf("health probe erased transfer failure: %+v", links)
	}
	if links := srv.transferObservationsAt(now.Add(33 * time.Second)); len(links) != 0 {
		t.Fatalf("expired failure persisted: %+v", links)
	}
}
