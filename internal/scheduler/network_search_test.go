package scheduler

import (
	"fmt"
	"testing"
	"time"
)

func TestWriteTransferPrefersDirectWhenMeasuredCostsMatch(t *testing.T) {
	s, obj, now := transferWorld()
	n := s.Network
	n.Links[1].ThroughputBPS = 10000
	n.Links = append(n.Links, LinkObservation{From: "a", To: "b", Path: TransferRelay, Available: true, RTTMs: 1, ThroughputBPS: 10000, Confidence: 1, ObservedAt: now, ValidUntil: now.Add(time.Minute)})
	if path := usableLink(n, "a", "b", "", now).Path; path != TransferDirect {
		t.Fatalf("preferred relay %s", path)
	}
	copy := *n
	indexTransferNetwork(&copy, now)
	for _, path := range []string{"", TransferDirect, TransferRelay} {
		before := usableLink(n, "a", "b", path, now)
		after := usableLink(&copy, "a", "b", path, now)
		if before.Path != after.Path {
			t.Fatalf("index changed path %s", path)
		}
	}
	d, err := PlanWriteAt(&s, obj, now)
	if err != nil || d.Transfer == nil || d.Transfer.Legs[1].Path != TransferDirect {
		t.Fatalf("decision %+v %v", d, err)
	}
}

func TestWriteTransferUsesMeasuredCostBeforeDirectPreference(t *testing.T) {
	for _, test := range []struct {
		name                string
		directBPS, relayBPS uint64
		want                string
	}{
		{name: "faster-relay", directBPS: 100, relayBPS: 200, want: TransferRelay},
		{name: "faster-direct", directBPS: 200, relayBPS: 100, want: TransferDirect},
		{name: "measured-relay-beats-unknown-direct", directBPS: 0, relayBPS: 200, want: TransferRelay},
		{name: "unknown-relay-does-not-beat-measured-direct", directBPS: 200, relayBPS: 0, want: TransferDirect},
		{name: "equal-measurement-prefers-direct", directBPS: 200, relayBPS: 200, want: TransferDirect},
		{name: "both-unknown-prefers-direct", directBPS: 0, relayBPS: 0, want: TransferDirect},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, obj, now := transferWorld()
			s.Network.Links[1].ThroughputBPS = test.directBPS
			s.Network.Links = append(s.Network.Links, LinkObservation{From: "a", To: "b", Path: TransferRelay, Available: true, RTTMs: 1, ThroughputBPS: test.relayBPS, Confidence: 1, ObservedAt: now, ValidUntil: now.Add(time.Minute)})
			d, err := PlanWriteAt(&s, obj, now)
			if err != nil || d.Transfer == nil {
				t.Fatalf("plan: %+v %v", d, err)
			}
			if got := d.Transfer.Legs[1].Path; got != test.want {
				t.Fatalf("path = %s, want %s (direct=%d relay=%d)", got, test.want, test.directBPS, test.relayBPS)
			}
		})
	}
}

func TestWriteTransferDenseNetworkSearchBound(t *testing.T) {
	s, obj, now := writeWorld()
	s.Nodes = nil
	s.Policy.MaxReplicaCount = 8
	s.Policy.Search.MaxCandidates = 64
	n := &TransferNetwork{Origin: "client", MaxUploadTargets: 4, MaxConcurrent: 32, PlanTTLSeconds: 300, MinConfidence: .7}
	n.Endpoints = append(n.Endpoints, EndpointBandwidth{ID: "client", UploadBPS: 1 << 30, DownloadBPS: 1 << 30, MaxConcurrent: 32})
	for i := 0; i < 32; i++ {
		id := fmt.Sprint(i + 1)
		s.Nodes = append(s.Nodes, Node{ID: id, Online: true, HardCapacityBytes: 1 << 30, CostPerGBMonth: 1, FailureDomains: map[string]string{"host": id}})
		n.Endpoints = append(n.Endpoints, EndpointBandwidth{ID: id, UploadBPS: 1 << 20, DownloadBPS: 1 << 24, MaxConcurrent: 32})
	}
	for _, from := range n.Endpoints {
		for _, to := range n.Endpoints {
			if from.ID == to.ID {
				continue
			}
			n.Links = append(n.Links, LinkObservation{From: from.ID, To: to.ID, Path: TransferDirect, Available: true, Confidence: 1, ObservedAt: now, ValidUntil: now.Add(time.Minute)})
		}
	}
	s.Network = n
	started := time.Now()
	d, err := PlanWriteAt(&s, obj, now)
	if err != nil || d.Plan == nil || d.EvaluatedCandidates > 64 {
		t.Fatalf("search %+v %v", d, err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("dense link search exceeded bounded test budget")
	}
}
