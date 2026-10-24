package scheduler

import (
	"fmt"
	"testing"
	"time"
)

func TestWriteTransferPrefersDirectAndIndexesExactPath(t *testing.T) {
	s, obj, now := transferWorld()
	n := s.Network
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
