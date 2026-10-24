package scheduler

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"
)

func transferWorld() (Snapshot, ObjectRequirement, time.Time) {
	s, obj, now := writeWorld()
	s.Nodes = s.Nodes[:2]
	s.Policy.MinFaultTolerance = 1
	s.Policy.MaxReplicaCount = 2
	s.Network = &TransferNetwork{Origin: "client", MaxUploadTargets: 2, MaxConcurrent: 4, PlanTTLSeconds: 300, MinConfidence: .7,
		Endpoints: []EndpointBandwidth{{ID: "client", UploadBPS: 1000, DownloadBPS: 10000, MaxConcurrent: 4}, {ID: "a", UploadBPS: 200, DownloadBPS: 1000, MaxConcurrent: 4}, {ID: "b", UploadBPS: 100, DownloadBPS: 2000, MaxConcurrent: 4}}}
	for _, pair := range [][2]string{{"client", "a"}, {"a", "b"}} {
		s.Network.Links = append(s.Network.Links, LinkObservation{From: pair[0], To: pair[1], Path: TransferDirect, Available: true, RTTMs: 20, Confidence: 1, ObservedAt: now, ValidUntil: now.Add(time.Minute)})
	}
	obj.SizeBytes = 100
	return s, obj, now
}

func TestWriteTransferIngressPreservesNamedConfirmations(t *testing.T) {
	s, obj, now := transferWorld()
	before, _ := json.Marshal(s)
	d, err := PlanWriteAt(&s, obj, now)
	if err != nil || d.Transfer == nil || d.RequiredConfirmations != 2 || !reflect.DeepEqual(d.Transfer.UploadTargets, []string{"a"}) {
		t.Fatalf("decision: %+v %v", d, err)
	}
	if !reflect.DeepEqual(d.Transfer.Legs, []TransferLeg{{From: "client", To: "a", Path: TransferDirect, BPS: 250}, {From: "a", To: "b", Path: TransferDirect, BPS: 50}}) {
		t.Fatalf("legs: %+v", d.Transfer.Legs)
	}
	if !ValidateWriteDecisionAt(&s, obj, d, now).Passed {
		t.Fatal("route failed independent validation")
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("network mutated")
	}
	s.Network.Endpoints[0], s.Network.Endpoints[2] = s.Network.Endpoints[2], s.Network.Endpoints[0]
	s.Network.Links[0], s.Network.Links[1] = s.Network.Links[1], s.Network.Links[0]
	s.Nodes[0], s.Nodes[1] = s.Nodes[1], s.Nodes[0]
	replay, err := PlanWriteAt(&s, obj, now)
	if err != nil || !reflect.DeepEqual(d, replay) {
		t.Fatalf("input order affected transfer plan: %+v %v", replay, err)
	}
}

func TestWriteTransferMultipleIngressUsesSharedUploadBudget(t *testing.T) {
	s, obj, now := transferWorld()
	s.Network.Links = append(s.Network.Links, LinkObservation{From: "client", To: "b", Path: TransferDirect, Available: true, RTTMs: 5, Confidence: 1, ObservedAt: now, ValidUntil: now.Add(time.Minute)})
	d, err := PlanWriteAt(&s, obj, now)
	if err != nil || d.Transfer == nil || len(d.Transfer.UploadTargets) != 2 {
		t.Fatalf("multiple ingress: %+v %v", d, err)
	}
	var upload uint64
	for _, leg := range d.Transfer.Legs {
		if leg.From == s.Network.Origin {
			upload += leg.BPS
		}
	}
	if upload != 500 || d.Transfer.EstimatedSeconds != .4 {
		t.Fatalf("double-booked client: %+v", d.Transfer)
	}
}

func TestWriteTransferDoesNotInventTransitiveConnectivity(t *testing.T) {
	for _, mutation := range []string{"missing", "reverse", "stale", "failed", "low-confidence", "occupied", "deadline"} {
		t.Run(mutation, func(t *testing.T) {
			s, obj, now := transferWorld()
			switch mutation {
			case "missing":
				s.Network.Links = s.Network.Links[:1]
			case "reverse":
				s.Network.Links[1].From, s.Network.Links[1].To = "b", "a"
			case "stale":
				s.Network.Links[1].ObservedAt = now.Add(-2 * time.Minute)
				s.Network.Links[1].ValidUntil = now.Add(-time.Minute)
			case "failed":
				s.Network.Links[1].Available = false
			case "low-confidence":
				s.Network.Links[1].Confidence = .2
			case "occupied":
				s.Network.Endpoints[1].InFlightUploadBPS = s.Network.Endpoints[1].UploadBPS
			case "deadline":
				s.Network.PlanTTLSeconds = 1
				obj.SizeBytes = 1000
			}
			d, err := PlanWriteAt(&s, obj, now)
			if err != nil || d.Plan != nil || d.Status != StatusNoFeasible {
				t.Fatalf("invented route or lowered confirmation floor: %+v %v", d, err)
			}
		})
	}
}

func TestWriteTransferRejectsTamperedRoutes(t *testing.T) {
	mutations := map[string]func(*WriteDecision){
		"missing":         func(d *WriteDecision) { d.Transfer = nil },
		"outside-ingress": func(d *WriteDecision) { d.Transfer.UploadTargets = []string{"other"} },
		"duplicate-leg":   func(d *WriteDecision) { d.Transfer.Legs[1] = d.Transfer.Legs[0] },
		"invented-direct": func(d *WriteDecision) { d.Transfer.Legs[1].From = "client" },
		"cycle":           func(d *WriteDecision) { d.Transfer.Legs[0].From = "b" },
		"rate":            func(d *WriteDecision) { d.Transfer.Legs[1].BPS++ },
		"zero-rate":       func(d *WriteDecision) { d.Transfer.Legs[1].BPS = 0 },
		"path":            func(d *WriteDecision) { d.Transfer.Legs[1].Path = TransferRelay },
		"deadline":        func(d *WriteDecision) { d.Transfer.ExpiresAt = d.Transfer.ExpiresAt.Add(time.Hour) },
		"estimate":        func(d *WriteDecision) { d.Transfer.EstimatedSeconds = 0 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s, obj, now := transferWorld()
			d, err := PlanWriteAt(&s, obj, now)
			if err != nil || d.Transfer == nil {
				t.Fatal(err)
			}
			mutate(&d)
			if ValidateWriteDecisionAt(&s, obj, d, now).Passed {
				t.Fatal("tampered transfer accepted")
			}
		})
	}
}

func TestWriteTransferRejectsInvalidNetwork(t *testing.T) {
	for _, mutation := range []string{"duplicate", "nan", "overcommitted", "missing-origin", "invalid-path", "future", "oversized-ttl", "empty-budget"} {
		t.Run(mutation, func(t *testing.T) {
			s, obj, now := transferWorld()
			switch mutation {
			case "duplicate":
				s.Network.Links = append(s.Network.Links, s.Network.Links[0])
			case "nan":
				s.Network.Links[0].Confidence = math.NaN()
			case "overcommitted":
				s.Network.Endpoints[0].InFlightUploadBPS = 1001
			case "missing-origin":
				s.Network.Origin = "missing"
			case "invalid-path":
				s.Network.Links[0].Path = "automatic"
			case "future":
				s.Network.Links[0].ObservedAt = now.Add(time.Minute)
			case "oversized-ttl":
				s.Network.PlanTTLSeconds = 100000
			case "empty-budget":
				s.Network.Endpoints[0].DownloadBPS = 0
			}
			if _, err := PlanWriteAt(&s, obj, now); err == nil {
				t.Fatal("invalid network accepted")
			}
		})
	}
}
