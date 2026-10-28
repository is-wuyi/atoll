package scheduler

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestWriteRecoveryPreservesAcceptedCountsAndCompletedNodes(t *testing.T) {
	s, o, now := writeWorld()
	s.Nodes[1].Online = false
	before, _ := json.Marshal(s)
	d, err := PlanWriteRecoveryAt(&s, o, 3, 2, []string{"a"}, now)
	if err != nil || d.Plan == nil || len(d.Plan.TargetLayout.Replicas) < 3 || d.RequiredConfirmations < 2 {
		t.Fatalf("accepted recovery floors lost: %+v %v", d, err)
	}
	if d.Plan.TargetLayout.LayoutEpoch != 1 || d.Plan.BaseLayoutEpoch != 0 || d.Plan.BaseContentVersion != 0 {
		t.Fatalf("recovery changed validator-shape contract: %+v", d.Plan)
	}
	var nodes []string
	for _, p := range d.Plan.TargetLayout.Replicas {
		nodes = append(nodes, p.NodeID)
	}
	if !stringMember(nodes, "a") || stringMember(nodes, "b") {
		t.Fatalf("completed/offline nodes: %v", nodes)
	}
	if !ValidateWriteRecoveryDecisionAt(&s, o, d, 3, 2, []string{"a"}, now).Passed {
		t.Fatal("recovery failed independent validation")
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("recovery mutated input")
	}
	second, err := PlanWriteRecoveryAt(&s, o, 3, 2, []string{"a"}, now)
	if err != nil || !reflect.DeepEqual(second, d) {
		t.Fatal("recovery was nondeterministic")
	}
	s.Nodes[0], s.Nodes[3] = s.Nodes[3], s.Nodes[0]
	third, err := PlanWriteRecoveryAt(&s, o, 3, 2, []string{"a"}, now)
	if err != nil || !reflect.DeepEqual(third, d) {
		t.Fatal("input node order changed recovery")
	}
}

func TestWriteRecoveryNeverWeakensDomainOrCapacityConstraints(t *testing.T) {
	for _, mode := range []string{"insufficient", "domain", "capacity", "retained-offline"} {
		t.Run(mode, func(t *testing.T) {
			s, o, now := writeWorld()
			s.Policy.MinFaultTolerance = 1
			s.Nodes[1].Online = false
			if mode == "insufficient" {
				s.Nodes = s.Nodes[:2]
			}
			if mode == "domain" {
				for i := range s.Nodes {
					s.Nodes[i].FailureDomains = map[string]string{"zone": "same"}
				}
			}
			if mode == "capacity" {
				for i := range s.Nodes {
					s.Nodes[i].ReservedBytes = 1024
				}
			}
			if mode == "retained-offline" {
				s.Nodes[0].Online = false
			}
			d, err := PlanWriteRecoveryAt(&s, o, 2, 2, []string{"a"}, now)
			if d.Plan != nil || err == nil && d.Status != StatusNoFeasible {
				t.Fatalf("recovery relaxed hard constraints: %+v %v", d, err)
			}
		})
	}
}

func TestWriteRecoveryValidatorRejectsDroppedCompletedCopy(t *testing.T) {
	s, o, now := writeWorld()
	d, err := PlanWriteRecoveryAt(&s, o, 2, 2, []string{"a"}, now)
	if err != nil || d.Plan == nil {
		t.Fatal(err)
	}
	if ValidateWriteRecoveryDecisionAt(&s, o, d, 2, 2, []string{"missing"}, now).Passed {
		t.Fatal("validator accepted lost completed copy")
	}
	if ValidateWriteRecoveryDecisionAt(&s, o, d, 5, 2, []string{"a"}, now).Passed {
		t.Fatal("validator accepted fewer than accepted replicas")
	}
}
