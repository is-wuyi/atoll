package scheduler

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func reviewNow() time.Time { return time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC) }

func reviewNode(id, zone string, rtt float64) Node {
	return Node{ID: id, Online: true, HardCapacityBytes: 100000, FailureDomains: map[string]string{"zone": zone}, RTTMs: rtt, CostPerGBMonth: 1}
}

func reviewWorld(nodes []Node, maxReplica, maxCandidates, minFault int) Snapshot {
	return Snapshot{SchemaVersion: SchemaVersion, Nodes: nodes, Policy: Policy{MaxReplicaCount: maxReplica, MinFaultTolerance: minFault, Search: SearchParams{MaxCandidates: maxCandidates}}}
}

func reviewObj() ObjectRequirement {
	return ObjectRequirement{ObjectID: "review-new", SizeBytes: 10, ContentVersion: 1, Intent: ProtectionIntent{Tier: "normal"}}
}

func feasibleCandidates(d WriteDecision) int {
	for _, reason := range d.Reasons {
		if i := strings.Index(reason, "from "); i >= 0 {
			var count int
			if _, err := fmt.Sscanf(reason[i+len("from "):], "%d", &count); err == nil {
				return count
			}
		}
	}
	return -1
}

func TestWriteReviewMaxCandidatesBoundsAllEvaluations(t *testing.T) {
	for _, nodeCount := range []int{12, 20, 32} {
		for _, budget := range []int{1, 2, 7, 128, 256, 4096} {
			t.Run(fmt.Sprintf("nodes%d-budget%d", nodeCount, budget), func(t *testing.T) {
				var nodes []Node
				for i := 0; i < nodeCount; i++ {
					nodes = append(nodes, reviewNode(fmt.Sprintf("n%03d", i), fmt.Sprint(i), float64(i+1)))
				}
				s := reviewWorld(nodes, nodeCount, budget, 0)
				d, err := PlanWriteAt(&s, reviewObj(), reviewNow())
				if err != nil || d.Plan == nil {
					t.Fatalf("planner: %+v %v", d, err)
				}
				feasible := feasibleCandidates(d)
				if feasible < 1 || d.EvaluatedCandidates < feasible || d.EvaluatedCandidates > budget {
					t.Fatalf("budget=%d evaluated=%d feasible=%d", budget, d.EvaluatedCandidates, feasible)
				}
				if report := ValidateWriteDecisionAt(&s, reviewObj(), d, reviewNow()); !report.Passed {
					t.Fatal(report.Violations)
				}
			})
		}
	}
}

func TestWriteReviewTightBudgetTriesCrossDomainLayout(t *testing.T) {
	var nodes []Node
	for i := 0; i < 4; i++ {
		nodes = append(nodes, reviewNode(fmt.Sprintf("n%d", i), "A", float64(i+1)))
	}
	for i := 0; i < 4; i++ {
		nodes = append(nodes, reviewNode(fmt.Sprintf("m%d", i), "B", float64(i+101)))
	}
	for _, budget := range []int{1, 2, 64} {
		s := reviewWorld(nodes, 2, budget, 1)
		d, err := PlanWriteAt(&s, reviewObj(), reviewNow())
		if err != nil || d.Plan == nil || d.RequiredConfirmations != 2 {
			t.Fatalf("budget=%d decision=%+v error=%v", budget, d, err)
		}
		if d.EvaluatedCandidates > budget {
			t.Fatal("evaluation cap exceeded")
		}
		hasA, hasB := false, false
		for _, p := range d.Plan.TargetLayout.Replicas {
			hasA = hasA || strings.HasPrefix(p.NodeID, "n")
			hasB = hasB || strings.HasPrefix(p.NodeID, "m")
		}
		if !hasA || !hasB {
			t.Fatal("cross-domain placement was not selected")
		}
	}
}

func TestWriteReviewExplanatoryActionsDoNotControlValidation(t *testing.T) {
	s := reviewWorld([]Node{reviewNode("a", "1", 1), reviewNode("b", "2", 2)}, 2, 64, 0)
	d, err := PlanWriteAt(&s, reviewObj(), reviewNow())
	if err != nil || d.Plan == nil {
		t.Fatal(err)
	}
	// Master consumes TargetLayout and ConfirmationNodes, never the explanatory action list.
	d.Plan.Actions = []Action{{Kind: "add_replica", NodeID: "ghost", Bytes: 999999999}}
	if report := ValidateWriteDecisionAt(&s, reviewObj(), d, reviewNow()); !report.Passed {
		t.Fatal(report.Violations)
	}
}

func TestWriteReviewConfirmationSubsetCarriesTheFaultFloor(t *testing.T) {
	s := reviewWorld([]Node{reviewNode("a", "1", 1), reviewNode("b", "2", 2)}, 2, 64, 1)
	o := reviewObj()
	d, err := PlanWriteAt(&s, o, reviewNow())
	if err != nil || d.Plan == nil || d.RequiredConfirmations != 2 {
		t.Fatalf("%+v %v", d, err)
	}
	d.ConfirmationNodes = []string{d.Plan.TargetLayout.Replicas[0].NodeID}
	d.RequiredConfirmations = 1
	if report := ValidateWriteDecisionAt(&s, o, d, reviewNow()); report.Passed {
		t.Fatal("confirmation set below hard floor accepted")
	}
}
