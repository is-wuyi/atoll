package scheduler

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"
)

func writeWorld() (Snapshot, ObjectRequirement, time.Time) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	s := Snapshot{SchemaVersion: SchemaVersion, Policy: Policy{MaxReplicaCount: 4, Search: SearchParams{MaxCandidates: 128}}}
	for i, id := range []string{"a", "b", "c", "d"} {
		s.Nodes = append(s.Nodes, Node{ID: id, Online: true, HardCapacityBytes: 1024, FailureDomains: map[string]string{"zone": id}, RTTMs: float64(1 + i*20), CostPerGBMonth: 1, Availability: []AvailabilityWindow{{HorizonSeconds: 86400, ProbabilityOnline: .8, Confidence: 1}}})
	}
	o := ObjectRequirement{ObjectID: "new", SizeBytes: 10, ContentVersion: 1, Intent: ProtectionIntent{Tier: "normal"}}
	return s, o, now
}

func TestWriteDecisionWeightsAndNoHiddenFloor(t *testing.T) {
	s, o, now := writeWorld()
	o.Intent.Weights = ScoreWeights{Cost: 1}
	cheap, err := PlanWriteAt(&s, o, now)
	if err != nil || cheap.Plan == nil {
		t.Fatalf("cheap: %+v %v", cheap, err)
	}
	if len(cheap.Plan.TargetLayout.Replicas) != 1 || cheap.RequiredConfirmations != 1 {
		t.Fatalf("cost did not choose single copy: %+v", cheap)
	}
	o.Intent.Weights = ScoreWeights{Durability: 1}
	safe, err := PlanWriteAt(&s, o, now)
	if err != nil || safe.Plan == nil {
		t.Fatalf("durability: %+v %v", safe, err)
	}
	if len(safe.Plan.TargetLayout.Replicas) <= 1 || safe.RequiredConfirmations <= 1 {
		t.Fatalf("durability did not affect layout and confirmation: %+v", safe)
	}
	s.Nodes = s.Nodes[:1]
	o.Intent = ProtectionIntent{Tier: "security"}
	d, err := PlanWriteAt(&s, o, now)
	if err != nil || d.Plan == nil || d.RequiredConfirmations != 1 {
		t.Fatalf("hidden one-failure floor: %+v %v", d, err)
	}
	s.Policy.MinFaultTolerance = 1
	d, err = PlanWriteAt(&s, o, now)
	if err != nil || d.Plan != nil || d.Status != StatusNoFeasible {
		t.Fatalf("explicit floor ignored: %+v %v", d, err)
	}
}

func TestWriteDecisionDeterministicAndPure(t *testing.T) {
	s, o, now := writeWorld()
	s.Policy.Search.MaxCandidates = 4
	before, _ := json.Marshal(s)
	a, err := PlanWriteAt(&s, o, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PlanWriteAt(&s, o, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("nondeterministic")
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("mutated input")
	}
	if a.Plan == nil {
		t.Fatalf("unexpected no plan: %+v", a)
	}
	s.Nodes[0], s.Nodes[3] = s.Nodes[3], s.Nodes[0]
	c, err := PlanWriteAt(&s, o, now)
	if err != nil || !reflect.DeepEqual(b, c) {
		t.Fatalf("node input order affected output: %v", err)
	}
}

func TestWriteDecisionIndependentValidation(t *testing.T) {
	mutations := map[string]func(*WriteDecision){
		"count":         func(d *WriteDecision) { d.RequiredConfirmations++ },
		"empty-confirm": func(d *WriteDecision) { d.ConfirmationNodes = nil; d.RequiredConfirmations = 0 },
		"duplicate-confirm": func(d *WriteDecision) {
			d.ConfirmationNodes = append(d.ConfirmationNodes, d.ConfirmationNodes[0])
			d.RequiredConfirmations++
		},
		"outside-confirm": func(d *WriteDecision) { d.ConfirmationNodes[0] = "missing" },
		"zero-bytes":      func(d *WriteDecision) { d.Plan.TargetLayout.Replicas[0].Bytes = 0 },
		"existing":        func(d *WriteDecision) { d.Plan.TargetLayout.Replicas[0].Origin = OriginExisting },
		"ec":              func(d *WriteDecision) { d.Plan.RequiresECBackend = true },
		"scheme":          func(d *WriteDecision) { d.Plan.TargetLayout.Scheme = SchemeRS },
		"migration":       func(d *WriteDecision) { d.Plan.MigrationBytes = 0 },
		"version":         func(d *WriteDecision) { d.Plan.TargetLayout.ContentVersion++ },
		"epoch":           func(d *WriteDecision) { d.Plan.TargetLayout.LayoutEpoch++ },
		"base":            func(d *WriteDecision) { d.Plan.BaseLayoutEpoch++ },
		"index":           func(d *WriteDecision) { d.Plan.TargetLayout.Replicas[0].FragmentIndex++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s, o, now := writeWorld()
			d, err := PlanWriteAt(&s, o, now)
			if err != nil || d.Plan == nil {
				t.Fatal(err)
			}
			mutate(&d)
			if ValidateWriteDecisionAt(&s, o, d, now).Passed {
				t.Fatal("tampered plan accepted")
			}
		})
	}
}

func TestWriteDecisionHardConstraints(t *testing.T) {
	for _, mode := range []string{"offline", "full", "undeclared", "same-domain", "too-large", "transfer-budget"} {
		t.Run(mode, func(t *testing.T) {
			s, o, now := writeWorld()
			s.Policy.MinFaultTolerance = 1
			for i := range s.Nodes {
				switch mode {
				case "offline":
					s.Nodes[i].Online = false
				case "full":
					s.Nodes[i].ReservedBytes = 1024
				case "undeclared":
					s.Nodes[i].FailureDomains = nil
				case "same-domain":
					s.Nodes[i].FailureDomains = map[string]string{"zone": "one"}
				case "too-large":
					o.SizeBytes = math.MaxUint64
				case "transfer-budget":
					s.Policy.MaxMigrationBytesBudget = 1
				}
			}
			d, err := PlanWriteAt(&s, o, now)
			if err != nil || d.Status != StatusNoFeasible || d.Plan != nil {
				t.Fatalf("constraint relaxed: %+v %v", d, err)
			}
		})
	}
	s, o, now := writeWorld()
	s.Policy.MinFaultTolerance = 1
	d, err := PlanWriteAt(&s, o, now)
	if err != nil || d.Plan == nil || d.RequiredConfirmations < 2 {
		t.Fatalf("valid explicit floor failed: %+v %v", d, err)
	}
	d.ConfirmationNodes = d.ConfirmationNodes[:1]
	d.RequiredConfirmations = 1
	if ValidateWriteDecisionAt(&s, o, d, now).Passed {
		t.Fatal("confirmation state ignored hard floor")
	}
}

func TestWriteDecisionRejectsInvalidInput(t *testing.T) {
	for _, mode := range []string{"nil", "size", "version", "tier", "nan", "inf", "duplicate", "negative-policy", "current", "zero-time"} {
		t.Run(mode, func(t *testing.T) {
			s, o, now := writeWorld()
			ptr := &s
			switch mode {
			case "nil":
				ptr = nil
			case "size":
				o.SizeBytes = 0
			case "version":
				o.ContentVersion = 0
			case "tier":
				o.Intent.Tier = "unknown"
			case "nan":
				o.Intent.Weights.Cost = math.NaN()
			case "inf":
				s.Nodes[0].RTTMs = math.Inf(1)
			case "duplicate":
				s.Nodes = append(s.Nodes, s.Nodes[0])
			case "negative-policy":
				s.Policy.MinFaultTolerance = -1
			case "current":
				o.CurrentLayout = &Layout{}
			case "zero-time":
				now = time.Time{}
			}
			if _, err := PlanWriteAt(ptr, o, now); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
}
