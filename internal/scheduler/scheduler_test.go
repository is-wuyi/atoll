package scheduler

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

const (
	KB = 1 << 10
	MB = 1 << 20
)

var testNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func forecast(prob, conf, spell float64) []AvailabilityWindow {
	return []AvailabilityWindow{{
		HorizonSeconds:               86400,
		ProbabilityOnline:            prob,
		Confidence:                   conf,
		PredictedOfflineSpellSeconds: spell,
	}}
}

func mkNode(id, zone string, capBytes uint64, online bool) Node {
	return Node{
		ID:                id,
		FailureDomains:    map[string]string{"zone": zone},
		HardCapacityBytes: capBytes,
		Online:            online,
		Availability:      forecast(0.99, 0.9, 0),
		RTTMs:             5,
		CostPerGBMonth:    1,
	}
}

func cluster5() []Node {
	return []Node{
		mkNode("n1", "z1", MB, true),
		mkNode("n2", "z2", MB, true),
		mkNode("n3", "z3", MB, true),
		mkNode("n4", "z4", MB, true),
		mkNode("n5", "z5", MB, true),
	}
}

func testPolicy() Policy {
	return Policy{
		MinFaultTolerance:        1,
		MaxReplicaCount:          3,
		CodecLimits:              CodecLimits{MinK: 2, MaxK: 4, MinM: 1, MaxM: 2, MaxTotalShards: 6},
		PredictionHorizonSeconds: 86400,
		MinPredictedReadability:  0,
		MinConfidence:            0.5,
		MaxDeferOfflineSeconds:   7200,
		MinFaultMarginToDefer:    1,
		ImprovementThreshold:     0.05,
		Search:                   SearchParams{ExactComboLimit: 252, BeamWidth: 8, MaxCandidates: 256},
	}
}

func snap(nodes []Node, policy Policy, objs ...ObjectRequirement) *Snapshot {
	return &Snapshot{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   testNow.Format(time.RFC3339),
		TraceID:       "test",
		Nodes:         nodes,
		Objects:       objs,
		Policy:        policy,
	}
}

func replicas(size uint64, nodeIDs ...string) []FragmentPlacement {
	out := make([]FragmentPlacement, 0, len(nodeIDs))
	for i, id := range nodeIDs {
		out = append(out, FragmentPlacement{NodeID: id, FragmentIndex: i, Bytes: size, Origin: OriginExisting})
	}
	return out
}

func hasViolation(rep *ValidationReport, code string) bool {
	if rep == nil {
		return false
	}
	for _, v := range rep.Violations {
		if v.Code == code {
			return true
		}
	}
	return false
}

func mustRun(t *testing.T, s *Snapshot) []Decision {
	t.Helper()
	d, err := RunAt(s, testNow)
	if err != nil {
		t.Fatalf("RunAt: %v", err)
	}
	return d
}

func indexOf(nodes []Node, id string) int {
	for i := range nodes {
		if nodes[i].ID == id {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// 1. Same failure-domain co-failure must not count as fault tolerance.
// ---------------------------------------------------------------------------

func TestSameFailureDomainCoFailure(t *testing.T) {
	nodes := cluster5()
	pol := testPolicy()
	obj := ObjectRequirement{ObjectID: "obj-a", SizeBytes: 300 * KB, ContentVersion: 1}

	// n1..n3 in z1, n4,n5 in z2.
	nodes[0].FailureDomains["zone"] = "z1"
	nodes[1].FailureDomains["zone"] = "z1"
	nodes[2].FailureDomains["zone"] = "z1"
	nodes[3].FailureDomains["zone"] = "z2"
	nodes[4].FailureDomains["zone"] = "z2"

	// Direct validator: 3 replicas all inside zone z1 -> a single group
	// loss kills everything.
	layout := Layout{ObjectID: "obj-a", ContentVersion: 1, LayoutEpoch: 1,
		Scheme: SchemeReplicate, Replicas: replicas(300*KB, "n1", "n2", "n3")}
	rep := ValidateLayout(snap(nodes, pol), obj, layout, pol)
	if rep.Passed {
		t.Fatalf("same-zone layout must fail validation")
	}
	if !hasViolation(rep, VFaultMargin) {
		t.Fatalf("want %s violation, got %+v", VFaultMargin, rep.Violations)
	}

	// Engine: any feasible placement must span zones, so the selected plan
	// must pass independent validation.
	s := snap(nodes, pol, obj)
	d := mustRun(t, s)[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s, want %s; reasons: %v", d.Status, StatusPlanProposed, d.Reasons)
	}
	pv := ValidatePlan(s, obj, *d.Plan, pol)
	if !pv.Passed {
		t.Fatalf("selected plan failed independent validation: %+v", pv.Violations)
	}
	zones := map[string]bool{}
	for _, p := range d.Plan.TargetLayout.Replicas {
		zones[nodes[indexOf(nodes, p.NodeID)].FailureDomains["zone"]] = true
	}
	if len(zones) < 2 {
		t.Fatalf("plan placement collapsed into one zone: %+v", d.Plan.TargetLayout.Replicas)
	}
}

// ---------------------------------------------------------------------------
// 2. Duplicate shards / fragment indices never inflate k.
// ---------------------------------------------------------------------------

func TestDuplicateShardDoesNotInflateK(t *testing.T) {
	nodes := cluster5()
	pol := testPolicy()
	obj := ObjectRequirement{ObjectID: "obj-d", SizeBytes: 300 * KB, ContentVersion: 1}
	s := snap(nodes, pol, obj)

	// Claims k=3 but only 2 distinct fragment indices exist (index 0 is
	// mirrored). Mirrors count ONCE.
	layout := Layout{ObjectID: "obj-d", ContentVersion: 1, LayoutEpoch: 1, Scheme: SchemeRS,
		EC: &ECParams{K: 3, M: 1},
		Replicas: []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: 100 * KB},
			{NodeID: "n2", FragmentIndex: 0, Bytes: 100 * KB},
			{NodeID: "n3", FragmentIndex: 1, Bytes: 100 * KB},
		}}
	rep := ValidateLayout(s, obj, layout, pol)
	if !hasViolation(rep, VInsufficientShards) {
		t.Fatalf("duplicate shard must not inflate k: got violations %+v", rep.Violations)
	}

	// Same fragment index twice on the SAME node is a generation error.
	layout2 := Layout{ObjectID: "obj-d", ContentVersion: 1, LayoutEpoch: 1, Scheme: SchemeRS,
		EC: &ECParams{K: 3, M: 1},
		Replicas: []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: 100 * KB},
			{NodeID: "n1", FragmentIndex: 0, Bytes: 100 * KB},
			{NodeID: "n2", FragmentIndex: 1, Bytes: 100 * KB},
			{NodeID: "n3", FragmentIndex: 2, Bytes: 100 * KB},
		}}
	rep2 := ValidateLayout(s, obj, layout2, pol)
	if !hasViolation(rep2, VDuplicatePlacement) {
		t.Fatalf("same-node duplicate index must be flagged: %+v", rep2.Violations)
	}

	// A legal mirror (index 0 twice on different nodes, k=2) passes the
	// distinct-shards check; mirrors still count as ONE shard.
	layout3 := Layout{ObjectID: "obj-d", ContentVersion: 1, LayoutEpoch: 1, Scheme: SchemeRS,
		EC: &ECParams{K: 2, M: 1},
		Replicas: []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: 150 * KB},
			{NodeID: "n2", FragmentIndex: 0, Bytes: 150 * KB},
			{NodeID: "n3", FragmentIndex: 1, Bytes: 150 * KB},
			{NodeID: "n4", FragmentIndex: 2, Bytes: 150 * KB},
		}}
	rep3 := ValidateLayout(s, obj, layout3, pol)
	if hasViolation(rep3, VInsufficientShards) {
		t.Fatalf("legal mirror layout flagged: %+v", rep3.Violations)
	}
}

// ---------------------------------------------------------------------------
// 3. Insufficient capacity is a hard rejection (reserved + in-flight).
// ---------------------------------------------------------------------------

func TestInsufficientCapacityRejected(t *testing.T) {
	nodes := cluster5()
	nodes[1].ReservedBytes = MB // n2 completely full
	pol := testPolicy()
	obj := ObjectRequirement{ObjectID: "obj-c", SizeBytes: 300 * KB, ContentVersion: 1, Intent: ProtectionIntent{Tier: "normal"}}
	s := snap(nodes, pol, obj)
	d := mustRun(t, s)[0]

	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s (%v)", d.Status, d.Reasons)
	}
	for _, p := range d.Plan.TargetLayout.Replicas {
		if p.Origin == OriginNew && p.NodeID == "n2" {
			t.Fatalf("plan places new bytes on a full node: %+v", d.Plan.TargetLayout.Replicas)
		}
	}

	// Direct validator: new replica on the full node -> capacity violation.
	layout := Layout{ObjectID: "obj-c", ContentVersion: 2, LayoutEpoch: 2, Scheme: SchemeReplicate,
		Replicas: []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: 300 * KB, Origin: OriginExisting},
			{NodeID: "n2", FragmentIndex: 1, Bytes: 300 * KB, Origin: OriginNew},
		}}
	rep := ValidateLayout(s, obj, layout, pol)
	if !hasViolation(rep, VCapacity) {
		t.Fatalf("want capacity violation, got %+v", rep.Violations)
	}

	// In-flight double-held bytes also consume the budget.
	nodes[2].ReservedBytes = 700 * KB
	nodes[2].InFlightBytes = 200 * KB
	layout.Replicas[1] = FragmentPlacement{NodeID: "n3", FragmentIndex: 1, Bytes: 300 * KB, Origin: OriginNew}
	rep2 := ValidateLayout(snap(nodes, pol), obj, layout, pol)
	if !hasViolation(rep2, VCapacity) {
		t.Fatalf("in-flight bytes must be subtracted: %+v", rep2.Violations)
	}

	// No budget declared -> refuse to place, never assume unlimited.
	noBudget := mkNode("nx", "z9", 0, true)
	layout3 := Layout{ObjectID: "obj-c", ContentVersion: 2, LayoutEpoch: 2, Scheme: SchemeReplicate,
		Replicas: []FragmentPlacement{{NodeID: "nx", FragmentIndex: 0, Bytes: 1, Origin: OriginNew}}}
	rep3 := ValidateLayout(snap([]Node{noBudget}, pol), obj, layout3, pol)
	if !hasViolation(rep3, VNoBudget) {
		t.Fatalf("want no-budget violation, got %+v", rep3.Violations)
	}
}

// ---------------------------------------------------------------------------
// 4. Policy weight changes flip the selection on the identical scenario.
// ---------------------------------------------------------------------------

func TestPolicyWeightsChangeSelection(t *testing.T) {
	nodes := cluster5()
	// n1,n2 cheap; n3..n5 expensive.
	for i := range nodes {
		if i >= 2 {
			nodes[i].CostPerGBMonth = 10
		}
	}
	obj := ObjectRequirement{ObjectID: "obj-w", SizeBytes: 100 * KB, ContentVersion: 1}

	costPol := testPolicy()
	costPol.CodecLimits.MaxK = -1 // replication-only contrast
	costObj := obj
	costObj.Intent = ProtectionIntent{Weights: ScoreWeights{Cost: 1}}

	durPol := testPolicy()
	durPol.CodecLimits.MaxK = -1 // replication-only contrast
	durObj := obj
	durObj.Intent = ProtectionIntent{Weights: ScoreWeights{Durability: 1}}

	dc := mustRun(t, snap(nodes, costPol, costObj))[0]
	dd := mustRun(t, snap(nodes, durPol, durObj))[0]

	if dc.Status != StatusPlanProposed || dd.Status != StatusPlanProposed {
		t.Fatalf("statuses: %s / %s", dc.Status, dd.Status)
	}
	if dc.Plan.TargetLayout.Scheme != SchemeReplicate || len(dc.Plan.TargetLayout.Replicas) != 2 {
		t.Fatalf("cost-weighted pick should be replication r=2, got %+v", dc.Plan.TargetLayout)
	}
	got := map[string]bool{}
	for _, p := range dc.Plan.TargetLayout.Replicas {
		got[p.NodeID] = true
	}
	if !got["n1"] || !got["n2"] {
		t.Fatalf("cost-weighted pick should use the two cheap nodes, got %v", got)
	}
	if len(dd.Plan.TargetLayout.Replicas) != 3 {
		t.Fatalf("durability-weighted pick should be r=3, got %+v", dd.Plan.TargetLayout)
	}
	domains := map[string]int{}
	for _, p := range dd.Plan.TargetLayout.Replicas {
		domains[nodes[indexOf(nodes, p.NodeID)].FailureDomains["zone"]]++
	}
	if len(domains) != 3 {
		t.Fatalf("durability pick must span 3 domains, got %v", domains)
	}
}

// ---------------------------------------------------------------------------
// 5. Predicted routine offline -> defer; long offline / margin breach -> rebuild.
// ---------------------------------------------------------------------------

func TestRoutineOfflineDefersRepair(t *testing.T) {
	nodes := cluster5()
	obj := ObjectRequirement{ObjectID: "obj-r", SizeBytes: 100 * KB, ContentVersion: 1, Intent: ProtectionIntent{Tier: "normal"}}
	obj.CurrentLayout = &Layout{ObjectID: "obj-r", ContentVersion: 1, LayoutEpoch: 3,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2", "n3", "n4")}
	// n3: nightly routine outage (~30 min), currently offline. The three
	// online survivors span three zones, so the ONLINE subset still carries
	// a fault margin of 1 after any single domain loss.
	nodes[2].Online = false
	nodes[2].Availability = forecast(0.97, 0.9, 1800)

	d := mustRun(t, snap(nodes, testPolicy(), obj))[0]
	if d.Status != StatusDeferred {
		t.Fatalf("status = %s, want deferred; reasons %v", d.Status, d.Reasons)
	}
	if d.Plan == nil || !d.Plan.Shadow {
		t.Fatalf("defer plan must exist and be shadow-only")
	}
	if len(d.Plan.Actions) != 1 || d.Plan.Actions[0].Kind != "defer" {
		t.Fatalf("defer plan must contain exactly one defer action: %+v", d.Plan.Actions)
	}
	if d.Plan.MigrationBytes != 0 {
		t.Fatalf("defer must not migrate: %d", d.Plan.MigrationBytes)
	}
	pv := ValidatePlan(snap(nodes, testPolicy()), obj, *d.Plan, testPolicy())
	if !pv.Passed {
		t.Fatalf("defer plan failed validation: %+v", pv.Violations)
	}

	// Same scenario, stricter margin requirement (>=2 spare shards after
	// any domain loss within the online set): defer is refused -> rebuild.
	pol := testPolicy()
	pol.MinFaultMarginToDefer = 2
	d2 := mustRun(t, snap(nodes, pol, obj))[0]
	if d2.Status != StatusPlanProposed {
		t.Fatalf("status = %s, want plan_proposed; reasons %v", d2.Status, d2.Reasons)
	}
	if d2.Plan.MigrationBytes == 0 {
		t.Fatalf("repair plan should move bytes")
	}
	for _, p := range d2.Plan.TargetLayout.Replicas {
		if p.Origin == OriginNew && !nodes[indexOf(nodes, p.NodeID)].Online {
			t.Fatalf("repair places new writes on an offline node: %+v", p)
		}
	}
}

func TestLongOfflineTriggersRebuild(t *testing.T) {
	nodes := cluster5()
	obj := ObjectRequirement{ObjectID: "obj-l", SizeBytes: 100 * KB, ContentVersion: 1,
		Intent: ProtectionIntent{Weights: ScoreWeights{Durability: 0.6, Readability: 0.2, Cost: 0.05, Performance: 0.05, Stability: 0.1}}}
	obj.CurrentLayout = &Layout{ObjectID: "obj-l", ContentVersion: 1, LayoutEpoch: 3,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2", "n3")}
	// n3: predicted long outage, currently offline.
	nodes[2].Online = false
	nodes[2].Availability = forecast(0.1, 0.9, 3*86400)

	pol := testPolicy()
	pol.CodecLimits.MaxK = -1 // replication-only for a crisp assertion
	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s, want plan_proposed; reasons %v", d.Status, d.Reasons)
	}
	found := false
	for _, a := range d.Plan.Actions {
		if a.Kind == "move_replica" || a.Kind == "add_replica" {
			found = true
		}
		if a.Kind == "defer" {
			t.Fatalf("long outage must not be deferred: %+v", d.Plan.Actions)
		}
	}
	if !found {
		t.Fatalf("want rebuild action, got %+v", d.Plan.Actions)
	}
	for _, p := range d.Plan.TargetLayout.Replicas {
		if p.Origin == OriginNew && p.NodeID == "n3" {
			t.Fatalf("new writes targeted the long-offline node")
		}
	}
	pv := ValidatePlan(snap(nodes, pol), obj, *d.Plan, pol)
	if !pv.Passed {
		t.Fatalf("rebuild plan failed validation: %+v", pv.Violations)
	}
}

// RS traversal must respect the configurable codec limits and mark every
// EC candidate as simulated (requires_ec_backend) — never executable here.
func TestRSCodecTraversalRespectsLimits(t *testing.T) {
	nodes := cluster5()
	pol := testPolicy()
	pol.CodecLimits = CodecLimits{MinK: 2, MaxK: 3, MinM: 1, MaxM: 1, MaxTotalShards: 4}
	obj := ObjectRequirement{ObjectID: "obj-ec", SizeBytes: 300 * KB, ContentVersion: 1,
		Intent: ProtectionIntent{Weights: ScoreWeights{Durability: 1}}}
	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusPlanProposed && d.Status != StatusNoChange {
		t.Fatalf("status = %s (%v)", d.Status, d.Reasons)
	}
	rsSeen := false
	for _, c := range d.Candidates {
		if c.Scheme != SchemeRS {
			continue
		}
		rsSeen = true
		if !c.RequiresECBackend {
			t.Fatalf("RS candidate %s must be flagged requires_ec_backend", c.CandidateID)
		}
		if c.EC == nil || c.EC.K < 2 || c.EC.K > 3 || c.EC.M != 1 || c.EC.K+c.EC.M > 4 {
			t.Fatalf("RS candidate %s violates codec limits: %+v", c.CandidateID, c.EC)
		}
		if c.R != 0 {
			t.Fatalf("RS candidate %s must not set r", c.CandidateID)
		}
	}
	if !rsSeen {
		t.Fatalf("expected RS candidates in the traversal")
	}
	if d.Plan != nil {
		pv := ValidatePlan(snap(nodes, pol), obj, *d.Plan, pol)
		if !pv.Passed {
			t.Fatalf("selected plan failed validation: %+v", pv.Violations)
		}
		if d.Plan.TargetLayout.Scheme == SchemeRS && !d.Plan.RequiresECBackend {
			t.Fatalf("RS plan must carry requires_ec_backend")
		}
	}
}

// ---------------------------------------------------------------------------
// 5b. Mirror copies of a shard never substitute for a missing distinct shard.
// ---------------------------------------------------------------------------

func TestMirrorCopiesDoNotSubstituteForMissingShard(t *testing.T) {
	nodes := cluster5()
	obj := ObjectRequirement{ObjectID: "obj-m", SizeBytes: 100 * KB, ContentVersion: 1,
		Intent: ProtectionIntent{Tier: "security"}}
	obj.CurrentLayout = &Layout{ObjectID: "obj-m", ContentVersion: 1, LayoutEpoch: 2, Scheme: SchemeRS,
		EC: &ECParams{K: 2, M: 1},
		Replicas: []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: 50 * KB}, // data shard 0
			{NodeID: "n2", FragmentIndex: 0, Bytes: 50 * KB}, // mirror of shard 0
			{NodeID: "n3", FragmentIndex: 1, Bytes: 50 * KB}, // data shard 1 (node offline)
		}}
	nodes[2].Online = false
	nodes[2].Availability = forecast(0.1, 0.9, 3*86400)

	s := snap(nodes, testPolicy(), obj)
	d := mustRun(t, s)[0]

	// Current layout: 3 placements but only 1 online distinct shard (< k=2).
	// It must NOT be considered readable, and never deferred.
	if d.Status == StatusDeferred {
		t.Fatalf("mirrors must not substitute for the missing shard; got defer")
	}
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s, want plan_proposed; reasons %v", d.Status, d.Reasons)
	}
	// Kept mirrors are not re-migrated; migration covers only new fragments
	// (mirrors are never recounted as new shards).
	if d.Plan.MigrationBytes == 0 || d.Plan.MigrationBytes > 3*50*KB {
		t.Fatalf("unexpected migration bytes %d", d.Plan.MigrationBytes)
	}
	pv := ValidatePlan(s, obj, *d.Plan, testPolicy())
	if !pv.Passed {
		t.Fatalf("plan failed validation: %+v", pv.Violations)
	}
	if countDistinctShards(d.Plan.TargetLayout.Replicas) < 2 {
		t.Fatalf("target has < k distinct shards: %+v", d.Plan.TargetLayout.Replicas)
	}
}

// ---------------------------------------------------------------------------
// 6. Stale plans are rejected.
// ---------------------------------------------------------------------------

func TestStalePlanRejected(t *testing.T) {
	nodes := cluster5()
	pol := testPolicy()
	obj := ObjectRequirement{ObjectID: "obj-s", SizeBytes: 100 * KB, ContentVersion: 7,
		CurrentLayout: &Layout{ObjectID: "obj-s", ContentVersion: 7, LayoutEpoch: 4,
			Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2")}}

	good := Plan{
		ObjectID: "obj-s", BaseContentVersion: 7, BaseLayoutEpoch: 4,
		TargetLayout: Layout{ObjectID: "obj-s", ContentVersion: 7, LayoutEpoch: 5,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: 100 * KB, Origin: OriginExisting},
				{NodeID: "n3", FragmentIndex: 1, Bytes: 100 * KB, Origin: OriginNew},
			}},
		Actions:        []Action{{Kind: "move_replica", NodeID: "n3", FromNodeID: "n2", FragmentIndex: 1, Bytes: 100 * KB, Reason: "test"}},
		MigrationBytes: 100 * KB,
		Shadow:         true,
	}
	if rep := ValidatePlan(snap(nodes, pol), obj, good, pol); !rep.Passed {
		t.Fatalf("baseline plan must pass: %+v", rep.Violations)
	}

	stale := good
	stale.BaseLayoutEpoch = 5 // not the current epoch 4
	if rep := ValidatePlan(snap(nodes, pol), obj, stale, pol); !hasViolation(rep, VStalePlan) {
		t.Fatalf("stale epoch must be rejected: %+v", rep.Violations)
	}

	staleCV := good
	staleCV.BaseContentVersion = 6
	if rep := ValidatePlan(snap(nodes, pol), obj, staleCV, pol); !hasViolation(rep, VStalePlan) {
		t.Fatalf("stale content version must be rejected: %+v", rep.Violations)
	}

	badEpoch := good
	badEpoch.TargetLayout.LayoutEpoch = 4 // must be current+1
	if rep := ValidatePlan(snap(nodes, pol), obj, badEpoch, pol); !hasViolation(rep, VEpochInvalid) {
		t.Fatalf("non-incremented epoch must be rejected: %+v", rep.Violations)
	}

	badMig := good
	badMig.MigrationBytes = 1
	if rep := ValidatePlan(snap(nodes, pol), obj, badMig, pol); !hasViolation(rep, VMigrationMismatch) {
		t.Fatalf("migration mismatch must be rejected: %+v", rep.Violations)
	}

	polBudget := testPolicy()
	polBudget.MaxMigrationBytesBudget = 1000
	if rep := ValidatePlan(snap(nodes, polBudget), obj, good, polBudget); !hasViolation(rep, VBudgetExceeded) {
		t.Fatalf("budget overflow must be rejected: %+v", rep.Violations)
	}

	notShadow := good
	notShadow.Shadow = false
	if rep := ValidatePlan(snap(nodes, pol), obj, notShadow, pol); rep.Passed {
		t.Fatalf("non-shadow plan must be rejected")
	}
}

// ---------------------------------------------------------------------------
// 7. The scheduler never mutates its input snapshot.
// ---------------------------------------------------------------------------

func TestNoMutation(t *testing.T) {
	nodes := cluster5()
	nodes[2].Online = false
	nodes[2].Availability = forecast(0.97, 0.9, 1800)
	objs := []ObjectRequirement{
		{ObjectID: "o1", SizeBytes: 100 * KB, ContentVersion: 1,
			CurrentLayout: &Layout{ObjectID: "o1", ContentVersion: 1, LayoutEpoch: 1,
				Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2", "n3")}},
		{ObjectID: "o2", SizeBytes: 250 * KB, ContentVersion: 1},
	}
	s := snap(nodes, testPolicy(), objs...)

	before, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RunAt(s, testNow); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("snapshot mutated by scheduler run")
	}
}

// ---------------------------------------------------------------------------
// 8. Determinism: fixed time + same input -> byte-identical output; the
//    seed field never changes anything.
// ---------------------------------------------------------------------------

func runJSON(t *testing.T, s *Snapshot) string {
	t.Helper()
	d, err := RunAt(s, testNow)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDeterminismAndSeeds(t *testing.T) {
	build := func() *Snapshot {
		nodes := cluster5()
		nodes[4].RTTMs = 42
		objs := []ObjectRequirement{
			{ObjectID: "o1", SizeBytes: 100 * KB, ContentVersion: 1,
				CurrentLayout: &Layout{ObjectID: "o1", ContentVersion: 1, LayoutEpoch: 1,
					Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2")}},
			{ObjectID: "o2", SizeBytes: 300 * KB, ContentVersion: 1},
		}
		return snap(nodes, testPolicy(), objs...)
	}

	first := runJSON(t, build())
	for i := 0; i < 5; i++ {
		if got := runJSON(t, build()); got != first {
			t.Fatalf("non-deterministic output on repeat run %d", i)
		}
	}
	for _, seed := range []int64{0, 1, 42, -7, 1 << 40} {
		s := build()
		s.Policy.Seed = seed
		if got := runJSON(t, s); got != first {
			t.Fatalf("seed %d changed the output (scheduler must be deterministic)", seed)
		}
	}
}

// ---------------------------------------------------------------------------
// 9. Invalid numbers: NaN/Inf, overflow, zero size, unknown nodes, weights.
// ---------------------------------------------------------------------------

func TestInvalidInputsRejected(t *testing.T) {
	pol := testPolicy()

	// NaN RTT
	n := mkNode("n1", "z1", MB, true)
	n.RTTMs = math.NaN()
	if rep := ValidateSnapshot(snap([]Node{n}, pol)); !hasViolation(rep, VNumberInvalid) {
		t.Fatalf("NaN RTT must be rejected")
	}
	// Inf cost
	n2 := mkNode("n2", "z2", MB, true)
	n2.CostPerGBMonth = math.Inf(1)
	if rep := ValidateSnapshot(snap([]Node{n, n2}, pol)); !hasViolation(rep, VNumberInvalid) {
		t.Fatalf("Inf cost must be rejected")
	}
	// Probability outside [0,1]
	n3 := mkNode("n3", "z3", MB, true)
	n3.Availability = forecast(1.5, 0.9, 0)
	if rep := ValidateSnapshot(snap([]Node{n3}, pol)); !hasViolation(rep, VNumberInvalid) {
		t.Fatalf("probability > 1 must be rejected")
	}
	// Weight NaN
	obj := ObjectRequirement{ObjectID: "o", SizeBytes: KB, ContentVersion: 1,
		Intent: ProtectionIntent{Weights: ScoreWeights{Cost: math.NaN()}}}
	if rep := ValidateSnapshot(snap(cluster5(), pol, obj)); !hasViolation(rep, VWeightsInvalid) {
		t.Fatalf("NaN weight must be rejected")
	}
	// Zero-size object
	zero := ObjectRequirement{ObjectID: "z", SizeBytes: 0, ContentVersion: 1}
	ds, err := RunAt(snap(cluster5(), pol, zero), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if ds[0].Status != StatusInvalid {
		t.Fatalf("zero-size object must be invalid, got %s", ds[0].Status)
	}
	// Unknown node in current layout -> invalid requirement, not a crash.
	ghost := ObjectRequirement{ObjectID: "g", SizeBytes: KB, ContentVersion: 1,
		CurrentLayout: &Layout{ObjectID: "g", ContentVersion: 1, LayoutEpoch: 1,
			Scheme: SchemeReplicate, Replicas: replicas(KB, "n1", "ghost-node")}}
	dsg, err := RunAt(snap(cluster5(), pol, ghost), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if dsg[0].Status != StatusInvalid {
		t.Fatalf("unknown node must invalidate the requirement, got %s", dsg[0].Status)
	}
	if !hasViolation(dsg[0].Validation, VUnknownNode) {
		t.Fatalf("want unknown_node violation: %+v", dsg[0].Validation)
	}
	// Schema version mismatch -> RunAt error.
	bad := snap(cluster5(), pol)
	bad.SchemaVersion = 99
	if _, err := RunAt(bad, testNow); err == nil {
		t.Fatalf("schema mismatch must error")
	}
	// Duplicate node ID
	dup := snap(cluster5(), pol)
	dup.Nodes = append(dup.Nodes, mkNode("n1", "zX", MB, true))
	if rep := ValidateSnapshot(dup); !hasViolation(rep, VDuplicatePlacement) {
		t.Fatalf("duplicate node id must be rejected")
	}
}

func TestOverflowAccounting(t *testing.T) {
	pol := testPolicy()
	// Reserved exceeds capacity -> underflow must be caught, not wrapped.
	n := mkNode("n1", "z1", math.MaxUint64, true)
	n.ReservedBytes = math.MaxUint64
	obj := ObjectRequirement{ObjectID: "o", SizeBytes: 1, ContentVersion: 1}
	layout := Layout{ObjectID: "o", ContentVersion: 2, LayoutEpoch: 2, Scheme: SchemeReplicate,
		Replicas: []FragmentPlacement{{NodeID: "n1", FragmentIndex: 0, Bytes: 1, Origin: OriginNew}}}
	rep := ValidateLayout(snap([]Node{n}, pol), obj, layout, pol)
	if !hasViolation(rep, VCapacity) {
		t.Fatalf("capacity underflow must be a violation: %+v", rep.Violations)
	}

	// In-flight overflow: capacity=Max, reserved=1, in-flight=Max.
	// (Layout references n2 for this case.)
	n2 := mkNode("n2", "z2", math.MaxUint64, true)
	n2.ReservedBytes = 1
	n2.InFlightBytes = math.MaxUint64
	layoutN2 := Layout{ObjectID: "o", ContentVersion: 2, LayoutEpoch: 2, Scheme: SchemeReplicate,
		Replicas: []FragmentPlacement{{NodeID: "n2", FragmentIndex: 0, Bytes: 1, Origin: OriginNew}}}
	rep2 := ValidateLayout(snap([]Node{n2}, pol), obj, layoutN2, pol)
	if !hasViolation(rep2, VCapacity) {
		t.Fatalf("in-flight underflow must be a violation: %+v", rep2.Violations)
	}

	// Huge object on normal nodes: no panic, clean no_feasible.
	huge := ObjectRequirement{ObjectID: "h", SizeBytes: math.MaxUint64, ContentVersion: 1}
	d, err := RunAt(snap(cluster5(), pol, huge), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if d[0].Status != StatusNoFeasible {
		t.Fatalf("huge object should be no_feasible, got %s (%v)", d[0].Status, d[0].Reasons)
	}
}

// ---------------------------------------------------------------------------
// 10. Migration budget: repairs that exceed it -> no_feasible (constraints
//     never quietly relaxed).
// ---------------------------------------------------------------------------

func TestMigrationBudgetBlocksRepair(t *testing.T) {
	nodes := cluster5()
	obj := ObjectRequirement{ObjectID: "obj-b", SizeBytes: 100 * KB, ContentVersion: 1}
	obj.CurrentLayout = &Layout{ObjectID: "obj-b", ContentVersion: 1, LayoutEpoch: 1,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2")}
	nodes[1].Online = false
	nodes[1].Availability = forecast(0.1, 0.9, 3*86400) // long outage

	pol := testPolicy()
	pol.MaxMigrationBytesBudget = 1000 // cannot move anything
	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusNoFeasible {
		t.Fatalf("status = %s, want no_feasible; reasons %v", d.Status, d.Reasons)
	}
	joined := strings.Join(d.Reasons, "\n")
	if !strings.Contains(joined, VBudgetExceeded) {
		t.Fatalf("reasons must mention budget violation: %s", joined)
	}
}

// ---------------------------------------------------------------------------
// 11. Healthy cluster + anti-jitter: no pointless churn.
// ---------------------------------------------------------------------------

func TestHealthyClusterNoChange(t *testing.T) {
	nodes := cluster5()
	obj := ObjectRequirement{ObjectID: "obj-h", SizeBytes: 100 * KB, ContentVersion: 1, Intent: ProtectionIntent{Tier: "normal"}}
	obj.CurrentLayout = &Layout{ObjectID: "obj-h", ContentVersion: 1, LayoutEpoch: 2,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2", "n3")}
	d := mustRun(t, snap(nodes, testPolicy(), obj))[0]
	if d.Status != StatusNoChange {
		t.Fatalf("status = %s, want no_change_needed; reasons %v", d.Status, d.Reasons)
	}
	if d.Plan != nil {
		t.Fatalf("no-change decision must not carry a plan")
	}
}

// ---------------------------------------------------------------------------
// 12. NodeHistory pure functions (conservative minimal implementation).
// ---------------------------------------------------------------------------

func TestHistoryPredictionConservative(t *testing.T) {
	// No samples + offline -> very long spell, zero probability.
	p := PredictFromHistory(nil, testNow, 86400, false)
	if !p.Conservative || p.ProbabilityOnline != 0 || p.OfflineSpellSeconds < 86400 {
		t.Fatalf("offline no-history must be conservative-long: %+v", p)
	}
	// No samples + online -> unproven (p=0.5, confidence 0).
	pu := PredictFromHistory(nil, testNow, 86400, true)
	if !pu.Conservative || pu.ProbabilityOnline != 0.5 || pu.Confidence != 0 {
		t.Fatalf("online no-history must be unproven: %+v", pu)
	}

	// Enough samples with a nightly outage at 03:00 UTC.
	hist := sampleHistory(testNow.Add(time.Hour), 5*24, func(hour int) bool { return hour != 3 })
	nowNoon := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	p3 := PredictFromHistory(hist, nowNoon, 86400, true)
	if p3.Conservative {
		t.Fatalf("120 samples should be enough: %+v", p3)
	}
	if p3.ProbabilityOnline < 0.5 {
		t.Fatalf("noon bucket (no outage at noon) should predict high availability: %+v", p3)
	}
	if p3.OfflineSpellSeconds <= 0 {
		t.Fatalf("observed offline spells must be reported: %+v", p3)
	}
	if p3.Confidence > MaxHistoryConfidence {
		t.Fatalf("history confidence must stay capped: %+v", p3)
	}

	// Inside the outage hour the per-period prediction must be lower.
	nowThree := time.Date(2026, 10, 6, 3, 30, 0, 0, time.UTC)
	p4 := PredictFromHistory(hist, nowThree, 86400, true)
	if p4.ProbabilityOnline > p3.ProbabilityOnline {
		t.Fatalf("per-period bucketing must lower the prediction inside the outage hour: %+v vs %+v", p4, p3)
	}

	// Insufficient samples -> conservative with zero confidence.
	few := sampleHistory(nowNoon.Add(time.Hour), 3, func(int) bool { return true })
	p5 := PredictFromHistory(few, nowNoon, 86400, true)
	if !p5.Conservative || p5.Confidence != 0 {
		t.Fatalf("scarce samples must be conservative: %+v", p5)
	}

	// Determinism: same inputs, same outputs.
	if got := PredictFromHistory(hist, nowNoon, 86400, true); got != p3 {
		t.Fatalf("history prediction must be deterministic: %+v vs %+v", got, p3)
	}
}

// sampleHistory builds hourly samples ending just before `now`, going back
// `hours` hours; online(hour) decides the state.
func sampleHistory(now time.Time, hours int, online func(int) bool) []OnlineSample {
	out := make([]OnlineSample, 0, hours)
	for i := hours; i >= 1; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		out = append(out, OnlineSample{At: t.Format(time.RFC3339), Online: online(t.UTC().Hour())})
	}
	return out
}

// ---------------------------------------------------------------------------
// 13. 20-node simulation: runtime report + benchmark (bounded deterministic
//     search; no global-optimum claim).
// ---------------------------------------------------------------------------

func twentyNodeSnapshot(objects int) *Snapshot {
	nodes := make([]Node, 0, 20)
	for i := 0; i < 20; i++ {
		n := mkNode(fmt.Sprintf("node-%02d", i), fmt.Sprintf("z%d", i%4), 64*MB, true)
		if i == 7 {
			n.Online = false // one routine-offline node
			n.Availability = forecast(0.97, 0.9, 1800)
		}
		n.RTTMs = float64(2 + i%7)
		nodes = append(nodes, n)
	}
	objs := make([]ObjectRequirement, 0, objects)
	for i := 0; i < objects; i++ {
		obj := ObjectRequirement{
			ObjectID:       fmt.Sprintf("obj-%03d", i),
			SizeBytes:      512 * KB,
			ContentVersion: 1,
			Intent:         ProtectionIntent{Tier: []string{"normal", "security", "performance"}[i%3]},
		}
		if i%2 == 0 {
			obj.CurrentLayout = &Layout{
				ObjectID: obj.ObjectID, ContentVersion: 1, LayoutEpoch: 1,
				Scheme:   SchemeReplicate,
				Replicas: replicas(512*KB, fmt.Sprintf("node-%02d", i%20), fmt.Sprintf("node-%02d", (i+3)%20), fmt.Sprintf("node-%02d", (i+7)%20)),
			}
		}
		objs = append(objs, obj)
	}
	return snap(nodes, testPolicy(), objs...)
}

func TestTwentyNodeRuntimeReport(t *testing.T) {
	s := twentyNodeSnapshot(50)
	start := time.Now()
	decisions, err := RunAt(s, testNow)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 50 {
		t.Fatalf("want 50 decisions, got %d", len(decisions))
	}
	proposed, deferred, nochange, infeasible := 0, 0, 0, 0
	for _, d := range decisions {
		switch d.Status {
		case StatusPlanProposed:
			proposed++
		case StatusDeferred:
			deferred++
		case StatusNoChange:
			nochange++
		case StatusNoFeasible:
			infeasible++
		}
		if d.Plan != nil && !d.Plan.Shadow {
			t.Fatalf("plan must be shadow")
		}
	}
	t.Logf("20 nodes / 50 objects: total %s (avg %s per object) — proposed=%d deferred=%d no_change=%d no_feasible=%d",
		elapsed, elapsed/50, proposed, deferred, nochange, infeasible)
}

func BenchmarkTwentyNodes(b *testing.B) {
	s := twentyNodeSnapshot(50)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := RunAt(s, testNow); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// 14. Beam width must never cap layout size: the greedy fill pool is bounded
//     by max(beamWidth, need) so policy-allowed replica/shard counts stay
//     reachable (regression: pool truncated to BeamWidth made every layout
//     needing more than BeamWidth nodes unbuildable -> candidates vanished).
// ---------------------------------------------------------------------------

func TestBeamWidthDoesNotCapLayoutSize(t *testing.T) {
	nodes := make([]Node, 0, 14)
	for i := 0; i < 14; i++ {
		nodes = append(nodes, mkNode(fmt.Sprintf("q%02d", i), fmt.Sprintf("z%d", i), MB, true))
	}
	pol := testPolicy()
	pol.Search.BeamWidth = 2 // deliberately far below the layout sizes under test
	obj := ObjectRequirement{ObjectID: "obj-big", SizeBytes: 100 * KB, ContentVersion: 1}

	e := newEngine(snap(nodes, pol, obj), pol, testNow)
	place := e.buildReplication(obj, 10, nil)
	if len(place) != 10 {
		t.Fatalf("buildReplication r=10 returned %d placements (beam-width cutoff capped layout size): %v", len(place), place)
	}
	frag, ok := fragBytes(obj.SizeBytes, 6)
	if !ok {
		t.Fatal("fragBytes overflow unexpectedly")
	}
	placeRS := e.buildRS(obj, 6, 6, frag, nil)
	if len(placeRS) != 12 {
		t.Fatalf("buildRS k=6 m=6 returned %d placements: %v", len(placeRS), placeRS)
	}
	for _, p := range placeRS {
		if p.Bytes != frag {
			t.Fatalf("fragment bytes %d, want %d", p.Bytes, frag)
		}
	}
	distinctWithin := func(ps []FragmentPlacement) int {
		m := map[string]bool{}
		for _, p := range ps {
			if m[p.NodeID] {
				t.Fatalf("placement reuses node %q; fill must produce distinct nodes", p.NodeID)
			}
			m[p.NodeID] = true
		}
		return len(m)
	}
	if n := distinctWithin(place); n != 10 {
		t.Fatalf("replication placement spans %d distinct nodes, want 10", n)
	}
	if n := distinctWithin(placeRS); n != 12 {
		t.Fatalf("RS placement spans %d distinct nodes, want 12", n)
	}

	// Black-box regression of the same cutoff: beam_width=1 with a need of 2+
	// used to leave NO buildable candidate at all (no_feasible).
	pol1 := testPolicy()
	pol1.Search.BeamWidth = 1
	d := mustRun(t, snap(cluster5(), pol1, obj))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s, want plan_proposed with beam_width=1; reasons %v", d.Status, d.Reasons)
	}
	if pv := ValidatePlan(snap(cluster5(), pol1), obj, *d.Plan, pol1); !pv.Passed {
		t.Fatalf("plan failed validation: %+v", pv.Violations)
	}
}

// ---------------------------------------------------------------------------
// 15. A new placement that omits its byte count is charged the scheme's
//     expected fragment size: omitting bytes must not bypass the budget.
// ---------------------------------------------------------------------------

func TestNewPlacementWithUndeclaredBytesCharged(t *testing.T) {
	pol := testPolicy()
	obj := ObjectRequirement{ObjectID: "o", SizeBytes: 100 * KB, ContentVersion: 1}

	full := mkNode("n1", "z1", MB, true)
	full.ReservedBytes = MB // completely full
	fullLayout := Layout{ObjectID: "o", ContentVersion: 1, LayoutEpoch: 2, Scheme: SchemeReplicate,
		Replicas: []FragmentPlacement{{NodeID: "n1", FragmentIndex: 0, Bytes: 0, Origin: OriginNew}}}
	rep := ValidateLayout(snap([]Node{full}, pol), obj, fullLayout, pol)
	if !hasViolation(rep, VCapacity) {
		t.Fatalf("new placement with undeclared bytes must be charged against capacity: %+v", rep.Violations)
	}

	// Control: an undeclared-bytes new replica among nodes with room stays
	// valid (charging expected bytes never false-positives).
	free1 := mkNode("n2", "z2", MB, true)
	free2 := mkNode("n3", "z3", MB, true)
	freeLayout := Layout{ObjectID: "o", ContentVersion: 1, LayoutEpoch: 2, Scheme: SchemeReplicate,
		Replicas: []FragmentPlacement{
			{NodeID: "n2", FragmentIndex: 0, Bytes: 100 * KB, Origin: OriginNew},
			{NodeID: "n3", FragmentIndex: 1, Bytes: 0, Origin: OriginNew}, // undeclared: charged 100KB
		}}
	rep2 := ValidateLayout(snap([]Node{free1, free2}, pol), obj, freeLayout, pol)
	if !rep2.Passed {
		t.Fatalf("undeclared-bytes placement on a node with room must pass: %+v", rep2.Violations)
	}
}

// ---------------------------------------------------------------------------
// 16. Fault margin: a layout must fail when MinFaultTolerance exceeds the
//     number of failure-domain groups it even spans. (Regression: the empty
//     subset list made the check vacuously pass.)
// ---------------------------------------------------------------------------

func TestFaultMarginMoreGroupsThanLayoutSpans(t *testing.T) {
	nodes := []Node{mkNode("n1", "z1", MB, true), mkNode("n2", "z2", MB, true)}
	pol := testPolicy()
	pol.MinFaultTolerance = 5 // layout spans only 4 groups: 2 zones + 2 hosts
	obj := ObjectRequirement{ObjectID: "obj-t5", SizeBytes: 100 * KB, ContentVersion: 1}

	layout := Layout{ObjectID: "obj-t5", ContentVersion: 1, LayoutEpoch: 1,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2")}
	rep := ValidateLayout(snap(nodes, pol), obj, layout, pol)
	if rep.Passed || !hasViolation(rep, VFaultMargin) {
		t.Fatalf("layout spanning fewer failure groups than MinFaultTolerance must fail: passed=%v violations=%+v", rep.Passed, rep.Violations)
	}

	obj.CurrentLayout = &Layout{ObjectID: "obj-t5", ContentVersion: 1, LayoutEpoch: 2,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2")}
	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusNoFeasible {
		t.Fatalf("status = %s, want no_feasible (policy demand cannot be met; constraints not relaxed); reasons %v", d.Status, d.Reasons)
	}
}

// ---------------------------------------------------------------------------
// 17. History prediction: the sample threshold itself is the boundary.
// ---------------------------------------------------------------------------

func TestHistorySampleThresholdBoundary(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	few := sampleHistory(now.Add(time.Hour), MinHistorySamples-1, func(int) bool { return true })
	if p := PredictFromHistory(few, now, 86400, true); !p.Conservative || p.Confidence != 0 {
		t.Fatalf("samples below MinHistorySamples must stay conservative: %+v", p)
	}
	enough := sampleHistory(now.Add(time.Hour), MinHistorySamples, func(int) bool { return true })
	p := PredictFromHistory(enough, now, 86400, true)
	if p.Conservative || p.SamplesUsed != MinHistorySamples {
		t.Fatalf("samples at MinHistorySamples must predict: %+v", p)
	}
}

// ---------------------------------------------------------------------------
// 18. Horizon gate: readable-now, fault margin and predicted readability are
//     reported as separate checks; the gate alone can reject a layout that
//     is readable and well-placed right now.
// ---------------------------------------------------------------------------

func TestPredictedReadabilityGateSeparateChecks(t *testing.T) {
	nodes := cluster5()
	for i := range nodes {
		nodes[i].Availability = forecast(0.2, 0.9, 0) // verifiably online now; bad horizon forecast
	}
	pol := testPolicy()
	pol.MinPredictedReadability = 0.9
	obj := ObjectRequirement{ObjectID: "obj-gate", SizeBytes: 100 * KB, ContentVersion: 1}
	layout := Layout{ObjectID: "obj-gate", ContentVersion: 1, LayoutEpoch: 1,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2", "n3")}

	rep := ValidateLayout(snap(nodes, pol), obj, layout, pol)
	if rep.Passed || !hasViolation(rep, VHorizonGate) {
		t.Fatalf("bad horizon forecast must trip the gate: %+v", rep.Violations)
	}
	names := map[string]bool{}
	for _, c := range rep.Checks {
		names[c.Name] = true
	}
	for _, want := range []string{"readable_now", "fault_margin", "predicted_readability"} {
		if !names[want] {
			t.Fatalf("check %q must be reported separately; got %+v", want, rep.Checks)
		}
	}

	polOff := testPolicy()
	polOff.MinPredictedReadability = 0
	if rep := ValidateLayout(snap(nodes, polOff), obj, layout, polOff); !rep.Passed {
		t.Fatalf("same layout must pass with the gate off: %+v", rep.Violations)
	}

	// Engine: with the gate on and bad forecasts everywhere, nothing is feasible.
	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusNoFeasible {
		t.Fatalf("status = %s, want no_feasible; reasons %v", d.Status, d.Reasons)
	}
}

// ---------------------------------------------------------------------------
// 19. A routine-outage claim with confidence below MinConfidence must not
//     enable deferral (conservative downgrade to a long outage).
// ---------------------------------------------------------------------------

func TestLowConfidenceForecastNotDeferred(t *testing.T) {
	nodes := cluster5()
	obj := ObjectRequirement{ObjectID: "obj-lc", SizeBytes: 100 * KB, ContentVersion: 1,
		Intent: ProtectionIntent{Tier: "normal"}}
	obj.CurrentLayout = &Layout{ObjectID: "obj-lc", ContentVersion: 1, LayoutEpoch: 3,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2", "n3")}
	nodes[2].Online = false
	nodes[2].Availability = forecast(0.97, 0.3, 1800) // claims a routine 30-min spell, low confidence

	d := mustRun(t, snap(nodes, testPolicy(), obj))[0]
	if d.Status == StatusDeferred {
		t.Fatalf("low-confidence routine-outage claim must not enable deferral")
	}
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s, want plan_proposed; reasons %v", d.Status, d.Reasons)
	}
	if pv := ValidatePlan(snap(nodes, testPolicy()), obj, *d.Plan, testPolicy()); !pv.Passed {
		t.Fatalf("plan failed validation: %+v", pv.Violations)
	}
}

// ---------------------------------------------------------------------------
// 20. Nodes that declare no failure domains at all share unmodeled topology:
//     they co-fail in one bucket and are never assumed independent.
// ---------------------------------------------------------------------------

func TestUndeclaredFailureDomainsCoFail(t *testing.T) {
	nodes := cluster5()
	for i := range nodes {
		nodes[i].FailureDomains = nil
	}
	pol := testPolicy()
	obj := ObjectRequirement{ObjectID: "obj-ud", SizeBytes: 100 * KB, ContentVersion: 1}
	layout := Layout{ObjectID: "obj-ud", ContentVersion: 1, LayoutEpoch: 1,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2", "n3")}

	rep := ValidateLayout(snap(nodes, pol), obj, layout, pol)
	if rep.Passed || !hasViolation(rep, VFaultMargin) {
		t.Fatalf("replicas on fully-undeclared nodes must not count as independent: %+v", rep.Violations)
	}

	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusNoFeasible {
		t.Fatalf("status = %s, want no_feasible (co-failure cannot be ruled out); reasons %v", d.Status, d.Reasons)
	}
}

// ---------------------------------------------------------------------------
// 21. Search.MaxCandidates bounds the reported candidate list and the search
//     stays deterministic under the cap.
// ---------------------------------------------------------------------------

func TestSearchMaxCandidatesBoundsOutput(t *testing.T) {
	pol := testPolicy()
	pol.Search.MaxCandidates = 3
	obj := ObjectRequirement{ObjectID: "obj-cap", SizeBytes: 100 * KB, ContentVersion: 1}
	s := snap(cluster5(), pol, obj)

	d1 := mustRun(t, s)[0]
	if len(d1.Candidates) > 3 {
		t.Fatalf("candidate cap violated: %d candidates", len(d1.Candidates))
	}
	d2 := mustRun(t, s)[0]
	b1, err := json.Marshal(d1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(d2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("capped search must stay deterministic")
	}
}

// ---------------------------------------------------------------------------
// 22. Illegal policy numbers are rejected (NaN comparisons would otherwise
//     silently disable gates); zero stays legal (documented defaults).
// ---------------------------------------------------------------------------

func TestPolicyNumericValidation(t *testing.T) {
	mk := func(f func(*Policy)) *Snapshot {
		s := snap(cluster5(), testPolicy())
		f(&s.Policy)
		return s
	}
	cases := []struct {
		name string
		snap *Snapshot
	}{
		{"NaN readability gate", mk(func(p *Policy) { p.MinPredictedReadability = math.NaN() })},
		{"Inf confidence", mk(func(p *Policy) { p.MinConfidence = math.Inf(1) })},
		{"NaN improvement threshold", mk(func(p *Policy) { p.ImprovementThreshold = math.NaN() })},
		{"negative MinFaultTolerance", mk(func(p *Policy) { p.MinFaultTolerance = -1 })},
		{"negative horizon", mk(func(p *Policy) { p.PredictionHorizonSeconds = -5 })},
		{"negative defer window", mk(func(p *Policy) { p.MaxDeferOfflineSeconds = -1 })},
		{"negative margin", mk(func(p *Policy) { p.MinFaultMarginToDefer = -1 })},
		{"negative MaxReplicaCount", mk(func(p *Policy) { p.MaxReplicaCount = -2 })},
		{"negative BeamWidth", mk(func(p *Policy) { p.Search.BeamWidth = -1 })},
		{"negative MaxCandidates", mk(func(p *Policy) { p.Search.MaxCandidates = -1 })},
		{"negative ExactComboLimit", mk(func(p *Policy) { p.Search.ExactComboLimit = -1 })},
		{"MinK above MaxK", mk(func(p *Policy) { p.CodecLimits = CodecLimits{MinK: 4, MaxK: 2, MinM: 1, MaxM: 2} })},
		{"MinM above MaxM", mk(func(p *Policy) { p.CodecLimits = CodecLimits{MinK: 2, MaxK: 4, MinM: 3, MaxM: 2} })},
		{"negative MinK with RS on", mk(func(p *Policy) { p.CodecLimits = CodecLimits{MinK: -1, MaxK: 4, MinM: 1, MaxM: 2} })},
		{"MaxK beyond supported RS range", mk(func(p *Policy) { p.CodecLimits = CodecLimits{MinK: 2, MaxK: 300, MinM: 1, MaxM: 2} })},
		{"MaxTotalShards beyond supported RS range", mk(func(p *Policy) { p.CodecLimits = CodecLimits{MinK: 2, MaxK: 4, MinM: 1, MaxM: 2, MaxTotalShards: 400} })},
	}
	for _, tc := range cases {
		rep := ValidateSnapshot(tc.snap)
		if rep.Passed || !hasViolation(rep, VNumberInvalid) {
			t.Fatalf("%s: want %s violation, got passed=%v violations=%+v", tc.name, VNumberInvalid, rep.Passed, rep.Violations)
		}
		if _, err := RunAt(tc.snap, testNow); err == nil {
			t.Fatalf("%s: RunAt must error on invalid policy", tc.name)
		}
	}

	// Tier defaults with NaN components are policy bugs.
	s := snap(cluster5(), testPolicy())
	s.Policy.TierDefaults = map[string]ScoreWeights{"gold": {Cost: math.NaN()}}
	if rep := ValidateSnapshot(s); !hasViolation(rep, VNumberInvalid) {
		t.Fatalf("NaN tier default must be rejected: %+v", rep.Violations)
	}

	// Duplicate and empty object IDs.
	dup := snap(cluster5(), testPolicy(),
		ObjectRequirement{ObjectID: "x", SizeBytes: KB, ContentVersion: 1},
		ObjectRequirement{ObjectID: "x", SizeBytes: KB, ContentVersion: 1})
	if rep := ValidateSnapshot(dup); !hasViolation(rep, VDuplicateObject) {
		t.Fatalf("duplicate object id must be rejected: %+v", rep.Violations)
	}
	empty := snap(cluster5(), testPolicy(), ObjectRequirement{ObjectID: "", SizeBytes: KB, ContentVersion: 1})
	if rep := ValidateSnapshot(empty); !hasViolation(rep, VObjectIDInvalid) {
		t.Fatalf("empty object id must be rejected: %+v", rep.Violations)
	}

	// The all-zero policy stays legal (zeros mean documented defaults).
	if rep := ValidateSnapshot(snap(cluster5(), Policy{})); !rep.Passed {
		t.Fatalf("zero policy must stay legal: %+v", rep.Violations)
	}
	// MaxK < 0 (RS traversal disabled) stays legal.
	pol := testPolicy()
	pol.CodecLimits.MaxK = -1
	if rep := ValidateSnapshot(snap(cluster5(), pol)); !rep.Passed {
		t.Fatalf("MaxK=-1 (RS disabled) must stay legal: %+v", rep.Violations)
	}
}

// ---------------------------------------------------------------------------
// 23. Plan identity: the plan and its target layout must belong to the
//     requirement's object and content version; a uint64-max epoch cannot be
//     incremented.
// ---------------------------------------------------------------------------

func TestPlanIdentityAndEpochBounds(t *testing.T) {
	nodes := cluster5()
	pol := testPolicy()
	obj := ObjectRequirement{ObjectID: "obj-id", SizeBytes: 100 * KB, ContentVersion: 7,
		CurrentLayout: &Layout{ObjectID: "obj-id", ContentVersion: 7, LayoutEpoch: 4,
			Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2")}}

	good := Plan{
		ObjectID: "obj-id", BaseContentVersion: 7, BaseLayoutEpoch: 4,
		TargetLayout: Layout{ObjectID: "obj-id", ContentVersion: 7, LayoutEpoch: 5,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: 100 * KB, Origin: OriginExisting},
				{NodeID: "n3", FragmentIndex: 1, Bytes: 100 * KB, Origin: OriginNew},
			}},
		MigrationBytes: 100 * KB,
		Shadow:         true,
	}
	if rep := ValidatePlan(snap(nodes, pol), obj, good, pol); !rep.Passed {
		t.Fatalf("baseline must pass: %+v", rep.Violations)
	}

	wrongID := good
	wrongID.ObjectID = "obj-other"
	if rep := ValidatePlan(snap(nodes, pol), obj, wrongID, pol); !hasViolation(rep, VObjectMismatch) {
		t.Fatalf("plan for another object must be rejected: %+v", rep.Violations)
	}
	wrongTargetID := good
	wrongTargetID.TargetLayout.ObjectID = "obj-other"
	if rep := ValidatePlan(snap(nodes, pol), obj, wrongTargetID, pol); !hasViolation(rep, VObjectMismatch) {
		t.Fatalf("target layout for another object must be rejected: %+v", rep.Violations)
	}
	wrongCV := good
	wrongCV.TargetLayout.ContentVersion = 8
	if rep := ValidatePlan(snap(nodes, pol), obj, wrongCV, pol); !hasViolation(rep, VObjectMismatch) {
		t.Fatalf("target content version mismatch must be rejected: %+v", rep.Violations)
	}

	overflow := ObjectRequirement{ObjectID: "obj-ovf", SizeBytes: 100 * KB, ContentVersion: 1,
		CurrentLayout: &Layout{ObjectID: "obj-ovf", ContentVersion: 1, LayoutEpoch: math.MaxUint64,
			Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2")}}
	ovfPlan := Plan{
		ObjectID: "obj-ovf", BaseContentVersion: 1, BaseLayoutEpoch: math.MaxUint64,
		TargetLayout: Layout{ObjectID: "obj-ovf", ContentVersion: 1, LayoutEpoch: 0,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: 100 * KB, Origin: OriginExisting},
				{NodeID: "n3", FragmentIndex: 1, Bytes: 100 * KB, Origin: OriginNew},
			}},
		MigrationBytes: 100 * KB,
		Shadow:         true,
	}
	if rep := ValidatePlan(snap(nodes, pol), overflow, ovfPlan, pol); !hasViolation(rep, VEpochInvalid) {
		t.Fatalf("epoch overflow must be rejected: %+v", rep.Violations)
	}
}

// ---------------------------------------------------------------------------
// 24. A mirrored replication current layout must not let a "repair" quietly
//     drop copies: the anti-shrink measure counts copies for replication,
//     and generated candidates never inherit duplicate indices.
// ---------------------------------------------------------------------------

func TestMirroredReplicationCurrentRepair(t *testing.T) {
	nodes := cluster5()
	obj := ObjectRequirement{ObjectID: "obj-mir", SizeBytes: 100 * KB, ContentVersion: 1}
	obj.CurrentLayout = &Layout{ObjectID: "obj-mir", ContentVersion: 1, LayoutEpoch: 2,
		Scheme: SchemeReplicate,
		Replicas: []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: 100 * KB, Origin: OriginExisting},
			{NodeID: "n2", FragmentIndex: 0, Bytes: 100 * KB, Origin: OriginExisting}, // mirror: duplicate index
			{NodeID: "n3", FragmentIndex: 1, Bytes: 100 * KB, Origin: OriginExisting},
		}}
	nodes[1].Online = false
	nodes[1].Availability = forecast(0.1, 0.9, 3*86400) // long outage on the mirror holder

	d := mustRun(t, snap(nodes, testPolicy(), obj))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s, want plan_proposed; reasons %v", d.Status, d.Reasons)
	}
	if len(d.Plan.TargetLayout.Replicas) < 3 {
		t.Fatalf("repair must not drop below the 3 existing copies: %+v", d.Plan.TargetLayout.Replicas)
	}
	if d.Plan.MigrationBytes == 0 {
		t.Fatalf("repair must move bytes to restore the lost copy")
	}
	seen := map[int]bool{}
	for _, p := range d.Plan.TargetLayout.Replicas {
		if seen[p.FragmentIndex] {
			t.Fatalf("target reuses fragment index %d: %+v", p.FragmentIndex, d.Plan.TargetLayout.Replicas)
		}
		seen[p.FragmentIndex] = true
	}
	if pv := ValidatePlan(snap(nodes, testPolicy()), obj, *d.Plan, testPolicy()); !pv.Passed {
		t.Fatalf("plan failed validation: %+v", pv.Violations)
	}
}

// ---------------------------------------------------------------------------
// 25. In the healthy path the decision's SelectedID must name the candidate
//     the plan was actually built from (an executable one), never a
//     simulated RS candidate that merely topped the score list.
// ---------------------------------------------------------------------------

func TestHealthyProposeSelectedIDMatchesPlan(t *testing.T) {
	nodes := cluster5()
	for i := range nodes {
		if i >= 2 {
			nodes[i].CostPerGBMonth = 10 // n3..n5 expensive
		}
	}
	obj := ObjectRequirement{ObjectID: "obj-sel", SizeBytes: 100 * KB, ContentVersion: 1,
		Intent: ProtectionIntent{Weights: ScoreWeights{Durability: 0.9, Cost: 0.1}}}
	obj.CurrentLayout = &Layout{ObjectID: "obj-sel", ContentVersion: 1, LayoutEpoch: 2,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n3", "n4")}

	d := mustRun(t, snap(nodes, testPolicy(), obj))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s, want plan_proposed; reasons %v", d.Status, d.Reasons)
	}
	if d.Plan != nil && d.Plan.TargetLayout.Scheme == SchemeReplicate && strings.HasPrefix(d.SelectedID, "rs-") {
		t.Fatalf("SelectedID %q must name the executable plan candidate, not a simulated RS candidate", d.SelectedID)
	}
	var match *Candidate
	for i := range d.Candidates {
		if d.Candidates[i].CandidateID == d.SelectedID {
			match = &d.Candidates[i]
			break
		}
	}
	if match == nil {
		t.Fatalf("SelectedID %q not among listed candidates", d.SelectedID)
	}
	placementKey := func(ps []FragmentPlacement) map[string]int {
		m := map[string]int{}
		for _, p := range ps {
			m[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)]++
		}
		return m
	}
	want, got := placementKey(match.Placement), placementKey(d.Plan.TargetLayout.Replicas)
	if len(want) != len(got) {
		t.Fatalf("selected candidate %+v does not match plan target %+v", match.Placement, d.Plan.TargetLayout.Replicas)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("selected candidate %+v does not match plan target %+v", match.Placement, d.Plan.TargetLayout.Replicas)
		}
	}
}

// ---------------------------------------------------------------------------
// 26. Over the exact-enumeration budget the fault-margin check must fall
//     back to a PROVEN lower bound, never a heuristic estimate: greedy can
//     only overestimate the surviving shard count and must never be what
//     passes a hard constraint.
// ---------------------------------------------------------------------------

func TestFaultMarginOverBudgetUsesProvenBound(t *testing.T) {
	const nNodes = 210
	nodes := make([]Node, 0, nNodes)
	ids := make([]string, 0, nNodes)
	for i := 0; i < nNodes; i++ {
		id := fmt.Sprintf("n%03d", i)
		ids = append(ids, id)
		n := mkNode(id, "", MB, true)
		if i < 205 {
			n.FailureDomains["zone"] = "z1"
		} else {
			n.FailureDomains["zone"] = "z2"
		}
		if i < 204 {
			n.FailureDomains["rack"] = "r1"
		} else {
			n.FailureDomains["rack"] = "r2"
		}
		nodes = append(nodes, n)
	}
	pol := testPolicy()
	// Two-group failures are the policy demand: the exact worst pair
	// (zone z1 + zone z2) kills all 210 shards and exceeds the enumeration
	// budget, while the top-2-by-blast greedy pair (zone z1 + rack r1)
	// leaves 5 survivors — the heuristic must never be what passes here.
	pol.MinFaultTolerance = 2
	obj := ObjectRequirement{ObjectID: "obj-ovb", SizeBytes: KB, ContentVersion: 1}
	place := make([]FragmentPlacement, 0, nNodes)
	for i := 0; i < nNodes; i++ {
		place = append(place, FragmentPlacement{NodeID: ids[i], FragmentIndex: i, Bytes: KB, Origin: OriginExisting})
	}
	layout := Layout{ObjectID: "obj-ovb", ContentVersion: 1, LayoutEpoch: 1,
		Scheme: SchemeReplicate, Replicas: place}

	// The exact worst case (losing zone z1 + zone z2 kills all 210 shards)
	// exceeds the enumeration budget; the top-2-by-blast greedy pair
	// (zone z1 + rack r1) would leave 5 survivors and wrongly pass.
	rep := ValidateLayout(snap(nodes, pol), obj, layout, pol)
	if rep.Passed || !hasViolation(rep, VFaultMargin) {
		t.Fatalf("over-budget fault margin must return a proven lower bound (true worst = 0 survivors): passed=%v violations=%+v", rep.Passed, rep.Violations)
	}
}

// ---------------------------------------------------------------------------
// 27. A plan cannot forge Origin="existing" or zero bytes to bypass capacity
//     and migration accounting: the validator re-derives both from the
//     current layout's same-generation geometry.
// ---------------------------------------------------------------------------

func TestPlanCannotForgeOriginOrBytes(t *testing.T) {
	nodes := cluster5()
	nodes[1].ReservedBytes = MB // n2 completely full
	pol := testPolicy()
	obj := ObjectRequirement{ObjectID: "obj-forge", SizeBytes: 100 * KB, ContentVersion: 3,
		CurrentLayout: &Layout{ObjectID: "obj-forge", ContentVersion: 3, LayoutEpoch: 1,
			Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1")}}

	forge := Plan{
		ObjectID: "obj-forge", BaseContentVersion: 3, BaseLayoutEpoch: 1,
		TargetLayout: Layout{ObjectID: "obj-forge", ContentVersion: 3, LayoutEpoch: 2,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: 100 * KB, Origin: OriginExisting},
				{NodeID: "n2", FragmentIndex: 1, Bytes: 0, Origin: OriginExisting}, // forged: (n2,1) is not in current
			}},
		MigrationBytes: 0,
		Shadow:         true,
	}
	rep := ValidatePlan(snap(nodes, pol), obj, forge, pol)
	if rep.Passed {
		t.Fatalf("forged existing/zero-byte placement must not pass validation")
	}
	if !hasViolation(rep, VMigrationMismatch) {
		t.Fatalf("recomputed migration must charge the forged placement: %+v", rep.Violations)
	}
	if !hasViolation(rep, VCapacity) {
		t.Fatalf("re-derived new placement on a full node must trip capacity: %+v", rep.Violations)
	}

	// The honest declaration of the same target fails on capacity alone.
	honest := forge
	honest.TargetLayout.Replicas[1].Origin = OriginNew
	honest.TargetLayout.Replicas[1].Bytes = 100 * KB
	honest.MigrationBytes = 100 * KB
	if rep := ValidatePlan(snap(nodes, pol), obj, honest, pol); rep.Passed || !hasViolation(rep, VCapacity) {
		t.Fatalf("honest full-node plan must fail capacity: passed=%v violations=%+v", rep.Passed, rep.Violations)
	}

	// An existing copy may still omit bytes (snapshot convention) and stays
	// valid when the rest of the target is sound.
	sound := forge
	sound.TargetLayout.Replicas = []FragmentPlacement{
		{NodeID: "n1", FragmentIndex: 0, Bytes: 0, Origin: OriginExisting},
		{NodeID: "n3", FragmentIndex: 1, Bytes: 100 * KB, Origin: OriginNew},
	}
	sound.MigrationBytes = 100 * KB
	if rep := ValidatePlan(snap(nodes, pol), obj, sound, pol); !rep.Passed {
		t.Fatalf("zero-byte existing copy with a sound target must stay valid: %+v", rep.Violations)
	}
}

// ---------------------------------------------------------------------------
// 28. Independent layout validation: identity must match the requirement,
//     EC parameters must lie inside the supported range, and ceil division
//     must saturate instead of wrapping on overflow.
// ---------------------------------------------------------------------------

func TestValidateLayoutIdentityAndECBounds(t *testing.T) {
	nodes := cluster5()
	pol := testPolicy()
	obj := ObjectRequirement{ObjectID: "obj-ec2", SizeBytes: 100 * KB, ContentVersion: 2}

	misID := Layout{ObjectID: "other-obj", ContentVersion: 2, LayoutEpoch: 1,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2")}
	if rep := ValidateLayout(snap(nodes, pol), obj, misID, pol); rep.Passed {
		t.Fatalf("layout object_id mismatch must be rejected")
	} else if !hasViolation(rep, VLayoutMismatch) {
		t.Fatalf("want %s, got %+v", VLayoutMismatch, rep.Violations)
	}
	misCV := Layout{ObjectID: "obj-ec2", ContentVersion: 9, LayoutEpoch: 1,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2")}
	if rep := ValidateLayout(snap(nodes, pol), obj, misCV, pol); !hasViolation(rep, VLayoutMismatch) {
		t.Fatalf("layout content_version mismatch must be rejected: %+v", rep.Violations)
	}

	rsShards := func(k, m int) []FragmentPlacement {
		out := make([]FragmentPlacement, 0, k+m)
		for i := 0; i < k+m; i++ {
			out = append(out, FragmentPlacement{
				NodeID: fmt.Sprintf("n%d", i%5+1), FragmentIndex: i,
				Bytes: (100*KB + uint64(k) - 1) / uint64(k), Origin: OriginExisting,
			})
		}
		return out
	}
	noParity := Layout{ObjectID: "obj-ec2", ContentVersion: 2, LayoutEpoch: 1,
		Scheme: SchemeRS, EC: &ECParams{K: 2, M: 0}, Replicas: rsShards(2, 0)}
	if rep := ValidateLayout(snap(nodes, pol), obj, noParity, pol); !hasViolation(rep, VECUnsupported) {
		t.Fatalf("RS m=0 is outside the supported range: %+v", rep.Violations)
	}
	tooWide := Layout{ObjectID: "obj-ec2", ContentVersion: 2, LayoutEpoch: 1,
		Scheme: SchemeRS, EC: &ECParams{K: 255, M: 1}, Replicas: rsShards(255, 1)}
	if rep := ValidateLayout(snap(nodes, pol), obj, tooWide, pol); !hasViolation(rep, VECUnsupported) {
		t.Fatalf("k+m > 255 is outside the supported range: %+v", rep.Violations)
	}

	if got := expectedFragmentBytes(math.MaxUint64, Layout{Scheme: SchemeRS}, 2); got != math.MaxUint64 {
		t.Fatalf("ceil(size/k) must saturate instead of wrapping on overflow, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// 29. Sequential joint budgeting: plans proposed in one run reserve their
//     new bytes against later objects — the sum over all plans may not
//     oversell any node's verifiable free capacity, and proposed plans
//     declare the joint-budget contract explicitly.
// ---------------------------------------------------------------------------

func TestRunJointlyBudgetsSequentialPlans(t *testing.T) {
	nodes := []Node{
		mkNode("n1", "z1", 150*KB, true),
		mkNode("n2", "z2", 150*KB, true),
		mkNode("n3", "z3", 150*KB, true),
	}
	pol := testPolicy()
	pol.CodecLimits.MaxK = -1 // replication only, crisp accounting
	objs := []ObjectRequirement{
		{ObjectID: "j1", SizeBytes: 100 * KB, ContentVersion: 1},
		{ObjectID: "j2", SizeBytes: 100 * KB, ContentVersion: 1},
	}
	decisions := mustRun(t, snap(nodes, pol, objs...))

	perNode := map[string]uint64{}
	haveJoint := false
	for _, d := range decisions {
		if d.Plan == nil {
			continue
		}
		b, err := json.Marshal(d.Plan)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"jointly_budgeted":true`) {
			haveJoint = true
		}
		for _, p := range d.Plan.TargetLayout.Replicas {
			if p.Origin == OriginNew {
				perNode[p.NodeID] += p.Bytes
			}
		}
	}
	for _, n := range nodes {
		free, ok := FreeBytes(n)
		if !ok {
			t.Fatalf("node %s has no budget", n.ID)
		}
		if perNode[n.ID] > free {
			t.Fatalf("plans oversell node %s: %d new bytes > %d free", n.ID, perNode[n.ID], free)
		}
	}
	if !haveJoint {
		t.Fatalf("proposed plans must declare jointly_budgeted=true (batch-execution contract)")
	}
}

// ---------------------------------------------------------------------------
// 30. The independent validator enforces the repair anti-shrink floor: a
//     plan whose target holds less redundancy than the current layout is
//     rejected even when it is otherwise self-consistent (no pseudo-keep).
// ---------------------------------------------------------------------------

func TestValidatePlanRejectsShrinkingRepair(t *testing.T) {
	nodes := cluster5()
	pol := testPolicy()
	obj := ObjectRequirement{ObjectID: "obj-shr", SizeBytes: 100 * KB, ContentVersion: 7,
		CurrentLayout: &Layout{ObjectID: "obj-shr", ContentVersion: 7, LayoutEpoch: 4,
			Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2", "n3")}}
	shrink := Plan{
		ObjectID: "obj-shr", BaseContentVersion: 7, BaseLayoutEpoch: 4,
		TargetLayout: Layout{ObjectID: "obj-shr", ContentVersion: 7, LayoutEpoch: 5,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: 100 * KB, Origin: OriginExisting},
				{NodeID: "n2", FragmentIndex: 1, Bytes: 100 * KB, Origin: OriginExisting},
			}},
		MigrationBytes: 0,
		Shadow:         true,
	}
	rep := ValidatePlan(snap(nodes, pol), obj, shrink, pol)
	if rep.Passed {
		t.Fatalf("plan shrinking 3 copies to 2 must be rejected by the independent validator")
	}
	if !hasViolation(rep, VAntiShrink) {
		t.Fatalf("want %s violation, got %+v", VAntiShrink, rep.Violations)
	}
}

// ---------------------------------------------------------------------------
// 31. Deferral must be protected by the ONLINE subset's failure-domain
//     margin: survivors that share a domain can co-fail, and a count-based
//     margin must not wave the outage through.
// ---------------------------------------------------------------------------

func TestDeferRequiresOnlineSubsetFaultMargin(t *testing.T) {
	nodes := cluster5()
	nodes[0].FailureDomains["zone"] = "z1"
	nodes[1].FailureDomains["zone"] = "z1" // both online survivors in z1
	nodes[2].FailureDomains["zone"] = "z2"
	obj := ObjectRequirement{ObjectID: "obj-dm", SizeBytes: 100 * KB, ContentVersion: 1,
		Intent: ProtectionIntent{Tier: "normal"}}
	obj.CurrentLayout = &Layout{ObjectID: "obj-dm", ContentVersion: 1, LayoutEpoch: 3,
		Scheme: SchemeReplicate, Replicas: replicas(100*KB, "n1", "n2", "n3")}
	nodes[2].Online = false
	nodes[2].Availability = forecast(0.97, 0.9, 1800) // routine spell

	d := mustRun(t, snap(nodes, testPolicy(), obj))[0]
	if d.Status == StatusDeferred {
		t.Fatalf("online survivors share one failure domain; the count-based margin must not enable deferral")
	}
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s, want plan_proposed; reasons %v", d.Status, d.Reasons)
	}
	if pv := ValidatePlan(snap(nodes, testPolicy()), obj, *d.Plan, testPolicy()); !pv.Passed {
		t.Fatalf("plan failed validation: %+v", pv.Violations)
	}
}
