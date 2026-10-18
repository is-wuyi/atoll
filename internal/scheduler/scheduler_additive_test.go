package scheduler

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Policy.AdditiveOnly — strict add-only mode for autonomous replica growth.
//
// Contract under test:
//   - targets are SchemeReplicate only (no EC, no scheme change);
//   - every current (node, fragment index) is retained verbatim, including
//     placements on currently-offline nodes; no truncation, reassignment or
//     same-count replacement;
//   - additions land on distinct, previously unused, verifiably-online nodes
//     at fragment indices strictly after the existing ones;
//   - retained (existing) placements are never re-charged against capacity;
//   - malformed currents are reported invalid and never carried into the
//     derivation; the independent validator rejects any plan that violates
//     the contract.
// ---------------------------------------------------------------------------

func additivePolicy() Policy {
	p := testPolicy()
	p.AdditiveOnly = true
	p.CodecLimits = CodecLimits{MaxK: -1} // production adapter shape: RS disabled
	return p
}

// offlineLong marks node "n2" as offline with a long (non-routine) predicted
// outage so the repair path (not deferral) engages.
func offlineLong(nodes []Node) {
	nodes[1].Online = false
	nodes[1].Availability = forecast(0.1, 0.9, 3*86400)
}

func currentOn(id string, cv, epoch uint64, ids ...string) (ObjectRequirement, *Layout) {
	cur := &Layout{ObjectID: id, ContentVersion: cv, LayoutEpoch: epoch,
		Scheme: SchemeReplicate, Replicas: replicas(MB, ids...)}
	obj := ObjectRequirement{ObjectID: id, SizeBytes: MB, ContentVersion: cv, CurrentLayout: cur}
	return obj, cur
}

func assertSuperset(t *testing.T, cur *Layout, target Layout) {
	t.Helper()
	need := map[string]int{}
	for _, p := range cur.Replicas {
		need[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)]++
	}
	have := map[string]int{}
	seenNode := map[string]bool{}
	for _, p := range target.Replicas {
		have[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)]++
		if seenNode[p.NodeID] {
			t.Fatalf("duplicate physical node %q in target: %+v", p.NodeID, target.Replicas)
		}
		seenNode[p.NodeID] = true
	}
	for k, n := range need {
		if have[k] < n {
			t.Fatalf("target dropped current placement %s: %+v", k, target.Replicas)
		}
	}
}

// 1. Offline existing placements are retained and the repair only ADDs
// replicas on distinct online nodes, at indices after the existing ones.
func TestAdditiveOnlyKeepsOfflineExistingAndAddsDistinctNode(t *testing.T) {
	nodes := cluster5()
	offlineLong(nodes)
	obj, cur := currentOn("obj-add", 2, 6, "n1", "n2")

	d := mustRun(t, snap(nodes, additivePolicy(), obj))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s (%s), want plan_proposed", d.Status, strings.Join(d.Reasons, "; "))
	}
	tl := d.Plan.TargetLayout
	if tl.Scheme != SchemeReplicate {
		t.Fatalf("additive target scheme = %s, want replicate", tl.Scheme)
	}
	assertSuperset(t, cur, tl)

	existingIdx := map[int]bool{}
	for _, p := range cur.Replicas {
		existingIdx[p.FragmentIndex] = true
	}
	added := 0
	for _, p := range tl.Replicas {
		if p.Origin != OriginNew {
			continue
		}
		added++
		if existingIdx[p.FragmentIndex] {
			t.Fatalf("new placement reuses an existing fragment index: %+v", p)
		}
		if p.NodeID == "n1" || p.NodeID == "n2" {
			t.Fatalf("new placement on a node that already holds the object: %+v", p)
		}
		if !nodes[indexOf(nodes, p.NodeID)].Online {
			t.Fatalf("new placement on offline node: %+v", p)
		}
	}
	if added == 0 {
		t.Fatalf("additive repair must add at least one replica: %+v", tl.Replicas)
	}
	// retained offline placement is reported as existing, never rewritten
	for _, p := range tl.Replicas {
		if p.NodeID == "n2" && p.Origin != OriginExisting {
			t.Fatalf("retained offline placement must be origin=existing: %+v", p)
		}
	}
	for _, a := range d.Plan.Actions {
		if a.Kind == "move_replica" || a.Kind == "regenerate_fragment" {
			t.Fatalf("additive plan contains a move/regenerate action: %+v", a)
		}
	}
	if pv := ValidatePlan(snap(nodes, additivePolicy()), obj, *d.Plan, additivePolicy()); !pv.Passed {
		t.Fatalf("additive plan failed independent validation: %+v", pv.Violations)
	}
}

// 2. Same-count move (one current position dropped, one new position added
// at an unchanged replica count) is rejected by the independent validator in
// additive mode — while default mode keeps the legacy replacement semantics.
func TestAdditiveOnlyValidatorRejectsSameCountMove(t *testing.T) {
	nodes := cluster5()
	obj, _ := currentOn("obj-mv", 1, 4, "n1", "n2")
	plan := Plan{
		ObjectID: "obj-mv", BaseContentVersion: 1, BaseLayoutEpoch: 4, Shadow: true,
		MigrationBytes: MB,
		TargetLayout: Layout{ObjectID: "obj-mv", ContentVersion: 1, LayoutEpoch: 5,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
				{NodeID: "n3", FragmentIndex: 1, Bytes: MB, Origin: OriginNew}, // replaces n2 at the same count
			}},
	}
	pol := additivePolicy()
	if pv := ValidatePlan(snap(nodes, pol), obj, plan, pol); !hasViolation(pv, VAdditiveNotSuperset) {
		t.Fatalf("same-count move must be rejected as %s, got %+v", VAdditiveNotSuperset, pv.Violations)
	}
	if pv := ValidatePlan(snap(nodes, testPolicy()), obj, plan, testPolicy()); !pv.Passed {
		t.Fatalf("default mode must keep legacy replacement semantics: %+v", pv.Violations)
	}
}

// 3. The independent validator and the engine both refuse EC layouts and
// duplicate physical nodes in additive mode.
func TestAdditiveOnlyRejectsECAndDuplicateNode(t *testing.T) {
	nodes := cluster5()
	pol := additivePolicy()

	// (a) validator: an EC target plan is rejected
	obj, _ := currentOn("obj-ec", 1, 1, "n1")
	ecPlan := Plan{
		ObjectID: "obj-ec", BaseContentVersion: 1, BaseLayoutEpoch: 1, Shadow: true,
		TargetLayout: Layout{ObjectID: "obj-ec", ContentVersion: 1, LayoutEpoch: 2,
			Scheme: SchemeRS, EC: &ECParams{K: 2, M: 1},
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: MB / 2, Origin: OriginNew},
				{NodeID: "n2", FragmentIndex: 1, Bytes: MB / 2, Origin: OriginNew},
				{NodeID: "n3", FragmentIndex: 2, Bytes: MB / 2, Origin: OriginNew},
			}},
	}
	if pv := ValidatePlan(snap(nodes, pol), obj, ecPlan, pol); !hasViolation(pv, VAdditiveScheme) {
		t.Fatalf("EC target must be rejected as %s, got %+v", VAdditiveScheme, pv.Violations)
	}

	// (b) validator: two replicas of the object on one physical node rejected
	dupPlan := Plan{
		ObjectID: "obj-ec", BaseContentVersion: 1, BaseLayoutEpoch: 1, Shadow: true,
		MigrationBytes: MB,
		TargetLayout: Layout{ObjectID: "obj-ec", ContentVersion: 1, LayoutEpoch: 2,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
				{NodeID: "n1", FragmentIndex: 1, Bytes: MB, Origin: OriginNew},
			}},
	}
	if pv := ValidatePlan(snap(nodes, pol), obj, dupPlan, pol); !hasViolation(pv, VAdditiveDupNode) {
		t.Fatalf("duplicate physical node must be rejected as %s, got %+v", VAdditiveDupNode, pv.Violations)
	}

	// (c) engine: no EC candidate is generated even with codec limits enabled
	nodes[1].Online = false
	nodes[1].Availability = forecast(0.1, 0.9, 3*86400)
	obj2, _ := currentOn("obj-ec2", 1, 3, "n1", "n2")
	ecOn := additivePolicy()
	ecOn.CodecLimits = CodecLimits{MinK: 2, MaxK: 4, MinM: 1, MaxM: 2, MaxTotalShards: 6}
	d := mustRun(t, snap(nodes, ecOn, obj2))[0]
	if d.Plan != nil && d.Plan.TargetLayout.Scheme != SchemeReplicate {
		t.Fatalf("additive engine selected scheme %s", d.Plan.TargetLayout.Scheme)
	}
	for _, c := range d.Candidates {
		if c.Scheme != SchemeReplicate || c.RequiresECBackend {
			t.Fatalf("additive engine generated EC candidate %s", c.CandidateID)
		}
	}
}

// 4. New placements on offline nodes are rejected by the independent
// validator in additive mode (additions require verifiably online nodes).
func TestAdditiveOnlyValidatorRejectsNewOnOfflineNode(t *testing.T) {
	nodes := cluster5()
	nodes[1].Online = false
	nodes[1].Availability = forecast(0.1, 0.9, 3*86400)
	obj, _ := currentOn("obj-off", 1, 1, "n1")
	plan := Plan{
		ObjectID: "obj-off", BaseContentVersion: 1, BaseLayoutEpoch: 1, Shadow: true,
		MigrationBytes: MB,
		TargetLayout: Layout{ObjectID: "obj-off", ContentVersion: 1, LayoutEpoch: 2,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
				{NodeID: "n2", FragmentIndex: 1, Bytes: MB, Origin: OriginNew},
			}},
	}
	pol := additivePolicy()
	if pv := ValidatePlan(snap(nodes, pol), obj, plan, pol); !hasViolation(pv, VAdditiveOfflineNew) {
		t.Fatalf("new placement on offline node must be rejected as %s, got %+v", VAdditiveOfflineNew, pv.Violations)
	}
	if pv := ValidatePlan(snap(nodes, testPolicy()), obj, plan, testPolicy()); !pv.Passed {
		t.Fatalf("default mode must keep legacy semantics: %+v", pv.Violations)
	}
}

// 5. Malformed currents (duplicate node, duplicate index, out-of-range index,
// unknown scheme) are explicitly invalid in additive mode and are never
// carried into the derivation.
func TestAdditiveOnlyBadCurrentInvalid(t *testing.T) {
	nodes := cluster5()
	pol := additivePolicy()
	cases := []struct {
		name string
		reps []FragmentPlacement
		code string
	}{
		{"duplicate node", []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
			{NodeID: "n1", FragmentIndex: 1, Bytes: MB, Origin: OriginExisting}}, VDuplicatePlacement},
		{"duplicate index", []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
			{NodeID: "n2", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting}}, VIndexDuplicate},
		{"index out of range", []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
			{NodeID: "n2", FragmentIndex: 5, Bytes: MB, Origin: OriginExisting}}, VIndexInvalid},
	}
	for _, tc := range cases {
		id := "obj-bad-" + strings.ReplaceAll(tc.name, " ", "-")
		cur := &Layout{ObjectID: id, ContentVersion: 1, LayoutEpoch: 2, Scheme: SchemeReplicate, Replicas: tc.reps}
		obj := ObjectRequirement{ObjectID: id, SizeBytes: MB, ContentVersion: 1, CurrentLayout: cur}
		d := mustRun(t, snap(nodes, pol, obj))[0]
		if d.Status != StatusInvalid {
			t.Fatalf("%s: status = %s (%v), want invalid_requirement", tc.name, d.Status, d.Reasons)
		}
		if d.Plan != nil || len(d.Candidates) > 0 {
			t.Fatalf("%s: bad current must not be carried into derivation (plan=%v candidates=%d)", tc.name, d.Plan, len(d.Candidates))
		}
		if d.Validation == nil || !hasViolation(d.Validation, tc.code) {
			t.Fatalf("%s: want violation %s, got %+v", tc.name, tc.code, d.Validation)
		}
	}

	// unknown scheme
	cur := &Layout{ObjectID: "obj-bad-scheme", ContentVersion: 1, LayoutEpoch: 2,
		Scheme: Scheme("erasure"), Replicas: replicas(MB, "n1", "n2")}
	obj := ObjectRequirement{ObjectID: "obj-bad-scheme", SizeBytes: MB, ContentVersion: 1, CurrentLayout: cur}
	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusInvalid || d.Plan != nil {
		t.Fatalf("unknown scheme: status = %s plan=%v, want invalid with no plan", d.Status, d.Plan)
	}
}

// 6. A migration budget too small for any addition yields an explicit
// no_feasible (additive mode never shrinks or replaces to fit the budget).
func TestAdditiveOnlyBudgetInsufficientNoFeasible(t *testing.T) {
	nodes := cluster5()
	offlineLong(nodes)
	obj, _ := currentOn("obj-budget", 1, 3, "n1", "n2")
	pol := additivePolicy()
	pol.MaxMigrationBytesBudget = MB / 2

	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusNoFeasible {
		t.Fatalf("status = %s (%v), want no_feasible", d.Status, d.Reasons)
	}
	if d.Plan != nil {
		t.Fatalf("no plan may be proposed when the budget cannot fund an addition")
	}
	found := false
	for _, r := range d.Reasons {
		if strings.Contains(r, VBudgetExceeded) {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons must mention the budget violation: %v", d.Reasons)
	}
}

// 7. Default mode (AdditiveOnly=false) keeps the legacy semantics: the
// offline holder is replaced rather than retained.
func TestAdditiveOnlyDefaultModeStillReplacesOffline(t *testing.T) {
	nodes := cluster5()
	offlineLong(nodes)
	obj, _ := currentOn("obj-def", 1, 3, "n1", "n2")

	d := mustRun(t, snap(nodes, testPolicy(), obj))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s (%v), want plan_proposed", d.Status, d.Reasons)
	}
	for _, p := range d.Plan.TargetLayout.Replicas {
		if p.NodeID == "n2" {
			t.Fatalf("default mode should retire the offline placement: %+v", d.Plan.TargetLayout.Replicas)
		}
	}
	if pv := ValidatePlan(snap(nodes, testPolicy()), obj, *d.Plan, testPolicy()); !pv.Passed {
		t.Fatalf("plan failed validation: %+v", pv.Violations)
	}
}

// 8. Existing count at/above MaxReplicaCount: healthy objects are kept
// (no_change), degraded objects get an explicit no_feasible — never a
// shrink, replacement or move.
func TestAdditiveOnlyCapReached(t *testing.T) {
	nodes := cluster5()
	pol := additivePolicy()
	pol.MaxReplicaCount = 3

	// (a) healthy at the cap: keep
	objA, _ := currentOn("obj-cap-a", 1, 2, "n1", "n2", "n3")
	d := mustRun(t, snap(nodes, pol, objA))[0]
	if d.Status != StatusNoChange {
		t.Fatalf("healthy at cap: status = %s (%v), want no_change_needed", d.Status, d.Reasons)
	}

	// (b) degraded at the cap: explicit no-feasible
	nodes[1].Online = false
	nodes[1].Availability = forecast(0.1, 0.9, 3*86400)
	objB, _ := currentOn("obj-cap-b", 1, 2, "n1", "n2", "n3")
	d = mustRun(t, snap(nodes, pol, objB))[0]
	if d.Status != StatusNoFeasible || d.Plan != nil {
		t.Fatalf("degraded at cap: status = %s plan=%v, want no_feasible", d.Status, d.Plan)
	}
	joined := strings.Join(d.Reasons, "; ")
	if !strings.Contains(joined, "MaxReplicaCount") {
		t.Fatalf("reasons must explain the cap: %v", d.Reasons)
	}

	// (c) existing above the cap: same outcome, never shrunk into a plan
	objC, _ := currentOn("obj-cap-c", 1, 2, "n1", "n2", "n3", "n4")
	d = mustRun(t, snap(nodes, pol, objC))[0]
	if d.Status != StatusNoFeasible || d.Plan != nil {
		t.Fatalf("existing above cap: status = %s plan=%v, want no_feasible with no plan", d.Status, d.Plan)
	}
}

// 9. Brand-new objects get an initial replicate placement in additive mode.
func TestAdditiveOnlyNewObjectReplicateOnly(t *testing.T) {
	nodes := cluster5()
	obj := ObjectRequirement{ObjectID: "obj-new", SizeBytes: MB, ContentVersion: 1}
	pol := additivePolicy()
	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s (%v), want plan_proposed", d.Status, d.Reasons)
	}
	if d.Plan.TargetLayout.Scheme != SchemeReplicate {
		t.Fatalf("scheme = %s, want replicate", d.Plan.TargetLayout.Scheme)
	}
	if pv := ValidatePlan(snap(nodes, pol), obj, *d.Plan, pol); !pv.Passed {
		t.Fatalf("plan failed validation: %+v", pv.Violations)
	}
}

// 10. Retained placements are never re-charged against capacity: an offline
// node with ZERO verifiable free space keeps its existing placement, and only
// the new replica consumes free bytes.
func TestAdditiveOnlyRetainedOfflineNotRecharged(t *testing.T) {
	nodes := cluster5()
	offlineLong(nodes)
	nodes[1].ReservedBytes = MB // == HardCapacityBytes: zero verifiable free
	obj, cur := currentOn("obj-nofree", 1, 3, "n1", "n2")

	pol := additivePolicy()
	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s (%v), want plan_proposed", d.Status, d.Reasons)
	}
	assertSuperset(t, cur, d.Plan.TargetLayout)
	if pv := ValidatePlan(snap(nodes, pol), obj, *d.Plan, pol); !pv.Passed {
		t.Fatalf("retained offline placement was re-charged or otherwise rejected: %+v", pv.Violations)
	}
}

// 11. Wide fan-out (MaxReplicaCount=64 over 20 nodes) stays bounded and
// deterministic; targets never exceed the distinct-node bound.
func TestAdditiveOnlyBoundedRuntimeWideFanout(t *testing.T) {
	nodes := make([]Node, 0, 20)
	for i := 1; i <= 20; i++ {
		nodes = append(nodes, mkNode(fmt.Sprintf("n%02d", i), fmt.Sprintf("z%02d", i), MB, true))
	}
	offlineLong(nodes)
	obj, cur := currentOn("obj-wide", 1, 1, "n01", "n02")

	pol := additivePolicy()
	pol.MaxReplicaCount = 64

	start := time.Now()
	d := mustRun(t, snap(nodes, pol, obj))[0]
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("wide fan-out run took %s; search must stay bounded", elapsed)
	}
	if d.Status != StatusPlanProposed {
		t.Fatalf("status = %s (%v), want plan_proposed", d.Status, d.Reasons)
	}
	assertSuperset(t, cur, d.Plan.TargetLayout)
	if len(d.Plan.TargetLayout.Replicas) > len(nodes) {
		t.Fatalf("target holds %d placements on %d distinct nodes", len(d.Plan.TargetLayout.Replicas), len(nodes))
	}
}
