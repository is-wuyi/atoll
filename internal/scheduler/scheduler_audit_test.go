package scheduler

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Independent audit tests for Policy.AdditiveOnly (strict add-only mode).
//
// These complement scheduler_additive_test.go with a second, independent
// pass over the contract, from different angles:
//   - degraded objects can never receive a zero-migration ("no-op") repair
//     proposal, at any MaxReplicaCount setting (sweep, including below-cap,
//     at-cap and absurdly-above-cap values);
//   - no plan can pass the independent validator for an object whose
//     CURRENT layout is malformed — the superset-with-multiplicity check
//     and the duplicate-physical-node / index checks compose to make every
//     such plan impossible, even one crafted by an external caller;
//   - a re-indexed target (same node set, shifted fragment indices) is a
//     positional drop and is rejected in additive mode while default mode
//     keeps its legacy semantics;
//   - forged Origin labels cannot bypass capacity, migration or the
//     online-additions requirement (origins are re-derived, never trusted);
//   - the healthy path keeps anti-jitter and never moves/drops; the
//     new-object path produces dense canonical indices;
//   - the migration-budget boundary is exact (one addition fits at ==,
//     fails at -1) and the physical node bound clamps absurd MaxReplicaCount.
// ---------------------------------------------------------------------------

// auditAdditionOK checks every property an additive target must have when a
// repair/addition is proposed: superset of current positions, distinct new
// nodes that are online and previously unused, new fragment indices strictly
// after the existing ones, positive migration bytes, and no move/regenerate
// actions. It fails the test with a descriptive message otherwise.
func auditAdditionOK(t *testing.T, cur *Layout, d Decision, nodes []Node) {
	t.Helper()
	if d.Plan == nil {
		t.Fatalf("status %s but no plan", d.Status)
	}
	tl := d.Plan.TargetLayout
	if tl.Scheme != SchemeReplicate {
		t.Fatalf("additive target scheme %s, want replicate", tl.Scheme)
	}
	assertSuperset(t, cur, tl)

	used := map[string]bool{}
	maxExisting := -1
	for _, p := range cur.Replicas {
		used[p.NodeID] = true
		if p.FragmentIndex > maxExisting {
			maxExisting = p.FragmentIndex
		}
	}
	added := 0
	seenIdx := map[int]bool{}
	for _, p := range tl.Replicas {
		if seenIdx[p.FragmentIndex] {
			t.Fatalf("target repeats fragment index %d: %+v", p.FragmentIndex, tl.Replicas)
		}
		seenIdx[p.FragmentIndex] = true
		if p.Origin != OriginNew {
			continue
		}
		added++
		if p.FragmentIndex <= maxExisting {
			t.Fatalf("new placement at index %d must come strictly after existing max index %d: %+v", p.FragmentIndex, maxExisting, p)
		}
		if used[p.NodeID] {
			t.Fatalf("new placement on node %q that already holds the object: %+v", p.NodeID, p)
		}
		if !nodes[indexOf(nodes, p.NodeID)].Online {
			t.Fatalf("new placement on offline node %q: %+v", p.NodeID, p)
		}
	}
	if added == 0 || d.Plan.MigrationBytes == 0 {
		t.Fatalf("additive repair must add bytes: added=%d mig=%d", added, d.Plan.MigrationBytes)
	}
	for _, a := range d.Plan.Actions {
		if a.Kind == "move_replica" || a.Kind == "regenerate_fragment" {
			t.Fatalf("additive plan contains %s action: %+v", a.Kind, a)
		}
	}
}

// A1. Degraded additive objects never receive a no-op proposal, at any cap.
// The sweep covers caps below the current count (rMin > rMax: no candidate
// family at all), equal to it (only the keep-clone) and far above it (the
// physical node bound must clamp).
func TestAuditAdditiveDegradeNeverNoOpAcrossCapSweep(t *testing.T) {
	for _, cap := range []int{1, 2, 3, 4, 5, 1000} {
		nodes := cluster5()
		offlineLong(nodes) // n2 offline, non-routine spell -> degraded path
		obj, cur := currentOn(fmt.Sprintf("obj-sweep-%d", cap), 1, 3, "n1", "n2")
		pol := additivePolicy()
		pol.MaxReplicaCount = cap

		d := mustRun(t, snap(nodes, pol, obj))[0]
		switch d.Status {
		case StatusPlanProposed:
			auditAdditionOK(t, cur, d, nodes)
			// physical + policy bounds on the target size
			r := len(d.Plan.TargetLayout.Replicas)
			wantCap := cap
			if wantCap > len(nodes) {
				wantCap = len(nodes)
			}
			if r > wantCap {
				t.Fatalf("cap %d: target r=%d exceeds min(MaxReplicaCount, nodes)=%d", cap, r, wantCap)
			}
			if r <= len(cur.Replicas) {
				t.Fatalf("cap %d: target r=%d must exceed the current count %d", cap, r, len(cur.Replicas))
			}
		case StatusNoFeasible:
			if d.Plan != nil {
				t.Fatalf("cap %d: no_feasible must not carry a plan", cap)
			}
			if cap > len(cur.Replicas) {
				// With headroom above the current count the cluster (3 spare
				// online nodes) must be able to fund an addition: only the
				// infeasible zero-op family may cause no_feasible here, and
				// that would be a routing bug.
				t.Fatalf("cap %d: degraded object with spare nodes got no_feasible: %v", cap, d.Reasons)
			}
		default:
			t.Fatalf("cap %d: unexpected status %s (%v)", cap, d.Status, d.Reasons)
		}
	}
}

// A2. Malformed currents: the engine refuses them AND no externally crafted
// plan can validate — the additive checks compose so that satisfying the
// position superset of a malformed current forces a target that the
// duplicate-node / index checks reject.
func TestAuditAdditiveMalformedCurrentNoPassingPlan(t *testing.T) {
	nodes := cluster5()
	pol := additivePolicy()

	mk := func(id string, reps []FragmentPlacement) (ObjectRequirement, Plan) {
		cur := &Layout{ObjectID: id, ContentVersion: 2, LayoutEpoch: 5,
			Scheme: SchemeReplicate, Replicas: reps}
		obj := ObjectRequirement{ObjectID: id, SizeBytes: MB, ContentVersion: 2, CurrentLayout: cur}
		// Best-intent target: exactly the current positions (a superset with
		// multiplicity) — if even this cannot pass, nothing can.
		target := append([]FragmentPlacement(nil), reps...)
		plan := Plan{ObjectID: id, BaseContentVersion: 2, BaseLayoutEpoch: 5, Shadow: true,
			MigrationBytes: 0,
			TargetLayout: Layout{ObjectID: id, ContentVersion: 2, LayoutEpoch: 6,
				Scheme: SchemeReplicate, Replicas: target}}
		return obj, plan
	}

	cases := []struct {
		name      string
		reps      []FragmentPlacement
		engineCod string
		planCod   string
	}{
		{"duplicate node", []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
			{NodeID: "n1", FragmentIndex: 1, Bytes: MB, Origin: OriginExisting}},
			VDuplicatePlacement, VAdditiveDupNode},
		{"duplicate index", []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
			{NodeID: "n2", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting}},
			VIndexDuplicate, VIndexDuplicate},
		{"negative index", []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: -1, Bytes: MB, Origin: OriginExisting}},
			VIndexInvalid, VIndexInvalid},
		{"index out of range", []FragmentPlacement{
			{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
			{NodeID: "n2", FragmentIndex: 2, Bytes: MB, Origin: OriginExisting}},
			VIndexInvalid, VIndexInvalid},
	}
	for _, tc := range cases {
		id := "obj-mal-" + strings.ReplaceAll(tc.name, " ", "-")
		obj, plan := mk(id, tc.reps)

		// Engine side: invalid requirement, nothing derived.
		d := mustRun(t, snap(nodes, pol, obj))[0]
		if d.Status != StatusInvalid || d.Plan != nil {
			t.Fatalf("%s: engine status %s plan=%v, want invalid with no plan", tc.name, d.Status, d.Plan)
		}
		if !hasViolation(d.Validation, tc.engineCod) {
			t.Fatalf("%s: engine want violation %s, got %+v", tc.name, tc.engineCod, d.Validation)
		}

		// Validator side: even the exact-superset plan is rejected.
		rep := ValidatePlan(snap(nodes, pol), obj, plan, pol)
		if rep.Passed {
			t.Fatalf("%s: malformed current produced a passing additive plan", tc.name)
		}
		if !hasViolation(rep, tc.planCod) {
			t.Fatalf("%s: plan want violation %s, got %+v", tc.name, tc.planCod, rep.Violations)
		}
	}
}

// A3. Re-indexing the same node set is a positional drop: additive mode
// rejects it, default mode keeps the legacy node-set semantics.
func TestAuditAdditiveReindexOnlyTargetRejected(t *testing.T) {
	nodes := cluster5()
	obj, _ := currentOn("obj-reidx", 4, 2, "n1", "n2", "n3")
	plan := Plan{
		ObjectID: "obj-reidx", BaseContentVersion: 4, BaseLayoutEpoch: 2, Shadow: true,
		MigrationBytes: 3 * MB, // no position survives: full rewrite per re-derivation
		TargetLayout: Layout{ObjectID: "obj-reidx", ContentVersion: 4, LayoutEpoch: 3,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 1, Bytes: MB, Origin: OriginNew},
				{NodeID: "n2", FragmentIndex: 2, Bytes: MB, Origin: OriginNew},
				{NodeID: "n3", FragmentIndex: 0, Bytes: MB, Origin: OriginNew},
			}},
	}
	pol := additivePolicy()
	rep := ValidatePlan(snap(nodes, pol), obj, plan, pol)
	if rep.Passed || !hasViolation(rep, VAdditiveNotSuperset) {
		t.Fatalf("re-indexed target must be rejected as %s, got passed=%v violations=%+v",
			VAdditiveNotSuperset, rep.Passed, rep.Violations)
	}
	if n := 0; false {
		_ = n
	}
	// Default mode: same plan is a legal legacy repair (positions may move).
	if rep := ValidatePlan(snap(nodes, testPolicy()), obj, plan, testPolicy()); !rep.Passed {
		t.Fatalf("default mode must keep legacy reindex semantics: %+v", rep.Violations)
	}
}

// A4. Forged origins cannot bypass capacity/migration accounting: the plan
// below is a valid positional superset — the additive superset check itself
// passes — but the forged "existing" label on a full node is re-derived and
// the plan dies on the recomputed migration bytes and capacity budget.
func TestAuditAdditiveForgedOriginSupersetStillRejected(t *testing.T) {
	nodes := cluster5()
	nodes[1].ReservedBytes = MB // n2 completely full
	pol := additivePolicy()
	obj, _ := currentOn("obj-forge2", 3, 1, "n1")
	plan := Plan{
		ObjectID: "obj-forge2", BaseContentVersion: 3, BaseLayoutEpoch: 1, Shadow: true,
		MigrationBytes: 0, // forged: claims nothing moves
		TargetLayout: Layout{ObjectID: "obj-forge2", ContentVersion: 3, LayoutEpoch: 2,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
				{NodeID: "n2", FragmentIndex: 1, Bytes: MB, Origin: OriginExisting}, // forged
			}},
	}
	rep := ValidatePlan(snap(nodes, pol), obj, plan, pol)
	if rep.Passed {
		t.Fatalf("forged-origin superset plan must not pass")
	}
	if hasViolation(rep, VAdditiveNotSuperset) {
		t.Fatalf("superset check should pass for this target; rejection must come from re-derivation: %+v", rep.Violations)
	}
	if !hasViolation(rep, VMigrationMismatch) {
		t.Fatalf("re-derived migration must expose the forged zero-byte claim: %+v", rep.Violations)
	}
	if !hasViolation(rep, VCapacity) {
		t.Fatalf("re-derived new placement on the full node must trip capacity: %+v", rep.Violations)
	}
}

// A5. Forged origin on an OFFLINE node: re-derivation marks the placement new
// and the additive online-additions requirement rejects it — even though the
// plan self-reports it as existing.
func TestAuditAdditiveForgedOriginOnOfflineNodeRejected(t *testing.T) {
	nodes := cluster5()
	offlineLong(nodes)
	pol := additivePolicy()
	obj, _ := currentOn("obj-off2", 3, 1, "n1")
	plan := Plan{
		ObjectID: "obj-off2", BaseContentVersion: 3, BaseLayoutEpoch: 1, Shadow: true,
		MigrationBytes: MB, // honestly declared, but the target itself is illegal
		TargetLayout: Layout{ObjectID: "obj-off2", ContentVersion: 3, LayoutEpoch: 2,
			Scheme: SchemeReplicate,
			Replicas: []FragmentPlacement{
				{NodeID: "n1", FragmentIndex: 0, Bytes: MB, Origin: OriginExisting},
				{NodeID: "n2", FragmentIndex: 1, Bytes: MB, Origin: OriginExisting}, // forged: n2 offline
			}},
	}
	rep := ValidatePlan(snap(nodes, pol), obj, plan, pol)
	if rep.Passed {
		t.Fatalf("addition on an offline node must not pass, whatever the origin label says")
	}
	if !hasViolation(rep, VAdditiveOfflineNew) {
		t.Fatalf("re-derived new placement on offline node must trip %s: %+v", VAdditiveOfflineNew, rep.Violations)
	}
}

// A6. Healthy additive objects: anti-jitter holds (a plain extra replica does
// not clear the default threshold -> no_change); with durability weighted,
// the same scene proposes a pure addition; at the cap, only keep remains.
func TestAuditAdditiveHealthyPaths(t *testing.T) {
	nodes := cluster5()

	// (a) default weights: keep (no churn, no move/drop).
	objA, _ := currentOn("obj-h1", 1, 2, "n1", "n2")
	d := mustRun(t, snap(nodes, additivePolicy(), objA))[0]
	if d.Status != StatusNoChange {
		t.Fatalf("healthy below cap: status %s (%v), want no_change_needed", d.Status, d.Reasons)
	}
	if d.Plan != nil {
		t.Fatalf("no_change decision must not carry a plan")
	}

	// (b) durability-weighted: a pure addition clears the threshold.
	objB, _ := currentOn("obj-h2", 1, 2, "n1", "n2")
	objB.Intent = ProtectionIntent{Weights: ScoreWeights{Durability: 1}}
	pol := additivePolicy()
	d = mustRun(t, snap(nodes, pol, objB))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("healthy durability-weighted: status %s (%v), want plan_proposed", d.Status, d.Reasons)
	}
	auditAdditionOK(t, objB.CurrentLayout, d, nodes)
	if got := len(d.Plan.TargetLayout.Replicas); got != 3 {
		t.Fatalf("healthy addition should grow r=2 -> 3, got %d: %+v", got, d.Plan.TargetLayout.Replicas)
	}
	if pv := ValidatePlan(snap(nodes, pol), objB, *d.Plan, pol); !pv.Passed {
		t.Fatalf("healthy addition plan failed validation: %+v", pv.Violations)
	}

	// (c) healthy at the cap: only the keep-clone exists; the anti-jitter
	// gate turns it into no_change (never a move, never a drop).
	polCap := additivePolicy()
	polCap.MaxReplicaCount = 2
	objC, _ := currentOn("obj-h3", 1, 2, "n1", "n2")
	d = mustRun(t, snap(nodes, polCap, objC))[0]
	if d.Status != StatusNoChange {
		t.Fatalf("healthy at cap: status %s (%v), want no_change_needed", d.Status, d.Reasons)
	}
}

// A7. New objects in additive mode: dense canonical indices 0..r-1, distinct
// online nodes, all placements new, within [MinFaultTolerance+1, cap].
func TestAuditAdditiveNewObjectDenseIndices(t *testing.T) {
	nodes := cluster5()
	pol := additivePolicy()
	pol.MaxReplicaCount = 3
	obj := ObjectRequirement{ObjectID: "obj-new2", SizeBytes: 100 * KB, ContentVersion: 1}

	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status %s (%v), want plan_proposed", d.Status, d.Reasons)
	}
	tl := d.Plan.TargetLayout
	r := len(tl.Replicas)
	if r < pol.MinFaultTolerance+1 || r > pol.MaxReplicaCount || r > len(nodes) {
		t.Fatalf("new-object r=%d out of [MFT+1=%d, min(cap=%d, nodes=%d)]",
			r, pol.MinFaultTolerance+1, pol.MaxReplicaCount, len(nodes))
	}
	seenNode, seenIdx := map[string]bool{}, map[int]bool{}
	for i, p := range tl.Replicas {
		if p.FragmentIndex != i {
			t.Fatalf("indices must be dense 0..r-1: %+v", tl.Replicas)
		}
		if seenIdx[p.FragmentIndex] || seenNode[p.NodeID] {
			t.Fatalf("duplicate index/node in target: %+v", tl.Replicas)
		}
		seenIdx[p.FragmentIndex], seenNode[p.NodeID] = true, true
		if p.Origin != OriginNew {
			t.Fatalf("new-object placement must be origin=new: %+v", p)
		}
		if !nodes[indexOf(nodes, p.NodeID)].Online {
			t.Fatalf("new-object placement on offline node: %+v", p)
		}
	}
	if pv := ValidatePlan(snap(nodes, pol), obj, *d.Plan, pol); !pv.Passed {
		t.Fatalf("new-object plan failed validation: %+v", pv.Violations)
	}
}

// A8. Migration budget boundary in additive mode: an addition that exactly
// fits is proposed; one byte less makes it explicitly no_feasible with the
// budget violation surfaced. The mode never shrinks/replaces to fit.
func TestAuditAdditiveBudgetBoundaryExact(t *testing.T) {
	for _, tc := range []struct {
		budget  uint64
		status  string
		wantMig uint64
	}{{MB, StatusPlanProposed, MB}, {MB - 1, StatusNoFeasible, 0}} {
		nodes := cluster5()
		offlineLong(nodes)
		obj, _ := currentOn("obj-bud", 1, 3, "n1", "n2")
		pol := additivePolicy()
		pol.MaxReplicaCount = 3 // exactly one addition is possible
		pol.MaxMigrationBytesBudget = tc.budget

		d := mustRun(t, snap(nodes, pol, obj))[0]
		if d.Status != tc.status {
			t.Fatalf("budget %d: status %s (%v), want %s", tc.budget, d.Status, d.Reasons, tc.status)
		}
		if d.Status == StatusPlanProposed {
			if d.Plan.MigrationBytes != tc.wantMig {
				t.Fatalf("budget %d: migration %d, want exactly %d", tc.budget, d.Plan.MigrationBytes, tc.wantMig)
			}
			if pv := ValidatePlan(snap(nodes, pol), obj, *d.Plan, pol); !pv.Passed {
				t.Fatalf("boundary-budget plan failed validation: %+v", pv.Violations)
			}
		} else {
			found := false
			for _, r := range d.Reasons {
				if strings.Contains(r, VBudgetExceeded) {
					found = true
				}
			}
			if !found {
				t.Fatalf("budget %d: no_feasible reasons must cite %s: %v", tc.budget, VBudgetExceeded, d.Reasons)
			}
		}
	}
}

// A9. The r knob is a search cap, not a fixed replication factor: candidates
// enumerate the whole legal r range; absurd MaxReplicaCount values clamp to
// the physical node bound and stay bounded in time. The degraded selection
// always names a real (non-keep) candidate matching the plan target.
func TestAuditAdditiveRateBoundAndSelectionMatch(t *testing.T) {
	nodes := cluster5()
	offlineLong(nodes)
	obj, cur := currentOn("obj-rate", 1, 3, "n1", "n2")
	pol := additivePolicy()
	pol.MaxReplicaCount = 1000 // absurd: must clamp to the node bound

	start := time.Now()
	d := mustRun(t, snap(nodes, pol, obj))[0]
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("clamped search took %s; must stay bounded", elapsed)
	}

	seenR := map[int]bool{}
	for _, c := range d.Candidates {
		if c.R > len(nodes) {
			t.Fatalf("candidate r=%d exceeds the physical node bound %d", c.R, len(nodes))
		}
		seenR[c.R] = true
	}
	// The family must span the whole legal range [max(MFT+1, curN), nodes].
	for r := 2; r <= len(nodes); r++ {
		if !seenR[r] {
			t.Fatalf("candidate family missing legal r=%d: seen %v", r, seenR)
		}
	}
	if d.Status != StatusPlanProposed {
		t.Fatalf("status %s (%v), want plan_proposed", d.Status, d.Reasons)
	}
	if d.SelectedID == "keep" {
		t.Fatalf("degraded selection must never be the keep candidate")
	}
	auditAdditionOK(t, cur, d, nodes)

	// Selected candidate's placement must match the plan target exactly.
	var match *Candidate
	for i := range d.Candidates {
		if d.Candidates[i].CandidateID == d.SelectedID {
			match = &d.Candidates[i]
			break
		}
	}
	if match == nil {
		t.Fatalf("SelectedID %q not among reported candidates", d.SelectedID)
	}
	key := func(ps []FragmentPlacement) []string {
		var out []string
		for _, p := range ps {
			out = append(out, fmt.Sprintf("%s#%d", p.NodeID, p.FragmentIndex))
		}
		return out
	}
	want, got := key(match.Placement), key(d.Plan.TargetLayout.Replicas)
	if len(want) != len(got) {
		t.Fatalf("selected candidate %v != plan target %v", want, got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("selected candidate %v != plan target %v", want, got)
		}
	}
}

// A10. Adapter shape (master autonomy mapping): history-only nodes — no
// Availability forecast — with a Done=false/Suspect holder mapped to
// Online=false and an offline sample history. The repair must keep the
// holder's position verbatim, add only on verifiably online nodes, and the
// plan must pass the independent exit gate.
func TestAuditAdditiveAdapterShapeHistoryNodes(t *testing.T) {
	nodes := make([]Node, 0, 5)
	for i := 1; i <= 5; i++ {
		n := mkNode(fmt.Sprintf("n%d", i), fmt.Sprintf("z%d", i), 10*MB, true)
		n.Availability = nil // adapter passes History, not forecasts
		n.History = sampleHistory(testNow, 24, func(int) bool { return true })
		nodes = append(nodes, n)
	}
	// Suspect holder: online heartbeat says offline, history says offline.
	nodes[1].Online = false
	nodes[1].History = sampleHistory(testNow, 24, func(int) bool { return false })

	pol := additivePolicy()
	pol.MaxReplicaCount = 4
	pol.MinConfidence = 0.7
	obj, cur := currentOn("obj-adapt", 1, 1, "n1", "n2", "n3")

	d := mustRun(t, snap(nodes, pol, obj))[0]
	if d.Status != StatusPlanProposed {
		t.Fatalf("status %s (%v), want plan_proposed", d.Status, d.Reasons)
	}
	auditAdditionOK(t, cur, d, nodes)
	// The suspect holder's position is retained verbatim, never re-written.
	for _, p := range d.Plan.TargetLayout.Replicas {
		if p.NodeID == "n2" && p.Origin != OriginExisting {
			t.Fatalf("suspect holder must be retained as existing: %+v", p)
		}
	}
	if pv := ValidatePlan(snap(nodes, pol), obj, *d.Plan, pol); !pv.Passed {
		t.Fatalf("adapter-shape plan failed independent validation: %+v", pv.Violations)
	}
}
