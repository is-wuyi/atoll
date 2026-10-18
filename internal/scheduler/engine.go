package scheduler

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Candidate engine.
//
// Generates fully-placed layout candidates (replication with auto-selected
// factor, RS k/m traversal bounded by configurable codec limits), scores
// them with explicit units and normalization, and hands every candidate to
// the independent validator before it can be selected. EC layouts are
// simulated only (RequiresECBackend) — the engine never encodes.
//
// Search strategy:
//   - small groups: exact enumeration of node combinations when
//     C(eligible, slots) <= Search.ExactComboLimit;
//   - otherwise: deterministic greedy fill preferring distinct failure
//     domains, improved by a bounded local swap search over the top
//     Search.BeamWidth nodes;
//   - migration cost is part of scoring (stability) so repairs prefer
//     small changes and healthy layouts are not perturbed (anti-jitter
//     threshold on top).
//
// Nothing here is a global-optimum claim: with the bounded search the
// result is a well-scored feasible candidate, deterministically produced.
// ---------------------------------------------------------------------------

type rawMetrics struct {
	durMinAfter int     // distinct shards readable after worst single group loss (t = MinFaultTolerance)
	readProb    float64 // predicted readability over horizon, [0,1]
	costRaw     float64 // sum(placement bytes * node cost) — cost-weighted GB-month
	perfRaw     float64 // read-set RTT, ms
	migBytes    uint64  // migration bytes vs current layout
	feasible    bool    // cheap proxy: margin + capacity + readable-now pass (final gate is the independent validator)
}

type builtCandidate struct {
	cand Candidate
	raw  rawMetrics
}

type engine struct {
	snap   *Snapshot
	nodes  map[string]*Node
	order  []string // canonical node order
	now    time.Time
	policy Policy
}

func newEngine(snap *Snapshot, policy Policy, now time.Time) *engine {
	e := &engine{snap: snap, nodes: nodeIndex(snap), now: now, policy: policy}
	for _, n := range snap.Nodes {
		e.order = append(e.order, n.ID)
	}
	// Deterministic desirability order: predicted online probability desc,
	// free bytes desc, RTT asc, cost asc, ID asc.
	sort.Slice(e.order, func(a, b int) bool {
		na, nb := e.nodes[e.order[a]], e.nodes[e.order[b]]
		pa, pb := e.predict(na), e.predict(nb)
		if pa.ProbabilityOnline != pb.ProbabilityOnline {
			return pa.ProbabilityOnline > pb.ProbabilityOnline
		}
		fa, _ := FreeBytes(*na)
		fb, _ := FreeBytes(*nb)
		if fa != fb {
			return fa > fb
		}
		if na.RTTMs != nb.RTTMs {
			return na.RTTMs < nb.RTTMs
		}
		if na.CostPerGBMonth != nb.CostPerGBMonth {
			return na.CostPerGBMonth < nb.CostPerGBMonth
		}
		return na.ID < nb.ID
	})
	return e
}

func (e *engine) predict(n *Node) Prediction {
	h := e.policy.PredictionHorizonSeconds
	if h <= 0 {
		h = 86400
	}
	return effectivePrediction(n, e.now, h, e.policy.MinConfidence)
}

// eligibleForNew returns node IDs that may receive new bytes: online, with
// a declared hard budget and verifiable free space >= need.
func (e *engine) eligibleForNew(need uint64) []string {
	var out []string
	for _, id := range e.order {
		n := e.nodes[id]
		free, ok := FreeBytes(*n)
		if !ok || !n.Online || free < need {
			continue
		}
		out = append(out, id)
	}
	return out
}

// decide produces the shadow decision for one object requirement.
func (e *engine) decide(obj ObjectRequirement) Decision {
	d := Decision{ObjectID: obj.ObjectID}

	if obj.SizeBytes == 0 {
		d.Status = StatusInvalid
		d.Validation = &ValidationReport{Passed: false, Violations: []Violation{{
			Code: VSizeInvalid, Message: fmt.Sprintf("object %q size_bytes must be > 0", obj.ObjectID),
		}}}
		d.Reasons = []string{"size_bytes must be > 0"}
		return d
	}

	var current *Layout
	if obj.CurrentLayout != nil {
		// Unknown node or malformed scheme in the current layout: refuse to
		// reason about storage we cannot identify.
		for _, p := range obj.CurrentLayout.Replicas {
			if _, ok := e.nodes[p.NodeID]; !ok {
				d.Status = StatusInvalid
				d.Validation = ValidateLayout(e.snap, obj, *obj.CurrentLayout, e.policy)
				d.Reasons = []string{fmt.Sprintf("current layout references unknown node %q", p.NodeID)}
				return d
			}
		}
		current = obj.CurrentLayout
	}

	// Strict add-only mode: screen the current layout before deriving
	// anything from it. Malformed currents are never carried into the
	// additive derivation (there is no honest guess about what to keep), and
	// an RS current has no additive action at all — replicate targets only,
	// and converting RS would be the forbidden EC/scheme change.
	if e.policy.AdditiveOnly && current != nil {
		switch {
		case current.Scheme == SchemeRS:
			d.Status = StatusNoFeasible
			d.Reasons = []string{"additive_only: current layout is SchemeRS; this mode extends replication layouts only and never re-splits or converts (no EC, no scheme change)"}
			return d
		case current.Scheme != SchemeReplicate:
			msg := fmt.Sprintf("current layout scheme %q is not supported in additive_only mode", current.Scheme)
			d.Status = StatusInvalid
			d.Validation = &ValidationReport{Passed: false, Violations: []Violation{{Code: VIndexInvalid, Message: msg}}}
			d.Reasons = []string{msg}
			return d
		default:
			if code, msg := additiveCurrentDefect(current); code != "" {
				d.Status = StatusInvalid
				d.Validation = &ValidationReport{Passed: false, Violations: []Violation{{Code: code, Message: msg}}}
				d.Reasons = []string{msg}
				return d
			}
		}
	}

	minRequired := 1
	if current != nil && current.Scheme == SchemeRS && current.EC != nil {
		minRequired = current.EC.K
	}
	onlineDistinct, offlineHolders := e.liveState(current)

	// --- validate current layout independently -----------------------------
	var currentRep *ValidationReport
	currentOK := false
	if current != nil {
		cur := *current
		for i := range cur.Replicas {
			if cur.Replicas[i].Origin == OriginNew {
				cur.Replicas[i].Origin = OriginExisting
			}
		}
		currentRep = validateLayoutAt(e.snap, obj, cur, e.policy, e.nodes, e.now, &ValidationReport{Passed: true})
		currentOK = currentRep.Passed
	}

	// --- defer eligibility ("regular offline can wait") --------------------
	deferEligible := false
	var deferReasons []string
	if current != nil && len(offlineHolders) > 0 {
		// Domain-aware ONLINE-subset margin: the shards that remain online
		// must themselves survive MinFaultTolerance group failures with the
		// required margin. A count-based onlineDistinct - k margin misses
		// correlated loss of the surviving set (e.g. all survivors in one
		// zone).
		onlineWorst := e.onlineWorstAfterGroupFailures(current)
		margin := onlineWorst - minRequired
		marginOK := margin >= e.policy.MinFaultMarginToDefer
		spellOK, maxSpell := e.spellsRoutine(offlineHolders)
		if marginOK && spellOK && currentOK {
			deferEligible = true
			deferReasons = append(deferReasons,
				fmt.Sprintf("object readable now: %d distinct online %s (need %d)", onlineDistinct, unitWord(*current), minRequired),
				fmt.Sprintf("online-subset fault margin %d >= MinFaultMarginToDefer %d (after any %d failure-domain loss within the online set, %d readable %s remain)",
					margin, e.policy.MinFaultMarginToDefer, maxInt(1, e.policy.MinFaultTolerance), onlineWorst, unitWord(*current)),
				fmt.Sprintf("longest predicted offline spell %.0fs <= MaxDeferOfflineSeconds %ds (routine outage; wait for return instead of migrating)", maxSpell, e.policy.MaxDeferOfflineSeconds),
			)
		} else {
			if !marginOK {
				deferReasons = append(deferReasons, fmt.Sprintf("online-subset fault margin %d < MinFaultMarginToDefer %d: surviving shards share failure domains or the outage eats the safety margin, rebuild required", margin, e.policy.MinFaultMarginToDefer))
			}
			if !spellOK {
				deferReasons = append(deferReasons, fmt.Sprintf("predicted offline spell %.0fs exceeds MaxDeferOfflineSeconds %ds: not a routine outage", maxSpell, e.policy.MaxDeferOfflineSeconds))
			}
		}
	}

	// --- build candidates ---------------------------------------------------
	var built []builtCandidate
	seq := 0
	// add returns the index of the appended candidate in `built`, or -1.
	// (An index, never a pointer: `built` reallocates as it grows, so a
	// pointer into it would dangle.)
	add := func(scheme Scheme, r int, ec *ECParams, placement []FragmentPlacement, requiresEC bool) int {
		if len(placement) == 0 {
			return -1
		}
		if e.policy.Search.MaxCandidates > 0 && seq >= e.policy.Search.MaxCandidates {
			return -1
		}
		seq++
		layout := Layout{
			ObjectID:       obj.ObjectID,
			ContentVersion: obj.ContentVersion,
			Scheme:         scheme,
			Replicas:       placement,
			EC:             ec,
		}
		if current != nil {
			layout.LayoutEpoch = current.LayoutEpoch + 1
		} else {
			layout.LayoutEpoch = 1
		}
		mig := migrationBytesBetween(current, &layout)

		// per-index probabilities + independent validation
		raw := e.rawMetricsFor(layout, obj, mig)
		cand := Candidate{
			CandidateID:       candidateID(scheme, r, ec, seq),
			Scheme:            scheme,
			R:                 r,
			EC:                ec,
			Placement:         placement,
			RequiresECBackend: requiresEC,
			MigrationBytes:    mig,
		}
		built = append(built, builtCandidate{cand: cand, raw: raw})
		return len(built) - 1
	}

	// keep-current candidate (stable ID "keep"; excluded from repairs)
	if current != nil {
		keep := make([]FragmentPlacement, len(current.Replicas))
		copy(keep, current.Replicas)
		for i := range keep {
			keep[i].Origin = OriginExisting
		}
		if kb := add(current.Scheme, len(keep), cloneEC(current.EC), keep, current.Scheme == SchemeRS); kb >= 0 {
			built[kb].cand.CandidateID = "keep"
		}
	}

	// Replication candidates are always generated (including for objects
	// currently on RS: an executable replication rebuild must compete with
	// simulated EC repairs). In strict add-only mode the whole search is
	// replaced: replication only, additive builder, r never below the
	// current placement count (kept verbatim) nor below
	// MinFaultTolerance+1, capped by MaxReplicaCount.
	if e.policy.AdditiveOnly {
		rMin := e.policy.MinFaultTolerance + 1
		if rMin < 1 {
			rMin = 1
		}
		curN := 0
		if current != nil {
			curN = len(current.Replicas)
		}
		if curN > rMin {
			rMin = curN
		}
		rMax := e.policy.MaxReplicaCount
		if rMax <= 0 {
			rMax = 3
		}
		// Physical bound: an additive target holds distinct nodes only, so
		// r can never exceed kept nodes + snapshot nodes. Clamping keeps the
		// loop bounded for any MaxReplicaCount input (e.g. 64 over 20 nodes).
		if hi := len(e.order) + curN; rMax > hi {
			rMax = hi
		}
		for r := rMin; r <= rMax; r++ {
			var place []FragmentPlacement
			if current == nil {
				// brand-new object: nothing to preserve, standard builder
				place = e.buildSlots(obj, r, obj.SizeBytes, nil, -1)
			} else {
				place = e.buildAdditive(obj, r, current)
			}
			add(SchemeReplicate, r, nil, place, false)
		}
	} else {
		{
			rMin := e.policy.MinFaultTolerance + 1
			if rMin < 1 {
				rMin = 1
			}
			rMax := e.policy.MaxReplicaCount
			if rMax <= 0 {
				rMax = 3
			}
			if rMax > len(e.order) {
				rMax = len(e.order)
			}
			for r := rMin; r <= rMax; r++ {
				place := e.buildReplication(obj, r, current)
				add(SchemeReplicate, r, nil, place, false)
			}
		}

		if e.codecEnabled() {
			cl := e.policy.CodecLimits
			// Physical/support caps on the traversal: shards never exceed the
			// node count or the supported RS range (the validator rejects
			// k+m > maxSupportedShards outright), so a huge MaxK can only cost
			// the clamped loop, never an unbounded one.
			kHi := cl.MaxK
			if kHi > len(e.order) {
				kHi = len(e.order)
			}
			if kHi > maxSupportedShards-1 {
				kHi = maxSupportedShards - 1 // m >= 1
			}
			for k := max(1, cl.MinK); k <= kHi; k++ {
				frag, ok := fragBytes(obj.SizeBytes, k)
				if !ok {
					continue // size/k overflows: object cannot be EC-split
				}
				mHi := cl.MaxM
				for _, capVal := range []int{maxSupportedShards - k, len(e.order) - k} {
					if mHi > capVal {
						mHi = capVal
					}
				}
				if cl.MaxTotalShards > 0 && mHi > cl.MaxTotalShards-k {
					mHi = cl.MaxTotalShards - k
				}
				for m := max(1, cl.MinM); m <= mHi; m++ {
					if m < e.policy.MinFaultTolerance {
						continue // RS tolerates m shard losses; must meet minimum
					}
					place := e.buildRS(obj, k, m, frag, current)
					add(SchemeRS, 0, &ECParams{K: k, M: m}, place, true)
				}
			}
		}
	}

	// --- validate every candidate independently; score feasible ones -------
	weights := resolveWeights(obj.Intent, &e.policy)
	for i := range built {
		b := &built[i]
		layout := Layout{
			ObjectID: obj.ObjectID, ContentVersion: obj.ContentVersion,
			LayoutEpoch: epochFor(current), Scheme: b.cand.Scheme,
			Replicas: b.cand.Placement, EC: b.cand.EC,
		}
		rep := validateLayoutAt(e.snap, obj, layout, e.policy, e.nodes, e.now, &ValidationReport{Passed: true})
		if e.policy.MaxMigrationBytesBudget > 0 && b.cand.MigrationBytes > e.policy.MaxMigrationBytesBudget {
			violate(rep, VBudgetExceeded,
				fmt.Sprintf("migration %d B exceeds policy budget %d B", b.cand.MigrationBytes, e.policy.MaxMigrationBytesBudget))
		}
		b.cand.Feasible = rep.Passed
		if !rep.Passed {
			b.cand.InfeasibleReason = rep.Violations[0].Code + ": " + rep.Violations[0].Message
		}
	}

	// normalize + score feasible candidates (round-relative normalization)
	var feasible []*builtCandidate
	for i := range built {
		if built[i].cand.Feasible {
			feasible = append(feasible, &built[i])
		}
	}
	e.scoreAll(feasible, weights)

	// --- select -------------------------------------------------------------
	sort.SliceStable(built, func(a, b int) bool {
		// output ordering: feasible first, then score desc, migration asc, id asc
		if built[a].cand.Feasible != built[b].cand.Feasible {
			return built[a].cand.Feasible
		}
		if built[a].cand.Score.Total != built[b].cand.Score.Total {
			return built[a].cand.Score.Total > built[b].cand.Score.Total
		}
		if built[a].cand.MigrationBytes != built[b].cand.MigrationBytes {
			return built[a].cand.MigrationBytes < built[b].cand.MigrationBytes
		}
		return built[a].cand.CandidateID < built[b].cand.CandidateID
	})
	for i := range built {
		built[i].cand.Reasons = e.reasonsFor(&built[i], obj)
	}

	var best *builtCandidate
	for i := range built {
		if built[i].cand.Feasible {
			best = &built[i]
			break
		}
	}

	// decision-level candidate list (bounded, deterministic)
	for i := range built {
		if len(d.Candidates) >= 8 {
			break
		}
		d.Candidates = append(d.Candidates, built[i].cand)
	}
	if best != nil {
		d.SelectedID = best.cand.CandidateID
	}

	// --- status -------------------------------------------------------------
	switch {
	case current == nil:
		if best == nil {
			d.Status = StatusNoFeasible
			d.Reasons = e.noFeasibleReasons(built, "new object: no feasible placement under hard budgets/constraints")
			return d
		}
		d.Status = StatusPlanProposed
		d.Plan = e.buildPlan(obj, current, &best.cand, false, nil)
		d.Reasons = []string{
			"new object: initial placement suggested (shadow only)",
			fmt.Sprintf("selected %s (%s)", best.cand.CandidateID, schemeWord(best.cand)),
		}
		d.Reasons = append(d.Reasons, best.cand.Reasons...)

	case deferEligible:
		d.Status = StatusDeferred
		d.SelectedID = "keep"
		keepCand := builtCandidate{cand: Candidate{
			CandidateID: "keep", Scheme: current.Scheme, EC: cloneEC(current.EC),
			Placement: withOrigin(current.Replicas, OriginExisting),
			Feasible:  true, MigrationBytes: 0,
		}}
		d.Plan = e.buildPlan(obj, current, &keepCand.cand, true, deferReasons)
		d.Reasons = append([]string{
			"defer: routine offline + readable now + margin intact; no mutation suggested this round",
		}, deferReasons...)

	case currentOK && len(offlineHolders) == 0:
		// Healthy: only propose a change when an EXECUTABLE candidate
		// (no EC backend required) clears the anti-jitter bar. A healthy,
		// running layout is never churned for a layout the cluster cannot
		// even build yet (simulated RS candidates).
		keep := e.findCandidate(built, func(c *Candidate) bool { return c.MigrationBytes == 0 && c.Feasible })
		bestExec := e.findCandidate(built, func(c *Candidate) bool { return c.Feasible && !c.RequiresECBackend && c.CandidateID != "keep" })
		if best == nil || keep == nil {
			if currentRep != nil {
				d.Validation = currentRep
			}
			d.Status = StatusNoFeasible
			d.Reasons = e.noFeasibleReasons(built, "no feasible candidate")
			return d
		}
		th := e.policy.ImprovementThreshold
		if bestExec == nil || bestExec.cand.Score.Total-keep.cand.Score.Total < th {
			reason := fmt.Sprintf("current layout passes all hard checks; best executable alternative improves weighted score by %.4f < ImprovementThreshold %.4f (anti-jitter, no mutation)",
				bestExecScore(bestExec)-keep.cand.Score.Total, th)
			if bestExec == nil {
				reason = "current layout passes all hard checks; no executable alternative exists (EC candidates are simulated only) — no mutation"
			}
			d.Status = StatusNoChange
			d.SelectedID = keep.cand.CandidateID
			d.Validation = currentRep
			d.Reasons = []string{reason}
			return d
		}
		d.Status = StatusPlanProposed
		d.SelectedID = bestExec.cand.CandidateID
		d.Plan = e.buildPlan(obj, current, &bestExec.cand, false, nil)
		d.Reasons = []string{fmt.Sprintf("selected %s (%s): weighted improvement %.4f over keeping current", bestExec.cand.CandidateID, schemeWord(bestExec.cand), bestExec.cand.Score.Total-keep.cand.Score.Total)}
		d.Reasons = append(d.Reasons, bestExec.cand.Reasons...)

	default:
		// Degraded: current violates hard checks, or offline holders exist
		// but the outage is not deferrable -> rebuild/add now. Repairs must
		// not silently shrink redundancy (for replication: no fewer copies;
		// for RS: no fewer distinct shard indices — mirrors never inflate it)
		// and never select the do-nothing "keep" candidate.
		currentRedundancy := 0
		if current != nil {
			currentRedundancy = layoutRedundancy(current.Scheme, current.Replicas)
		}
		var repairBest *builtCandidate
		for i := range built {
			b := &built[i]
			if !b.cand.Feasible || b.cand.CandidateID == "keep" {
				continue
			}
			if e.policy.AdditiveOnly && b.cand.MigrationBytes == 0 {
				// In additive mode a zero-migration candidate is the
				// r==len(current) keep-clone: selecting it would "repair" a
				// degraded object with a no-op plan. A real additive repair
				// always adds bytes.
				continue
			}
			if layoutRedundancy(b.cand.Scheme, b.cand.Placement) < currentRedundancy {
				b.cand.Feasible = false
				b.cand.InfeasibleReason = "repair would shrink redundancy below the current layout's (copies for replication, distinct shards for RS); not offered as a repair"
				continue
			}
			if repairBest == nil {
				repairBest = b
			}
		}
		if repairBest == nil {
			d.Status = StatusNoFeasible
			msg := "repair infeasible: no candidate satisfies hard constraints (constraints NOT relaxed)"
			if currentRep != nil && len(currentRep.Violations) > 0 {
				msg += "; current-layout violations: " + currentRep.Violations[0].Code
			}
			if e.policy.AdditiveOnly && current != nil {
				msg += "; " + e.additiveNoAddReason(current)
			}
			d.Reasons = e.noFeasibleReasons(built, msg)
			return d
		}
		d.SelectedID = repairBest.cand.CandidateID
		d.Status = StatusPlanProposed
		d.Plan = e.buildPlan(obj, current, &repairBest.cand, false, nil)
		d.Reasons = []string{fmt.Sprintf("repair: selected %s (%s)", repairBest.cand.CandidateID, schemeWord(repairBest.cand))}
		if currentRep != nil {
			for _, v := range currentRep.Violations {
				d.Reasons = append(d.Reasons, "current layout: "+v.Code+" — "+v.Message)
			}
		}
		d.Reasons = append(d.Reasons, deferReasons...)
		d.Reasons = append(d.Reasons, repairBest.cand.Reasons...)
	}

	d.Validation = currentRep
	return d
}

func bestExecScore(bestExec *builtCandidate) float64 {
	if bestExec == nil {
		return 0
	}
	return bestExec.cand.Score.Total
}

func (e *engine) findCandidate(built []builtCandidate, pred func(*Candidate) bool) *builtCandidate {
	for i := range built {
		if pred(&built[i].cand) {
			return &built[i]
		}
	}
	return nil
}

func (e *engine) noFeasibleReasons(built []builtCandidate, prefix string) []string {
	out := []string{prefix}
	seen := map[string]bool{}
	for i := range built {
		r := built[i].cand.InfeasibleReason
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
		if len(out) >= 6 {
			break
		}
	}
	return out
}

// liveState returns (distinct online shard indices, offline node IDs holding shards).
func (e *engine) liveState(current *Layout) (int, []string) {
	if current == nil {
		return 0, nil
	}
	online := map[int]bool{}
	offMap := map[string]bool{}
	for _, p := range current.Replicas {
		if n, ok := e.nodes[p.NodeID]; ok {
			if n.Online {
				online[p.FragmentIndex] = true
			} else {
				offMap[p.NodeID] = true
			}
		}
	}
	var offs []string
	for _, id := range e.order {
		if offMap[id] {
			offs = append(offs, id)
		}
	}
	return len(online), offs
}

// spellsRoutine reports whether every offline holder's predicted spell is a
// routine outage (<= MaxDeferOfflineSeconds, and > 0 — an offline node with
// no spell prediction is treated as NOT routine).
func (e *engine) spellsRoutine(offlineHolders []string) (bool, float64) {
	ok := true
	maxSpell := 0.0
	for _, id := range offlineHolders {
		p := e.predict(e.nodes[id])
		s := p.OfflineSpellSeconds
		if s <= 0 || s > float64(e.policy.MaxDeferOfflineSeconds) {
			ok = false
		}
		if s > maxSpell {
			maxSpell = s
		}
	}
	return ok, maxSpell
}

// onlineWorstAfterGroupFailures computes, over the CURRENT layout's online
// placements only, the minimum distinct-shard survivors after any
// MinFaultTolerance failure-domain group losses (exact within the
// enumeration budget, else the proven lower bound). Deferral is gated on
// this because a count-based onlineDistinct - k margin ignores correlated
// loss of the surviving set.
func (e *engine) onlineWorstAfterGroupFailures(current *Layout) int {
	t := e.policy.MinFaultTolerance
	if t < 1 {
		t = 1
	}
	online := Layout{Scheme: current.Scheme, EC: cloneEC(current.EC)}
	for _, p := range current.Replicas {
		if n := e.nodes[p.NodeID]; n != nil && n.Online {
			online.Replicas = append(online.Replicas, p)
		}
	}
	shardsByNode := map[string][]int{}
	perIndex := map[int]int{}
	for _, p := range online.Replicas {
		shardsByNode[p.NodeID] = append(shardsByNode[p.NodeID], p.FragmentIndex)
		perIndex[p.FragmentIndex]++
	}
	groups := failureGroups(online, e.nodes)
	return worstRemainingAfterGroupFailures(groups, shardsByNode, perIndex, t)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Placement builders.
// ---------------------------------------------------------------------------

// buildReplication produces the best replication placement of factor r.
func (e *engine) buildReplication(obj ObjectRequirement, r int, current *Layout) []FragmentPlacement {
	return e.buildSlots(obj, r, obj.SizeBytes, current, -1)
}

// buildRS produces the best RS placement for (k,m); frag is per-fragment size.
func (e *engine) buildRS(obj ObjectRequirement, k, m int, frag uint64, current *Layout) []FragmentPlacement {
	return e.buildSlots(obj, k+m, frag, current, k)
}

// buildSlots fills `slots` positions with distinct nodes holding `frag`
// bytes each. When currentLayout has an EC with the same k (ecK>=0) or is a
// replication layout (ecK<0 for replication path), healthy existing
// placements are kept (small-change preference); the rest is filled by
// deterministic greedy preferring distinct failure domains, then improved
// by bounded local swap search. Exact enumeration is used for small groups.
func (e *engine) buildSlots(obj ObjectRequirement, slots int, frag uint64, current *Layout, ecK int) []FragmentPlacement {
	eligible := e.eligibleForNew(frag)
	if len(eligible) < slots {
		return nil
	}

	// Seed with healthy current placements (same role: same fragment index
	// for RS with same k; any index for replication).
	var seeded []FragmentPlacement
	if current != nil {
		sameGeometry := (ecK < 0 && current.Scheme == SchemeReplicate) ||
			(ecK >= 0 && current.Scheme == SchemeRS && current.EC != nil && current.EC.K == ecK)
		if sameGeometry {
			for _, p := range current.Replicas {
				n := e.nodes[p.NodeID]
				if n == nil || !n.Online {
					continue
				}
				if ecK >= 0 && p.FragmentIndex >= ecK+max(0, slots-ecK) {
					continue
				}
				seeded = append(seeded, FragmentPlacement{
					NodeID: p.NodeID, FragmentIndex: p.FragmentIndex, Bytes: frag, Origin: OriginExisting,
				})
			}
		}
	}
	// Drop seed duplicates, then cap at the slot count. Replication keeps
	// one seed per fragment index: duplicate indices are a generation error
	// there, so a mirrored copy is dropped from the seeds and the freed slot
	// is refilled (the copy itself is retired by the plan). RS keeps mirror
	// copies (same index, different nodes) — same-shard mirrors are
	// legitimate and must survive into the target.
	sort.SliceStable(seeded, func(a, b int) bool { return seeded[a].FragmentIndex < seeded[b].FragmentIndex })
	used := map[string]bool{}
	usedIdx := map[int]bool{}
	var kept []FragmentPlacement
	for _, p := range seeded {
		if used[p.NodeID] {
			continue
		}
		if ecK < 0 {
			if usedIdx[p.FragmentIndex] {
				continue
			}
			usedIdx[p.FragmentIndex] = true
		}
		used[p.NodeID] = true
		kept = append(kept, p)
	}
	if len(kept) > slots {
		kept = kept[:slots]
	}

	need := slots - len(kept)
	fill := e.greedyFill(eligible, need, kept, frag, ecK)
	place := append(kept, fill...)

	// Assign fragment indices: kept keep theirs; new ones take the lowest
	// free indices (replication: 0..r-1; RS: 0..k+m-1).
	place = e.assignIndices(place, slots, ecK)

	// Small group: exact enumeration when unseeded and cheap.
	if len(kept) == 0 && ecK < 0 {
		limit := e.policy.Search.ExactComboLimit
		if limit <= 0 {
			limit = 252
		}
		if combos := combinations(len(eligible), slots, limit); combos != nil {
			var bestPlace []FragmentPlacement
			var bestRaw *rawMetrics
			for _, combo := range combos {
				cand := make([]FragmentPlacement, 0, slots)
				for _, i := range combo {
					cand = append(cand, FragmentPlacement{NodeID: eligible[i], FragmentIndex: -1, Bytes: frag, Origin: OriginNew})
				}
				cand = e.assignIndices(cand, slots, ecK)
				raw := e.rawMetricsFor(e.layoutFor(obj, SchemeReplicate, nil, cand), obj, 0)
				if !raw.feasible {
					continue // never seed "best" with an infeasible combo
				}
				if rawBetter(bestRaw, raw) {
					bestRaw = &raw
					bestPlace = cand
				}
			}
			if bestPlace != nil {
				return bestPlace
			}
		}
	}

	// Bounded local swap search (beam-width capped pool, deterministic).
	place = e.localSearch(obj, place, frag, ecK, eligible)
	return place
}

// buildAdditive extends the current replication layout to r placements
// without ever dropping, moving or re-indexing an existing placement: every
// current (node, fragment index) — including placements on offline nodes —
// is kept verbatim, and the remaining slots are filled with distinct,
// previously-unused ONLINE nodes with verifiable free capacity, at fragment
// indices strictly after the existing ones (the engine screens the current
// for canonical indices 0..r-1 first, so "after existing" is well-defined).
// Returns nil when fewer than r distinct usable nodes exist — never
// truncates to fit.
func (e *engine) buildAdditive(obj ObjectRequirement, r int, current *Layout) []FragmentPlacement {
	frag := obj.SizeBytes
	kept := make([]FragmentPlacement, 0, r)
	used := make(map[string]bool, len(current.Replicas))
	for _, p := range current.Replicas {
		kept = append(kept, FragmentPlacement{
			NodeID: p.NodeID, FragmentIndex: p.FragmentIndex, Bytes: frag, Origin: OriginExisting,
		})
		used[p.NodeID] = true
	}
	if len(kept) > r {
		return nil // belt-and-braces: additive mode never truncates
	}
	need := r - len(kept)
	if need == 0 {
		return kept
	}
	// eligibleForNew already filters to online + declared budget + free;
	// exclude every node that holds the object (no duplicate physical node).
	var pool []string
	for _, id := range e.eligibleForNew(frag) {
		if !used[id] {
			pool = append(pool, id)
		}
	}
	fill := e.greedyFill(pool, need, kept, frag, -1)
	if len(fill) < need {
		return nil
	}
	next := len(kept) // new indices come strictly after the existing ones
	for i := range fill {
		fill[i].FragmentIndex = next
		next++
	}
	out := append(kept, fill...)
	sort.SliceStable(out, func(a, b int) bool { return out[a].FragmentIndex < out[b].FragmentIndex })
	return out
}

// additiveCurrentDefect screens a replication current layout for strict
// add-only mode: canonical dense indices 0..r-1 and at most one placement
// per physical node. r placements with distinct in-range indices are exactly
// 0..r-1, so range + distinctness checks make "new indices after existing"
// well-defined. Anything else is refused before derivation.
func additiveCurrentDefect(cur *Layout) (code, msg string) {
	seenNode := map[string]bool{}
	seenIdx := map[int]bool{}
	for _, p := range cur.Replicas {
		if seenNode[p.NodeID] {
			return VDuplicatePlacement,
				fmt.Sprintf("additive_only current layout holds multiple placements on node %q; refusing to derive from an ambiguous layout", p.NodeID)
		}
		seenNode[p.NodeID] = true
		if p.FragmentIndex < 0 || p.FragmentIndex >= len(cur.Replicas) {
			return VIndexInvalid,
				fmt.Sprintf("additive_only current layout replica index %d out of range [0,%d); refusing to derive from a non-canonical layout", p.FragmentIndex, len(cur.Replicas))
		}
		if seenIdx[p.FragmentIndex] {
			return VIndexDuplicate,
				fmt.Sprintf("additive_only current layout repeats fragment index %d; refusing to derive additions from an ambiguous layout", p.FragmentIndex)
		}
		seenIdx[p.FragmentIndex] = true
	}
	return "", ""
}

// additiveNoAddReason explains why strict add-only mode has no addition to
// offer a degraded object. It never suggests shrinking or replacing.
func (e *engine) additiveNoAddReason(current *Layout) string {
	n := len(current.Replicas)
	switch {
	case n >= e.policy.MaxReplicaCount:
		return fmt.Sprintf("additive_only: %d existing placements >= MaxReplicaCount %d — the mode never shrinks or replaces existing placements, so nothing can be added", n, e.policy.MaxReplicaCount)
	case max(e.policy.MinFaultTolerance+1, n) > e.policy.MaxReplicaCount:
		return fmt.Sprintf("additive_only: required r >= %d (min_fault_tolerance+1 / existing count) exceeds MaxReplicaCount %d", max(e.policy.MinFaultTolerance+1, n), e.policy.MaxReplicaCount)
	default:
		return "additive_only: no additional distinct online node with verifiable free capacity is available to extend the layout"
	}
}

// rawBetter returns true when raw improves over best (nil best => true).
// Feasibility dominates everything; then durability, readability, cost.
func rawBetter(best *rawMetrics, raw rawMetrics) bool {
	if best == nil {
		return true
	}
	if raw.feasible != best.feasible {
		return raw.feasible
	}
	// prefer more durability, then higher readability, then cheaper
	if raw.durMinAfter != best.durMinAfter {
		return raw.durMinAfter > best.durMinAfter
	}
	if raw.readProb != best.readProb {
		return raw.readProb > best.readProb
	}
	return raw.costRaw < best.costRaw
}

// greedyFill picks `need` distinct nodes not already used, preferring nodes
// whose failure domains are all new relative to `kept`.
func (e *engine) greedyFill(eligible []string, need int, kept []FragmentPlacement, frag uint64, ecK int) []FragmentPlacement {
	if need <= 0 {
		return nil
	}
	usedDomains := map[string]bool{}
	for _, p := range kept {
		for _, d := range e.domainSignatures(p.NodeID) {
			usedDomains[d] = true
		}
	}
	used := map[string]bool{}
	for _, p := range kept {
		used[p.NodeID] = true
	}
	var fresh, reused []string
	for _, id := range eligible {
		if used[id] {
			continue
		}
		doms := e.domainSignatures(id)
		conflict := false
		for _, d := range doms {
			if usedDomains[d] {
				conflict = true
				break
			}
		}
		if !conflict {
			fresh = append(fresh, id)
		} else {
			reused = append(reused, id)
		}
	}
	pool := append(fresh, reused...)
	// Beam-width bound on the fill pool, but never below `need`: truncating a
	// pool smaller than the slots to fill would make whole candidate families
	// (r > BeamWidth, k+m > BeamWidth) silently unbuildable and de facto cap
	// layout size at the beam width regardless of policy.
	bw := e.policy.Search.BeamWidth
	if bw < need {
		bw = need
	}
	if bw > 0 && len(pool) > bw {
		pool = pool[:bw]
	}
	out := make([]FragmentPlacement, 0, need)
	for _, id := range pool {
		if len(out) >= need {
			break
		}
		out = append(out, FragmentPlacement{NodeID: id, FragmentIndex: -1, Bytes: frag, Origin: OriginNew})
		for _, d := range e.domainSignatures(id) {
			usedDomains[d] = true
		}
	}
	if len(out) < need {
		return nil // not enough eligible nodes
	}
	return out
}

// domainSignatures returns the deterministic failure-domain keys of a node
// (including the implicit host axis, the shared "unknown" buckets, and the
// shared "undeclared" bucket for nodes with no declared domains at all).
func (e *engine) domainSignatures(nodeID string) []string {
	n := e.nodes[nodeID]
	if n == nil {
		return []string{"host=" + nodeID, "undeclared=*"}
	}
	axes := map[string]bool{"host": true}
	for a := range n.FailureDomains {
		axes[a] = true
	}
	var out []string
	for _, a := range sortedStringKeys(axes) {
		val, ok := n.FailureDomains[a]
		if a == "host" {
			if !ok {
				val = n.ID
			}
		} else if !ok || val == "" {
			val = "unknown"
		}
		out = append(out, a+"="+val)
	}
	if len(n.FailureDomains) == 0 {
		// Unmodeled topology: never assume independence (matches the
		// validator's shared "undeclared=*" co-failure bucket).
		out = append(out, "undeclared=*")
	}
	return out
}

func (e *engine) assignIndices(place []FragmentPlacement, slots int, ecK int) []FragmentPlacement {
	usedIdx := map[int]bool{}
	for i := range place {
		usedIdx[place[i].FragmentIndex] = place[i].FragmentIndex >= 0 && place[i].FragmentIndex < slots
		if place[i].FragmentIndex < 0 || place[i].FragmentIndex >= slots {
			place[i].FragmentIndex = -1
		}
	}
	next := 0
	for i := range place {
		if place[i].FragmentIndex < 0 {
			for next < slots && usedIdx[next] {
				next++
			}
			place[i].FragmentIndex = next
			usedIdx[next] = true
		}
	}
	sort.SliceStable(place, func(a, b int) bool { return place[a].FragmentIndex < place[b].FragmentIndex })
	return place
}

// localSearch improves a placement by bounded single-node swaps, scored by
// the internal raw metrics (durability, readability, cost), keeping
// feasibility by re-checking capacity per swap. Deterministic; bounded work.
func (e *engine) localSearch(obj ObjectRequirement, place []FragmentPlacement, frag uint64, ecK int, eligible []string) []FragmentPlacement {
	if len(place) == 0 {
		return place
	}
	pool := eligible
	bw := e.policy.Search.BeamWidth
	if bw > 0 && len(pool) > bw {
		pool = pool[:bw]
	}
	inPlace := map[string]bool{}
	for _, p := range place {
		inPlace[p.NodeID] = true
	}
	cur := append([]FragmentPlacement(nil), place...)
	curRaw := e.rawMetricsFor(e.layoutFor(obj, schemeFor(ecK), ecParamsFor(ecK, place), cur), obj, 0)
	rounds := 0
	improved := true
	for improved && rounds < 4 {
		improved = false
		rounds++
		for i := range cur {
			if cur[i].Origin == OriginExisting {
				continue // never churn kept placements
			}
			for _, candID := range pool {
				if inPlace[candID] {
					continue
				}
				trial := append([]FragmentPlacement(nil), cur...)
				oldID := trial[i].NodeID
				trial[i].NodeID = candID
				// capacity guard for the trial
				if !e.capacityOK(trial) {
					continue
				}
				raw := e.rawMetricsFor(e.layoutFor(obj, schemeFor(ecK), ecParamsFor(ecK, trial), trial), obj, 0)
				if rawBetter(&curRaw, raw) {
					cur, curRaw = trial, raw
					inPlace[oldID] = false
					inPlace[candID] = true
					improved = true
				}
			}
		}
	}
	return cur
}

func (e *engine) capacityOK(place []FragmentPlacement) bool {
	per := map[string]uint64{}
	for _, p := range place {
		if p.Origin != OriginNew {
			continue
		}
		sum, of := addOverflow(per[p.NodeID], p.Bytes)
		if of {
			return false
		}
		per[p.NodeID] = sum
	}
	for id, add := range per {
		n := e.nodes[id]
		if n == nil {
			return false
		}
		free, ok := FreeBytes(*n)
		if !ok || add > free {
			return false
		}
	}
	return true
}

func schemeFor(ecK int) Scheme {
	if ecK >= 0 {
		return SchemeRS
	}
	return SchemeReplicate
}

func ecParamsFor(ecK int, place []FragmentPlacement) *ECParams {
	if ecK < 0 {
		return nil
	}
	// m inferred from placement count
	return &ECParams{K: ecK, M: len(place) - ecK}
}

func (e *engine) layoutFor(obj ObjectRequirement, scheme Scheme, ec *ECParams, place []FragmentPlacement) Layout {
	return Layout{
		ObjectID: obj.ObjectID, ContentVersion: obj.ContentVersion,
		LayoutEpoch: 1, Scheme: scheme, Replicas: place, EC: ec,
	}
}

// rawMetricsFor computes the unscaled scoring metrics of a placement, plus
// a cheap feasibility proxy (margin + capacity + readable-now). The proxy
// only steers the search; the authoritative gate is the independent
// validator run on every final candidate.
func (e *engine) rawMetricsFor(layout Layout, obj ObjectRequirement, mig uint64) rawMetrics {
	minRequired, k, _ := requiredReadableShards(layout)

	shardsByNode := map[string][]int{}
	perIndex := map[int]int{}
	for _, p := range layout.Replicas {
		shardsByNode[p.NodeID] = append(shardsByNode[p.NodeID], p.FragmentIndex)
		perIndex[p.FragmentIndex]++
	}
	groups := failureGroups(layout, e.nodes)
	t := e.policy.MinFaultTolerance
	if t < 1 {
		t = 1
	}
	// Search-side proxy: bounded by the search budget; the authoritative
	// fault-margin gate in the validator uses the wider work-budget window.
	dur := minShardsAfterGroupFailures(groups, shardsByNode, perIndex, t, e.policy.Search.ExactComboLimit)

	probs := e.shardProbs(layout)
	read := probAtLeast(probs, minRequired)

	cost := 0.0
	rtts := []float64{}
	for _, p := range layout.Replicas {
		if n := e.nodes[p.NodeID]; n != nil {
			cost += float64(p.Bytes) * n.CostPerGBMonth
			rtts = append(rtts, n.RTTMs)
		}
	}
	sort.Float64s(rtts)
	perf := 0.0
	if len(rtts) > 0 {
		if layout.Scheme == SchemeRS && k > 0 {
			if k-1 < len(rtts) {
				perf = rtts[k-1] // k-th smallest: shards needed for a read
			} else {
				perf = rtts[len(rtts)-1]
			}
		} else {
			perf = rtts[0] // min RTT replica
		}
	}

	prox := e.capacityOK(layout.Replicas)
	if prox {
		online := map[int]bool{}
		for _, p := range layout.Replicas {
			if n := e.nodes[p.NodeID]; n != nil && n.Online {
				online[p.FragmentIndex] = true
			}
		}
		prox = len(online) >= minRequired
	}

	return rawMetrics{durMinAfter: dur, readProb: read, costRaw: cost, perfRaw: perf, migBytes: mig,
		feasible: prox && dur >= minRequired}
}

func (e *engine) shardProbs(layout Layout) []float64 {
	best := map[int]float64{}
	for _, p := range layout.Replicas {
		if n := e.nodes[p.NodeID]; n != nil {
			pr := e.predict(n).ProbabilityOnline
			if pr > best[p.FragmentIndex] {
				best[p.FragmentIndex] = pr
			}
		}
	}
	idxs := sortedIntKeys(best)
	out := make([]float64, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, best[i])
	}
	return out
}

// scoreAll normalizes raw metrics round-relatively and fills Score+Reasons.
func (e *engine) scoreAll(feasible []*builtCandidate, w ScoreWeights) {
	if len(feasible) == 0 {
		return
	}
	maxDur, maxMig := 0, uint64(0)
	minCost, minPerf := math.MaxFloat64, math.MaxFloat64
	for _, b := range feasible {
		if b.raw.durMinAfter > maxDur {
			maxDur = b.raw.durMinAfter
		}
		if b.raw.migBytes > maxMig {
			maxMig = b.raw.migBytes
		}
		if b.raw.costRaw < minCost {
			minCost = b.raw.costRaw
		}
		if b.raw.perfRaw < minPerf {
			minPerf = b.raw.perfRaw
		}
	}
	horizon := e.policy.PredictionHorizonSeconds
	if horizon <= 0 {
		horizon = 86400
	}
	for _, b := range feasible {
		dur := 0.0
		if maxDur > 0 {
			dur = clamp01(float64(b.raw.durMinAfter) / float64(maxDur))
		}
		read := clamp01(b.raw.readProb)
		cost := 1.0
		if b.raw.costRaw > 0 && minCost > 0 {
			cost = clamp01(minCost / b.raw.costRaw)
		} else if b.raw.costRaw > 0 && minCost == 0 {
			cost = 0
		}
		perf := 1.0
		if b.raw.perfRaw > 0 && minPerf > 0 {
			perf = clamp01(minPerf / b.raw.perfRaw)
		} else if b.raw.perfRaw > 0 && minPerf == 0 {
			perf = 0
		}
		stab := 1.0
		if maxMig > 0 {
			stab = clamp01(1 - float64(b.raw.migBytes)/float64(maxMig))
		}
		total := w.Durability*dur + w.Readability*read + w.Cost*cost + w.Performance*perf + w.Stability*stab
		b.cand.Score = ScoreBreakdown{
			Total:       total,
			Durability:  dur,
			Readability: read,
			Cost:        cost,
			Performance: perf,
			Stability:   stab,
			Units:       scoreUnitsDoc(horizon),
		}
	}
}

func scoreUnitsDoc(horizon int) string {
	return fmt.Sprintf("all components in [0,1]; durability=relative shard-survival after worst failure-domain loss (NOT a nines durability promise); "+
		"readability=predicted readable probability over %ds horizon (score model assumes shard independence — a modeling assumption that guarantees nothing; the hard gate uses a distribution-free union bound); "+
		"cost=relative (1=cheapest; unit: placement-bytes x node cost = cost-weighted GB-month); "+
		"performance=relative read-set RTT ms (1=fastest); stability=1-migrationBytes/roundMax (1=no data movement)", horizon)
}

func (e *engine) reasonsFor(b *builtCandidate, obj ObjectRequirement) []string {
	if !b.cand.Feasible {
		return []string{"infeasible: " + b.cand.InfeasibleReason}
	}
	s := b.cand.Score
	r := []string{
		fmt.Sprintf("%s: durability rank %.4f (worst failure-domain loss leaves %d shards readable)", b.cand.CandidateID, s.Durability, b.raw.durMinAfter),
		fmt.Sprintf("predicted readability %.4f over finite horizon (relative; not a durability guarantee)", s.Readability),
		fmt.Sprintf("cost %.0f cost-weighted-GB-month, normalized %.4f", b.raw.costRaw, s.Cost),
		fmt.Sprintf("read-set RTT %.1f ms, normalized %.4f", b.raw.perfRaw, s.Performance),
		fmt.Sprintf("migration %d B, stability %.4f (small-change preference)", b.cand.MigrationBytes, s.Stability),
	}
	if b.cand.RequiresECBackend {
		r = append(r, "simulated candidate: requires_ec_backend=true — scheduler does NOT encode; executable only after an EC backend exists")
	}
	return r
}

func (e *engine) buildPlan(obj ObjectRequirement, current *Layout, best *Candidate, deferOnly bool, deferReasons []string) *Plan {
	epoch := uint64(1)
	if current != nil {
		epoch = current.LayoutEpoch + 1
	}
	target := Layout{
		ObjectID:       obj.ObjectID,
		ContentVersion: obj.ContentVersion,
		LayoutEpoch:    epoch,
		Scheme:         best.Scheme,
		EC:             cloneEC(best.EC),
		Replicas:       append([]FragmentPlacement(nil), best.Placement...),
	}
	var baseEpoch, baseCV uint64
	if current != nil {
		baseEpoch, baseCV = current.LayoutEpoch, current.ContentVersion
	}
	// mark origins vs current (only when stripe geometry is compatible;
	// an RS k change re-splits the object, so every fragment is new)
	have := map[string]bool{}
	compatible := current != nil && geometryCompatible(current, &target)
	if compatible {
		for _, p := range current.Replicas {
			have[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)] = true
		}
	}
	for i := range target.Replicas {
		p := &target.Replicas[i]
		if have[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)] {
			p.Origin = OriginExisting
		} else {
			p.Origin = OriginNew
		}
	}

	var actions []Action
	if deferOnly {
		actions = append(actions, Action{
			Kind:   "defer",
			Reason: strings.Join(deferReasons, "; "),
		})
	} else {
		// removals/moves first (suggestions)
		if current != nil {
			for _, p := range current.Replicas {
				if !have[targetKey(p)] {
					// will be reported via move actions below when a
					// replacement exists; otherwise note retirement implicitly
					_ = p
				}
			}
		}
		curByIdx := map[int]string{}
		if compatible {
			for _, p := range current.Replicas {
				if _, ok := curByIdx[p.FragmentIndex]; !ok {
					curByIdx[p.FragmentIndex] = p.NodeID
				}
			}
		}
		for _, p := range target.Replicas {
			if p.Origin == OriginExisting {
				actions = append(actions, Action{Kind: "keep", NodeID: p.NodeID, FragmentIndex: p.FragmentIndex,
					Bytes: p.Bytes, Simulated: best.RequiresECBackend, Reason: "placement unchanged"})
				continue
			}
			reason := fmt.Sprintf("new placement (%d B)", p.Bytes)
			kind := "add_replica"
			if best.Scheme == SchemeRS {
				kind = "add_fragment"
				reason = fmt.Sprintf("new EC fragment %d (%d B, simulated)", p.FragmentIndex, p.Bytes)
			}
			if src, ok := curByIdx[p.FragmentIndex]; ok && src != p.NodeID {
				if best.Scheme == SchemeRS {
					kind = "regenerate_fragment"
					reason = fmt.Sprintf("regenerate fragment %d from surviving shards onto %s (simulated; replaces copy on %s)", p.FragmentIndex, p.NodeID, src)
				} else {
					kind = "move_replica"
					reason = fmt.Sprintf("rebuild replica from surviving copies onto %s (replaces stale copy on %s)", p.NodeID, src)
				}
				actions = append(actions, Action{Kind: kind, NodeID: p.NodeID, FromNodeID: src,
					FragmentIndex: p.FragmentIndex, Bytes: p.Bytes, Simulated: best.RequiresECBackend, Reason: reason})
				continue
			}
			actions = append(actions, Action{Kind: kind, NodeID: p.NodeID, FragmentIndex: p.FragmentIndex,
				Bytes: p.Bytes, Simulated: best.RequiresECBackend, Reason: reason})
		}
	}

	return &Plan{
		ObjectID:           obj.ObjectID,
		BaseContentVersion: baseCV,
		BaseLayoutEpoch:    baseEpoch,
		TargetLayout:       target,
		Actions:            actions,
		RequiresECBackend:  best.RequiresECBackend,
		MigrationBytes:     best.MigrationBytes,
		Shadow:             true,
	}
}

// fragBytes returns ceil(size/k) with overflow protection; ok=false when
// the computation would overflow (object cannot be split this wide).
func fragBytes(size uint64, k int) (uint64, bool) {
	if k <= 0 {
		return 0, false
	}
	s, of := addOverflow(size, uint64(k)-1)
	if of {
		return 0, false
	}
	return s / uint64(k), true
}

func targetKey(p FragmentPlacement) string {
	return p.NodeID + "#" + fmt.Sprint(p.FragmentIndex)
}

// countDistinctShards counts distinct fragment indices in a placement —
// mirror copies of the same shard count once. (layoutRedundancy, the
// anti-shrink measure shared with the validator, lives in validator.go.)
func countDistinctShards(place []FragmentPlacement) int {
	seen := map[int]bool{}
	for _, p := range place {
		seen[p.FragmentIndex] = true
	}
	return len(seen)
}

func withOrigin(ps []FragmentPlacement, origin string) []FragmentPlacement {
	out := append([]FragmentPlacement(nil), ps...)
	for i := range out {
		out[i].Origin = origin
	}
	return out
}

func cloneEC(ec *ECParams) *ECParams {
	if ec == nil {
		return nil
	}
	c := *ec
	return &c
}

func epochFor(current *Layout) uint64 {
	if current == nil {
		return 1
	}
	return current.LayoutEpoch + 1
}

func candidateID(scheme Scheme, r int, ec *ECParams, seq int) string {
	if scheme == SchemeRS && ec != nil {
		return fmt.Sprintf("rs-k%dm%d-%03d", ec.K, ec.M, seq)
	}
	return fmt.Sprintf("rep-r%d-%03d", r, seq)
}

func schemeWord(c Candidate) string {
	if c.Scheme == SchemeRS {
		return fmt.Sprintf("RS(%d,%d), simulated", c.EC.K, c.EC.M)
	}
	return fmt.Sprintf("replication r=%d", c.R)
}

func (e *engine) codecEnabled() bool {
	cl := e.policy.CodecLimits
	return cl.MaxK > 0 && cl.MaxM > 0
}
