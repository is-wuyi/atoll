package scheduler

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// ---------------------------------------------------------------------------
// Independent validator.
//
// Every constraint is re-derived from the Snapshot + Policy only. Candidate
// self-scores are never consulted, so a candidate cannot talk its way past
// a budget, a fault margin, or an epoch check. Insufficient resources yield
// explicit violations — constraints are never relaxed to manufacture a
// feasible answer.
// ---------------------------------------------------------------------------

// FreeBytes returns the verifiable free capacity of a node after subtracting
// reserved bytes and in-flight (double-held) migration bytes.
// ok=false means the accounting underflows (over-committed node) or no hard
// budget is declared; both are hard violations for any new placement.
func FreeBytes(n Node) (uint64, bool) {
	if n.HardCapacityBytes == 0 {
		return 0, false
	}
	afterReserved, under1 := subOverflow(n.HardCapacityBytes, n.ReservedBytes)
	if under1 {
		return 0, false
	}
	free, under2 := subOverflow(afterReserved, n.InFlightBytes)
	if under2 {
		return 0, false
	}
	return free, true
}

// ValidateSnapshot checks node identity, numeric sanity and policy sanity.
// Object-level layout problems are reported per-object by the engine as
// invalid_requirement decisions; everything here is snapshot-global.
func ValidateSnapshot(snap *Snapshot) *ValidationReport {
	rep := &ValidationReport{Passed: true}

	if snap.SchemaVersion != SchemaVersion {
		violate(rep, VSchemaMismatch, fmt.Sprintf("snapshot schema_version=%d, want %d", snap.SchemaVersion, SchemaVersion))
	}
	seen := map[string]bool{}
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if n.ID == "" {
			violate(rep, VUnknownNode, fmt.Sprintf("node[%d] has empty ID", i))
		} else if seen[n.ID] {
			violate(rep, VDuplicatePlacement, fmt.Sprintf("duplicate node ID %q", n.ID))
		}
		seen[n.ID] = true
		if !finiteNonNeg(n.RTTMs) {
			violate(rep, VNumberInvalid, fmt.Sprintf("node %q rtt_ms must be finite >= 0, got %v", n.ID, n.RTTMs))
		}
		if !finiteNonNeg(n.CostPerGBMonth) {
			violate(rep, VNumberInvalid, fmt.Sprintf("node %q cost_per_gb_month must be finite >= 0, got %v", n.ID, n.CostPerGBMonth))
		}
		for _, w := range n.Availability {
			if !unitInterval(w.ProbabilityOnline) || !unitInterval(w.Confidence) {
				violate(rep, VNumberInvalid, fmt.Sprintf("node %q availability window has probability/confidence outside [0,1] or non-finite", n.ID))
			}
			if w.HorizonSeconds <= 0 {
				violate(rep, VNumberInvalid, fmt.Sprintf("node %q availability window horizon_seconds must be > 0", n.ID))
			}
			if !finiteNonNeg(w.PredictedOfflineSpellSeconds) {
				violate(rep, VNumberInvalid, fmt.Sprintf("node %q availability window spell seconds must be finite >= 0", n.ID))
			}
		}
		for _, s := range n.History {
			if _, err := ParseSample(s); err != nil {
				violate(rep, VNumberInvalid, fmt.Sprintf("node %q history sample %q: %v", n.ID, s.At, err))
			}
		}
	}
	objSeen := map[string]bool{}
	for i := range snap.Objects {
		o := &snap.Objects[i]
		// NOTE: object size and layout problems are reported per-object by
		// the engine (invalid_requirement decision) so one bad object does
		// not poison the whole trace; only node/policy sanity fails hard.
		if o.ObjectID == "" {
			violate(rep, VObjectIDInvalid, fmt.Sprintf("object[%d] has empty object_id", i))
		} else if objSeen[o.ObjectID] {
			violate(rep, VDuplicateObject, fmt.Sprintf("duplicate object ID %q", o.ObjectID))
		}
		objSeen[o.ObjectID] = true
		if err := validateWeights(o.Intent, &snap.Policy); err != "" {
			violate(rep, VWeightsInvalid, fmt.Sprintf("object %q: %s", o.ObjectID, err))
		}
	}
	validatePolicyNumbers(&snap.Policy, rep)
	return rep
}

// validatePolicyNumbers rejects non-finite, out-of-range or negative policy
// values. Zeros stay legal (documented defaults); genuinely illegal numbers
// never reach the engine, where a NaN gate like MinPredictedReadability
// would silently disable its check (NaN comparisons are always false).
func validatePolicyNumbers(p *Policy, rep *ValidationReport) {
	if !unitInterval(p.MinPredictedReadability) {
		violate(rep, VNumberInvalid, "policy.min_predicted_readability must be finite in [0,1] (0 disables the gate)")
	}
	if !unitInterval(p.MinConfidence) {
		violate(rep, VNumberInvalid, "policy.min_confidence must be finite in [0,1]")
	}
	if !unitInterval(p.ImprovementThreshold) {
		violate(rep, VNumberInvalid, "policy.improvement_threshold must be finite in [0,1]")
	}
	for _, f := range []struct {
		name string
		val  int
	}{
		{"min_fault_tolerance", p.MinFaultTolerance},
		{"max_replica_count", p.MaxReplicaCount},
		{"prediction_horizon_seconds", p.PredictionHorizonSeconds},
		{"max_defer_offline_seconds", p.MaxDeferOfflineSeconds},
		{"min_fault_margin_to_defer", p.MinFaultMarginToDefer},
		{"search.exact_combo_limit", p.Search.ExactComboLimit},
		{"search.beam_width", p.Search.BeamWidth},
		{"search.max_candidates", p.Search.MaxCandidates},
	} {
		if f.val < 0 {
			violate(rep, VNumberInvalid, fmt.Sprintf("policy.%s must be >= 0, got %d", f.name, f.val))
		}
	}
	if cl := p.CodecLimits; cl.MaxK > 0 {
		if cl.MinK < 0 || cl.MinM < 0 || cl.MaxM < 0 || cl.MaxTotalShards < 0 {
			violate(rep, VNumberInvalid, "policy.codec_limits: negative bounds are illegal (only MaxK < 0 disables RS, and then it disables RS entirely)")
		}
		if cl.MinK > 0 && cl.MinK > cl.MaxK {
			violate(rep, VNumberInvalid, fmt.Sprintf("policy.codec_limits.min_k %d exceeds max_k %d", cl.MinK, cl.MaxK))
		}
		if cl.MinM > 0 && cl.MaxM > 0 && cl.MinM > cl.MaxM {
			violate(rep, VNumberInvalid, fmt.Sprintf("policy.codec_limits.min_m %d exceeds max_m %d", cl.MinM, cl.MaxM))
		}
		if cl.MaxK > maxSupportedShards || cl.MaxM > maxSupportedShards || (cl.MaxTotalShards > 0 && cl.MaxTotalShards > maxSupportedShards) {
			violate(rep, VNumberInvalid, fmt.Sprintf("policy.codec_limits exceeds the supported RS range (k+m <= %d, GF(256))", maxSupportedShards))
		}
	}
	for tier, w := range p.TierDefaults {
		sum := 0.0
		for _, f := range []struct {
			name string
			val  float64
		}{{"durability", w.Durability}, {"readability", w.Readability}, {"cost", w.Cost},
			{"performance", w.Performance}, {"stability", w.Stability}} {
			if !finiteNonNeg(f.val) {
				violate(rep, VNumberInvalid, fmt.Sprintf("policy.tier_defaults[%q].%s must be finite >= 0", tier, f.name))
			}
			sum += f.val
		}
		if math.IsNaN(sum) || math.IsInf(sum, 1) {
			violate(rep, VNumberInvalid, fmt.Sprintf("policy.tier_defaults[%q] sums to a non-finite weight", tier))
		} else if sum <= 0 {
			violate(rep, VNumberInvalid, fmt.Sprintf("policy.tier_defaults[%q] must not be all-zero", tier))
		}
	}
}

// resolveWeights returns normalized weights (sum to 1) for the intent.
// Empty weights fall back to the tier preset (policy override, else built-in).
func resolveWeights(intent ProtectionIntent, policy *Policy) ScoreWeights {
	w := intent.Weights
	if w.Durability == 0 && w.Readability == 0 && w.Cost == 0 && w.Performance == 0 && w.Stability == 0 {
		if policy != nil && policy.TierDefaults != nil {
			if p, ok := policy.TierDefaults[intent.Tier]; ok {
				w = p
			} else {
				w = builtinTierWeights(intent.Tier)
			}
		} else {
			w = builtinTierWeights(intent.Tier)
		}
	}
	sum := w.Durability + w.Readability + w.Cost + w.Performance + w.Stability
	if sum <= 0 || math.IsNaN(sum) || math.IsInf(sum, 0) {
		// Callers must have validated; fail safe to the "normal" preset.
		w = builtinTierWeights("normal")
		sum = w.Durability + w.Readability + w.Cost + w.Performance + w.Stability
	}
	return ScoreWeights{
		Durability:  w.Durability / sum,
		Readability: w.Readability / sum,
		Cost:        w.Cost / sum,
		Performance: w.Performance / sum,
		Stability:   w.Stability / sum,
	}
}

func builtinTierWeights(tier string) ScoreWeights {
	switch tier {
	case "performance":
		return ScoreWeights{Durability: 0.2, Readability: 0.2, Performance: 0.4, Cost: 0.1, Stability: 0.1}
	case "security":
		return ScoreWeights{Durability: 0.45, Readability: 0.25, Performance: 0.05, Cost: 0.1, Stability: 0.15}
	default: // "normal"
		return ScoreWeights{Durability: 0.25, Readability: 0.25, Performance: 0.15, Cost: 0.2, Stability: 0.15}
	}
}

func validateWeights(intent ProtectionIntent, policy *Policy) string {
	w := intent.Weights
	allZero := w.Durability == 0 && w.Readability == 0 && w.Cost == 0 && w.Performance == 0 && w.Stability == 0
	for _, f := range []float64{w.Durability, w.Readability, w.Cost, w.Performance, w.Stability} {
		if !finiteNonNeg(f) {
			return "weights must be finite and >= 0 (NaN/Inf/negative rejected)"
		}
	}
	if allZero {
		if policy != nil {
			if p, ok := policy.TierDefaults[intent.Tier]; ok {
				w = p
			} else {
				w = builtinTierWeights(intent.Tier)
			}
		} else {
			w = builtinTierWeights(intent.Tier)
		}
	}
	sum := w.Durability + w.Readability + w.Cost + w.Performance + w.Stability
	if sum <= 0 || math.IsNaN(sum) || math.IsInf(sum, 0) {
		return "weights sum must be finite and > 0"
	}
	return ""
}

// ValidateLayout independently verifies a layout (target or current) against
// hard constraints. Origin=="new" placements consume verifiable free
// capacity; "existing"/"" placements are assumed already covered by the
// node's ReservedBytes (no double counting).
func ValidateLayout(snap *Snapshot, obj ObjectRequirement, layout Layout, policy Policy) *ValidationReport {
	rep := &ValidationReport{Passed: true}
	nodeMap := nodeIndex(snap)
	now := time.Now() // only used for history-derived predictions
	return validateLayoutAt(snap, obj, layout, policy, nodeMap, now, rep)
}

func validateLayoutAt(snap *Snapshot, obj ObjectRequirement, layout Layout, policy Policy,
	nodeMap map[string]*Node, now time.Time, rep *ValidationReport) *ValidationReport {

	// Identity: an independently validated layout must belong to the
	// requirement it is checked against.
	if layout.ObjectID != obj.ObjectID {
		violate(rep, VLayoutMismatch,
			fmt.Sprintf("layout object_id %q does not match requirement %q", layout.ObjectID, obj.ObjectID))
	}
	if layout.ContentVersion != obj.ContentVersion {
		violate(rep, VLayoutMismatch,
			fmt.Sprintf("layout content_version %d does not match requirement %d", layout.ContentVersion, obj.ContentVersion))
	}

	minRequired, k, m := requiredReadableShards(layout)
	horizon := policy.PredictionHorizonSeconds
	if horizon <= 0 {
		horizon = 86400
	}

	// --- node identity & placement sanity ---------------------------------
	shardsByNode := map[string][]int{}
	seenNodeIndex := map[string]bool{}
	perIndex := map[int]int{}
	unknownSeen := false
	for _, p := range layout.Replicas {
		if _, ok := nodeMap[p.NodeID]; !ok {
			violate(rep, VUnknownNode, fmt.Sprintf("placement references unknown node %q", p.NodeID))
			unknownSeen = true
			continue
		}
		key := p.NodeID + "#" + fmt.Sprint(p.FragmentIndex)
		if seenNodeIndex[key] {
			violate(rep, VDuplicatePlacement,
				fmt.Sprintf("node %q holds fragment index %d twice in the same generation", p.NodeID, p.FragmentIndex))
		}
		seenNodeIndex[key] = true
		shardsByNode[p.NodeID] = append(shardsByNode[p.NodeID], p.FragmentIndex)
		perIndex[p.FragmentIndex]++

		// Byte accounting must match the scheme's geometry.
		expect := expectedFragmentBytes(obj.SizeBytes, layout, k)
		if p.Bytes == 0 {
			// tolerated: snapshot inputs may omit; engine always fills it
		} else if p.Bytes != expect {
			violate(rep, VNumberInvalid,
				fmt.Sprintf("fragment index %d on %q declares %d B, expected %d B for this scheme",
					p.FragmentIndex, p.NodeID, p.Bytes, expect))
		}
	}

	switch layout.Scheme {
	case SchemeReplicate:
		r := len(layout.Replicas)
		for _, p := range layout.Replicas {
			if p.FragmentIndex < 0 || p.FragmentIndex >= r {
				violate(rep, VIndexInvalid,
					fmt.Sprintf("replica index %d out of range [0,%d)", p.FragmentIndex, max(r, 1)))
			}
		}
		if len(perIndex) != r && !unknownSeen {
			// Duplicate indices exist; for replication each copy is numbered
			// distinctly, so duplicates are a generation error. Distinct
			// copies still count once each — they never inflate r.
			violate(rep, VIndexDuplicate,
				fmt.Sprintf("replication layout has %d placements but only %d distinct indices", r, len(perIndex)))
		}
	case SchemeRS:
		if !supportedEC(layout.EC) {
			violate(rep, VECUnsupported,
				fmt.Sprintf("rs layout EC params outside the supported range (need k >= 1, m >= 1, k+m <= %d)", maxSupportedShards))
			break
		}
		for _, p := range layout.Replicas {
			if p.FragmentIndex < 0 || p.FragmentIndex >= k+m {
				violate(rep, VIndexInvalid,
					fmt.Sprintf("fragment index %d out of range [0,%d)", p.FragmentIndex, k+m))
			}
		}
		// Duplicate same-shard copies (same index, different nodes) are
		// legitimate mirrors, but they count ONCE toward k.
		distinct := len(perIndex)
		for idx, cnt := range perIndex {
			if cnt > 1 {
				rep.Checks = append(rep.Checks, CheckResult{Name: "duplicate_shard_counted_once", Passed: true,
					Detail: fmt.Sprintf("fragment index %d appears %d times; counted as ONE shard", idx, cnt)})
			}
		}
		if distinct < k {
			violate(rep, VInsufficientShards,
				fmt.Sprintf("layout declares k=%d but only %d distinct fragment indices exist (duplicate shards never inflate k)", k, distinct))
		}
	default:
		violate(rep, VIndexInvalid, fmt.Sprintf("unknown scheme %q", layout.Scheme))
	}

	// Strict add-only target contract (re-derived from the requirement's
	// current layout; candidate self-descriptions never decide it).
	if policy.AdditiveOnly {
		validateAdditiveOnlyTarget(obj, layout, nodeMap, rep)
	}

	// --- capacity: hard budget minus reserved minus in-flight -------------
	planned := map[string]uint64{}
	for _, p := range layout.Replicas {
		if p.Origin == OriginNew {
			// New placements with undeclared bytes are charged the scheme's
			// expected fragment size: a budget can never be bypassed by
			// omitting the byte count of a placement that must be written.
			charge := p.Bytes
			if charge == 0 {
				charge = expectedFragmentBytes(obj.SizeBytes, layout, k)
			}
			sum, of := addOverflow(planned[p.NodeID], charge)
			if of {
				violate(rep, VNumberInvalid, fmt.Sprintf("planned bytes overflow on node %q", p.NodeID))
			} else {
				planned[p.NodeID] = sum
			}
		}
	}
	nodeIDs := sortedKeys(planned)
	for _, id := range nodeIDs {
		n := nodeMap[id]
		if n == nil {
			continue // already reported as unknown_node above
		}
		add := planned[id]
		free, ok := FreeBytes(*n)
		if !ok {
			if n.HardCapacityBytes == 0 {
				violate(rep, VNoBudget, fmt.Sprintf("node %q has no hard capacity budget; refusing to place %d B", id, add))
			} else {
				violate(rep, VCapacity, fmt.Sprintf("node %q over-committed: capacity=%d reserved=%d in_flight=%d", id, n.HardCapacityBytes, n.ReservedBytes, n.InFlightBytes))
			}
			continue
		}
		if add > free {
			violate(rep, VCapacity,
				fmt.Sprintf("node %q needs %d B free for new fragments but only %d B verifiable (hard_capacity=%d - reserved=%d - in_flight=%d)", id, add, free, n.HardCapacityBytes, n.ReservedBytes, n.InFlightBytes))
		} else {
			rep.Checks = append(rep.Checks, CheckResult{Name: "capacity_budget", Passed: true,
				Detail: fmt.Sprintf("node %q: %d B new <= %d B free (capacity-reserved-inflight)", id, add, free)})
		}
	}

	// --- readability right now (verifiable online state) -------------------
	readable := readableDistinctIndices(layout, nodeMap)
	if readable < minRequired {
		violate(rep, VNotReadableNow,
			fmt.Sprintf("readable now: %d distinct %s online, need %d", readable, unitWord(layout), minRequired))
	} else {
		rep.Checks = append(rep.Checks, CheckResult{Name: "readable_now", Passed: true,
			Detail: fmt.Sprintf("%d distinct %s online >= %d required", readable, unitWord(layout), minRequired)})
	}

	// --- design fault margin: failure-domain co-failure --------------------
	groups := failureGroups(layout, nodeMap)
	t := policy.MinFaultTolerance
	if t < 1 {
		t = 1
	}
	// Hard constraint: exact when within the enumeration budget, otherwise a
	// PROVEN lower bound — a heuristic estimate never proves a constraint.
	worst := worstRemainingAfterGroupFailures(groups, shardsByNode, perIndex, t)
	if worst < minRequired {
		violate(rep, VFaultMargin,
			fmt.Sprintf("losing any %d failure-domain group(s) leaves %d readable shards < %d required (co-located shards are not independent; undeclared domains share one conservative bucket; over-budget cases use a proven lower bound and may conservatively reject)", t, worst, minRequired))
	} else {
		rep.Checks = append(rep.Checks, CheckResult{Name: "fault_margin", Passed: true,
			Detail: fmt.Sprintf("after any %d failure-domain group loss, >= %d shards remain (required %d)", t, worst, minRequired)})
	}

	// --- predicted readability over the finite horizon ---------------------
	// Hard gate on a DISTRIBUTION-FREE lower bound (union bound over the
	// distinct shards, no independence assumption). The DP in the scoring
	// engine assumes shard independence and is never a gate.
	if policy.MinPredictedReadability > 0 {
		probs := shardProbabilities(layout, nodeMap, now, horizon, policy.MinConfidence)
		floor := readabilityFloor(probs)
		check := CheckResult{Name: "predicted_readability",
			Detail: fmt.Sprintf("distribution-free readability lower bound %.4f vs gate %.4f over %ds horizon (union bound; no independence assumption)", floor, policy.MinPredictedReadability, horizon)}
		if floor < policy.MinPredictedReadability {
			check.Passed = false
			rep.Checks = append(rep.Checks, check)
			violate(rep, VHorizonGate,
				fmt.Sprintf("distribution-free readability lower bound %.4f over %ds horizon < gate %.4f (union bound over distinct shards; low-confidence forecasts handled conservatively)", floor, horizon, policy.MinPredictedReadability))
		} else {
			check.Passed = true
			rep.Checks = append(rep.Checks, check)
		}
	}

	return rep
}

// validateAdditiveOnlyTarget enforces the strict add-only contract on a
// layout interpreted as a repair target for obj: replicate-only (no EC
// layout, no scheme change), a positional superset of the current layout
// (every current (node, fragment index) retained — offline holders included,
// with multiplicity), at most one replica per physical node, and new
// placements only on verifiably online nodes. It runs inside
// validateLayoutAt, so it gates engine candidate validation and the plan
// exit gate alike; nothing here trusts candidate-reported scores or origins
// (origins are re-derived upstream in validatePlanAt).
func validateAdditiveOnlyTarget(obj ObjectRequirement, layout Layout, nodeMap map[string]*Node, rep *ValidationReport) {
	if layout.Scheme != SchemeReplicate {
		violate(rep, VAdditiveScheme,
			fmt.Sprintf("additive_only accepts SchemeReplicate targets only, got %q (no EC layout and no scheme change)", layout.Scheme))
		return
	}
	cur := obj.CurrentLayout
	if cur == nil {
		return
	}

	// Position superset with multiplicity: every current (node, index) must
	// survive into the target. This single check rejects truncation,
	// reassignment and same-count replacement (moves) alike.
	need := map[string]int{}
	for _, p := range cur.Replicas {
		need[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)]++
	}
	have := map[string]int{}
	for _, p := range layout.Replicas {
		have[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)]++
	}
	keys := make([]string, 0, len(need))
	for k := range need {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if have[k] < need[k] {
			violate(rep, VAdditiveNotSuperset,
				fmt.Sprintf("additive_only target drops current placement %q (truncation, reassignment and same-count replacement are forbidden)", k))
		}
	}

	// One physical node may hold at most one replica of the object.
	perNode := map[string]int{}
	ids := make([]string, 0, len(layout.Replicas))
	for _, p := range layout.Replicas {
		if perNode[p.NodeID] == 0 {
			ids = append(ids, p.NodeID)
		}
		perNode[p.NodeID]++
	}
	sort.Strings(ids)
	for _, id := range ids {
		if perNode[id] > 1 {
			violate(rep, VAdditiveDupNode,
				fmt.Sprintf("additive_only target holds %d replicas of the object on node %q; one physical node may hold at most one", perNode[id], id))
		}
	}

	// Additions must land on verifiably online nodes (capacity for new bytes
	// is checked separately by the budget accounting above).
	for _, p := range layout.Replicas {
		if p.Origin != OriginNew {
			continue
		}
		if n, ok := nodeMap[p.NodeID]; ok && !n.Online {
			violate(rep, VAdditiveOfflineNew,
				fmt.Sprintf("additive_only new placement on node %q but the node is not verifiably online; additions require online nodes with free capacity", p.NodeID))
		}
	}
}

// readabilityFloor returns a distribution-free LOWER bound on the
// probability that all distinct shards stay readable over the horizon:
// P(unreadable) <= sum_i P(shard i lost) with P(shard i lost) <= 1 -
// max mirror probability (union bound; no independence assumption between
// shards, and within a shard the best mirror bounds the loss).
func readabilityFloor(probs []float64) float64 {
	lost := 0.0
	for _, p := range probs {
		lost += 1 - clamp01(p)
	}
	return clamp01(1 - lost)
}

// deriveTargetPlacements re-derives target placement semantics from the
// current layout: a placement counts as "existing" iff the geometry-
// compatible current layout already holds the same (node, fragment index)
// in the same content generation; everything else is a NEW write. Zero-byte
// declarations are filled with the scheme's expected fragment size. A
// plan's self-reported Origin/Bytes therefore never decide a hard budget.
func deriveTargetPlacements(current *Layout, target *Layout, size uint64) []FragmentPlacement {
	out := append([]FragmentPlacement(nil), target.Replicas...)
	have := map[string]bool{}
	if current != nil && geometryCompatible(current, target) {
		for _, p := range current.Replicas {
			have[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)] = true
		}
	}
	k, _, _ := requiredReadableShards(*target)
	for i := range out {
		p := &out[i]
		if have[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)] {
			p.Origin = OriginExisting
		} else {
			p.Origin = OriginNew
		}
		if p.Bytes == 0 {
			p.Bytes = expectedFragmentBytes(size, *target, k)
		}
	}
	return out
}

// layoutRedundancy is the redundancy measure a repair may never shrink:
// independent copies for replication (every placement is a full copy), and
// distinct shard indices for RS (mirror copies of one shard never inflate
// it).
func layoutRedundancy(scheme Scheme, place []FragmentPlacement) int {
	if scheme == SchemeReplicate {
		return len(place)
	}
	return countDistinctShards(place)
}

// validatePlanAt verifies a suggestion-only plan at an explicit evaluation
// time: shadow flag, object identity (plan and target must belong to the
// requirement), staleness (epoch/content version, with a uint64-overflow
// guard on the epoch), target epoch, the repair anti-shrink floor,
// independently recomputed migration bytes and budget — all computed from
// RE-DERIVED target placements — plus every ValidateLayout check on the
// target.
func validatePlanAt(snap *Snapshot, obj ObjectRequirement, plan Plan, policy Policy, now time.Time) *ValidationReport {
	rep := &ValidationReport{Passed: true}
	nodeMap := nodeIndex(snap)

	if !plan.Shadow {
		violate(rep, VEpochInvalid, "plan must be shadow-only (shadow=true); the scheduler never executes")
	}

	if plan.ObjectID != obj.ObjectID {
		violate(rep, VObjectMismatch,
			fmt.Sprintf("plan object_id %q does not match requirement %q", plan.ObjectID, obj.ObjectID))
	}
	if plan.TargetLayout.ObjectID != obj.ObjectID {
		violate(rep, VObjectMismatch,
			fmt.Sprintf("target layout object_id %q does not match requirement %q", plan.TargetLayout.ObjectID, obj.ObjectID))
	}
	if plan.TargetLayout.ContentVersion != obj.ContentVersion {
		violate(rep, VObjectMismatch,
			fmt.Sprintf("target content_version %d does not match requirement %d", plan.TargetLayout.ContentVersion, obj.ContentVersion))
	}

	var current *Layout
	if obj.CurrentLayout != nil {
		current = obj.CurrentLayout
		if current.LayoutEpoch == math.MaxUint64 {
			violate(rep, VEpochInvalid, "current layout_epoch is at the uint64 maximum; no successor epoch exists")
		} else {
			if plan.BaseLayoutEpoch != current.LayoutEpoch || plan.BaseContentVersion != current.ContentVersion {
				violate(rep, VStalePlan,
					fmt.Sprintf("plan base epoch/content (%d/%d) does not match current layout (%d/%d); plan is stale",
						plan.BaseLayoutEpoch, plan.BaseContentVersion, current.LayoutEpoch, current.ContentVersion))
			}
			wantEpoch := current.LayoutEpoch + 1
			if plan.TargetLayout.LayoutEpoch != wantEpoch {
				violate(rep, VEpochInvalid,
					fmt.Sprintf("target layout_epoch=%d, want current+1=%d", plan.TargetLayout.LayoutEpoch, wantEpoch))
			}
		}
	} else {
		if plan.BaseLayoutEpoch != 0 || plan.BaseContentVersion != 0 {
			violate(rep, VStalePlan, "plan declares a base for an object with no current layout")
		}
		if plan.TargetLayout.LayoutEpoch != 1 {
			violate(rep, VEpochInvalid, fmt.Sprintf("first layout_epoch must be 1, got %d", plan.TargetLayout.LayoutEpoch))
		}
	}

	// Re-derive the target from the current layout; self-reported
	// origins/bytes never decide capacity or migration accounting.
	target := plan.TargetLayout
	target.Replicas = deriveTargetPlacements(current, &plan.TargetLayout, obj.SizeBytes)

	// Anti-shrink floor: a repair target must not hold less redundancy than
	// the current layout (copies for replication, distinct shard indices for
	// RS). A pseudo-keep that quietly drops redundancy is rejected here.
	if current != nil && layoutRedundancy(target.Scheme, target.Replicas) < layoutRedundancy(current.Scheme, current.Replicas) {
		violate(rep, VAntiShrink,
			fmt.Sprintf("repair target holds %d %s but the current layout holds %d: repairs never shrink redundancy",
				layoutRedundancy(target.Scheme, target.Replicas), unitWord(target), layoutRedundancy(current.Scheme, current.Replicas)))
	}

	// Independently recompute migration bytes from the placement diff over
	// the derived placements.
	mig := migrationBytesBetween(current, &target)
	if mig != plan.MigrationBytes {
		violate(rep, VMigrationMismatch,
			fmt.Sprintf("plan declares %d migration B but placement diff is %d B", plan.MigrationBytes, mig))
	}
	if policy.MaxMigrationBytesBudget > 0 && mig > policy.MaxMigrationBytesBudget {
		violate(rep, VBudgetExceeded,
			fmt.Sprintf("migration %d B exceeds policy budget %d B", mig, policy.MaxMigrationBytesBudget))
	}

	// Full layout validation of the derived target (independent, ignores
	// scores and self-reported fields).
	layoutRep := validateLayoutAt(snap, obj, target, policy, nodeMap, now, &ValidationReport{Passed: true})
	rep.Violations = append(rep.Violations, layoutRep.Violations...)
	rep.Checks = append(rep.Checks, layoutRep.Checks...)

	if len(rep.Violations) > 0 {
		rep.Passed = false
	}
	return rep
}

// ValidatePlan verifies a suggestion-only plan at the current wall clock.
// RunAt uses validatePlanAt with its own evaluation time for determinism.
func ValidatePlan(snap *Snapshot, obj ObjectRequirement, plan Plan, policy Policy) *ValidationReport {
	return validatePlanAt(snap, obj, plan, policy, time.Now())
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

func nodeIndex(snap *Snapshot) map[string]*Node {
	m := make(map[string]*Node, len(snap.Nodes))
	for i := range snap.Nodes {
		m[snap.Nodes[i].ID] = &snap.Nodes[i]
	}
	return m
}

func requiredReadableShards(layout Layout) (minRequired, k, m int) {
	if layout.Scheme == SchemeRS && layout.EC != nil {
		k, m = layout.EC.K, layout.EC.M
		return k, k, m
	}
	return 1, 0, 0
}

// expectedFragmentBytes returns the size of one fragment: the object size
// for replication, ceil(size/k) for RS. The ceil saturates at MaxUint64
// when size+k-1 would wrap, so an overflowing declaration can only fail
// byte and capacity checks — it can never produce a tiny forged expectation.
func expectedFragmentBytes(size uint64, layout Layout, k int) uint64 {
	if layout.Scheme == SchemeRS && k > 0 {
		s, ok := addOverflow(size, uint64(k)-1)
		if ok {
			// size+k-1 wrapped: saturate so an overflowing declaration can
			// only fail byte and capacity checks.
			return math.MaxUint64
		}
		return s / uint64(k)
	}
	return size
}

// maxSupportedShards is the simulated RS envelope (GF(256) field limit:
// k+m <= 255). Layouts and codec policies beyond it are rejected.
const maxSupportedShards = 255

// supportedEC reports whether the EC parameters lie inside the supported
// simulated range.
func supportedEC(ec *ECParams) bool {
	return ec != nil && ec.K >= 1 && ec.M >= 1 &&
		ec.K < maxSupportedShards && ec.M <= maxSupportedShards-ec.K
}

func unitWord(layout Layout) string {
	if layout.Scheme == SchemeRS {
		return "shards"
	}
	return "replicas"
}

// readableDistinctIndices counts distinct fragment indices that have at
// least one placement on a currently-online node. Mirror copies of the same
// index count once.
func readableDistinctIndices(layout Layout, nodeMap map[string]*Node) int {
	readable := map[int]bool{}
	for _, p := range layout.Replicas {
		if n, ok := nodeMap[p.NodeID]; ok && n.Online {
			readable[p.FragmentIndex] = true
		}
	}
	return len(readable)
}

// failureGroup is a set of node IDs that may co-fail: they share a declared
// failure-domain value, or they all lack a declared value for an axis
// (shared "unknown" — conservative), or they are the same physical host
// (implicit per-node "host" axis). Nodes that declare no failure domains at
// all additionally share one "undeclared" bucket: unmodeled topology (same
// room, power feed, uplink) is never assumed independent.
type failureGroup struct {
	Key   string
	Nodes map[string]bool
}

func failureGroups(layout Layout, nodeMap map[string]*Node) []failureGroup {
	// Collect axes across the layout's nodes.
	axes := map[string]bool{"host": true}
	for _, p := range layout.Replicas {
		if n, ok := nodeMap[p.NodeID]; ok {
			for a := range n.FailureDomains {
				axes[a] = true
			}
		}
	}
	axisNames := sortedStringKeys(axes)
	groups := map[string]map[string]bool{}
	for _, axis := range axisNames {
		for _, p := range layout.Replicas {
			n, ok := nodeMap[p.NodeID]
			if !ok {
				continue
			}
			val, declared := n.FailureDomains[axis]
			if axis == "host" {
				if !declared {
					val = n.ID // implicit: each node is its own host domain
				}
			} else if !declared || val == "" {
				val = "unknown" // undeclared nodes may co-fail
			}
			key := axis + "=" + val
			if groups[key] == nil {
				groups[key] = map[string]bool{}
			}
			groups[key][p.NodeID] = true
		}
	}
	// Shared bucket for fully-undeclared nodes (reported in the group key so
	// trace explanations show why independence was denied).
	for _, p := range layout.Replicas {
		if n, ok := nodeMap[p.NodeID]; ok && len(n.FailureDomains) == 0 {
			if groups["undeclared=*"] == nil {
				groups["undeclared=*"] = map[string]bool{}
			}
			groups["undeclared=*"][p.NodeID] = true
		}
	}
	keys := sortedStringKeys2(groups)
	out := make([]failureGroup, 0, len(keys))
	for _, k := range keys {
		out = append(out, failureGroup{Key: k, Nodes: groups[k]})
	}
	return out
}

// faultMarginWorkBudget bounds the exact group-subset enumeration in the
// validator's fault-margin check: subsets x per-subset work above this
// falls back to the proven lower bound, so the check stays bounded and
// deterministic for any policy input. The bound is deliberately independent
// of the search tuning (Search.ExactComboLimit steers candidate placement,
// never a hard constraint check).
const faultMarginWorkBudget = 50000

// aliveShardsAfter counts the distinct shard indices still held by nodes
// not marked dead.
func aliveShardsAfter(shardsByNode map[string][]int, dead map[string]bool) int {
	alive := map[int]bool{}
	for id, idxs := range shardsByNode {
		if dead[id] {
			continue
		}
		for _, idx := range idxs {
			alive[idx] = true
		}
	}
	return len(alive)
}

// worstRemainingAfterGroupFailures is the authoritative fault-margin
// computation for HARD constraint checks. It returns
//
//   - the exact minimum number of distinct shard indices surviving any t
//     group failures, when C(n,t) is within the work budget;
//   - otherwise a PROVEN LOWER BOUND on that minimum: removing t groups
//     kills at most the sum of their individual distinct-shard blast
//     radii, so survivors >= totalDistinct - sum(top-t distinct blasts)
//     (clamped at 0).
//
// The bound can be loose and may then reject a layout whose true worst case
// would pass — constraints are conservatively refused, never proven by a
// heuristic. (The engine's scoring proxy, minShardsAfterGroupFailures, may
// use heuristics because it only ranks candidates.)
func worstRemainingAfterGroupFailures(groups []failureGroup, shardsByNode map[string][]int,
	perIndex map[int]int, t int) int {

	if t <= 0 {
		t = 1
	}
	if len(groups) == 0 {
		return len(perIndex)
	}

	remaining := func(remove []failureGroup) int {
		dead := map[string]bool{}
		for _, g := range remove {
			for id := range g.Nodes {
				dead[id] = true
			}
		}
		return aliveShardsAfter(shardsByNode, dead)
	}

	n := len(groups)
	if t >= n {
		// More required group-failure tolerance than the layout even spans:
		// the adversary can fail every group the layout touches, which kills
		// every placement. (Regression: an empty subset list used to make
		// this case vacuously pass with a MaxInt32 sentinel.)
		return remaining(groups)
	}

	opsPerSubset := len(shardsByNode) + n + 8
	maxSubsets := faultMarginWorkBudget / opsPerSubset
	if maxSubsets < 1 {
		maxSubsets = 1
	}
	if binomUpTo(n, t, int64(maxSubsets)) <= int64(maxSubsets) {
		worst := math.MaxInt32
		for _, subset := range combinations(n, t, maxSubsets) {
			rm := make([]failureGroup, 0, len(subset))
			for _, i := range subset {
				rm = append(rm, groups[i])
			}
			if r := remaining(rm); r < worst {
				worst = r
			}
		}
		if worst != math.MaxInt32 {
			return worst // exact
		}
	}

	// Over budget: proven lower bound via top-t distinct-shard blast radii.
	blasts := make([]int, n)
	for i, g := range groups {
		idxs := map[int]bool{}
		for id := range g.Nodes {
			for _, idx := range shardsByNode[id] {
				idxs[idx] = true
			}
		}
		blasts[i] = len(idxs)
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	// Compare via precomputed keys: a comparator must never read the slice
	// being sorted.
	sort.SliceStable(order, func(a, b int) bool {
		if blasts[order[a]] != blasts[order[b]] {
			return blasts[order[a]] > blasts[order[b]]
		}
		return groups[order[a]].Key < groups[order[b]].Key
	})
	killed := 0
	for i := 0; i < t; i++ {
		killed += blasts[order[i]]
	}
	bound := len(perIndex) - killed
	if bound < 0 {
		bound = 0
	}
	return bound
}

// minShardsAfterGroupFailures is the SCORING PROXY of the fault margin used
// by the candidate engine: exact subset enumeration while C(n,t) stays
// within exactLimit, else a deterministic dual greedy heuristic (worse of
// two blast orderings). It only ranks candidates — the authoritative hard
// constraint check is worstRemainingAfterGroupFailures, which never uses a
// heuristic estimate.
func minShardsAfterGroupFailures(groups []failureGroup, shardsByNode map[string][]int,
	perIndex map[int]int, t int, exactLimit int) int {

	if t <= 0 {
		t = 1
	}
	if len(groups) == 0 {
		return len(perIndex)
	}

	remaining := func(remove []failureGroup) int {
		dead := map[string]bool{}
		for _, g := range remove {
			for id := range g.Nodes {
				dead[id] = true
			}
		}
		return aliveShardsAfter(shardsByNode, dead)
	}

	n := len(groups)
	if t >= n {
		return remaining(groups)
	}

	limit := exactLimit
	if limit <= 0 {
		limit = math.MaxInt32
	}
	if binomUpTo(n, t, int64(limit)) <= int64(limit) {
		worst := math.MaxInt32
		for _, subset := range combinations(n, t, limit) {
			rm := make([]failureGroup, 0, len(subset))
			for _, i := range subset {
				rm = append(rm, groups[i])
			}
			if r := remaining(rm); r < worst {
				worst = r
			}
		}
		if worst != math.MaxInt32 {
			return worst
		}
	}

	// Bounded heuristic fallback: min over two greedy orderings.
	worst := math.MaxInt32
	for mode := 0; mode < 2; mode++ {
		blast := make([]int, n)
		for i, g := range groups {
			if mode == 0 {
				for id := range g.Nodes {
					blast[i] += len(shardsByNode[id])
				}
			} else {
				idxs := map[int]bool{}
				for id := range g.Nodes {
					for _, idx := range shardsByNode[id] {
						idxs[idx] = true
					}
				}
				blast[i] = len(idxs)
			}
		}
		order := make([]int, n)
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool {
			if blast[order[a]] != blast[order[b]] {
				return blast[order[a]] > blast[order[b]]
			}
			return groups[order[a]].Key < groups[order[b]].Key
		})
		rm := make([]failureGroup, 0, t)
		for i := 0; i < t; i++ {
			rm = append(rm, groups[order[i]])
		}
		if r := remaining(rm); r < worst {
			worst = r
		}
	}
	return worst
}

// combinations returns all index combinations of size t from n items when
// C(n,t) <= limit, else nil (signal to use the greedy fallback).
func combinations(n, t, limit int) [][]int {
	if t > n || t < 0 {
		return nil
	}
	if binomUpTo(n, t, int64(limit)) > int64(limit) {
		return nil
	}
	var out [][]int
	cur := make([]int, t)
	var rec func(start, d int)
	rec = func(start, d int) {
		if d == t {
			c := make([]int, t)
			copy(c, cur)
			out = append(out, c)
			return
		}
		for i := start; i <= n-(t-d); i++ {
			cur[d] = i
			rec(i+1, d+1)
		}
	}
	rec(0, 0)
	return out
}

// binomUpTo returns min(C(n,t), cap+1) without int64 overflow: callers only
// need to know whether the binomial exceeds their enumeration budget. The
// running product is a binomial coefficient prefix (always an integer) and
// is capped as soon as it exceeds cap, so no intermediate can overflow.
func binomUpTo(n, t int, cap int64) int64 {
	if t > n || t < 0 {
		return 0
	}
	t = minInt(t, n-t)
	r := int64(1)
	for i := 0; i < t; i++ {
		r = r * int64(n-i) / int64(i+1)
		if r > cap {
			return cap + 1
		}
	}
	return r
}

// shardProbabilities returns, per distinct fragment index, the best
// placement's predicted online probability over the horizon. Duplicate
// shards contribute exactly once (one entry per distinct index).
func shardProbabilities(layout Layout, nodeMap map[string]*Node, now time.Time, horizon int, minConf float64) []float64 {
	best := map[int]float64{}
	for _, p := range layout.Replicas {
		n, ok := nodeMap[p.NodeID]
		if !ok {
			continue
		}
		pr := effectivePrediction(n, now, horizon, minConf).ProbabilityOnline
		if previous, exists := best[p.FragmentIndex]; !exists || pr > previous {
			best[p.FragmentIndex] = pr
		}
	}
	idxs := sortedIntKeys(best)
	out := make([]float64, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, best[i])
	}
	return out
}

// effectivePrediction resolves a node's finite-horizon forecast: explicit
// snapshot window if present (nearest horizon), else NodeHistory pure
// functions, else the conservative fallback. Forecasts with confidence
// below minConf are downgraded to "unproven" (online: p=0.5; offline:
// assumed long outage) — never treated as proof of uptime.
func effectivePrediction(n *Node, now time.Time, horizon int, minConf float64) Prediction {
	var pred Prediction
	if len(n.Availability) > 0 {
		bw := n.Availability[0]
		bestDiff := abs(bw.HorizonSeconds - horizon)
		for _, w := range n.Availability[1:] {
			if d := abs(w.HorizonSeconds - horizon); d < bestDiff {
				bw, bestDiff = w, d
			}
		}
		pred = Prediction{
			ProbabilityOnline:   clamp01(bw.ProbabilityOnline),
			Confidence:          clamp01(bw.Confidence),
			OfflineSpellSeconds: bw.PredictedOfflineSpellSeconds,
			Source:              "forecast",
		}
	} else {
		pred = PredictFromHistory(n.History, now, horizon, n.Online)
	}
	if pred.Confidence < minConf {
		if n.Online {
			return Prediction{ProbabilityOnline: 0.5, Confidence: pred.Confidence,
				OfflineSpellSeconds: pred.OfflineSpellSeconds, Source: pred.Source + "+conservative"}
		}
		return Prediction{ProbabilityOnline: 0, Confidence: pred.Confidence,
			OfflineSpellSeconds: maxF(pred.OfflineSpellSeconds, conservativeOfflineSpellSeconds),
			Source:              pred.Source + "+conservative"}
	}
	return pred
}

// probAtLeast computes P(X >= need) for X ~ poisson-binomial(probs)
// (exact DP; deterministic). State `need` is absorbing, so dp[need] is the
// tail probability P(at least need shards online).
func probAtLeast(probs []float64, need int) float64 {
	if need <= 0 {
		return 1
	}
	if need > len(probs) {
		return 0
	}
	dp := make([]float64, need+1)
	dp[0] = 1
	for _, p := range probs {
		p = clamp01(p)
		for j := need; j >= 1; j-- {
			if j == need {
				// absorbing: existing tail mass keeps the object readable
				// regardless of further successes.
				dp[j] = dp[j] + dp[j-1]*p
			} else {
				dp[j] = dp[j]*(1-p) + dp[j-1]*p
			}
		}
		dp[0] = dp[0] * (1 - p)
	}
	return clamp01(dp[need])
}

// geometryCompatible reports whether two layouts share stripe geometry, i.e.
// a fragment with the same index holds the same bytes: replication layouts
// are always compatible with each other; RS layouts only when k matches
// (changing k re-splits the object, invalidating every existing fragment).
func geometryCompatible(a, b *Layout) bool {
	if a == nil || b == nil || a.Scheme != b.Scheme {
		return false
	}
	if a.Scheme == SchemeRS {
		return a.EC != nil && b.EC != nil && a.EC.K == b.EC.K
	}
	return true
}

// migrationBytesBetween computes bytes that must be written to satisfy
// target: every target placement whose (node, index) is not already present
// in a geometry-compatible current layout. Space freed on removed sources
// is NOT credited (conservative: the source copy stays resident until the
// migration completes). Incompatible geometry (e.g. RS k change) rewrites
// every fragment.
func migrationBytesBetween(current, target *Layout) uint64 {
	if target == nil {
		return 0
	}
	have := map[string]bool{}
	if current != nil && geometryCompatible(current, target) {
		for _, p := range current.Replicas {
			have[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)] = true
		}
	}
	var sum uint64
	for _, p := range target.Replicas {
		if !have[p.NodeID+"#"+fmt.Sprint(p.FragmentIndex)] {
			s, of := addOverflow(sum, p.Bytes)
			if of {
				return math.MaxUint64
			}
			sum = s
		}
	}
	return sum
}

func violate(rep *ValidationReport, code, msg string) {
	rep.Passed = false
	rep.Violations = append(rep.Violations, Violation{Code: code, Message: msg})
}

func sortedKeys(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys2(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedIntKeys(m map[int]float64) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
