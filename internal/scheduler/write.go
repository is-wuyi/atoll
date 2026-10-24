package scheduler

import (
	"fmt"
	"math"
	"sort"
	"time"
)

type WriteDecision struct {
	ObjectID              string            `json:"object_id"`
	Status                string            `json:"status"`
	Plan                  *Plan             `json:"plan,omitempty"`
	ConfirmationNodes     []string          `json:"confirmation_nodes,omitempty"`
	RequiredConfirmations int               `json:"required_confirmations"`
	Score                 ScoreBreakdown    `json:"score"`
	Reasons               []string          `json:"reasons"`
	Validation            *ValidationReport `json:"validation,omitempty"`
	EvaluatedCandidates   int               `json:"evaluated_candidates"`
	Transfer              *WriteTransfer    `json:"transfer,omitempty"`
}

type writeCandidate struct {
	decision                               WriteDecision
	durability, readability, cost, latency float64
	bytes                                  uint64
	key                                    string
}

func writeInput(snap *Snapshot, obj ObjectRequirement, now time.Time) (*Snapshot, error) {
	if snap == nil || now.IsZero() {
		return nil, fmt.Errorf("scheduler: snapshot and evaluation time required")
	}
	if len(snap.Nodes) > 256 || obj.ObjectID == "" || obj.ContentVersion == 0 || obj.SizeBytes == 0 || obj.CurrentLayout != nil {
		return nil, fmt.Errorf("scheduler: invalid new object requirement")
	}
	if obj.Intent.Tier != "" && obj.Intent.Tier != "performance" && obj.Intent.Tier != "normal" && obj.Intent.Tier != "security" {
		return nil, fmt.Errorf("scheduler: unknown protection preference")
	}
	copy := *snap
	if copy.Network != nil {
		if err := validateTransferNetwork(copy.Network, now); err != nil {
			return nil, fmt.Errorf("scheduler: %w", err)
		}
	}
	copy.Objects = []ObjectRequirement{obj}
	if rep := ValidateSnapshot(&copy); !rep.Passed {
		return nil, fmt.Errorf("scheduler: invalid write snapshot: %s", summarizeViolations(rep))
	}
	work := deepCopySnapshot(&copy)
	work.Policy = normalizePolicy(work.Policy)
	if work.Policy.MaxReplicaCount > 32 || work.Policy.Search.MaxCandidates > 4096 || work.Policy.Search.BeamWidth > 256 || work.Policy.Search.ExactComboLimit > 65536 {
		return nil, fmt.Errorf("scheduler: write search exceeds supported bounds")
	}
	work.Policy.CodecLimits = CodecLimits{MaxK: -1}
	if work.Network != nil {
		indexTransferNetwork(work.Network, now)
	}
	return work, nil
}

// PlanWriteAt jointly ranks the eventual layout and the exact nodes required at publication.
// A decision reserves no capacity until the metadata transaction accepts it.
func PlanWriteAt(snap *Snapshot, obj ObjectRequirement, now time.Time) (WriteDecision, error) {
	d := WriteDecision{ObjectID: obj.ObjectID, Status: StatusNoFeasible}
	work, err := writeInput(snap, obj, now)
	if err != nil {
		return d, err
	}
	e := newEngine(work, work.Policy, now)
	eligible := e.eligibleForNew(obj.SizeBytes)
	rMax := minInt(work.Policy.MaxReplicaCount, len(eligible))
	if rMax == 0 || work.Policy.MinFaultTolerance >= rMax {
		d.Reasons = []string{"no online capacity satisfies the write constraints"}
		return d, nil
	}
	candidates, evaluated := writeCandidates(e, obj, now)
	d.EvaluatedCandidates = evaluated
	if len(candidates) == 0 {
		d.Reasons = []string{fmt.Sprintf("bounded search evaluated %d candidate pairs; no layout and confirmation set passed the hard constraints", evaluated)}
		return d, nil
	}
	minCost, minLatency, maxBytes := math.MaxFloat64, math.MaxFloat64, uint64(0)
	for _, c := range candidates {
		minCost = math.Min(minCost, c.cost)
		minLatency = math.Min(minLatency, c.latency)
		if c.bytes > maxBytes {
			maxBytes = c.bytes
		}
	}
	weights := resolveWeights(obj.Intent, &work.Policy)
	for i := range candidates {
		c := &candidates[i]
		cost := 1.0
		if c.cost > 0 {
			cost = minCost / c.cost
		}
		performance := .75*minLatency/c.latency + .25/float64(c.decision.RequiredConfirmations)
		stability := 1 - float64(c.bytes)/float64(maxBytes)
		score := ScoreBreakdown{Durability: c.durability, Readability: c.readability, Cost: cost, Performance: performance, Stability: stability,
			Units: "relative ranking only; protection blends confirmed state (65%) and target state (35%); durability averages readability after one modeled domain loss; performance uses slowest required-node RTT and confirmation fan-out; cost is physical bytes times node cost; stability favors fewer newly stored bytes"}
		if work.Network != nil {
			score.Units = "relative ranking only; protection blends confirmed and target state; performance uses budgeted endpoint transfer completion and confirmation fan-out; unknown link goodput uses configured ceilings, not measured throughput"
		}
		score.Total = weights.Durability*score.Durability + weights.Readability*score.Readability + weights.Cost*score.Cost + weights.Performance*score.Performance + weights.Stability*score.Stability
		c.decision.Score = score
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.decision.Score.Total != b.decision.Score.Total {
			return a.decision.Score.Total > b.decision.Score.Total
		}
		if a.bytes != b.bytes {
			return a.bytes < b.bytes
		}
		if a.decision.RequiredConfirmations != b.decision.RequiredConfirmations {
			return a.decision.RequiredConfirmations < b.decision.RequiredConfirmations
		}
		return a.key < b.key
	})
	d = candidates[0].decision
	d.EvaluatedCandidates = evaluated
	d.Reasons = []string{fmt.Sprintf("jointly selected %d replica targets and %d required nodes from %d feasible candidates", len(d.Plan.TargetLayout.Replicas), d.RequiredConfirmations, len(candidates)),
		fmt.Sprintf("bounded search evaluated %d pairs within MaxCandidates=%d", evaluated, work.Policy.Search.MaxCandidates),
		"every named confirmation is required; retries cannot reduce this set", "scores are finite-horizon heuristics, not availability guarantees"}
	d.Validation = ValidateWriteDecisionAt(work, obj, d, now)
	if !d.Validation.Passed {
		d.Status = StatusNoFeasible
		d.Plan = nil
		d.ConfirmationNodes = nil
		d.RequiredConfirmations = 0
		d.Reasons = []string{"selected write plan failed independent validation"}
	}
	return d, nil
}

func writeLayout(obj ObjectRequirement, ids []string) Layout {
	l := Layout{ObjectID: obj.ObjectID, ContentVersion: obj.ContentVersion, LayoutEpoch: 1, Scheme: SchemeReplicate}
	for i, id := range ids {
		l.Replicas = append(l.Replicas, FragmentPlacement{NodeID: id, FragmentIndex: i, Bytes: obj.SizeBytes, Origin: OriginNew})
	}
	return l
}

func stringMember(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func writeNodeSets(e *engine, ids []string, count, limit int) [][]string {
	if count < 1 || count > len(ids) || limit < 1 {
		return nil
	}
	ordered := append([]string(nil), ids...)
	sort.Strings(ordered)
	if combos := combinations(len(ordered), count, minInt(limit, e.policy.Search.ExactComboLimit)); combos != nil {
		out := make([][]string, 0, len(combos))
		for _, combo := range combos {
			set := make([]string, 0, count)
			for _, i := range combo {
				set = append(set, ordered[i])
			}
			out = append(out, set)
		}
		return out
	}
	var out [][]string
	seen := map[string]bool{}
	for mode := 0; mode < 3 && len(out) < limit; mode++ {
		pool := append([]string(nil), ordered...)
		sort.SliceStable(pool, func(i, j int) bool {
			a, b := e.nodes[pool[i]], e.nodes[pool[j]]
			switch mode {
			case 0:
				if a.RTTMs != b.RTTMs {
					return a.RTTMs < b.RTTMs
				}
			case 1:
				if a.CostPerGBMonth != b.CostPerGBMonth {
					return a.CostPerGBMonth < b.CostPerGBMonth
				}
			case 2:
				pa, pb := e.predict(a).ProbabilityOnline, e.predict(b).ProbabilityOnline
				if pa != pb {
					return pa > pb
				}
			}
			return a.ID < b.ID
		})
		appendWriteSet(&out, seen, diverseWriteSet(e, pool, count), limit)
		for shift := 0; shift < minInt(len(pool), e.policy.Search.BeamWidth) && len(out) < limit; shift++ {
			set := make([]string, 0, count)
			for i := 0; i < count; i++ {
				set = append(set, pool[(shift+i)%len(pool)])
			}
			sort.Strings(set)
			appendWriteSet(&out, seen, set, limit)
			if len(out) >= max(1, limit*(mode+1)/3) {
				break
			}
		}
	}
	return out
}

func writeProtectionScore(e *engine, l Layout) (float64, float64) {
	read := probAtLeast(e.shardProbs(l), 1)
	groups := failureGroups(l, e.nodes)
	if len(groups) == 0 {
		return 0, read
	}
	dur := 0.0
	for _, g := range groups {
		var probs []float64
		for _, p := range l.Replicas {
			if !g.Nodes[p.NodeID] {
				probs = append(probs, e.predict(e.nodes[p.NodeID]).ProbabilityOnline)
			}
		}
		dur += probAtLeast(probs, 1)
	}
	return dur / float64(len(groups)), read
}

func validateWriteLayout(snap *Snapshot, obj ObjectRequirement, l Layout, now time.Time) *ValidationReport {
	rep := &ValidationReport{Passed: true}
	if l.ObjectID != obj.ObjectID || l.ContentVersion != obj.ContentVersion || l.LayoutEpoch != 1 {
		violate(rep, VLayoutMismatch, "write object identity or epoch mismatch")
	}
	if l.Scheme != SchemeReplicate || l.EC != nil {
		violate(rep, VECUnsupported, "new writes require executable replication")
	}
	if len(l.Replicas) == 0 || len(l.Replicas) > snap.Policy.MaxReplicaCount {
		violate(rep, VIndexInvalid, "write target count outside policy")
	}
	nodes := nodeIndex(snap)
	seen := map[string]bool{}
	shards := map[string][]int{}
	indices := map[int]int{}
	total := uint64(0)
	floor := 0.0
	for i, p := range l.Replicas {
		if p.FragmentIndex != i || seen[p.NodeID] {
			violate(rep, VDuplicatePlacement, "write placements require unique nodes and dense indices")
		}
		seen[p.NodeID] = true
		if p.Bytes != obj.SizeBytes || p.Origin != OriginNew {
			violate(rep, VSizeInvalid, "write placement byte count or origin mismatch")
		}
		n := nodes[p.NodeID]
		if n == nil {
			violate(rep, VUnknownNode, "unknown write target")
			continue
		}
		if !n.Online {
			violate(rep, VNotReadableNow, "write target is offline")
		}
		free, ok := FreeBytes(*n)
		if !ok || obj.SizeBytes > free {
			violate(rep, VCapacity, "write exceeds node free capacity")
		}
		var overflow bool
		total, overflow = addOverflow(total, obj.SizeBytes)
		if overflow {
			violate(rep, VNumberInvalid, "write storage size overflow")
		}
		shards[p.NodeID] = []int{i}
		indices[i] = 1
		floor = math.Max(floor, effectivePrediction(n, now, snap.Policy.PredictionHorizonSeconds, snap.Policy.MinConfidence).ProbabilityOnline)
	}
	if snap.Policy.MaxMigrationBytesBudget > 0 && total > snap.Policy.MaxMigrationBytesBudget {
		violate(rep, VBudgetExceeded, "write exceeds transfer budget")
	}
	// Zero is an actual zero-failure constraint here, not the repair engine's historical default.
	if snap.Policy.MinFaultTolerance > 0 && worstRemainingAfterGroupFailures(failureGroups(l, nodes), shards, indices, snap.Policy.MinFaultTolerance) < 1 {
		violate(rep, VFaultMargin, "required confirmation state cannot survive the configured domain losses")
	}
	// For replication P(any readable) >= max(P(each replica readable)), without independence assumptions.
	if floor < snap.Policy.MinPredictedReadability {
		violate(rep, VHorizonGate, "replica readability lower bound below policy")
	}
	return rep
}

func ValidateWriteDecisionAt(snap *Snapshot, obj ObjectRequirement, d WriteDecision, now time.Time) *ValidationReport {
	rep := &ValidationReport{Passed: true}
	work, err := writeInput(snap, obj, now)
	if err != nil {
		violate(rep, VNumberInvalid, err.Error())
		return rep
	}
	if d.Status != StatusPlanProposed || d.Plan == nil || d.ObjectID != obj.ObjectID {
		violate(rep, VObjectMismatch, "write decision has no matching executable plan")
		return rep
	}
	p := d.Plan
	if p.RequiresECBackend || !p.Shadow || p.BaseLayoutEpoch != 0 || p.BaseContentVersion != 0 || p.ObjectID != obj.ObjectID {
		violate(rep, VStalePlan, "write plan identity or base is invalid")
	}
	layoutRep := validateWriteLayout(work, obj, p.TargetLayout, now)
	rep.Violations = append(rep.Violations, layoutRep.Violations...)
	var bytes uint64
	for range p.TargetLayout.Replicas {
		var overflow bool
		bytes, overflow = addOverflow(bytes, obj.SizeBytes)
		if overflow {
			violate(rep, VNumberInvalid, "write byte sum overflow")
		}
	}
	if p.MigrationBytes != bytes {
		violate(rep, VMigrationMismatch, "write byte sum differs from plan")
	}
	if d.RequiredConfirmations < 1 || d.RequiredConfirmations != len(d.ConfirmationNodes) {
		violate(rep, VInsufficientShards, "every named confirmation must be required")
	}
	targets := map[string]bool{}
	for _, t := range p.TargetLayout.Replicas {
		targets[t.NodeID] = true
	}
	for _, id := range d.ConfirmationNodes {
		if !targets[id] {
			violate(rep, VUnknownNode, "confirmation outside target layout")
		}
	}
	if len(p.TargetLayout.Replicas) > 0 && !stringMember(d.ConfirmationNodes, p.TargetLayout.Replicas[0].NodeID) {
		violate(rep, VInsufficientShards, "primary target must be a required confirmation")
	}
	confirmationRep := validateWriteLayout(work, obj, writeLayout(obj, d.ConfirmationNodes), now)
	rep.Violations = append(rep.Violations, confirmationRep.Violations...)
	if work.Network != nil {
		var targetIDs []string
		for _, target := range p.TargetLayout.Replicas {
			targetIDs = append(targetIDs, target.NodeID)
		}
		if err := validateWriteTransfer(work.Network, d.Transfer, targetIDs, d.ConfirmationNodes, obj.SizeBytes, now); err != nil {
			violate(rep, VBudgetExceeded, err.Error())
		}
	} else if d.Transfer != nil {
		violate(rep, VBudgetExceeded, "transfer plan has no directional network snapshot")
	}
	rep.Passed = len(rep.Violations) == 0
	return rep
}
