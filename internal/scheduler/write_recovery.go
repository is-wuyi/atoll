package scheduler

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Counts are the accepted write contract, not a new global replica policy.
func PlanWriteRecoveryAt(snap *Snapshot, obj ObjectRequirement, minReplicas, minConfirmations int, retained []string, now time.Time) (WriteDecision, error) {
	out := WriteDecision{ObjectID: obj.ObjectID, Status: StatusNoFeasible}
	work, err := writeInput(snap, obj, now)
	if err != nil {
		return out, err
	}
	if minReplicas < 1 || minReplicas > 32 || minConfirmations < 1 || minConfirmations > minReplicas || len(retained) > minReplicas {
		return out, fmt.Errorf("scheduler: invalid accepted recovery requirements")
	}
	e := newEngine(work, work.Policy, now)
	eligible := e.eligibleForNew(obj.SizeBytes)
	keep := append([]string(nil), retained...)
	sort.Strings(keep)
	for i, id := range keep {
		if id == "" || i > 0 && id == keep[i-1] || !stringMember(eligible, id) {
			return out, fmt.Errorf("scheduler: invalid retained write replica")
		}
	}
	var remaining []string
	for _, id := range eligible {
		if !stringMember(keep, id) {
			remaining = append(remaining, id)
		}
	}
	low := max(minReplicas, work.Policy.MinFaultTolerance+1)
	high := min(work.Policy.MaxReplicaCount, len(eligible))
	families := writeCountOrder(low, high)
	if len(families) == 0 {
		out.Reasons = []string{"accepted write protection cannot be maintained by available nodes"}
		return out, nil
	}
	var candidates []writeCandidate
	evaluated := 0
	for family, count := range families {
		budget := work.Policy.Search.MaxCandidates / len(families)
		if family < work.Policy.Search.MaxCandidates%len(families) {
			budget++
		}
		if budget == 0 {
			continue
		}
		var targetSets [][]string
		if count == len(keep) {
			targetSets = append(targetSets, append([]string(nil), keep...))
		} else {
			for _, extra := range writeNodeSets(e, remaining, count-len(keep), budget) {
				ids := append(append([]string(nil), keep...), extra...)
				sort.Strings(ids)
				targetSets = append(targetSets, ids)
			}
		}
		confirmCounts := writeCountOrder(max(minConfirmations, work.Policy.MinFaultTolerance+1), count)
		used := 0
		for round := 0; used < budget; round++ {
			progress := false
			for _, targets := range targetSets {
				for _, confirms := range confirmCounts {
					sets := writeNodeSets(e, targets, confirms, min(budget, work.Policy.Search.BeamWidth))
					if round >= len(sets) {
						continue
					}
					progress = true
					used++
					evaluated++
					if candidate, ok := buildWriteCandidate(e, obj, targets, sets[round], now); ok {
						candidates = append(candidates, candidate)
					}
					if used == budget {
						break
					}
				}
				if used == budget {
					break
				}
			}
			if !progress {
				break
			}
		}
	}
	out.EvaluatedCandidates = evaluated
	if len(candidates) == 0 {
		out.Reasons = []string{"no recovery layout preserves the accepted protection and retained replicas"}
		return out, nil
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
		score := ScoreBreakdown{Durability: c.durability, Readability: c.readability, Cost: cost,
			Performance: .75*minLatency/c.latency + .25/float64(c.decision.RequiredConfirmations),
			Stability:   1 - float64(c.bytes)/float64(maxBytes), Units: "recovery ranking preserves accepted replica and confirmation floors; same bounded write constraints and transfer validation"}
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
	out = candidates[0].decision
	out.EvaluatedCandidates = evaluated
	out.Reasons = []string{"recovery preserved accepted protection requirements and completed replicas", "replacement selection is bounded and independently validated"}
	out.Validation = ValidateWriteRecoveryDecisionAt(work, obj, out, minReplicas, minConfirmations, keep, now)
	if !out.Validation.Passed {
		out.Status, out.Plan, out.Transfer = StatusNoFeasible, nil, nil
		out.ConfirmationNodes, out.RequiredConfirmations = nil, 0
		out.Reasons = []string{"selected recovery plan failed independent validation"}
	}
	return out, nil
}

func ValidateWriteRecoveryDecisionAt(snap *Snapshot, obj ObjectRequirement, decision WriteDecision, minReplicas, minConfirmations int, retained []string, now time.Time) *ValidationReport {
	report := ValidateWriteDecisionAt(snap, obj, decision, now)
	if minReplicas < 1 || minConfirmations < 1 || minConfirmations > minReplicas || decision.Plan == nil || len(decision.Plan.TargetLayout.Replicas) < minReplicas || decision.RequiredConfirmations < minConfirmations {
		violate(report, VInsufficientShards, "recovery weakened accepted write requirements")
	}
	if decision.Plan != nil {
		var targets []string
		for _, placement := range decision.Plan.TargetLayout.Replicas {
			targets = append(targets, placement.NodeID)
		}
		seen := map[string]bool{}
		for _, id := range retained {
			if seen[id] || !stringMember(targets, id) {
				violate(report, VLayoutMismatch, "recovery lost or duplicated a retained replica")
			}
			seen[id] = true
		}
	}
	report.Passed = len(report.Violations) == 0
	return report
}
