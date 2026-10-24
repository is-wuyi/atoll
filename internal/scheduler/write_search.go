package scheduler

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Budget both rejected and feasible pairs; a small family must not consume all work before wider layouts are visited.
func writeCandidates(e *engine, obj ObjectRequirement, now time.Time) ([]writeCandidate, int) {
	eligible := e.eligibleForNew(obj.SizeBytes)
	rMin := e.policy.MinFaultTolerance + 1
	rMax := minInt(e.policy.MaxReplicaCount, len(eligible))
	families := writeCountOrder(rMin, rMax)
	if len(families) == 0 {
		return nil, 0
	}
	budget := e.policy.Search.MaxCandidates
	var out []writeCandidate
	evaluated := 0
	for family, r := range families {
		share := budget / len(families)
		if family < budget%len(families) {
			share++
		}
		if share == 0 {
			continue
		}
		targetSets := writeNodeSets(e, eligible, r, share)
		qOrder := writeCountOrder(rMin, r)
		// Fully confirmed layouts compete even when this family has only one evaluation slot.
		if len(qOrder) > 1 {
			qOrder[0], qOrder[1] = qOrder[1], qOrder[0]
		}
		used := 0
		for round := 0; used < share; round++ {
			progress := false
			for _, targets := range targetSets {
				for _, q := range qOrder {
					sets := writeNodeSets(e, targets, q, minInt(share, e.policy.Search.BeamWidth))
					if round >= len(sets) {
						continue
					}
					progress = true
					used++
					evaluated++
					if candidate, ok := buildWriteCandidate(e, obj, targets, sets[round], now); ok {
						out = append(out, candidate)
					}
					if used == share {
						break
					}
				}
				if used == share {
					break
				}
			}
			if !progress {
				break
			}
		}
	}
	return out, evaluated
}

func writeCountOrder(low, high int) []int {
	var out []int
	for low <= high {
		out = append(out, low)
		if low != high {
			out = append(out, high)
		}
		low++
		high--
	}
	return out
}

func buildWriteCandidate(e *engine, obj ObjectRequirement, targets, confirms []string, now time.Time) (writeCandidate, bool) {
	layout, confirmed := writeLayout(obj, targets), writeLayout(obj, confirms)
	if !validateWriteLayout(e.snap, obj, layout, now).Passed || !validateWriteLayout(e.snap, obj, confirmed, now).Passed {
		return writeCandidate{}, false
	}
	ordered := append([]string(nil), confirms...)
	for _, id := range targets {
		if !stringMember(confirms, id) {
			ordered = append(ordered, id)
		}
	}
	stored := obj.SizeBytes * uint64(len(targets))
	plan := &Plan{ObjectID: obj.ObjectID, TargetLayout: writeLayout(obj, ordered), MigrationBytes: stored, Shadow: true}
	for _, target := range plan.TargetLayout.Replicas {
		plan.Actions = append(plan.Actions, Action{Kind: "add_replica", NodeID: target.NodeID, FragmentIndex: target.FragmentIndex, Bytes: target.Bytes, Reason: "new immutable object"})
	}
	decision := WriteDecision{ObjectID: obj.ObjectID, Status: StatusPlanProposed, Plan: plan, ConfirmationNodes: append([]string(nil), confirms...), RequiredConfirmations: len(confirms)}
	durTarget, readTarget := writeProtectionScore(e, layout)
	durConfirmed, readConfirmed := writeProtectionScore(e, confirmed)
	candidate := writeCandidate{decision: decision, bytes: stored, key: fmt.Sprint(ordered, "/", confirms),
		durability: .65*durConfirmed + .35*durTarget, readability: .65*readConfirmed + .35*readTarget}
	for _, id := range targets {
		candidate.cost += float64(obj.SizeBytes) * e.nodes[id].CostPerGBMonth
	}
	for _, id := range confirms {
		candidate.latency = math.Max(candidate.latency, math.Max(1, e.nodes[id].RTTMs))
	}
	if e.snap.Network != nil {
		transfer, err := planWriteTransfer(e.snap.Network, ordered, confirms, obj.SizeBytes, now)
		if err != nil {
			return writeCandidate{}, false
		}
		candidate.decision.Transfer = transfer
		candidate.latency = math.Max(1, transfer.EstimatedSeconds*1000)
	}
	return candidate, finiteNonNeg(candidate.cost)
}

// With a constrained search, try a diverse placement before RTT/cost-only seeds.
func diverseWriteSet(e *engine, pool []string, count int) []string {
	if count < 1 || count > len(pool) {
		return nil
	}
	selected := make([]string, 0, count)
	used := map[string]bool{}
	domainUse := map[string]int{}
	for len(selected) < count {
		best, bestOverlap := "", math.MaxInt
		for _, id := range pool {
			if used[id] {
				continue
			}
			overlap := 0
			for _, domain := range e.domainSignatures(id) {
				overlap += domainUse[domain]
			}
			if overlap < bestOverlap {
				best, bestOverlap = id, overlap
			}
		}
		selected = append(selected, best)
		used[best] = true
		for _, domain := range e.domainSignatures(best) {
			domainUse[domain]++
		}
	}
	sort.Strings(selected)
	return selected
}

func appendWriteSet(out *[][]string, seen map[string]bool, set []string, limit int) {
	if len(set) == 0 || len(*out) >= limit {
		return
	}
	key := strings.Join(set, "\x00")
	if !seen[key] {
		seen[key] = true
		*out = append(*out, set)
	}
}
