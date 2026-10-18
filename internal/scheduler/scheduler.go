package scheduler

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// ---------------------------------------------------------------------------
// Top-level orchestration: Run / RunAt.
//
// RunAt is the pure entry point: it takes an explicit evaluation time so
// history-based predictions are reproducible in tests; Run uses time.Now().
// The input snapshot is deep-copied and NEVER mutated (verified by tests);
// every produced Plan is shadow-only (suggestions) and every selected
// candidate has passed the independent validator.
//
// Two safety nets wrap the per-object decisions:
//   - Exit gate: every proposed/deferred plan passes validatePlanAt (the
//     independent validator, including re-derived origins/bytes and the
//     anti-shrink floor) at the evaluation time before it leaves; a failing
//     plan is withdrawn to no_feasible, never relaxed.
//   - Sequential joint budgeting: a plan's new-placement bytes are charged
//     into the working snapshot's ReservedBytes, so later objects in the
//     same run cannot oversell the same nodes. The run's plans are jointly
//     budgeted (Plan.JointlyBudgeted) — but a batch containing simulated
//     plans (requires_ec_backend) is still not executable until an EC
//     backend exists.
// ---------------------------------------------------------------------------

// Run evaluates the snapshot at the current wall clock.
func Run(snap *Snapshot) ([]Decision, error) {
	return RunAt(snap, time.Now())
}

// RunAt evaluates the snapshot at an explicit time (deterministic testing).
func RunAt(snap *Snapshot, now time.Time) ([]Decision, error) {
	if snap == nil {
		return nil, fmt.Errorf("scheduler: nil snapshot")
	}
	rep := ValidateSnapshot(snap)
	if !rep.Passed {
		return nil, fmt.Errorf("scheduler: invalid snapshot: %s", summarizeViolations(rep))
	}

	pol := normalizePolicy(snap.Policy)
	work := deepCopySnapshot(snap)
	work.Policy = pol

	e := newEngine(work, pol, now)
	decisions := make([]Decision, 0, len(work.Objects))
	for i := range work.Objects {
		d := e.decide(work.Objects[i])
		if d.Plan != nil {
			gate := validatePlanAt(work, work.Objects[i], *d.Plan, pol, now)
			if !gate.Passed {
				// The exit gate never relaxes constraints: a plan that
				// fails independent validation is withdrawn.
				d.Status = StatusNoFeasible
				d.Plan = nil
				d.SelectedID = ""
				d.Validation = gate
				d.Reasons = []string{"plan withdrawn: failed independent exit validation (constraints not relaxed)"}
				for j, v := range gate.Violations {
					if j >= 6 {
						break
					}
					d.Reasons = append(d.Reasons, v.Code+": "+v.Message)
				}
			} else {
				d.Plan.JointlyBudgeted = true
				if d.Status == StatusPlanProposed {
					d.Reasons = append(d.Reasons,
						"joint budget: this run reserves the plan's new bytes against later objects; simulated (requires_ec_backend) plans cannot be batch-executed until an EC backend exists")
				}
				chargePlan(work, work.Objects[i], d.Plan)
			}
		}
		decisions = append(decisions, d)
	}
	return decisions, nil
}

// chargePlan reserves a proposed plan's new-placement bytes in the working
// snapshot so that later objects in the same run cannot oversell the same
// nodes (sequential joint budgeting). Placement semantics are re-derived
// from the object's current layout, mirroring the validator.
func chargePlan(snap *Snapshot, obj ObjectRequirement, plan *Plan) {
	derived := deriveTargetPlacements(obj.CurrentLayout, &plan.TargetLayout, obj.SizeBytes)
	perNode := map[string]uint64{}
	for i := range derived {
		p := &derived[i]
		if p.Origin != OriginNew {
			continue
		}
		if sum, of := addOverflow(perNode[p.NodeID], p.Bytes); of {
			perNode[p.NodeID] = math.MaxUint64
		} else {
			perNode[p.NodeID] = sum
		}
	}
	if len(perNode) == 0 {
		return
	}
	for i := range snap.Nodes {
		add, ok := perNode[snap.Nodes[i].ID]
		if !ok {
			continue
		}
		if sum, of := addOverflow(snap.Nodes[i].ReservedBytes, add); of {
			snap.Nodes[i].ReservedBytes = math.MaxUint64
		} else {
			snap.Nodes[i].ReservedBytes = sum
		}
	}
}

// normalizePolicy fills unset policy fields with conservative defaults so
// callers only set what they care about. Explicit zeros for gates that
// mean "disabled" (MinPredictedReadability, MaxMigrationBytesBudget) stay 0.
func normalizePolicy(p Policy) Policy {
	out := p
	if out.MinFaultTolerance < 0 {
		out.MinFaultTolerance = 0
	}
	if out.MaxReplicaCount <= 0 {
		out.MaxReplicaCount = 3
	}
	if out.CodecLimits.MaxK == 0 {
		out.CodecLimits = CodecLimits{MinK: 2, MaxK: 4, MinM: 1, MaxM: 2, MaxTotalShards: 6}
	} else if out.CodecLimits.MaxK < 0 {
		// Negative MaxK = RS traversal explicitly disabled (replication-only).
		out.CodecLimits.MaxK = -1
	} else {
		if out.CodecLimits.MinK < 1 {
			out.CodecLimits.MinK = 1
		}
		if out.CodecLimits.MaxM <= 0 {
			out.CodecLimits.MaxM = 2
		}
		if out.CodecLimits.MinM < 0 {
			out.CodecLimits.MinM = 0
		}
		if out.CodecLimits.MaxTotalShards <= 0 {
			out.CodecLimits.MaxTotalShards = out.CodecLimits.MaxK + out.CodecLimits.MaxM
		}
	}
	if out.PredictionHorizonSeconds <= 0 {
		out.PredictionHorizonSeconds = 86400
	}
	if out.MinConfidence <= 0 {
		out.MinConfidence = 0.5
	}
	if out.MaxDeferOfflineSeconds <= 0 {
		out.MaxDeferOfflineSeconds = 7200
	}
	if out.MinFaultMarginToDefer < 0 {
		out.MinFaultMarginToDefer = 0
	}
	// MinFaultMarginToDefer stays as provided: 0 means deferral is allowed
	// even with zero spare shards (routine short spells only, since the
	// spell-length check and the horizon gate still apply). Examples and
	// tests set 1 explicitly for the stricter stance.
	if out.ImprovementThreshold <= 0 {
		out.ImprovementThreshold = 0.05
	}
	if out.Search.ExactComboLimit <= 0 {
		out.Search.ExactComboLimit = 252
	}
	if out.Search.BeamWidth <= 0 {
		out.Search.BeamWidth = 8
	}
	if out.Search.MaxCandidates <= 0 {
		out.Search.MaxCandidates = 256
	}
	return out
}

func summarizeViolations(rep *ValidationReport) string {
	out := ""
	for i, v := range rep.Violations {
		if i > 0 {
			out += "; "
		}
		out += v.Code + ": " + v.Message
		if i >= 4 {
			out += "; ..."
			break
		}
	}
	return out
}

// deepCopySnapshot round-trips through JSON. All fields are JSON-mapped by
// construction, so this is a faithful deep copy and guarantees the input
// snapshot cannot be mutated by scheduler code.
func deepCopySnapshot(snap *Snapshot) *Snapshot {
	b, err := json.Marshal(snap)
	if err != nil {
		// Snapshots are JSON-marshalable by definition; this is defensive.
		panic(fmt.Sprintf("scheduler: snapshot not marshalable: %v", err))
	}
	var out Snapshot
	if err := json.Unmarshal(b, &out); err != nil {
		panic(fmt.Sprintf("scheduler: snapshot round-trip failed: %v", err))
	}
	return &out
}
