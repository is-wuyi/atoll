// Package scheduler implements the Atoll edge-storage shadow scheduler
// (Phase A + Phase B prototype).
//
// It is a *suggestion-only* ("shadow") optimizer: given a serializable
// Snapshot of nodes, object layouts and policy, it produces scored layout
// candidates and a Plan of recommended actions. It never mutates cluster
// state, never talks to a cluster, and never executes erasure coding —
// RS layouts are simulated candidates flagged RequiresECBackend.
//
// Design invariants enforced here:
//   - Hard resource budgets (capacity minus reserved minus in-flight
//     double-held migration bytes) are constraints, never soft costs.
//   - Failure-domain co-failure is modeled: fragments/replicas sharing a
//     failure domain do not count as independent fault tolerance.
//   - Duplicate copies of the same EC shard (same fragment index) never
//     inflate the number of independent shards.
//   - An independent Validator re-derives every constraint from the
//     Snapshot + Policy and never trusts candidate self-scores.
//   - Output is fully deterministic (no randomness; the seed field is
//     accepted for interface stability and asserted not to change results).
package scheduler

import (
	"fmt"
	"math"
)

// SchemaVersion is the version of the JSON wire format consumed/produced
// by the scheduler and cmd/atoll-scheduler.
const SchemaVersion = 1

// ---------------------------------------------------------------------------
// Snapshot input types (all JSON-serializable, stdlib encoding/json only).
// ---------------------------------------------------------------------------

// Snapshot is the world view the scheduler optimizes against. It is a pure
// input: scheduler code must never modify it (tested in scheduler_test.go).
type Snapshot struct {
	SchemaVersion int                 `json:"schema_version"`
	GeneratedAt   string              `json:"generated_at"` // RFC3339; informational
	TraceID       string              `json:"trace_id,omitempty"`
	Nodes         []Node              `json:"nodes"`
	Objects       []ObjectRequirement `json:"objects"`
	Policy        Policy              `json:"policy"`
	Network       *TransferNetwork    `json:"network,omitempty"`
}

// Node is one storage node with its hard resource budget and the best
// available availability information.
type Node struct {
	// ID is the stable node identity. Must be unique within the snapshot.
	ID string `json:"id"`

	// FailureDomains maps an axis (e.g. "zone", "rack", "host") to a value.
	// Unknown-axis handling (conservative): if a node does not declare an
	// axis, it is treated as sharing the single "unknown" domain on that
	// axis with every other node that also does not declare it (they might
	// co-fail). The special axis "host" always defaults to the node ID
	// itself (single-machine failures are independent even when undeclared).
	FailureDomains map[string]string `json:"failure_domains,omitempty"`

	// HardCapacityBytes is a HARD budget. 0 means "no budget declared":
	// the validator refuses to place any new bytes on such a node (we never
	// assume unlimited capacity).
	HardCapacityBytes uint64 `json:"hard_capacity_bytes"`

	// ReservedBytes are bytes already reserved on this node (existing data,
	// reservations, headroom). Hard-constraint accounting:
	// free = HardCapacityBytes - ReservedBytes - InFlightBytes - planned.
	ReservedBytes uint64 `json:"reserved_bytes"`

	// InFlightBytes are bytes of migrations already in progress that are
	// double-held (source copy still resident until handover). Subtracted
	// from free capacity to avoid double-booking during migration.
	InFlightBytes uint64 `json:"in_flight_bytes"`

	// Online is the currently verifiable liveness state.
	Online bool `json:"online"`

	// Availability is an explicit finite-horizon forecast from upstream
	// telemetry, optional. When absent it is derived from History via
	// NodeHistory pure functions; when both are absent a conservative
	// fallback applies (see history.go).
	Availability []AvailabilityWindow `json:"availability_forecast,omitempty"`

	// History is an optional raw online/offline sample log used by
	// NodeHistory (pure functions) to produce per-period predictions.
	History []OnlineSample `json:"history,omitempty"`

	// RTTMs is the measured round-trip time in milliseconds (>= 0).
	// Used only as a relative performance weight, never as a hard gate.
	RTTMs float64 `json:"rtt_ms"`

	// CostPerGBMonth is a relative storage cost unit (currency-agnostic).
	CostPerGBMonth float64 `json:"cost_per_gb_month"`
}

// AvailabilityWindow predicts P(node continuously online for the next
// HorizonSeconds) with a confidence in [0,1] for that forecast, plus the
// expected duration of a typical offline spell in the horizon (seconds;
// 0 = no offline spell predicted). Horizon is finite by construction.
type AvailabilityWindow struct {
	HorizonSeconds               int     `json:"horizon_seconds"`
	ProbabilityOnline            float64 `json:"probability_online"`
	Confidence                   float64 `json:"confidence"`
	PredictedOfflineSpellSeconds float64 `json:"predicted_offline_spell_seconds,omitempty"`
}

// OnlineSample is one liveness observation for NodeHistory.
type OnlineSample struct {
	At     string `json:"at"` // RFC3339
	Online bool   `json:"online"`
}

// ObjectRequirement is the scheduling request for one immutable object.
type ObjectRequirement struct {
	ObjectID       string           `json:"object_id"`
	SizeBytes      uint64           `json:"size_bytes"` // must be > 0
	ContentVersion uint64           `json:"content_version"`
	Intent         ProtectionIntent `json:"intent"`
	// CurrentLayout is nil for a brand-new object.
	CurrentLayout *Layout `json:"current_layout,omitempty"`
}

// ProtectionIntent carries the soft weights for this object. Hard
// constraints (fault tolerance, budgets) live in Policy and are never
// traded away by weights. If all weights are zero, they are derived from
// Tier (one of "performance", "normal", "security").
type ProtectionIntent struct {
	Tier    string       `json:"tier,omitempty"`
	Weights ScoreWeights `json:"weights"`
}

// ScoreWeights are soft preference weights. The scheduler normalizes them
// to sum to 1 (validator rejects non-finite or non-positive-total weights).
type ScoreWeights struct {
	Durability  float64 `json:"durability,omitempty"`
	Readability float64 `json:"readability,omitempty"`
	Cost        float64 `json:"cost,omitempty"`
	Performance float64 `json:"performance,omitempty"`
	Stability   float64 `json:"stability,omitempty"`
}

// Scheme selects the layout family.
type Scheme string

const (
	SchemeReplicate Scheme = "replicate"
	SchemeRS        Scheme = "rs"
)

// Layout is the unified layout shape used both for current layouts
// (snapshot input) and target layouts (plan output). It only ever
// *describes* a layout; it never triggers writes.
type Layout struct {
	ObjectID       string `json:"object_id"`
	ContentVersion uint64 `json:"content_version"`
	LayoutEpoch    uint64 `json:"layout_epoch"`
	Scheme         Scheme `json:"scheme"`
	// Replicas holds one placement per replica (SchemeReplicate,
	// FragmentIndex = copy number 0..r-1) or per EC fragment
	// (SchemeRS, FragmentIndex in 0..k+m-1). Duplicate entries with the
	// same FragmentIndex on different nodes are legitimate same-shard
	// copies; they never count as additional independent shards.
	Replicas []FragmentPlacement `json:"replicas"`
	// EC is non-nil iff Scheme == SchemeRS.
	EC *ECParams `json:"ec,omitempty"`
}

// ECParams are the RS parameters. The scheduler does NOT encode; RS
// layouts are simulated candidates only. Supported simulated range
// (GF(256) field limit): k >= 1, m >= 1, k+m <= 255 — layouts outside it
// are rejected by the validator.
type ECParams struct {
	K int `json:"k"`
	M int `json:"m"`
}

// FragmentPlacement is one shard/replica on one node.
type FragmentPlacement struct {
	NodeID        string `json:"node_id"`
	FragmentIndex int    `json:"fragment_index"`
	// Bytes stored by this placement (replica: object size; RS data or
	// parity fragment: ceil(objectSize / k)).
	Bytes uint64 `json:"bytes"`
	// Origin marks plan semantics: "existing" (kept from current layout),
	// "new" (must be written/transferred now). Empty in snapshot inputs.
	Origin string `json:"origin,omitempty"`
}

const (
	OriginExisting = "existing"
	OriginNew      = "new"
)

// ---------------------------------------------------------------------------
// Policy (hard constraints + soft normalization + search budget).
// ---------------------------------------------------------------------------

// Policy holds every hard constraint and tunable. The validator reads
// ONLY these (plus the snapshot) — constraints are never derived from
// candidate output, so "no feasible" can never be produced by quietly
// lowering a constraint.
type Policy struct {
	// TierDefaults optionally override the built-in tier weight presets.
	TierDefaults map[string]ScoreWeights `json:"tier_defaults,omitempty"`

	// MinFaultTolerance is the minimum number of *simultaneous failure-
	// domain failures* the layout must tolerate (hard). For replication
	// this forces replica count >= MinFaultTolerance+1 (when enough
	// eligible nodes exist); for RS it constrains k/m traversal.
	MinFaultTolerance int `json:"min_fault_tolerance"`

	// MaxReplicaCount caps the replication factor searched (hard cap).
	// The engine auto-selects r within [MinFaultTolerance+1, min(MaxReplicaCount, eligible)].
	MaxReplicaCount int `json:"max_replica_count"`

	// AdditiveOnly is the strict add-only mode for autonomous replica
	// growth. When true the engine proposes SchemeReplicate targets only,
	// and every target must contain every current (node, fragment index)
	// placement — including placements on currently-offline nodes — with
	// additions only on distinct, previously unused, verifiably-online
	// nodes at fragment indices after the existing ones. No truncation,
	// reassignment, same-count replacement, EC layout or scheme change may
	// be generated, and the independent validator rejects any plan that
	// violates that contract. Retained placements are never re-charged
	// against capacity; only new bytes are. Existing counts at/above
	// MaxReplicaCount yield keep (healthy) or explicit no_feasible
	// (degraded) — never a shrink. Default false preserves the legacy
	// repair semantics (offline holders may be replaced/moved).
	AdditiveOnly bool `json:"additive_only"`

	// CodecLimits bound the RS k/m traversal — no fixed tiers: every
	// (k,m) in the box is enumerated subject to MinFaultTolerance.
	CodecLimits CodecLimits `json:"codec_limits"`

	// PredictionHorizonSeconds is the finite forecast window used for all
	// predicted-readability math (0 => default 86400).
	PredictionHorizonSeconds int `json:"prediction_horizon_seconds"`

	// MinPredictedReadability is the hard gate on predicted readability
	// over the horizon (probability in [0,1]).
	MinPredictedReadability float64 `json:"min_predicted_readability"`

	// MinConfidence: forecasts with confidence below this are handled
	// conservatively (treated as uncertain), never as proof of uptime.
	MinConfidence float64 `json:"min_confidence"`

	// Offline-deferral policy ("regular offline can wait"):
	// defer a repair only if ALL of:
	//   - the expected offline spell <= MaxDeferOfflineSeconds (routine),
	//   - at least one verifiably online replica (or >= k distinct online
	//     RS shards) remains — the object is readable right now,
	//   - remaining fault margin >= MinFaultMarginToDefer, where margin =
	//     onlineDistinctShards - minimumRequiredReadable,
	//   - the horizon gate (MinPredictedReadability) still passes.
	MaxDeferOfflineSeconds int `json:"max_defer_offline_seconds"`
	MinFaultMarginToDefer  int `json:"min_fault_margin_to_defer"`

	// MaxMigrationBytesBudget caps planned migration bytes per plan
	// (hard; 0 = unlimited).
	MaxMigrationBytesBudget uint64 `json:"max_migration_bytes_budget"`

	// ImprovementThreshold: a repair plan is only proposed when the best
	// candidate improves the weighted score over "keep current" by at
	// least this much (anti-jitter, keeps changes small). 0 => default 0.05.
	ImprovementThreshold float64 `json:"improvement_threshold"`

	// Search bounds the candidate engine.
	Search SearchParams `json:"search"`

	// Seed is accepted for interface stability. The engine is fully
	// deterministic (sorted nodes, stable tie-breaks); tests assert that
	// changing Seed does NOT change any output.
	Seed int64 `json:"seed,omitempty"`
}

// CodecLimits configure the RS k/m traversal without hardcoding tiers.
type CodecLimits struct {
	MinK           int `json:"min_k"`
	MaxK           int `json:"max_k"`
	MinM           int `json:"min_m"`
	MaxM           int `json:"max_m"`
	MaxTotalShards int `json:"max_total_shards"` // k+m cap
}

// SearchParams bound candidate enumeration.
type SearchParams struct {
	// ExactComboLimit: enumerate all C(n, r) node combinations exactly
	// when the binomial is <= this; otherwise beam search. 0 => 252.
	ExactComboLimit int `json:"exact_combo_limit"`
	// BeamWidth for the beam/local search fallback. 0 => 8.
	BeamWidth int `json:"beam_width"`
	// MaxCandidates caps total scored candidates per object. 0 => 256.
	// Candidates are generated replication-first, then RS (k ascending,
	// m ascending); when the cap binds, the tail of that order (the widest
	// RS combinations) is dropped first, never replication.
	MaxCandidates int `json:"max_candidates"`
}

// ---------------------------------------------------------------------------
// Candidate, Score, Plan, Decision, Validation output types.
// ---------------------------------------------------------------------------

// Candidate is one scored, fully-placed layout proposal.
type Candidate struct {
	CandidateID string              `json:"candidate_id"`
	Scheme      Scheme              `json:"scheme"`
	R           int                 `json:"r,omitempty"`  // replication factor (SchemeReplicate)
	EC          *ECParams           `json:"ec,omitempty"` // SchemeRS (simulated only)
	Placement   []FragmentPlacement `json:"placement"`
	Score       ScoreBreakdown      `json:"score"`
	Reasons     []string            `json:"reasons"`
	// RequiresECBackend is true for every RS candidate: the layout was
	// scored by simulation only and cannot be executed until a real EC
	// backend exists. The scheduler never encodes.
	RequiresECBackend bool   `json:"requires_ec_backend"`
	MigrationBytes    uint64 `json:"migration_bytes"`
	Feasible          bool   `json:"feasible"`
	InfeasibleReason  string `json:"infeasible_reason,omitempty"`
}

// ScoreBreakdown makes every component's unit and normalization explicit.
//
// All components live in [0,1]. Units & normalization (no component may be
// read as an absolute durability promise):
//   - Durability: RELATIVE ranking heuristic over the finite horizon —
//     the mean, over each failure domain holding shards, of the predicted
//     readability after that domain is fully lost. NOT a "n nines"
//     durability figure; online probability is never exponentiated into
//     a longevity claim.
//   - Readability: predicted probability the object is readable over the
//     horizon (poisson-binomial DP for RS / independence approximation
//     for replication), clamped to [0,1]. SCORE ONLY: the DP assumes
//     shard independence — a modeling assumption that guarantees nothing;
//     the hard gate in the validator uses a distribution-free union bound
//     instead. Conservative low-confidence substitution is applied per
//     node first.
//   - Cost: relative; 1.0 = cheapest candidate in the round, else
//     cheapestCost/(thisCost) clamped. Cost unit = sum(placement bytes ×
//     node CostPerGBMonth) (cost-weighted GB-month).
//   - Performance: relative; 1.0 = fastest read-set RTT in the round
//     (min replica RTT / k-th smallest shard RTT), else
//     bestRTT/(thisRTT) clamped. Unit = milliseconds.
//   - Stability: 1.0 = zero migration bytes, else
//     1 - migrationBytes/max(roundRef,1) clamped. Unit = bytes moved.
type ScoreBreakdown struct {
	Total       float64 `json:"total"`
	Durability  float64 `json:"durability"`
	Readability float64 `json:"readability"`
	Cost        float64 `json:"cost"`
	Performance float64 `json:"performance"`
	Stability   float64 `json:"stability"`
	Units       string  `json:"units_explanation"`
}

// Action is one suggested step. Suggestions only — nothing here is
// executed by the scheduler.
type Action struct {
	Kind          string `json:"kind"` // keep|add_replica|move_replica|add_fragment|regenerate_fragment|defer|no_action
	NodeID        string `json:"node_id,omitempty"`
	FromNodeID    string `json:"from_node_id,omitempty"`
	FragmentIndex int    `json:"fragment_index"`
	Bytes         uint64 `json:"bytes,omitempty"`
	Simulated     bool   `json:"simulated,omitempty"` // EC-dependent actions are simulated
	Reason        string `json:"reason"`
}

// Plan is the suggestion-only output for one object.
type Plan struct {
	ObjectID           string   `json:"object_id"`
	BaseContentVersion uint64   `json:"base_content_version"`
	BaseLayoutEpoch    uint64   `json:"base_layout_epoch"`
	TargetLayout       Layout   `json:"target_layout"`
	Actions            []Action `json:"actions"`
	RequiresECBackend  bool     `json:"requires_ec_backend"`
	MigrationBytes     uint64   `json:"migration_bytes"`
	Shadow             bool     `json:"shadow"` // always true; enforced by tests
	// JointlyBudgeted is true when this plan passed the scheduler's exit
	// validation and its new-placement bytes were reserved against later
	// plans in the same run (sequential joint budgeting). It does NOT make
	// a batch executable: simulated plans (requires_ec_backend) hold
	// reserved capacity but cannot be executed until an EC backend exists.
	JointlyBudgeted bool `json:"jointly_budgeted"`
}

// Decision is the scheduler verdict for one object requirement.
type Decision struct {
	ObjectID   string            `json:"object_id"`
	Status     string            `json:"status"`
	Reasons    []string          `json:"reasons"`
	Plan       *Plan             `json:"plan,omitempty"`
	Validation *ValidationReport `json:"validation,omitempty"`
	Candidates []Candidate       `json:"candidates,omitempty"` // deterministic top-8 by score; feasible candidates first, infeasible (with reasons) may fill the tail
	SelectedID string            `json:"selected_candidate_id,omitempty"`
}

// Decision statuses.
const (
	StatusNoChange     = "no_change_needed"
	StatusPlanProposed = "plan_proposed"
	StatusDeferred     = "deferred"
	StatusNoFeasible   = "no_feasible"
	StatusInvalid      = "invalid_requirement"
)

// ValidationReport is the independent validator's output. The scheduler
// never feeds candidate scores into it — it re-derives everything.
type ValidationReport struct {
	Passed     bool          `json:"passed"`
	Violations []Violation   `json:"violations,omitempty"`
	Checks     []CheckResult `json:"checks,omitempty"`
}

// Violation codes (stable strings for tests/CLI consumers).
const (
	VUnknownNode        = "unknown_node"
	VDuplicatePlacement = "duplicate_placement_same_node"
	VIndexInvalid       = "fragment_index_invalid"
	VIndexDuplicate     = "fragment_index_duplicate_copy_counted_once"
	VInsufficientShards = "insufficient_distinct_shards"
	VNotReadableNow     = "not_readable_now"
	VHorizonGate        = "predicted_readability_below_gate"
	VFaultMargin        = "fault_margin_below_minimum"
	VCapacity           = "capacity_budget_exceeded"
	VNoBudget           = "no_capacity_budget_declared"
	VStalePlan          = "stale_plan_epoch_mismatch"
	VEpochInvalid       = "target_epoch_invalid"
	VMigrationMismatch  = "migration_bytes_mismatch"
	VBudgetExceeded     = "migration_budget_exceeded"
	VWeightsInvalid     = "weights_invalid"
	VNumberInvalid      = "number_invalid"
	VSizeInvalid        = "size_invalid"
	VSchemaMismatch     = "schema_version_mismatch"
	VDuplicateObject    = "duplicate_object_id"
	VObjectIDInvalid    = "object_id_invalid"
	VObjectMismatch     = "plan_object_mismatch"
	VLayoutMismatch     = "layout_identity_mismatch"
	VECUnsupported      = "ec_params_unsupported"
	VAntiShrink         = "repair_shrinks_redundancy"

	// Strict add-only mode (Policy.AdditiveOnly) violations.
	VAdditiveScheme      = "additive_only_target_not_replicate"
	VAdditiveNotSuperset = "additive_only_drops_current_placement"
	VAdditiveDupNode     = "additive_only_duplicate_physical_node"
	VAdditiveOfflineNew  = "additive_only_new_placement_on_offline_node"
)

// Violation is one failed check.
type Violation struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// CheckResult records a passed check for explainability.
type CheckResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// ---------------------------------------------------------------------------
// Number guards (NaN/Inf/overflow protection).
// ---------------------------------------------------------------------------

func finiteNonNeg(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 }

func unitInterval(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 && f <= 1 }

// subOverflow returns a-b and whether it underflowed.
func subOverflow(a, b uint64) (uint64, bool) {
	if b > a {
		return 0, true
	}
	return a - b, false
}

// addOverflow returns a+b and whether it overflowed.
func addOverflow(a, b uint64) (uint64, bool) {
	sum := a + b
	if sum < a {
		return 0, true
	}
	return sum, false
}

func clamp01(f float64) float64 {
	if math.IsNaN(f) {
		return 0
	}
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func fmtF(f float64) string { return fmt.Sprintf("%.4f", f) }
