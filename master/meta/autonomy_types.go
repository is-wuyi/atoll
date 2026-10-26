package meta

import (
	"time"

	"atoll/internal/scheduler"
	"atoll/pkg/types"
)

const (
	ProtectionPending     = "pending"
	ProtectionCompleted   = "completed"
	ProtectionStale       = "stale"
	ProtectionCancelled   = "cancelled"
	MaxObservationSamples = 2048
)

type NodeSample struct {
	At         time.Time `json:"at"`
	Online     bool      `json:"online"`
	UsedBytes  int64     `json:"used_bytes"`
	TotalBytes int64     `json:"total_bytes"`
	RTTMillis  float64   `json:"rtt_ms"`
}

type NodeObservation struct {
	NodeID  uint64       `json:"node_id"`
	Samples []NodeSample `json:"samples"`
}

// NodePlacementProfile is the operator-declared placement and network profile.
// UploadBPS/DownloadBPS are configured budgets in bytes per second, not
// measurements: a non-zero value is a ceiling the master may commit to, and 0
// means the budget is NOT configured. 0 is never read as unlimited — it keeps
// the legacy bounded behaviour (no per-flow rate is claimed or enforced), and
// an unconfigured rate never disqualifies a node from serving as a source.
type NodePlacementProfile struct {
	NodeID         uint64            `json:"node_id"`
	FailureDomains map[string]string `json:"failure_domains"`
	HeadroomBytes  int64             `json:"headroom_bytes"`
	UploadBPS      uint64            `json:"upload_bps,omitempty"`
	DownloadBPS    uint64            `json:"download_bps,omitempty"`
	// MaxTransferConcurrency is the number of simultaneous transfer streams
	// this node may hold (0 = not configured). It bounds the per-endpoint
	// concurrency of a transfer budget, and replica source binding refuses to
	// add a lease once the cap is reached.
	MaxTransferConcurrency int `json:"max_transfer_concurrency,omitempty"`
}

// ProtectionTarget is one committed replica addition. SourceID/SourceAddr name
// the bound upload source; UploadBPS/DownloadBPS are the source upload and
// target download budgets captured at bind time. SourceID == 0 means the
// target was claimed before source binding existed and is executed by the
// legacy rotation path.
//
// Feedback fields (AttemptToken and below, before Done) exist only on plans
// whose claim ran with protection-feedback enabled; zero values mean the
// legacy fence still applies. AttemptToken is regenerated on every claim so a
// superseded attempt's progress, receipts and tickets all become invalid at
// once, without relying on timestamp inequality. ProgressBytes/LastProgressAt
// are monotonic node-reported bytes; GoodputBPS is measured payload bytes per
// second (never the configured budget); Renewals counts bounded in-flight
// lease extensions of the current attempt; FailureKind is ""|"failed"|
// "corrupt". Progress never marks Done and never releases reservations.
type ProtectionTarget struct {
	NodeID                uint64    `json:"node_id"`
	Addr                  string    `json:"addr"`
	SourceID              uint64    `json:"source_id,omitempty"`
	SourceAddr            string    `json:"source_addr,omitempty"`
	UploadBPS             uint64    `json:"upload_bps,omitempty"`
	DownloadBPS           uint64    `json:"download_bps,omitempty"`
	AttemptToken          string    `json:"attempt_token,omitempty"`
	LeaseStart            time.Time `json:"lease_start,omitempty"`
	HardUntil             time.Time `json:"hard_until,omitzero"`
	AttemptIntegrityEpoch uint64    `json:"attempt_integrity_epoch,omitempty"`
	AttemptEpochKnown     bool      `json:"attempt_epoch_known,omitempty"`
	ProgressBytes         int64     `json:"progress_bytes,omitempty"`
	LastProgressAt        time.Time `json:"last_progress_at,omitempty"`
	GoodputBPS            uint64    `json:"goodput_bps,omitempty"`
	Renewals              uint32    `json:"renewals,omitempty"`
	FailureKind           string    `json:"failure_kind,omitempty"`
	Done                  bool      `json:"done"`
	Attempts              uint32    `json:"attempts"`
	NextAttempt           time.Time `json:"next_attempt,omitempty"`
	RetryAt               time.Time `json:"retry_at,omitzero"`
	LastError             string    `json:"last_error,omitempty"`
}

type ProtectionPlan struct {
	ID              string                `json:"id"`
	InputHash       string                `json:"input_hash"`
	ProfileRevision uint64                `json:"profile_revision"`
	State           string                `json:"state"`
	Feedback        bool                  `json:"feedback,omitempty"`
	Expected        types.ObjectIntegrity `json:"expected"`
	Targets         []ProtectionTarget    `json:"targets"`
	// NodeMaxAge is the liveness window captured at reservation time. Source
	// binding runs later, possibly minutes after the reservation, so the claim
	// re-checks source heartbeat age against this value. 0 means the plan
	// predates the field (migration) and binding falls back to metadata-only
	// source gating.
	NodeMaxAge time.Duration `json:"node_max_age,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
	Reason     string        `json:"reason"`
	LastError  string        `json:"last_error,omitempty"`
}

type ProtectionRequest struct {
	ID              string                `json:"id"`
	Expected        types.ObjectIntegrity `json:"expected"`
	Targets         []uint64              `json:"targets"`
	MaxBytes        int64                 `json:"max_bytes"`
	NodeMaxAge      time.Duration         `json:"node_max_age"`
	ProfileRevision uint64                `json:"profile_revision"`
	Reason          string                `json:"reason"`
}

// ProtectionExecutionBudget bounds one dispatch round. MaxConcurrent counts
// active protection leases only (one lease once, never mixed with write
// flows); MaxSourceConcurrent/MaxTargetConcurrent are per-node caps (0 = no
// cap). The *BPS fields are optional per-flow ceilings that only lower the
// allocated rate. NodeMaxAge is the liveness window for source binding when
// the plan predates the field (<= 0 keeps the identity-only fallback).
type ProtectionExecutionBudget struct {
	MaxConcurrent        int                         `json:"max_concurrent"`
	MaxBytes             int64                       `json:"max_bytes"`
	MaxSourceConcurrent  int                         `json:"max_source_concurrent"`
	MaxTargetConcurrent  int                         `json:"max_target_concurrent"`
	MaxSourceUploadBPS   uint64                      `json:"max_source_upload_bps"`
	MaxTargetDownloadBPS uint64                      `json:"max_target_download_bps"`
	NodeMaxAge           time.Duration               `json:"node_max_age,omitempty"`
	MaxTotalLease        time.Duration               `json:"max_total_lease,omitempty"`
	Links                []scheduler.LinkObservation `json:"links,omitempty"`
	Path                 string                      `json:"path,omitempty"`
}

type NodeCapacity struct {
	NodeID    uint64 `json:"node_id"`
	Capacity  int64  `json:"capacity_bytes"`
	Accounted int64  `json:"accounted_bytes"`
	Reserved  int64  `json:"reserved_bytes"`
	Headroom  int64  `json:"headroom_bytes"`
	Free      int64  `json:"free_bytes"`
}

type AutonomySnapshot struct {
	ScanAfter       uint64                  `json:"scan_after"`
	ProfileRevision uint64                  `json:"profile_revision"`
	Nodes           []types.NodeInfo        `json:"nodes"`
	Objects         []types.ObjectIntegrity `json:"objects"`
	Profiles        []NodePlacementProfile  `json:"profiles"`
	Observations    []NodeObservation       `json:"observations"`
	Plans           []ProtectionPlan        `json:"plans"`
	Capacity        []NodeCapacity          `json:"capacity"`
}
