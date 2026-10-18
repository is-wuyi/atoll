package meta

import (
	"time"

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

type NodePlacementProfile struct {
	NodeID         uint64            `json:"node_id"`
	FailureDomains map[string]string `json:"failure_domains"`
	HeadroomBytes  int64             `json:"headroom_bytes"`
}

type ProtectionTarget struct {
	NodeID      uint64    `json:"node_id"`
	Addr        string    `json:"addr"`
	Done        bool      `json:"done"`
	Attempts    uint32    `json:"attempts"`
	NextAttempt time.Time `json:"next_attempt,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

type ProtectionPlan struct {
	ID              string                `json:"id"`
	InputHash       string                `json:"input_hash"`
	ProfileRevision uint64                `json:"profile_revision"`
	State           string                `json:"state"`
	Expected        types.ObjectIntegrity `json:"expected"`
	Targets         []ProtectionTarget    `json:"targets"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
	Reason          string                `json:"reason"`
	LastError       string                `json:"last_error,omitempty"`
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

type ProtectionExecutionBudget struct {
	MaxConcurrent int
	MaxBytes      int64
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
