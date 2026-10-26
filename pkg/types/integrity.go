package types

import "time"

const IntegrityProtocol = "integrity-v1"

// ObjectIntegrity binds a physical object to the metadata snapshot used to verify it.
// ChecksumKnown distinguishes an explicit CRC of zero from legacy unrecorded checksums.
// PlanAttempt identifies the protection claim attempt this descriptor/receipt
// belongs to; 0 means a legacy plan fenced only by PlanLeaseUntil equality.
type ObjectIntegrity struct {
	PlanID           string    `json:"plan_id,omitempty"`
	PlanLeaseUntil   time.Time `json:"plan_lease_until,omitzero"`
	PlanAttempt      uint32    `json:"plan_attempt,omitzero"`
	PlanAttemptToken string    `json:"plan_attempt_token,omitempty"`
	PlanHardUntil    time.Time `json:"plan_hard_until,omitzero"`
	ObjectID         uint64    `json:"object_id"`
	InodeID          uint64    `json:"inode_id"`
	Generation       uint64    `json:"generation"`
	IntegrityEpoch   uint64    `json:"integrity_epoch"`
	Chunked          bool      `json:"chunked"`
	ChunkIndex       int       `json:"chunk_index"`
	Size             int64     `json:"size"`
	Checksum         uint32    `json:"checksum"`
	ChecksumKnown    bool      `json:"checksum_known"`
	Replicas         []uint64  `json:"replicas"`
	Done             []uint64  `json:"done,omitempty"`
	Suspect          []uint64  `json:"suspect,omitempty"`
}

type ProtectionProgress struct {
	PlanID         string `json:"plan_id"`
	ObjectID       uint64 `json:"object_id"`
	Generation     uint64 `json:"generation"`
	IntegrityEpoch uint64 `json:"integrity_epoch"`
	NodeID         uint64 `json:"node_id"`
	Attempt        uint32 `json:"attempt"`
	AttemptToken   string `json:"attempt_token"`
	BytesDone      int64  `json:"bytes_done"`
	GoodputBPS     uint64 `json:"goodput_bps"`
	FailureKind    string `json:"failure_kind,omitempty"`
	Message        string `json:"message,omitempty"`
}

type ProtectionProgressResult struct {
	Recorded   bool      `json:"recorded"`
	Renewed    bool      `json:"renewed"`
	Action     string    `json:"action"`
	LeaseUntil time.Time `json:"lease_until,omitzero"`
	HardUntil  time.Time `json:"hard_until,omitzero"`
	SourceID   uint64    `json:"source_id"`
	GoodputBPS uint64    `json:"goodput_bps"`
}

type NodeUsage struct {
	Epoch     string `json:"epoch"`
	Sequence  uint64 `json:"sequence"`
	UsedBytes int64  `json:"used_bytes"`
}

// ReplicaTransfer is the committed network binding for one plan target.
// PlanAttempt mirrors the owning claim's attempt counter; a ticket whose
// attempt differs is a superseded attempt and must be refused.
type ReplicaTransfer struct {
	SourceID         uint64    `json:"source_id"`
	TargetID         uint64    `json:"target_id"`
	PlanAttempt      uint32    `json:"plan_attempt,omitzero"`
	PlanAttemptToken string    `json:"plan_attempt_token,omitempty"`
	HardUntil        time.Time `json:"hard_until,omitzero"`
	UploadBPS        uint64    `json:"upload_bps"`
	DownloadBPS      uint64    `json:"download_bps"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type ReplicationPlan struct {
	Protocol      string             `json:"protocol"`
	Object        ObjectIntegrity    `json:"object"`
	Targets       []NodeInfo         `json:"targets"`
	Sources       []NodeInfo         `json:"sources,omitempty"`
	WriteTransfer *WriteTransferPlan `json:"write_transfer,omitempty"`
	Transfer      *ReplicaTransfer   `json:"transfer,omitempty"`
}
