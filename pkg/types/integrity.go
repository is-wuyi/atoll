package types

import "time"

const IntegrityProtocol = "integrity-v1"

// ObjectIntegrity binds a physical object to the metadata snapshot used to verify it.
// ChecksumKnown distinguishes an explicit CRC of zero from legacy unrecorded checksums.
type ObjectIntegrity struct {
	PlanID         string    `json:"plan_id,omitempty"`
	PlanLeaseUntil time.Time `json:"plan_lease_until,omitzero"`
	ObjectID       uint64    `json:"object_id"`
	InodeID        uint64    `json:"inode_id"`
	Generation     uint64    `json:"generation"`
	IntegrityEpoch uint64    `json:"integrity_epoch"`
	Chunked        bool      `json:"chunked"`
	ChunkIndex     int       `json:"chunk_index"`
	Size           int64     `json:"size"`
	Checksum       uint32    `json:"checksum"`
	ChecksumKnown  bool      `json:"checksum_known"`
	Replicas       []uint64  `json:"replicas"`
	Done           []uint64  `json:"done,omitempty"`
	Suspect        []uint64  `json:"suspect,omitempty"`
}

type NodeUsage struct {
	Epoch     string `json:"epoch"`
	Sequence  uint64 `json:"sequence"`
	UsedBytes int64  `json:"used_bytes"`
}

type ReplicationPlan struct {
	Protocol string          `json:"protocol"`
	Object   ObjectIntegrity `json:"object"`
	Targets  []NodeInfo      `json:"targets"`
	Sources  []NodeInfo      `json:"sources,omitempty"`
}
