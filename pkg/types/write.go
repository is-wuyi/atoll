package types

import "time"

const (
	WritePlanFeature = "write-plan-v1"
	PlainEncoding    = "plain-v1"
	WritePending     = "pending"
	WriteCommitted   = "committed"
	WriteAborted     = "aborted"
)

type ProtectionTier string

const (
	ProtectionPerformance ProtectionTier = "performance"
	ProtectionNormal      ProtectionTier = "normal"
	ProtectionSecurity    ProtectionTier = "security"
)

func (t ProtectionTier) Valid() bool {
	return t == ProtectionPerformance || t == ProtectionNormal || t == ProtectionSecurity
}

type EffectiveProtection struct {
	Tier          ProtectionTier `json:"tier"`
	SourceInodeID uint64         `json:"source_inode_id"`
	Revision      uint64         `json:"revision"`
}

type ContentObject struct {
	ID            uint64 `json:"id"`
	Version       uint64 `json:"version"`
	LogicalSize   int64  `json:"logical_size"`
	StoredSize    int64  `json:"stored_size"`
	Encoding      string `json:"encoding"`
	Checksum      uint32 `json:"checksum"`
	ChecksumKnown bool   `json:"checksum_known"`
}

type ContentExtent struct {
	Offset       int64         `json:"offset"`
	Length       int64         `json:"length"`
	ObjectOffset int64         `json:"object_offset"`
	Object       ContentObject `json:"object"`
}

// ID identifies immutable contents, independently of a file's mutable Generation.
type ContentVersion struct {
	ID          uint64          `json:"id"`
	LogicalSize int64           `json:"logical_size"`
	Extents     []ContentExtent `json:"extents"`
}

type ReplicaLayout struct {
	ObjectID uint64   `json:"object_id"`
	Epoch    uint64   `json:"epoch"`
	Scheme   string   `json:"scheme"`
	Nodes    []uint64 `json:"nodes"`
}

type WriteChunkPlan struct {
	Index                 int           `json:"index"`
	Object                ContentObject `json:"object"`
	Layout                ReplicaLayout `json:"layout"`
	Confirmations         []uint64      `json:"confirmations"`
	RequiredConfirmations int           `json:"required_confirmations"`
	Reasons               []string      `json:"reasons,omitempty"`
}

type WriteUpload struct {
	ID        uint64              `json:"id"`
	PlanID    string              `json:"plan_id"`
	Revision  uint64              `json:"revision"`
	Policy    EffectiveProtection `json:"policy"`
	Size      int64               `json:"size"`
	State     string              `json:"state"`
	CreatedAt time.Time           `json:"created_at"`
	ExpiresAt time.Time           `json:"expires_at"`
	Chunks    []WriteChunkPlan    `json:"chunks,omitempty"`
	Result    *Inode              `json:"result,omitempty"`
}

type BeginWriteRequest struct {
	Path      string `json:"path"`
	OpID      string `json:"op_id"`
	Overwrite bool   `json:"overwrite"`
	// -1 means streaming length; object sizes are frozen before each payload is sent.
	Size int64 `json:"size"`
}

type BeginWriteResponse struct {
	Upload WriteUpload `json:"upload"`
}

type WriteBinding struct {
	UploadID uint64 `json:"upload_id"`
	PlanID   string `json:"plan_id"`
	Revision uint64 `json:"revision"`
}

type PlanWriteChunkRequest struct {
	WriteBinding
	Index       int    `json:"index"`
	LogicalSize int64  `json:"logical_size"`
	StoredSize  int64  `json:"stored_size"`
	Encoding    string `json:"encoding"`
	Checksum    uint32 `json:"checksum"`
}

type PlanWriteChunkResponse struct {
	Plan  WriteChunkPlan `json:"plan"`
	Chunk ChunkInfo      `json:"chunk"`
	Nodes []NodeInfo     `json:"nodes"`
}

type CommitWriteRequest struct {
	WriteBinding
	OpID       string `json:"op_id"`
	Size       int64  `json:"size"`
	ChunkCount int    `json:"chunk_count"`
}

type CommitWriteResponse struct {
	Inode Inode `json:"inode"`
}

type Capabilities struct {
	Features      []string `json:"features"`
	WritePlanning bool     `json:"write_planning"`
}

type ProtectionRequest struct {
	Path string         `json:"path"`
	Tier ProtectionTier `json:"tier"`
}

type ProtectionResponse struct {
	InodeID  uint64              `json:"inode_id"`
	Override ProtectionTier      `json:"override,omitempty"`
	Policy   EffectiveProtection `json:"policy"`
}

type WriteError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

const (
	WritePlanRequired = "write_plan_required"
	WriteNotReady     = "write_not_ready"
	WritePlanConflict = "write_plan_conflict"
	WriteNoFeasible   = "write_no_feasible"
	WriteBudget       = "write_budget"
	WriteExpired      = "write_expired"
)
