package types

import "time"

const (
	WritePlanFeature     = "write-plan-v1"
	WriteTransferFeature = "write-transfer-v1"
	WriteRecoveryFeature = "write-recovery-v2"
	WriteEpochHeader     = "X-Atoll-Write-Epoch"
	WriteResumeHeader    = "X-Atoll-Write-Resume"
	WriteAttemptHeader   = "X-Atoll-Write-Attempt-ID"
	MaxWriteRecoveries   = 3
	WriteRecoveryMaxTime = 30 * time.Minute
	PlainEncoding        = "plain-v1"
	WritePending         = "pending"
	WriteCommitted       = "committed"
	WriteAborted         = "aborted"
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

type WriteTransferLeg struct {
	FromNodeID uint64 `json:"from_node_id"`
	ToNodeID   uint64 `json:"to_node_id"`
	Path       string `json:"path"`
	BPS        uint64 `json:"bps"`
}

type WriteTransferPlan struct {
	UploadTargets []uint64           `json:"upload_targets"`
	Legs          []WriteTransferLeg `json:"legs"`
	ExpiresAt     time.Time          `json:"expires_at"`
}

type WriteRecovery struct {
	Epoch       uint64    `json:"epoch"`
	Attempts    uint32    `json:"attempts"`
	HardUntil   time.Time `json:"hard_until"`
	Excluded    []uint64  `json:"excluded,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
	RequestHash string    `json:"request_hash,omitempty"`
	FailedNodes []uint64  `json:"failed_nodes,omitempty"`
}

type WriteChunkPlan struct {
	Index                 int                `json:"index"`
	Object                ContentObject      `json:"object"`
	Layout                ReplicaLayout      `json:"layout"`
	Confirmations         []uint64           `json:"confirmations"`
	RequiredConfirmations int                `json:"required_confirmations"`
	Reasons               []string           `json:"reasons,omitempty"`
	Transfer              *WriteTransferPlan `json:"transfer,omitempty"`
	Recovery              *WriteRecovery     `json:"recovery,omitempty"`
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
	Index       int                       `json:"index"`
	LogicalSize int64                     `json:"logical_size"`
	StoredSize  int64                     `json:"stored_size"`
	Encoding    string                    `json:"encoding"`
	Checksum    uint32                    `json:"checksum"`
	Network     *WriteTransferObservation `json:"network,omitempty"`
}

type BeginWriteProgressRequest struct {
	ObjectID        uint64 `json:"object_id"`
	NodeID          uint64 `json:"node_id"`
	Epoch           uint64 `json:"epoch"`
	ExpectedAttempt uint64 `json:"expected_attempt"`
	RequestID       string `json:"request_id"`
}

type BeginWriteProgressResponse struct {
	Attempt      uint64 `json:"attempt"`
	AttemptToken string `json:"attempt_token"`
}

type WriteProgressState struct {
	Attempt   uint64    `json:"attempt"`
	HardUntil time.Time `json:"hard_until"`
}

type WriteProgress struct {
	ObjectID     uint64 `json:"object_id"`
	NodeID       uint64 `json:"node_id"`
	Epoch        uint64 `json:"epoch"`
	Attempt      uint64 `json:"attempt"`
	AttemptToken string `json:"attempt_token,omitempty"`
	Bytes        int64  `json:"bytes"`
}

type WriteNodeProgress struct {
	NodeID    uint64    `json:"node_id"`
	Attempt   uint64    `json:"attempt"`
	RequestID string    `json:"request_id,omitempty"`
	Bytes     int64     `json:"bytes"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RecoverWriteChunkRequest struct {
	WriteBinding
	Index         int                       `json:"index"`
	ExpectedEpoch uint64                    `json:"expected_epoch"`
	OpID          string                    `json:"op_id"`
	FailedNodes   []uint64                  `json:"failed_nodes"`
	Network       *WriteTransferObservation `json:"network,omitempty"`
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

// ContentKeyResponse 是 GET /auth/content-key 的响应：授权空间/对象/代际下
// 解包出的对象 DEK（base64）。经用户会话 + TLS 传输；密钥 ID 用于轮换比对。
type ContentKeyResponse struct {
	ObjectID   uint64 `json:"object_id"`
	Generation uint64 `json:"generation"`
	KeyID      string `json:"key_id"`
	DEK        string `json:"dek"`
}

// PrepareContentKeyRequest 请求为计划上传的某个块对象预创建（或幂等取回）wrapped
// DEK。UploadID 即 Begin 返回的 staging ID，也是加密记录 AAD 的内容身份；
// 块对象 ID 由 (UploadID, Index) 派生。SpaceID 由 X-Atoll-Space 头提供。
type PrepareContentKeyRequest struct {
	UploadID uint64 `json:"upload_id"`
	Index    int    `json:"index"`
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
	WritePlanRequired  = "write_plan_required"
	WriteNotReady      = "write_not_ready"
	WritePlanConflict  = "write_plan_conflict"
	WriteRecoveryRetry = "write_recovery_retry"
	WriteNoFeasible    = "write_no_feasible"
	WriteBudget        = "write_budget"
	WriteExpired       = "write_expired"
)
