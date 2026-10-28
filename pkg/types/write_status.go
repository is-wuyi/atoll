package types

type WriteChunkStatus struct {
	Index    int                 `json:"index"`
	Ready    bool                `json:"ready"`
	Epoch    uint64              `json:"epoch,omitempty"`
	Done     []uint64            `json:"done,omitempty"`
	Progress []WriteNodeProgress `json:"progress,omitempty"`
}

type WriteStatus struct {
	UploadID uint64             `json:"upload_id"`
	Chunks   []WriteChunkStatus `json:"chunks"`
}
