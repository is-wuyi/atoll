package types

type WriteChunkStatus struct {
	Index int  `json:"index"`
	Ready bool `json:"ready"`
}

type WriteStatus struct {
	UploadID uint64             `json:"upload_id"`
	Chunks   []WriteChunkStatus `json:"chunks"`
}
