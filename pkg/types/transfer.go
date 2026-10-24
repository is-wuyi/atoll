package types

import "time"

type TransferObservation struct {
	FromNodeID    uint64    `json:"from_node_id"`
	ToNodeID      uint64    `json:"to_node_id"`
	Path          string    `json:"path"`
	Available     bool      `json:"available"`
	RTTMs         float64   `json:"rtt_ms"`
	ThroughputBPS uint64    `json:"throughput_bps"`
	ObservedAt    time.Time `json:"observed_at"`
}

type TransferBudget struct {
	UploadBPS     uint64 `json:"upload_bps"`
	DownloadBPS   uint64 `json:"download_bps"`
	MaxConcurrent int    `json:"max_concurrent"`
}

type WriteTransferObservation struct {
	Budget TransferBudget        `json:"budget"`
	Links  []TransferObservation `json:"links"`
}
