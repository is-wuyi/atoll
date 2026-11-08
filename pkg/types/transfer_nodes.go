package types

type WriteTransferNodes struct {
	Nodes                 []NodeInfo `json:"nodes"`
	ObservationTTLSeconds uint64     `json:"observation_ttl_seconds,omitempty"`
}
