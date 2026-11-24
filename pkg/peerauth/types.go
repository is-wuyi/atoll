package peerauth

import (
	"context"
	"time"
)

const (
	Feature           = "peer-discovery-v1"
	RoleNode          = "node"
	RoleClient        = "client"
	RoleControl       = "control"
	MaxAddresses      = 16
	MaxAddressLength  = 512
	MaxDirectoryPeers = 512
	MaxDirectoryBytes = 8 << 20
	EndpointLease     = 2 * time.Minute
	// LeaseRequestMargin is subtracted from EndpointLease when a peer asks the
	// center for a new lease. The center rejects any NotAfter beyond its own
	// now+EndpointLease, so a peer whose clock runs slightly ahead, or whose
	// request spends time in transit, must not ask for the full window.
	LeaseRequestMargin = 10 * time.Second
)

// RequestNotAfter returns the lease deadline a peer should sign for a request
// starting at now. It keeps a bounded safety margin so the center's strictly
// validated window is never exceeded by clock skew or request transit.
func RequestNotAfter(now time.Time) time.Time {
	return now.UTC().Add(EndpointLease - LeaseRequestMargin)
}

type Identity interface {
	PeerID() string
	PublicKey() []byte
	Sign(message []byte) ([]byte, error)
}

type sourcePeerKey struct{}

// The source is set from an authenticated connection, never from an HTTP header.
func WithSourcePeerID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sourcePeerKey{}, id)
}

func SourcePeerID(ctx context.Context) string {
	id, _ := ctx.Value(sourcePeerKey{}).(string)
	return id
}

type Enrollment struct {
	PeerID           string `json:"peer_id"`
	PublicKey        []byte `json:"public_key"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

type Binding struct {
	PeerID    string `json:"peer_id"`
	PublicKey []byte `json:"public_key"`
	Revision  uint64 `json:"revision"`
}

type NodeState struct {
	Binding          *Binding `json:"binding,omitempty"`
	EndpointRevision uint64   `json:"endpoint_revision"`
}

type Endpoint struct {
	NodeID          uint64    `json:"node_id,omitempty"`
	Addr            string    `json:"addr,omitempty"`
	Role            string    `json:"role"`
	PeerID          string    `json:"peer_id"`
	PublicKey       []byte    `json:"public_key"`
	BindingRevision uint64    `json:"binding_revision,omitempty"`
	Revision        uint64    `json:"revision,omitempty"`
	Addresses       []string  `json:"addresses,omitempty"`
	ValidUntil      time.Time `json:"valid_until"`
}

type Infrastructure struct {
	PeerID    string   `json:"peer_id"`
	PublicKey []byte   `json:"public_key"`
	Addresses []string `json:"addresses"`
	Relay     bool     `json:"relay"`
}

type Directory struct {
	Protocol       string         `json:"protocol"`
	Endpoints      []Endpoint     `json:"endpoints"`
	Infrastructure Infrastructure `json:"infrastructure"`
}

type AddressPublication struct {
	PeerID           string    `json:"peer_id"`
	BindingRevision  uint64    `json:"binding_revision"`
	ExpectedRevision uint64    `json:"expected_revision"`
	OperationID      string    `json:"operation_id"`
	Addresses        []string  `json:"addresses"`
	NotAfter         time.Time `json:"not_after"`
	Signature        []byte    `json:"signature"`
}

type ClientState struct {
	Revision uint64 `json:"revision"`
}

type ClientRegistration struct {
	PeerID           string    `json:"peer_id"`
	PublicKey        []byte    `json:"public_key"`
	ExpectedRevision uint64    `json:"expected_revision"`
	OperationID      string    `json:"operation_id"`
	NotAfter         time.Time `json:"not_after"`
	Signature        []byte    `json:"signature"`
}
