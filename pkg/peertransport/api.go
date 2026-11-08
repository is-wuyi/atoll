package peertransport

import (
	"context"
	"errors"
	"net"
	"time"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
)

const ProtoID = "/atoll/peerhttp/1"

var (
	ErrInfrastructureInvalid = errors.New("peertransport: invalid infrastructure binding or address")
	ErrPeerUnauthorized      = errors.New("peertransport: peer is not authorized")
)

type Config struct {
	IdentityPath      string
	ListenAddresses   []string
	AnnounceAddresses []string
	PublicOnly        bool
	DirectTimeout     time.Duration
	RelayTimeout      time.Duration
	MaxConnections    int
	Observe           func(RuntimeEvent)
}

// RuntimeEvent contains connection and traversal facts, never credentials or request bodies.
// Observers must be concurrency-safe, nonblocking and must not call Close.
type RuntimeEvent struct {
	Time             time.Time     `json:"time"`
	Kind             string        `json:"kind"`
	RequestID        string        `json:"request_id,omitempty"`
	LocalPeerID      string        `json:"local_peer_id,omitempty"`
	RemotePeerID     string        `json:"remote_peer_id,omitempty"`
	ConnectionID     string        `json:"connection_id,omitempty"`
	StreamID         string        `json:"stream_id,omitempty"`
	Protocol         string        `json:"protocol,omitempty"`
	Transport        string        `json:"transport,omitempty"`
	LocalAddress     string        `json:"local_address,omitempty"`
	RemoteAddress    string        `json:"remote_address,omitempty"`
	Candidates       []string      `json:"candidates,omitempty"`
	Success          bool          `json:"success"`
	ErrorKind        string        `json:"error_kind,omitempty"`
	Elapsed          time.Duration `json:"elapsed_ns,omitempty"`
	Path             peerhttp.Path `json:"path,omitempty"`
	Fallback         bool          `json:"fallback,omitempty"`
	FallbackUpgraded bool          `json:"fallback_upgraded,omitempty"`
	ProbeStatus      string        `json:"probe_status,omitempty"`
	Reachability     string        `json:"reachability,omitempty"`
	Side             string        `json:"side,omitempty"`
	Attempt          int           `json:"attempt,omitempty"`
}

type DialResult struct {
	peerhttp.PeerDial
}

type DialObserver func(DialResult)

type RuntimeAPI interface {
	peerauth.Identity
	Addresses() []string
	SetDirectory(peerauth.Directory) error
	SetAuthorizer(func(context.Context, string) bool)
	AllowedPeer(string) bool
	Listener() (net.Listener, error)
	ConnContext(context.Context, net.Conn) context.Context
	PrepareInfrastructure(context.Context, peerauth.Infrastructure) error
	ReserveRelay(context.Context, peerauth.Infrastructure) (time.Time, error)
	EnableRelay() error
	Dial(context.Context, peerauth.Endpoint, peerauth.Infrastructure, peerhttp.Path) DialResult
	Close() error
}
