package peertransport

import (
	"context"
	"net"
	"time"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
)

const ProtoID = "/atoll/peerhttp/1"

type Config struct {
	IdentityPath      string
	ListenAddresses   []string
	AnnounceAddresses []string
	PublicOnly        bool
	DirectTimeout     time.Duration
	RelayTimeout      time.Duration
	MaxConnections    int
}

type DialResult struct {
	peerhttp.PeerDial
	Fallback      bool
	RemoteAddress string
	LocalAddress  string
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
	ReserveRelay(context.Context, peerauth.Infrastructure) (time.Time, error)
	EnableRelay() error
	Dial(context.Context, peerauth.Endpoint, peerauth.Infrastructure, peerhttp.Path) DialResult
	Close() error
}
