package peertransport

import (
	"context"
	"log"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"

	ma "github.com/multiformats/go-multiaddr"
)

// RelayConfig configures the standalone CircuitRelay v2 hop node.
type RelayConfig struct {
	DataDir string
	// Allowlist: ONLY these experiment peers may reserve on / traverse the
	// relay. Enforced twice: connection gater (transport level) and relay
	// ACL (reservation level).
	Allowlist *Allowlist
	// Limit is the per-circuit limit (duration + data per direction). It is
	// required and must be finite; WithInfiniteLimits is never used.
	Limit relay.RelayLimit
	// ReservationTTL bounds how long a reservation stays valid.
	ReservationTTL time.Duration
	// MaxReservations caps total active reservations (global budget),
	// MaxCircuits caps open circuits per peer.
	MaxReservations int
	MaxCircuits     int
	Logger          *log.Logger
	// WAN mode (zero values = historical loopback behavior):
	ListenIP     string        // listen IP, e.g. "0.0.0.0"
	AnnounceAddrs []ma.Multiaddr // force-announced public endpoint(s)
	ListenPort   int
}

// DefaultRelayLimit returns the prototype's default finite per-circuit limit:
// 1 hour duration and 256 MiB of relayed data per direction — large enough
// for the >64 MiB streams under test, small enough to be a real budget.
func DefaultRelayLimit() relay.RelayLimit {
	return relay.RelayLimit{Duration: time.Hour, Data: 256 << 20}
}

// RelayNode is the independent relay role. It is a real CircuitRelay v2 hop
// (protocol /libp2p/circuit/relay/0.2.0/hop), not an HTTP proxy.
type RelayNode struct {
	Host host.Host
	ID   peer.ID
	svc  *relay.Relay
	rm   network.ResourceManager
	log  *log.Logger
}

// NewRelayNode starts the relay host and the circuit v2 hop service.
func NewRelayNode(ctx context.Context, cfg RelayConfig) (*RelayNode, error) {
	if cfg.Allowlist == nil {
		cfg.Allowlist = NewAllowlist()
	}
	if cfg.Limit.Data <= 0 || cfg.Limit.Duration <= 0 {
		cfg.Limit = DefaultRelayLimit()
	}
	if cfg.ReservationTTL <= 0 {
		cfg.ReservationTTL = 30 * time.Minute
	}
	if cfg.MaxReservations <= 0 {
		cfg.MaxReservations = 16
	}
	if cfg.MaxCircuits <= 0 {
		cfg.MaxCircuits = 8
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	id, err := LoadOrCreateIdentity(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	r := &RelayNode{log: cfg.Logger}

	h, err := newHost(ctx, HostOptions{
		Priv:          id.Priv,
		ListenTCP:     true,
		ListenQUIC:    true,
		// Transport-level gate: only experiment peers may connect at all.
		Gater:         NewConnGater(cfg.Allowlist),
		Logger:        cfg.Logger,
		ListenIP:      cfg.ListenIP,
		ListenPort:    cfg.ListenPort,
		AnnounceAddrs: cfg.AnnounceAddrs,
	})
	if err != nil {
		return nil, err
	}
	r.Host = h
	r.ID = id.ID

	res := relay.DefaultResources()
	res.Limit = &cfg.Limit
	res.ReservationTTL = cfg.ReservationTTL
	res.MaxReservations = cfg.MaxReservations
	res.MaxCircuits = cfg.MaxCircuits

	svc, err := relay.New(h,
		relay.WithACL(NewRelayACL(cfg.Allowlist)),
		relay.WithResources(res),
	)
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	r.svc = svc
	cfg.Logger.Printf("relay started id=%s addrs=%v limit=%+v ttl=%s maxReservations=%d maxCircuits=%d",
		id.ID, h.Addrs(), cfg.Limit, cfg.ReservationTTL, cfg.MaxReservations, cfg.MaxCircuits)
	return r, nil
}

// AddrInfo returns the relay's current endpoints.
func (r *RelayNode) AddrInfo() peer.AddrInfo {
	return peer.AddrInfo{ID: r.ID, Addrs: r.Host.Addrs()}
}

// Close shuts the relay down.
func (r *RelayNode) Close() error {
	return r.Host.Close()
}
