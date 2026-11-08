package peertransport

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	basichost "github.com/libp2p/go-libp2p/p2p/host/basic"
	"github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	libp2pconnmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/holepunch"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2ptcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/fx"
)

const (
	hostMemoryBudget = 512 << 20 // 512 MiB
	hostFDBudget     = 256
)

// newMainHost builds the host used for direct dials, hole punching and the
// default direct-then-relay path. It carries the circuit v2 client transport,
// AutoNAT v2, hole punching, a finite resource manager whose connection budget
// (when MaxConnections > 0) rejects a new dial rather than trimming an existing
// connection with an active stream, and the bounded authorization gate shared
// with the listener.
func newMainHost(ctx context.Context, priv crypto.PrivKey, listen, announce []ma.Multiaddr, publicOnly bool, auth *protocolGate, maxConns int, observed *trustedObservations, observe func(RuntimeEvent)) (host.Host, error) {
	service, probe, err := newProbeService(priv, auth, !publicOnly, observe)
	if err != nil {
		return nil, err
	}
	tracer := &traversalEvents{observe: observe, metrics: holepunch.NewMetricsTracer(holepunch.WithRegisterer(prometheus.DefaultRegisterer))}
	var constructed *basichost.BasicHost
	quicOwner := new(quicManagerOwner)
	gate := &mainGate{publicOnly: publicOnly, auth: auth}
	opts := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.NoListenAddrs,
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(libp2ptcp.NewTCPTransport),
		libp2p.Transport(quic.NewTransport),
		quicOwner.option(),
		libp2p.ResourceManager(finiteResourceManager(maxConns)),
		libp2p.ConnectionManager(noTrimConnMgr()),
		libp2p.ConnectionGater(gate),
		libp2p.SwarmOpts(swarm.WithDialTimeout(30 * time.Second)),
		libp2p.DisableRelay(),
		libp2p.WithFxOption(fx.Invoke(func(h *basichost.BasicHost) {
			constructed = h
			gate.network = h.Network()
		})),
		tcpRelayTransport(auth, observe),
		libp2p.EnableHolePunching(holepunch.WithMetricsAndEventTracer(tracer, tracer)),
		// Injecting the client into BasicHost preserves its reachability tracker;
		// merely starting an AutoNAT service after construction would not.
		libp2p.WithFxOption(
			fx.Replace(service),
			fx.Replace(fx.Annotate(observed, fx.As(new(basichost.ObservedAddrsManager)))),
			fx.Invoke(func(bus event.Bus, n *basichost.BasicHost) error { return observed.start(bus, n.Network()) }),
		),
		// The address factory always runs so the published set obeys the
		// public-only policy even for learned addresses; an explicit announce
		// list wins and was already validated against the policy.
		libp2p.AddrsFactory(func(addrs []ma.Multiaddr) []ma.Multiaddr {
			if len(announce) > 0 {
				return append([]ma.Multiaddr(nil), announce...)
			}
			return filterPublishedAddrs(addrs, publicOnly)
		}),
	}
	h, err := libp2p.New(opts...)
	if err != nil {
		_ = observed.Close()
		if constructed != nil {
			_ = constructed.Close()
		}
		_ = quicOwner.Close()
		_ = probe.Close()
		return nil, fmt.Errorf("peertransport: new main host: %w", err)
	}
	// The graph is fully started before binding physical listeners. A bind
	// failure can now use the same shutdown path as a running host, and one
	// successful transport cannot conceal another requested listener's failure.
	for _, address := range listen {
		if err := h.Network().Listen(address); err != nil {
			_ = observed.Close()
			_ = h.Close()
			_ = probe.Close()
			return nil, fmt.Errorf("peertransport: listen: %w", err)
		}
	}
	if ctx.Err() != nil {
		_ = observed.Close()
		_ = h.Close()
		_ = probe.Close()
		return nil, ctx.Err()
	}
	return &runtimeHost{Host: h, probe: probe, service: service, observed: observed, quicManager: quicOwner.manager}, nil
}

// newRelayDialHost builds the lazy, dial-only host used exclusively for
// forced-relay (required circuit) dials. It shares the PeerID with the main
// host but has its own peerstore and a strict relay gate, so a direct
// connection to an authorized target can never be reused: only an authorized
// target's circuit address and the relay's direct addresses are dialable.
func newRelayDialHost(ctx context.Context, priv crypto.PrivKey, relay peer.ID, publicOnly bool, auth *protocolGate, maxConns int, observe func(RuntimeEvent)) (host.Host, error) {
	var constructed *basichost.BasicHost
	quicOwner := new(quicManagerOwner)
	opts := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.NoListenAddrs,
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(libp2ptcp.NewTCPTransport),
		libp2p.Transport(quic.NewTransport),
		quicOwner.option(),
		libp2p.ResourceManager(finiteResourceManager(maxConns)),
		libp2p.ConnectionManager(noTrimConnMgr()),
		libp2p.ConnectionGater(&relayGate{auth: auth, relay: relay, publicOnly: publicOnly}),
		libp2p.DisableRelay(),
		libp2p.WithFxOption(fx.Invoke(func(h *basichost.BasicHost) {
			constructed = h
		})),
		tcpRelayTransport(auth, observe),
	}
	h, err := libp2p.New(opts...)
	if err != nil {
		if constructed != nil {
			_ = constructed.Close()
		}
		_ = quicOwner.Close()
		return nil, fmt.Errorf("peertransport: new relay dial host: %w", err)
	}
	if ctx.Err() != nil {
		_ = h.Close()
		return nil, ctx.Err()
	}
	return h, nil
}

func tcpRelayTransport(auth *protocolGate, observe func(RuntimeEvent)) libp2p.Option {
	return libp2p.WithFxOption(fx.Invoke(func(h *basichost.BasicHost, upgrader transport.Upgrader) error {
		selected := &connectionHost{Host: h, observe: observe, connection: func(ctx context.Context, remote peer.ID) (network.Conn, error) {
			return ensureTCP(ctx, h, auth, remote)
		}}
		return relayclient.AddTransport(selected, upgrader)
	}))
}

// noTrimConnMgr returns a connection manager with trimming disabled
// (low/high water 0): libp2p's trim closes connections that may carry active
// streams, so the finite resource manager is the sole connection budget — a
// new connection is rejected once the budget is exhausted and an existing one
// is never reclaimed.
func noTrimConnMgr() connmgr.ConnManager {
	mgr, err := libp2pconnmgr.NewConnManager(0, 0)
	if err != nil {
		// A conn manager with valid defaults cannot fail to construct.
		panic(fmt.Sprintf("peertransport: connection manager: %v", err))
	}
	return mgr
}

// finiteResourceManager returns a finite resource manager. When maxConns > 0 the
// system and transient connection budgets are set to that value, so a new
// connection is rejected once the budget is exhausted while existing connections
// and their streams are never reclaimed. The other limits are the scaled
// defaults (memory and FD budget).
func finiteResourceManager(maxConns int) network.ResourceManager {
	base := rcmgr.DefaultLimits.Scale(hostMemoryBudget, hostFDBudget)
	if maxConns > 0 {
		conn := rcmgr.ResourceLimits{
			Conns:         rcmgr.LimitVal(maxConns),
			ConnsInbound:  rcmgr.LimitVal(maxConns),
			ConnsOutbound: rcmgr.LimitVal(maxConns),
		}
		base = rcmgr.PartialLimitConfig{System: conn, Transient: conn}.Build(base)
	}
	limiter := rcmgr.NewFixedLimiter(base)
	rm, err := rcmgr.NewResourceManager(limiter)
	if err != nil {
		// A fixed limiter with a valid config cannot fail to construct.
		panic(fmt.Sprintf("peertransport: resource manager: %v", err))
	}
	return rm
}
