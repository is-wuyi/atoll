package peertransport

import (
	"context"
	"fmt"
	"log"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	libp2ptcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-libp2p/p2p/security/noise"

	ma "github.com/multiformats/go-multiaddr"
)

// HostLimits memory budget handed to the fixed resource manager. All limits
// are finite; there is no WithInfiniteLimits anywhere in this prototype.
const (
	HostMemoryBudget = 512 << 20 // 512 MiB
	HostFDBudget     = 256
)

// HostOptions configures a prototype libp2p host.
type HostOptions struct {
	Priv        crypto.PrivKey
	ListenTCP   bool
	ListenQUIC  bool
	Gater       connmgr.ConnectionGater
	HolePunch   bool // enable the libp2p hole punching service (idle on loopback)
	Logger      *log.Logger
	// WAN mode (empty = loopback default, unchanged historical behavior):
	// ListenIP replaces the loopback listen IP (e.g. "0.0.0.0"); ListenPort
	// fixes the TCP/QUIC port (0 = random); AnnounceAddrs force-announce the
	// host's public addresses (behind NAT: learned out-of-band; the listen
	// port and announced port may differ under NAT port-forwarding).
	// AutoNAT is enabled in WAN mode so peers learn real reachability.
	ListenIP     string
	ListenPort   int
	AnnounceAddrs []ma.Multiaddr
}

// newHost builds a libp2p host with:
//   - Noise security only on TCP streams (identity-locked, E2E secure channel;
//     QUIC uses libp2p's embedded identity-locked TLS). No plaintext option
//     exists in this configuration, so an unencrypted fallback is impossible.
//   - TCP and optionally QUIC loopback transports.
//   - the CircuitRelay v2 client transport (EnableRelay).
//   - a fixed, finite resource manager.
//   - NO discovery / public DHT / bootstrap: every connection is created by
//     explicit dial to an explicitly configured, allowlisted peer.
func newHost(ctx context.Context, o HostOptions) (host.Host, error) {
	listenIP := o.ListenIP
	if listenIP == "" {
		listenIP = "127.0.0.1"
	}
	var addrs []ma.Multiaddr
	if o.ListenTCP {
		a, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", listenIP, o.ListenPort))
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, a)
	}
	if o.ListenQUIC {
		a, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/udp/%d/quic-v1", listenIP, o.ListenPort))
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, a)
	}

	limiter := rcmgr.NewFixedLimiter(rcmgr.DefaultLimits.Scale(HostMemoryBudget, HostFDBudget))
	rm, err := rcmgr.NewResourceManager(limiter)
	if err != nil {
		return nil, fmt.Errorf("peertransport: resource manager: %w", err)
	}

	opts := []libp2p.Option{
		libp2p.Identity(o.Priv),
		libp2p.ListenAddrs(addrs...),
		// Security: Noise only. The libp2p Noise handshake is bound to the
		// peer's Ed25519 identity, giving end-to-end encrypted, authenticated
		// channels (transport security — explicitly NOT static disk
		// encryption). With no plaintext security registered there is no way
		// to fall back to an unencrypted connection.
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(libp2ptcp.NewTCPTransport),
		libp2p.ResourceManager(rm),
		// CircuitRelay v2 CLIENT transport: allows dialing
		// /p2p/<relay>/p2p-circuit/p2p/<target> addresses.
		libp2p.EnableRelay(),
	}
	if o.ListenQUIC {
		opts = append(opts, libp2p.Transport(quic.NewTransport))
	}
	if o.Gater != nil {
		opts = append(opts, libp2p.ConnectionGater(o.Gater))
	}
	if o.HolePunch {
		// Hole punching coordinates simultaneous dials through a relay when
		// both sides are behind NATs. On loopback it stays idle; including it
		// exercises the option plumbing. WAN traversal is NOT claimed to be
		// verified by this prototype (see README).
		opts = append(opts, libp2p.EnableHolePunching())
	}
	wan := len(o.AnnounceAddrs) > 0 || (o.ListenIP != "" && o.ListenIP != "127.0.0.1")
	if len(o.AnnounceAddrs) > 0 {
		// Behind NAT: the host must not announce its private listen
		// addresses — only the operator-provided public endpoint(s).
		opts = append(opts, libp2p.AddrsFactory(func([]ma.Multiaddr) []ma.Multiaddr {
			return append([]ma.Multiaddr(nil), o.AnnounceAddrs...)
		}))
	}
	if wan {
		// AutoNAT service + client: peers probe each other's real
		// reachability and drop private guesses from their announced set.
		opts = append(opts, libp2p.EnableNATService(), libp2p.EnableAutoNATv2())
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("peertransport: libp2p.New: %w", err)
	}
	if o.Logger != nil {
		o.Logger.Printf("host started id=%s addrs=%v", h.ID(), h.Addrs())
	}
	return h, nil
}
