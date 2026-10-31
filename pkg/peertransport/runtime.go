package peertransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"atoll/pkg/peerauth"
)

// maxRelayHosts bounds the lazy per-relay dial host cache so it cannot grow
// unboundedly with a large directory. A full cache refuses a new relay host
// rather than evicting one that may be serving active streams.
const maxRelayHosts = 4

// maxAdvertisedAddresses bounds the published address set so a host cannot
// advertise an unbounded number of learned addresses.
const maxAdvertisedAddresses = 16

// maxConfigMaxConns rejects an implausibly large configured connection budget
// up front rather than feeding it to the resource manager.
const maxConfigMaxConns = 100000

var errRuntimeClosed = errors.New("peertransport: runtime is closed")

// Runtime is the production peer transport runtime: a persistent per-peer
// Ed25519 identity, a main libp2p host (TCP + QUIC, Noise, finite resources,
// AutoNAT, hole punching, circuit v2 client), a bounded lazy isolated
// relay-dial host cache, a protocol-gated listener, a bounded relay
// reservation/service, and strict direct / forced-relay dialing. It implements
// peerauth.Identity.
type Runtime struct {
	ctx    context.Context
	cancel context.CancelFunc

	ident *runtimeIdentity
	id    peer.ID

	cfg      Config
	mainHost host.Host
	auth     *protocolGate

	closeOnce sync.Once
	closeErr  error

	// lifeMu guards the lifecycle: the closed flag, the listener pointer and
	// the relay host / relay service sets. Creation of a listener, relay host
	// or relay service happens under lifeMu so Close can never tear down a
	// half-created resource, and concurrent creators are single-flighted
	// (bounded), never racing to create duplicate hosts.
	lifeMu     sync.Mutex
	closed     bool
	listener   *peerListener
	relayHosts map[peer.ID]host.Host
	relayOrder []peer.ID
	relaySvc   interface{ Close() error }
}

// New constructs a Runtime from a Config. An empty IdentityPath yields an
// ephemeral in-process Ed25519 key (used by clients); a non-empty path must
// point at an existing or creatable canonical libp2p Ed25519 private key at
// mode 0600, never a symlink, and is never overwritten or derived from the
// device identity. A cancelled context, or an invalid Config, fails New without
// creating an identity file or a host.
func New(ctx context.Context, cfg Config) (*Runtime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	rctx, cancel := context.WithCancel(ctx)
	r := &Runtime{
		ctx:        rctx,
		cancel:     cancel,
		cfg:        cfg,
		auth:       newProtocolGate(rctx),
		relayHosts: map[peer.ID]host.Host{},
	}

	// The full configuration is validated before any identity file or host is
	// created, so an invalid listen/announce list never leaves a key behind.
	listen, err := parseListenAddresses(cfg.ListenAddresses)
	if err != nil {
		cancel()
		return nil, err
	}
	announce, err := parseAnnounceAddresses(cfg.AnnounceAddresses, cfg.PublicOnly)
	if err != nil {
		cancel()
		return nil, err
	}

	ident, err := loadOrCreateRuntimeIdentity(cfg.IdentityPath)
	if err != nil {
		cancel()
		return nil, err
	}
	r.ident = ident
	r.id = ident.id

	mainHost, err := newMainHost(rctx, ident.priv, listen, announce, cfg.PublicOnly, r.auth, cfg.MaxConnections)
	if err != nil {
		cancel()
		return nil, err
	}
	r.mainHost = mainHost
	return r, nil
}

// ---- peerauth.Identity ----

func (r *Runtime) PeerID() string { return r.id.String() }

func (r *Runtime) PublicKey() []byte { return append([]byte(nil), r.ident.pub...) }

func (r *Runtime) Sign(message []byte) ([]byte, error) { return r.ident.priv.Sign(message) }

// String and GoString never expose the private key.
func (r *Runtime) String() string   { return "peertransport.Runtime(" + r.id.String() + ")" }
func (r *Runtime) GoString() string { return r.String() }

// validateConfig rejects a Config whose budget or timeouts are invalid before
// any identity file or host is created.
func validateConfig(cfg Config) error {
	if cfg.MaxConnections < 0 {
		return errors.New("peertransport: MaxConnections must not be negative")
	}
	if cfg.MaxConnections > maxConfigMaxConns {
		return fmt.Errorf("peertransport: MaxConnections %d exceeds %d", cfg.MaxConnections, maxConfigMaxConns)
	}
	if cfg.DirectTimeout < 0 {
		return errors.New("peertransport: DirectTimeout must not be negative")
	}
	if cfg.RelayTimeout < 0 {
		return errors.New("peertransport: RelayTimeout must not be negative")
	}
	return nil
}

// Addresses returns the current publishable endpoints of the main host as
// canonical sorted strings. They are filtered by the public-only policy and by
// usability (no circuit, unspecified, multicast, link-local or zero port), so a
// public-only runtime never publishes a loopback, private, CGNAT or DNS
// address. Relay/circuit addresses are never included.
func (r *Runtime) Addresses() []string {
	filtered := filterPublishedAddrs(r.mainHost.Addrs(), r.cfg.PublicOnly)
	out := make([]string, 0, len(filtered))
	for _, a := range filtered {
		out = append(out, a.String())
	}
	return out
}

// filterPublishedAddrs returns the addresses that may be published: canonical
// and usable (no circuit component, no unspecified/multicast/link-local host,
// no zero port), de-duplicated, capped at maxAdvertisedAddresses, and — when
// publicOnly is set — with no loopback, private, CGNAT or DNS address. A single
// unusable learned address is dropped rather than failing the whole set.
func filterPublishedAddrs(raw []ma.Multiaddr, publicOnly bool) []ma.Multiaddr {
	seen := make(map[string]bool, len(raw))
	out := make([]ma.Multiaddr, 0, len(raw))
	for _, a := range raw {
		if hasCircuitComponent(a) {
			continue
		}
		s := a.String()
		if seen[s] {
			continue
		}
		// Reuse the published-address canonical/classify rules per address; an
		// unusable learned address is dropped, not fatal.
		if _, err := peerauth.NormalizeAddresses([]string{s}, publicOnly); err != nil {
			continue
		}
		seen[s] = true
		out = append(out, a)
		if len(out) >= maxAdvertisedAddresses {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// SetDirectory validates and snapshots a peer directory. The allow-set it
// builds is immutable for the lifetime of the snapshot (rebuilt on the next
// call) and every entry carries its own expiry, so AllowedPeer never consults
// the online authorizer.
func (r *Runtime) SetDirectory(d peerauth.Directory) error {
	if err := peerauth.ValidateDirectory(d, time.Now()); err != nil {
		return err
	}
	r.auth.setDirectory(d)
	return nil
}

// SetAuthorizer installs the optional online authorizer used as the
// authoritative decision when installed. It is called outside any lock (see
// protocolGate.authorize) and may refresh the directory; AllowedPeer itself
// never triggers it.
func (r *Runtime) SetAuthorizer(fn func(context.Context, string) bool) {
	r.auth.setAuthorizer(fn)
}

// AllowedPeer reports whether id is a currently valid member of the validated
// directory snapshot (nodes, clients, or the local infrastructure peer). It is
// a pure in-memory check, never calls the SetAuthorizer callback and never
// admits anyone after Close.
func (r *Runtime) AllowedPeer(id string) bool {
	r.lifeMu.Lock()
	closed := r.closed
	r.lifeMu.Unlock()
	if closed {
		return false
	}
	return r.auth.allowedPeer(id)
}

// Listener returns the protocol-gated net.Listener over ProtoID streams. It is
// created on first use and reused thereafter.
func (r *Runtime) Listener() (net.Listener, error) {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	if r.closed {
		return nil, errRuntimeClosed
	}
	if r.listener != nil {
		return r.listener, nil
	}
	r.listener = newPeerListener(r.ctx, r.mainHost, r.auth)
	return r.listener, nil
}

// ConnContext attaches the verified source PeerID (from the real peer stream,
// unwrapped through any TLS layer) to a request context. It never reads the
// identity from an HTTP header.
func (r *Runtime) ConnContext(ctx context.Context, conn net.Conn) context.Context {
	if sc, ok := unwrapStreamConn(conn); ok {
		return peerauth.WithSourcePeerID(ctx, sc.remotePeer())
	}
	return ctx
}

// Close shuts down the listener, relay service, lazy relay hosts and the main
// host once, waiting for any in-flight creation to finish. Idempotent; no
// goroutine is left running.
func (r *Runtime) Close() error {
	r.closeOnce.Do(func() { r.closeErr = r.shutdown() })
	return r.closeErr
}

func (r *Runtime) shutdown() error {
	r.lifeMu.Lock()
	if r.closed {
		r.lifeMu.Unlock()
		return nil
	}
	r.closed = true
	r.cancel()
	listener := r.listener
	r.listener = nil
	hosts := r.relayHosts
	r.relayHosts = map[peer.ID]host.Host{}
	r.relayOrder = nil
	svc := r.relaySvc
	r.relaySvc = nil
	r.lifeMu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	if svc != nil {
		_ = svc.Close()
	}
	for _, h := range hosts {
		_ = h.Close()
	}
	if r.mainHost != nil {
		return r.mainHost.Close()
	}
	return nil
}

// relayHostFor returns the lazy relay-dial host for a given relay. It is
// created on first forced-relay use and cached per relay, single-flighted
// under the lifecycle lock so concurrent creators never race. A full cache
// refuses a new relay host instead of evicting one that may be serving active
// streams.
func (r *Runtime) relayHostFor(relay peer.ID) (host.Host, error) {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	if r.closed {
		return nil, errRuntimeClosed
	}
	if h, ok := r.relayHosts[relay]; ok {
		return h, nil
	}
	if len(r.relayHosts) >= maxRelayHosts {
		return nil, errors.New("peertransport: relay host cache is full")
	}
	h, err := newRelayDialHost(r.ctx, r.ident.priv, relay, r.cfg.PublicOnly, r.auth, r.cfg.MaxConnections)
	if err != nil {
		return nil, err
	}
	r.relayHosts[relay] = h
	r.relayOrder = append(r.relayOrder, relay)
	return h, nil
}

func parseListenAddresses(in []string) ([]ma.Multiaddr, error) {
	if len(in) == 0 {
		in = []string{"/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/udp/0/quic-v1"}
	}
	if len(in) > maxAdvertisedAddresses {
		return nil, fmt.Errorf("peertransport: too many listen addresses (%d, max %d)", len(in), maxAdvertisedAddresses)
	}
	out := make([]ma.Multiaddr, 0, len(in))
	seen := make(map[string]bool)
	for _, s := range in {
		a, err := ma.NewMultiaddr(s)
		if err != nil || a.String() != s {
			return nil, errors.New("peertransport: invalid listen address " + s)
		}
		if err := validateListenAddr(a); err != nil {
			return nil, err
		}
		if seen[a.String()] {
			return nil, errors.New("peertransport: duplicate listen address " + s)
		}
		seen[a.String()] = true
		out = append(out, a)
	}
	return out, nil
}

func validateListenAddr(a ma.Multiaddr) error {
	protos := a.Protocols()
	if len(protos) < 2 || len(protos) > 3 {
		return errors.New("peertransport: unsupported listen address " + a.String())
	}
	switch protos[0].Code {
	case ma.P_IP4, ma.P_IP6, ma.P_DNS4, ma.P_DNS6:
	default:
		return errors.New("peertransport: unsupported listen host " + a.String())
	}
	switch protos[1].Code {
	case ma.P_TCP:
		if len(protos) != 2 {
			return errors.New("peertransport: malformed TCP listen address " + a.String())
		}
	case ma.P_UDP:
		if len(protos) != 3 || protos[2].Code != ma.P_QUIC_V1 {
			return errors.New("peertransport: malformed QUIC listen address " + a.String())
		}
	default:
		return errors.New("peertransport: unsupported listen transport " + a.String())
	}
	return nil
}

func parseAnnounceAddresses(in []string, publicOnly bool) ([]ma.Multiaddr, error) {
	if len(in) == 0 {
		return nil, nil
	}
	normalized, err := peerauth.NormalizeAddresses(in, publicOnly)
	if err != nil {
		return nil, err
	}
	out := make([]ma.Multiaddr, 0, len(normalized))
	for _, s := range normalized {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// compile-time assertion that Runtime satisfies the runtime API contract.
var _ RuntimeAPI = (*Runtime)(nil)
