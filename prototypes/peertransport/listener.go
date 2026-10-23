package peertransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"

	ma "github.com/multiformats/go-multiaddr"
)

// ProtoID is the libp2p protocol that carries the HTTP/1.1 object service.
// Every HTTP request/response is exchanged over one libp2p stream secured by
// the identity-locked Noise handshake.
const ProtoID = "/atoll/peerhttp/1"

// p2pListener is a net.Listener adapter over libp2p streams: net/http servers
// run unmodified on top of it (http.Server.Serve(listener)).
type p2pListener struct {
	host      host.Host
	allow     *Allowlist // nil = accept any verified peer (control role)
	ch        chan *countingConn
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// NewHTTPListener turns a libp2p host into a net.Listener for net/http.
//
// Every inbound stream is verified before it is handed to the HTTP server:
//   - the remote PeerID must be cryptographically verified by the secure
//     handshake (peerstore public key must exist), and
//   - the end-to-end remote PeerID must be in the allowlist. This check sees
//     the true end-to-end peer even for CircuitRelay v2 connections and is
//     defense in depth on top of the connection gater.
//
// Unauthorized or unverified streams are reset, never served.
func NewHTTPListener(ctx context.Context, h host.Host, allow *Allowlist) (net.Listener, *PeerRegistry, error) {
	lctx, cancel := context.WithCancel(ctx)
	l := &p2pListener{
		host:   h,
		allow:  allow,
		ch:     make(chan *countingConn, 16),
		ctx:    lctx,
		cancel: cancel,
	}
	reg := NewPeerRegistry()
	h.SetStreamHandler(ProtoID, func(s network.Stream) {
		remote := s.Conn().RemotePeer()
		if h.Peerstore().PubKey(remote) == nil {
			s.Reset()
			return
		}
		if l.allow != nil && !l.allow.Contains(remote) {
			s.Reset()
			return
		}
		isCircuit := hasCircuitComponent(s.Conn().RemoteMultiaddr())
		cc := &countingConn{
			Stream:  s,
			peerID:  remote,
			circuit: isCircuit,
		}
		select {
		case l.ch <- cc:
		case <-lctx.Done():
			s.Reset()
		}
	})
	return l, reg, nil
}

// Accept implements net.Listener.
func (l *p2pListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

// Close stops accepting new streams.
func (l *p2pListener) Close() error {
	l.closeOnce.Do(func() { l.cancel() })
	return nil
}

// Addr implements net.Listener; it identifies the owning peer.
func (l *p2pListener) Addr() net.Addr { return p2pAddr(l.host.ID()) }

type p2pAddr peer.ID

func (a p2pAddr) Network() string { return "libp2p" }
func (a p2pAddr) String() string  { return string(a) }

func hasCircuitComponent(m ma.Multiaddr) bool {
	_, err := m.ValueForProtocol(PCircuitP2PID)
	return err == nil
}

// multiaddr protocol codes used below.
const (
	// PCircuitP2PID is the /p2p-circuit protocol code.
	PCircuitP2PID = 290
)

// DialConfig describes one HTTP client over libp2p with an explicit transport
// policy. It is bound to one expected remote PeerID.
type DialConfig struct {
	Host        host.Host
	Expected    peer.ID        // verified after every connection
	DirectAddrs []ma.Multiaddr // known direct endpoints of Expected (mutable endpoints, from the control registry)
	Relay       *peer.AddrInfo // relay hop, required for relay paths
	Policy      DialPolicy
	// DirectTimeout bounds each direct dial attempt for DirectThenRelay
	// (default 3s).
	DirectTimeout time.Duration
	ConnectTimeout time.Duration
	logf           func(format string, args ...any)

	lastConn *countingConn
	lastMu   sync.Mutex
	connsMu  sync.Mutex
	conns    []*countingConn
}

// LastStats aggregates counters over every connection opened by this config
// (HTTP keep-alive may open more than one) plus the path metadata of the most
// recent connection.
func (d *DialConfig) LastStats() TransferStats {
	d.lastMu.Lock()
	defer d.lastMu.Unlock()
	out := TransferStats{Path: string(d.Policy)}
	d.connsMu.Lock()
	defer d.connsMu.Unlock()
	if len(d.conns) == 0 {
		return out
	}
	last := d.conns[len(d.conns)-1]
	last.Snapshot()
	out = *last.stats
	out.PayloadBytesWritten = 0
	out.PayloadBytesRead = 0
	for _, c := range d.conns {
		out.PayloadBytesWritten += c.written.Load()
		out.PayloadBytesRead += c.read.Load()
	}
	return out
}

func (d *DialConfig) track(c *countingConn) {
	d.lastMu.Lock()
	d.lastConn = c
	d.lastMu.Unlock()
	d.connsMu.Lock()
	d.conns = append(d.conns, c)
	d.connsMu.Unlock()
}

// DialPolicy selects the transport path explicitly. There is no automatic,
// silent policy: any fallback (direct-then-relay) is recorded in stats.
type DialPolicy string

const (
	// PolicyDirect dials the peer's direct endpoints only.
	PolicyDirect DialPolicy = "direct"
	// PolicyForcedRelay dials ONLY via the CircuitRelay v2 circuit address.
	// The connection must be Limited and carry /p2p-circuit in its
	// RemoteMultiaddr, otherwise it is an error (never a silent direct
	// fallback).
	PolicyForcedRelay DialPolicy = "forced-relay"
	// PolicyDirectThenRelay tries direct first and falls back to the relay,
	// recording the fallback in stats.
	PolicyDirectThenRelay DialPolicy = "direct-then-relay"
)

// ErrUnauthorized is returned when a peer is not in the allowlist.
var ErrUnauthorized = errors.New("peertransport: peer not authorized")

// NewHTTPClient returns an http.Client whose connections are libp2p streams
// obeying the configured DialPolicy. The existing net/http processing model
// is preserved end to end (server handlers never learn about libp2p).
func (d *DialConfig) NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:         d.DialContext,
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// DialContext implements http.Transport.DialContext.
func (d *DialConfig) DialContext(ctx context.Context, network_, addr string) (net.Conn, error) {
	if network_ != "tcp" && network_ != "tcp4" && network_ != "tcp6" {
		return nil, fmt.Errorf("peertransport: unsupported network %q", network_)
	}
	conn, _, err := d.dial(ctx)
	return conn, err
}

// Dial establishes one libp2p-backed connection per policy and returns the
// wrapped conn plus stats.
func (d *DialConfig) Dial(ctx context.Context) (net.Conn, TransferStats, error) {
	conn, stats, err := d.dial(ctx)
	return conn, stats, err
}

func (d *DialConfig) dial(ctx context.Context) (*countingConn, TransferStats, error) {
	var (
		conn *countingConn
		err  error
	)
	switch d.Policy {
	case PolicyDirect:
		conn, err = d.dialDirect(ctx, d.DirectAddrs)
	case PolicyForcedRelay:
		conn, err = d.dialRelay(ctx, false)
	case PolicyDirectThenRelay:
		conn, err = d.dialDirect(ctx, d.DirectAddrs)
		if err != nil {
			d.logf("direct dial to %s failed (%v); falling back to relay", d.Expected, err)
			conn, err = d.dialRelay(ctx, true)
		}
	default:
		return nil, TransferStats{}, fmt.Errorf("peertransport: unknown dial policy %q", d.Policy)
	}
	if err != nil {
		return nil, TransferStats{}, err
	}
	d.track(conn)
	return conn, *conn.stats, nil
}

func (d *DialConfig) directTimeout() time.Duration {
	if d.DirectTimeout > 0 {
		return d.DirectTimeout
	}
	return 3 * time.Second
}

func (d *DialConfig) dialDirect(ctx context.Context, addrs []ma.Multiaddr) (*countingConn, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("peertransport: no direct endpoints for %s", d.Expected)
	}
	// Strict address set: purge everything learned before (identify adds the
	// peer's other endpoints, possibly relayed ones) so this dial can only
	// use the direct endpoints we were given. Also drop any circuit conns so
	// host.NewStream cannot reuse a relayed connection for a direct dial.
	d.resetPeerAddrs(addrs)
	d.closeConnsExcept(pathDirect)
	ai := peer.AddrInfo{ID: d.Expected, Addrs: addrs}
	dctx, cancel := context.WithTimeout(ctx, d.connectTimeout())
	defer cancel()
	if err := d.Host.Connect(dctx, ai); err != nil {
		return nil, fmt.Errorf("peertransport: direct connect to %s: %w", d.Expected, err)
	}
	stream, err := d.openVerifiedStream(ctx, pathDirect, false)
	if err != nil {
		return nil, err
	}
	return wrapStream(stream, pathDirect, false), nil
}

// dialRelay connects via the CircuitRelay v2 circuit address. When fallback is
// false (forced relay) any pre-existing connection is torn down and the
// peerstore address set is reduced to exactly the circuit address; a
// non-Limited, non-circuit connection is a hard error.
func (d *DialConfig) dialRelay(ctx context.Context, fallback bool) (*countingConn, error) {
	if d.Relay == nil {
		return nil, errors.New("peertransport: relay endpoint not configured")
	}
	circuitAI, err := CircuitAddrInfo(*d.Relay, d.Expected)
	if err != nil {
		return nil, err
	}
	// Strict address set: only the circuit address, so the swarm cannot
	// silently dial a direct endpoint instead. Direct conns are dropped so
	// the new stream cannot ride on them.
	d.resetPeerAddrs(circuitAI.Addrs)
	d.closeConnsExcept(pathCircuit)
	dctx, cancel := context.WithTimeout(ctx, d.connectTimeout())
	defer cancel()
	if err := d.Host.Connect(dctx, circuitAI); err != nil {
		return nil, fmt.Errorf("peertransport: relay connect to %s via %s: %w", d.Expected, d.Relay.ID, err)
	}
	stream, err := d.openVerifiedStream(ctx, pathCircuit, fallback)
	if err != nil {
		return nil, err
	}
	return wrapStream(stream, pathCircuit, fallback), nil
}

// closeConnsExcept tears down connections to the expected peer that do NOT
// match the requested path, so a subsequent NewStream can only ride on the
// right kind of connection.
func (d *DialConfig) closeConnsExcept(path string) {
	for _, c := range d.Host.Network().ConnsToPeer(d.Expected) {
		isCircuit := hasCircuitComponent(c.RemoteMultiaddr())
		match := (path == pathCircuit && isCircuit) || (path == pathDirect && !isCircuit)
		if !match {
			c.Close()
		}
	}
}

// resetPeerAddrs replaces ALL known addresses of Expected with exactly the
// given set (stored with PermanentAddrTTL). It purges the standard TTL
// buckets so neither direct nor circuit endpoints learned earlier can leak
// into the next policy-scoped dial.
func (d *DialConfig) resetPeerAddrs(addrs []ma.Multiaddr) {
	ps := d.Host.Peerstore()
	for _, ttl := range []time.Duration{
		peerstore.PermanentAddrTTL,
		peerstore.ConnectedAddrTTL,
		peerstore.TempAddrTTL,
	} {
		ps.UpdateAddrs(d.Expected, ttl, 0)
	}
	if len(addrs) > 0 {
		ps.AddAddrs(d.Expected, addrs, peerstore.PermanentAddrTTL)
	}
}

func (d *DialConfig) connectTimeout() time.Duration {
	if d.ConnectTimeout > 0 {
		return d.ConnectTimeout
	}
	return 15 * time.Second
}

// openVerifiedStream opens a protocol-negotiated stream toward the expected
// peer and enforces the transport invariants:
//   - the stream's connection must match the requested path (direct vs
//     Limited /p2p-circuit conn),
//   - the end-to-end PeerID must match the expectation,
//   - the secure handshake must have verified the remote identity (peerstore
//     public key present).
//
// Anything else is an error — never a silent unencrypted fallback.
func (d *DialConfig) openVerifiedStream(ctx context.Context, path string, fallback bool) (network.Stream, error) {
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Explicitly allow streams over Limited (CircuitRelay v2) connections;
	// the swarm otherwise waits for a direct connection before opening a
	// stream on a relayed one.
	sctx = network.WithAllowLimitedConn(sctx, "atoll-prototype-forced-relay")
	stream, err := d.Host.NewStream(sctx, d.Expected, ProtoID)
	if err != nil {
		return nil, fmt.Errorf("peertransport: open stream to %s: %w", d.Expected, err)
	}
	conn := stream.Conn()
	if conn.RemotePeer() != d.Expected {
		stream.Reset()
		return nil, fmt.Errorf("peertransport: connected to %s but expected %s", conn.RemotePeer(), d.Expected)
	}
	if d.Host.Peerstore().PubKey(conn.RemotePeer()) == nil {
		stream.Reset()
		return nil, fmt.Errorf("peertransport: remote peer %s identity not verified by secure handshake", conn.RemotePeer())
	}
	isCircuit := hasCircuitComponent(conn.RemoteMultiaddr())
	if path == pathCircuit && (!isCircuit || !conn.Stat().Limited) {
		// CircuitRelay v2 connection upgrade: after relay traversal the swarm
		// may migrate the connection to a direct one (observed on a real WAN
		// run: the relay hop upgraded the circuit to a QUIC direct
		// connection). For DirectThenRelay fallback this upgrade is a success
		// — the bytes DID traverse the relay first; only forced-relay keeps
		// the strict limited-circuit requirement.
		if !fallback {
			stream.Reset()
			return nil, fmt.Errorf("peertransport: expected limited circuit connection, got %s (limited=%v)",
				conn.RemoteMultiaddr(), conn.Stat().Limited)
		}
	}
	if path == pathDirect && isCircuit {
		stream.Reset()
		return nil, fmt.Errorf("peertransport: expected direct connection, got circuit %s", conn.RemoteMultiaddr())
	}
	return stream, nil
}

func wrapStream(s network.Stream, effective string, fallbackUsed bool) *countingConn {
	isCircuit := hasCircuitComponent(s.Conn().RemoteMultiaddr())
	cc := &countingConn{Stream: s, peerID: s.Conn().RemotePeer(), circuit: isCircuit}
	cc.stats = &TransferStats{
		Path:            effective,
		Effective:       effective,
		RemotePeer:      s.Conn().RemotePeer().String(),
		RemoteMultiaddr: s.Conn().RemoteMultiaddr().String(),
		Limited:         s.Conn().Stat().Limited,
		Secure:          true,
		FallbackUsed:    fallbackUsed,
	}
	return cc
}

// CircuitAddrInfo builds the CircuitRelay v2 dial address
// <relayAddr>/p2p/<relayID>/p2p-circuit/p2p/<targetID>.
func CircuitAddrInfo(relay peer.AddrInfo, target peer.ID) (peer.AddrInfo, error) {
	if len(relay.Addrs) == 0 {
		return peer.AddrInfo{}, fmt.Errorf("peertransport: relay %s has no addresses", relay.ID)
	}
	base := relay.Addrs[0]
	// Ensure the relay peer ID component is present exactly once.
	if _, err := base.ValueForProtocol(P_P2PID); err != nil {
		base = ma.Join(base, ma.StringCast("/p2p/"+relay.ID.String()))
	}
	full := ma.Join(base, ma.StringCast(maCircuitProto), ma.StringCast("/p2p/"+target.String()))
	return peer.AddrInfo{ID: target, Addrs: []ma.Multiaddr{full}}, nil
}

// P_P2PID is the /p2p (formerly /ipfs) multiaddr protocol code.
const P_P2PID = 421
