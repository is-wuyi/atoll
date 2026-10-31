package peertransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multistream"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
)

const streamOpenTimeout = 30 * time.Second

// connClass selects which existing connection a stream is opened on: only
// non-circuit connections, only circuit connections, or circuit connections
// preferred with non-circuit (hole-punch upgraded) ones accepted afterwards.
type connClass int

const (
	connDirectOnly connClass = iota
	connCircuitOnly
	connCircuitFirst
)

// Dial establishes one peer stream toward the endpoint with an explicit path
// policy:
//
//   - peerhttp.PathDirect requires a direct connection (main host, force
//     direct dial, no fallback, actual connection verified direct).
//   - peerhttp.PathRelay requires a circuit connection (lazy isolated relay
//     dial host, strict gate, no direct fallback).
//   - peerhttp.PathHTTP / PathHTTPS are ordinary TCP paths and are refused: a
//     peer transport must never present a plain TCP path as a peer dial.
//   - an empty or PathUnknown path is the normal policy: prefer a direct dial
//     (bounded), and on failure fall back to the relay through the main host so
//     hole punching / connection reversal can still upgrade the circuit to a
//     direct connection.
//
// The reported path is always derived from the connection that actually opened
// (its RemoteMultiaddr), never from the requested policy. On success Conn is
// non-nil and Err is nil; on failure Conn is nil and Err carries the reason.
// The returned stream, its completed protocol negotiation included, is not
// tied to the caller's context: it remains usable after ctx is canceled.
func (r *Runtime) Dial(ctx context.Context, ep peerauth.Endpoint, infra peerauth.Infrastructure, reqPath peerhttp.Path) DialResult {
	if err := peerauth.ValidateIdentity(ep.PeerID, ep.PublicKey); err != nil {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: err, Identity: ep.PeerID, Path: peerhttp.PathUnknown}}
	}
	if err := ctx.Err(); err != nil {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: err, Identity: ep.PeerID, Path: peerhttp.PathUnknown}}
	}
	if !r.auth.authorize(ctx, ep.PeerID) {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: fmt.Errorf("peertransport: peer %s is not authorized", ep.PeerID), Identity: ep.PeerID, Path: peerhttp.PathUnknown}}
	}
	target, err := peer.Decode(ep.PeerID)
	if err != nil {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: fmt.Errorf("peertransport: invalid PeerID: %w", err), Identity: ep.PeerID, Path: peerhttp.PathUnknown}}
	}

	switch reqPath {
	case peerhttp.PathHTTP, peerhttp.PathHTTPS:
		return DialResult{PeerDial: peerhttp.PeerDial{Err: fmt.Errorf("peertransport: %s is not a peer path", reqPath), Identity: ep.PeerID, Path: peerhttp.PathUnknown}}
	case peerhttp.PathRelay:
		return r.dialRequiredRelay(ctx, target, ep.PublicKey, infra)
	case peerhttp.PathDirect:
		return r.dialRequiredDirect(ctx, target, ep.PublicKey, filterDirectAddrs(ep.Addresses))
	default:
		return r.dialNormal(ctx, target, ep.PublicKey, filterDirectAddrs(ep.Addresses), infra)
	}
}

func (r *Runtime) dialRequiredDirect(ctx context.Context, target peer.ID, pub []byte, addrs []ma.Multiaddr) DialResult {
	if len(addrs) == 0 {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: errors.New("peertransport: no direct endpoints"), Identity: target.String(), Path: peerhttp.PathUnknown}}
	}
	ai := peer.AddrInfo{ID: target, Addrs: addrs}
	dctx, cancel := context.WithTimeout(ctx, r.directTimeout())
	defer cancel()
	dctx = network.WithForceDirectDial(dctx, "atoll-direct")
	if err := r.mainHost.Connect(dctx, ai); err != nil {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: fmt.Errorf("peertransport: direct connect: %w", err), Identity: target.String(), Path: peerhttp.PathUnknown}}
	}
	stream, err := r.openVerifiedStream(dctx, r.mainHost, target, pub, connDirectOnly)
	if err != nil {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: err, Identity: target.String(), Path: peerhttp.PathUnknown}}
	}
	return wrapDialResult(stream, false)
}

func (r *Runtime) dialRequiredRelay(ctx context.Context, target peer.ID, pub []byte, infra peerauth.Infrastructure) DialResult {
	ai, err := circuitAddrInfo(infra, target)
	if err != nil {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: err, Identity: target.String(), Path: peerhttp.PathUnknown}}
	}
	relayID, derr := peer.Decode(infra.PeerID)
	if derr != nil {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: derr, Identity: target.String(), Path: peerhttp.PathUnknown}}
	}
	rh, err := r.relayHostFor(relayID)
	if err != nil {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: err, Identity: target.String(), Path: peerhttp.PathUnknown}}
	}
	cctx, cancel := context.WithTimeout(ctx, r.relayTimeout())
	defer cancel()
	if err := rh.Connect(cctx, ai); err != nil {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: fmt.Errorf("peertransport: relay connect: %w", err), Identity: target.String(), Path: peerhttp.PathUnknown}}
	}
	stream, err := r.openVerifiedStream(cctx, rh, target, pub, connCircuitOnly)
	if err != nil {
		return DialResult{PeerDial: peerhttp.PeerDial{Err: err, Identity: target.String(), Path: peerhttp.PathUnknown}}
	}
	return wrapDialResult(stream, false)
}

func (r *Runtime) dialNormal(ctx context.Context, target peer.ID, pub []byte, addrs []ma.Multiaddr, infra peerauth.Infrastructure) DialResult {
	var firstErr error
	if len(addrs) > 0 {
		ai := peer.AddrInfo{ID: target, Addrs: addrs}
		dctx, cancel := context.WithTimeout(ctx, r.directTimeout())
		dctx = network.WithForceDirectDial(dctx, "atoll-direct")
		err := r.mainHost.Connect(dctx, ai)
		if err == nil {
			// The stream and its full protocol negotiation run while dctx is
			// still live; cancel is only issued once the negotiation completed
			// or the attempt failed. Cancelling before that would fail a
			// working direct path and produce a false relay fallback.
			stream, serr := r.openVerifiedStream(dctx, r.mainHost, target, pub, connDirectOnly)
			cancel()
			if serr == nil {
				return wrapDialResult(stream, false)
			}
			firstErr = serr
		} else {
			cancel()
			firstErr = err
		}
	} else {
		firstErr = errors.New("peertransport: no direct endpoints")
	}

	// Direct failed: fall back to the relay through the MAIN host so a circuit
	// can still be upgraded to direct by hole punching / connection reversal.
	if infra.Relay {
		ai, err := circuitAddrInfo(infra, target)
		if err != nil {
			// No relay attempt was even constructible: this is not a fallback.
			return DialResult{PeerDial: peerhttp.PeerDial{Err: fmt.Errorf("peertransport: %v; relay: %w", firstErr, err), Identity: target.String(), Path: peerhttp.PathUnknown}}
		}
		// The relay attempt is a fact from here on: a failed attempt is still
		// reported as a fallback (Path stays unknown, Err carries the reason).
		fallback := DialResult{PeerDial: peerhttp.PeerDial{Identity: target.String(), Path: peerhttp.PathUnknown}, Fallback: true}
		cctx, cancel := context.WithTimeout(ctx, r.relayTimeout())
		defer cancel()
		if err := r.mainHost.Connect(cctx, ai); err != nil {
			fallback.PeerDial.Err = fmt.Errorf("peertransport: %v; relay connect: %w", firstErr, err)
			return fallback
		}
		// The stream opens on the circuit connection, or on a direct one when
		// hole punching already upgraded it; the actual path is reported.
		stream, err := r.openVerifiedStream(cctx, r.mainHost, target, pub, connCircuitFirst)
		if err != nil {
			fallback.PeerDial.Err = fmt.Errorf("peertransport: %v; relay stream: %w", firstErr, err)
			return fallback
		}
		return wrapDialResult(stream, true)
	}
	return DialResult{PeerDial: peerhttp.PeerDial{Err: firstErr, Identity: target.String(), Path: peerhttp.PathUnknown}}
}

// openVerifiedStream opens a fully negotiated ProtoID stream to the expected
// peer on an existing connection of the requested class. It never dials: the
// stream opens on a connection the caller just established, so no hidden
// re-dial can bypass the caller's path policy. The multistream handshake must
// complete before the stream is returned — libp2p can defer the negotiation
// (lazily or in the background) after NewStream returns, so opening the stream
// alone never counts as a completed handshake. The peer identity is verified
// against the secure handshake (end-to-end PeerID and public key bytes). The
// returned stream is not tied to the context: it remains usable after ctx is
// cancelled.
func (r *Runtime) openVerifiedStream(ctx context.Context, h host.Host, target peer.ID, pub []byte, class connClass) (network.Stream, error) {
	if ctx == nil {
		ctx = r.ctx
	}
	sctx, cancel := context.WithTimeout(ctx, streamOpenTimeout)
	defer cancel()
	// Circuit connections are limited: opening a stream on one requires the
	// explicit allow flag (direct-class connections are never limited).
	if class != connDirectOnly {
		sctx = network.WithAllowLimitedConn(sctx, "atoll-relay")
	}
	conns := selectConns(h.Network().ConnsToPeer(target), class)
	lastErr := errors.New("peertransport: no usable connection to peer")
	for _, c := range conns {
		stream, err := c.NewStream(sctx)
		if err != nil {
			if !c.IsClosed() {
				lastErr = fmt.Errorf("peertransport: open stream: %w", err)
			}
			continue
		}
		if err := negotiateStream(sctx, stream, ProtoID); err != nil {
			lastErr = err
			continue
		}
		if err := stream.SetProtocol(ProtoID); err != nil {
			stream.Reset()
			lastErr = fmt.Errorf("peertransport: set protocol: %w", err)
			continue
		}
		if err := verifyStreamPeer(c, target, pub); err != nil {
			stream.Reset()
			return nil, err
		}
		return stream, nil
	}
	return nil, lastErr
}

// negotiableStream is the part of a libp2p stream the multistream handshake
// needs: a pipe plus reset.
type negotiableStream interface {
	io.ReadWriteCloser
	Reset() error
}

// negotiateStream runs the multistream handshake for proto on s under ctx.
// SelectOneOf itself has no context: a silent peer would block it forever, so
// it runs on a goroutine and a cancelled context resets the stream, which
// unblocks and fails the negotiation. The stream is reset on any error.
func negotiateStream(ctx context.Context, s negotiableStream, proto protocol.ID) error {
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		selected, err := multistream.SelectOneOf([]protocol.ID{proto}, s)
		if err == nil && selected != proto {
			err = fmt.Errorf("peer selected %s", selected)
		}
		ch <- result{err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			_ = s.Reset()
			return fmt.Errorf("peertransport: negotiate %s: %w", proto, r.err)
		}
		return nil
	case <-ctx.Done():
		_ = s.Reset()
		<-ch
		return fmt.Errorf("peertransport: negotiate %s: %w", proto, ctx.Err())
	}
}

// verifyStreamPeer checks the secure handshake identity of the connection: the
// end-to-end PeerID matches the expected peer and the remote public key
// matches the expected bytes.
func verifyStreamPeer(c network.Conn, target peer.ID, pub []byte) error {
	if c.RemotePeer() != target {
		return fmt.Errorf("peertransport: connected to %s but expected %s", c.RemotePeer(), target)
	}
	rp := c.RemotePublicKey()
	if rp == nil {
		return errors.New("peertransport: remote public key unavailable")
	}
	raw, err := rp.Raw()
	if err != nil || !bytes.Equal(raw, pub) {
		return errors.New("peertransport: remote public key mismatch")
	}
	return nil
}

// selectConns filters the connections to a peer by class: circuit addresses
// carry the /p2p-circuit component, everything else counts as direct.
func selectConns(conns []network.Conn, class connClass) []network.Conn {
	var direct, circuit []network.Conn
	for _, c := range conns {
		if hasCircuitComponent(c.RemoteMultiaddr()) {
			circuit = append(circuit, c)
		} else {
			direct = append(direct, c)
		}
	}
	switch class {
	case connDirectOnly:
		return direct
	case connCircuitOnly:
		return circuit
	default:
		return append(circuit, direct...)
	}
}

func wrapDialResult(stream network.Stream, fallback bool) DialResult {
	conn := stream.Conn()
	path := peerhttp.PathDirect
	if hasCircuitComponent(conn.RemoteMultiaddr()) {
		path = peerhttp.PathRelay
	}
	sc := &streamConn{
		Stream: stream,
		peerID: conn.RemotePeer(),
		local:  conn.LocalMultiaddr(),
		remote: conn.RemoteMultiaddr(),
	}
	return DialResult{
		PeerDial:      peerhttp.PeerDial{Conn: sc, Identity: conn.RemotePeer().String(), Path: path},
		Fallback:      fallback,
		RemoteAddress: conn.RemoteMultiaddr().String(),
		LocalAddress:  conn.LocalMultiaddr().String(),
	}
}

func filterDirectAddrs(in []string) []ma.Multiaddr {
	out := make([]ma.Multiaddr, 0, len(in))
	for _, s := range in {
		a, err := ma.NewMultiaddr(s)
		if err != nil || hasCircuitComponent(a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func (r *Runtime) directTimeout() time.Duration {
	if r.cfg.DirectTimeout > 0 {
		return r.cfg.DirectTimeout
	}
	return 3 * time.Second
}

func (r *Runtime) relayTimeout() time.Duration {
	if r.cfg.RelayTimeout > 0 {
		return r.cfg.RelayTimeout
	}
	return 15 * time.Second
}
