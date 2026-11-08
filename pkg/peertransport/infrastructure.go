package peertransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	relayproto "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	ma "github.com/multiformats/go-multiaddr"
)

func tcpAddress(address ma.Multiaddr) bool {
	if address == nil || hasCircuitComponent(address) {
		return false
	}
	protocols := address.Protocols()
	return len(protocols) == 2 && protocols[1].Code == ma.P_TCP
}

func infrastructureHasTCP(infra peerauth.Infrastructure) bool {
	for _, address := range infra.Addresses {
		parsed, err := ma.NewMultiaddr(address)
		if err == nil && tcpAddress(parsed) {
			return true
		}
	}
	return false
}

func sameInfrastructure(a, b peerauth.Infrastructure) bool {
	return a.PeerID == b.PeerID && bytes.Equal(a.PublicKey, b.PublicKey) && a.Relay == b.Relay && slices.Equal(a.Addresses, b.Addresses)
}

func (g *protocolGate) requiresInfrastructureTCP(remote peer.ID) bool {
	g.dirMu.RLock()
	defer g.dirMu.RUnlock()
	_, pinned := g.relayTCP[remote]
	return pinned || g.infrastructure == remote.String() && g.infrastructureTCP
}

func (g *protocolGate) pinRelayTCP(remote peer.ID) error {
	g.dirMu.Lock()
	defer g.dirMu.Unlock()
	if _, ok := g.relayTCP[remote]; ok {
		return nil
	}
	if len(g.relayTCP) >= maxRelayHosts+1 {
		return errors.New("peertransport: relay connection policy is full")
	}
	if g.relayTCP == nil {
		g.relayTCP = make(map[peer.ID]struct{})
	}
	g.relayTCP[remote] = struct{}{}
	return nil
}

func isTCPConnection(conn network.Conn) bool {
	return conn != nil && !conn.IsClosed() && conn.ConnState().Transport == "tcp" && !conn.Stat().Limited && tcpAddress(conn.RemoteMultiaddr())
}

func connectedTCP(h host.Host, remote peer.ID) network.Conn {
	for _, conn := range h.Network().ConnsToPeer(remote) {
		if isTCPConnection(conn) {
			return conn
		}
	}
	return nil
}

func selectedTCP(ctx context.Context, h host.Host, auth *protocolGate, remote peer.ID) (network.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !auth.authorize(ctx, remote.String()) {
		return nil, ErrPeerUnauthorized
	}
	if conn := connectedTCP(h, remote); conn != nil {
		return conn, nil
	}
	return nil, network.ErrNoConn
}

func ensureTCP(ctx context.Context, h host.Host, auth *protocolGate, remote peer.ID) (network.Conn, error) {
	if conn, err := selectedTCP(ctx, h, auth, remote); err == nil {
		return conn, nil
	} else if errors.Is(err, ErrPeerUnauthorized) || ctx.Err() != nil {
		return nil, err
	}
	if noDial, _ := network.GetNoDial(ctx); noDial {
		return nil, network.ErrNoConn
	}
	if err := auth.pinRelayTCP(remote); err != nil {
		return nil, err
	}
	// Swarm cannot add another registered transport connection to an already
	// connected peer. Reject a mismatched pool instead of closing live streams.
	for _, conn := range h.Network().ConnsToPeer(remote) {
		if !conn.IsClosed() && !hasCircuitComponent(conn.RemoteMultiaddr()) {
			return nil, errors.New("peertransport: relay peer has no TCP connection")
		}
	}
	ctx = network.WithForceDirectDial(ctx, "atoll-relay-tcp")
	if _, err := h.Network().DialPeer(ctx, remote); err != nil {
		return nil, err
	}
	return selectedTCP(ctx, h, auth, remote)
}

// Relay control streams select a physical TCP connection; host.NewStream may
// otherwise choose a same-PeerID QUIC observation connection.
type connectionHost struct {
	host.Host
	connection func(context.Context, peer.ID) (network.Conn, error)
	observe    func(RuntimeEvent)
}

func (h *connectionHost) NewStream(ctx context.Context, remote peer.ID, protocols ...protocol.ID) (result network.Stream, err error) {
	started := time.Now()
	var conn network.Conn
	defer func() {
		if h.observe == nil {
			return
		}
		event := RuntimeEvent{Time: time.Now().UTC(), Kind: "relay_control_stream", RequestID: peerhttp.RequestID(ctx), LocalPeerID: h.ID().String(), RemotePeerID: remote.String(), Success: err == nil && result != nil, ErrorKind: runtimeErrorKind(err), Elapsed: time.Since(started)}
		if len(protocols) == 1 {
			event.Protocol = string(protocols[0])
		}
		if conn != nil {
			event.ConnectionID = conn.ID()
			event.LocalAddress = conn.LocalMultiaddr().String()
			event.RemoteAddress = conn.RemoteMultiaddr().String()
			event.Transport = conn.ConnState().Transport
		}
		if result != nil {
			event.StreamID = result.ID()
		}
		h.observe(event)
	}()
	if len(protocols) != 1 || protocols[0] != relayproto.ProtoIDv2Hop && protocols[0] != relayproto.ProtoIDv2Stop {
		return nil, errors.New("peertransport: one relay control protocol is required")
	}
	conn, err = h.connection(ctx, remote)
	if err != nil {
		return nil, err
	}
	if !isTCPConnection(conn) || conn.RemotePeer() != remote {
		return nil, errors.New("peertransport: no verified TCP relay connection")
	}
	stream, err := conn.NewStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := negotiateStream(ctx, stream, protocols[0]); err != nil {
		return nil, err
	}
	if err := stream.SetProtocol(protocols[0]); err != nil {
		_ = stream.Reset()
		return nil, err
	}
	return boundRelayHandshake(ctx, stream), nil
}

func (r *Runtime) prepareTCPInfrastructure(ctx context.Context, infra peerauth.Infrastructure) (network.Conn, error) {
	ai, err := infraAddrInfo(infra)
	if err != nil || !infrastructureHasTCP(infra) {
		return nil, fmt.Errorf("%w: relay infrastructure needs a TCP endpoint", ErrInfrastructureInvalid)
	}
	if _, err := peerauth.NormalizeAddresses(infra.Addresses, r.cfg.PublicOnly); err != nil {
		return nil, ErrInfrastructureInvalid
	}
	if !r.auth.authorize(ctx, infra.PeerID) {
		return nil, ErrPeerUnauthorized
	}
	if err := r.auth.pinRelayTCP(ai.ID); err != nil {
		return nil, err
	}
	r.mainHost.Peerstore().AddAddrs(ai.ID, preferTCP(ai.Addrs), time.Minute)
	conn, err := ensureTCP(ctx, r.mainHost, r.auth, ai.ID)
	if err != nil {
		return nil, err
	}
	if err := verifyStreamPeer(conn, ai.ID, infra.PublicKey); err != nil {
		return nil, ErrInfrastructureInvalid
	}
	return conn, nil
}

func addressHasQUIC(address ma.Multiaddr) bool {
	if address == nil {
		return false
	}
	protocols := address.Protocols()
	return len(protocols) == 3 && (protocols[0].Code == ma.P_IP4 || protocols[0].Code == ma.P_IP6) && protocols[1].Code == ma.P_UDP && protocols[2].Code == ma.P_QUIC_V1
}

func sameUDPListener(conn network.Conn, listeners []ma.Multiaddr) bool {
	if conn == nil || !addressHasQUIC(conn.LocalMultiaddr()) {
		return false
	}
	for _, listen := range listeners {
		if addressHasQUIC(listen) && sameListenTransport(listen, conn.LocalMultiaddr()) {
			return true
		}
	}
	return false
}

func limitedObservedAddress(raw []byte, publicOnly bool) (ma.Multiaddr, error) {
	if len(raw) == 0 || len(raw) > peerauth.MaxAddressLength {
		return nil, errors.New("peertransport: invalid QUIC observation length")
	}
	address, err := ma.NewMultiaddrBytes(raw)
	if err != nil || !addressHasQUIC(address) || !bytes.Equal(address.Bytes(), raw) {
		return nil, errors.New("peertransport: invalid QUIC observation")
	}
	if _, err := peerauth.NormalizeAddresses([]string{address.String()}, publicOnly); err != nil {
		return nil, errors.New("peertransport: unusable QUIC observation")
	}
	return address, nil
}
