package peertransport

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	relaypb "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/pb"
	relayproto "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	"github.com/libp2p/go-msgio/pbio"
	ma "github.com/multiformats/go-multiaddr"
)

func mixedInfrastructure(t *testing.T) (*Runtime, *Runtime, peerauth.Infrastructure) {
	t.Helper()
	listen := []string{"/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/udp/0/quic-v1"}
	center := newTestRuntime(t, Config{ListenAddresses: listen})
	edge := newTestRuntime(t, Config{ListenAddresses: listen})
	center.SetAuthorizer(allowIDs(edge.PeerID()))
	edge.SetAuthorizer(allowIDs(center.PeerID()))
	return center, edge, infraOf(center)
}

func infrastructureWithQUICConnection(t *testing.T) (*Runtime, *Runtime, peerauth.Infrastructure, network.Conn) {
	t.Helper()
	center, edge, infra := mixedInfrastructure(t)
	var quic []ma.Multiaddr
	for _, address := range center.mainHost.Addrs() {
		if addressHasQUIC(address) {
			quic = append(quic, address)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// This deliberately creates the legacy mismatch before the infrastructure
	// policy is installed. Public DialPeer cannot transparently add TCP later.
	if err := edge.mainHost.Connect(ctx, peer.AddrInfo{ID: center.id, Addrs: quic}); err != nil {
		t.Fatal(err)
	}
	if err := edge.SetDirectory(peerauth.Directory{Protocol: peerauth.Feature, Infrastructure: infra}); err != nil {
		t.Fatal(err)
	}
	for _, conn := range edge.mainHost.Network().ConnsToPeer(center.id) {
		if !conn.IsClosed() && addressHasQUIC(conn.RemoteMultiaddr()) {
			return center, edge, infra, conn
		}
	}
	t.Fatal("fixture never established its real legacy QUIC connection")
	return nil, nil, peerauth.Infrastructure{}, nil
}

func preparedInfrastructure(t *testing.T) (*Runtime, *Runtime, peerauth.Infrastructure, network.Conn) {
	t.Helper()
	center, edge, infra := mixedInfrastructure(t)
	if err := edge.SetDirectory(peerauth.Directory{Protocol: peerauth.Feature, Infrastructure: infra}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := edge.PrepareInfrastructure(ctx, infra); err != nil {
		t.Fatal(err)
	}
	if edge.observationHost == nil {
		t.Fatal("preparation did not create the separate QUIC observer")
	}
	for _, conn := range edge.observationHost.Network().ConnsToPeer(center.id) {
		if !conn.IsClosed() && addressHasQUIC(conn.RemoteMultiaddr()) {
			return center, edge, infra, conn
		}
	}
	t.Fatal("preparation never established its actual QUIC observation")
	return nil, nil, peerauth.Infrastructure{}, nil
}

func TestInfrastructurePreparationRetainsBothObservationTransports(t *testing.T) {
	center, edge, _, observation := preparedInfrastructure(t)
	if connectedTCP(edge.mainHost, center.id) == nil || observation.IsClosed() {
		t.Fatal("TCP baseline and separate QUIC observation are not both alive")
	}
	if !sameUDPListener(observation, edge.mainHost.Network().ListenAddresses()) {
		t.Fatal("QUIC observer used a different UDP listener socket")
	}
	for _, conn := range edge.mainHost.Network().ConnsToPeer(center.id) {
		if !isTCPConnection(conn) {
			t.Fatalf("main infrastructure pool unexpectedly contains %s", conn.RemoteMultiaddr())
		}
	}
	candidates := edge.observed.AddrsFor(observation.LocalMultiaddr())
	if len(candidates) == 0 {
		t.Fatal("separate shared-socket QUIC observation supplied no candidate")
	}
	for _, address := range candidates {
		if !addressHasQUIC(address) {
			t.Fatalf("QUIC observation invented another transport: %s", address)
		}
	}
	for _, protocol := range edge.observationHost.Mux().Protocols() {
		if protocol == ProtoID || protocol == identify.ID || protocol == identify.IDPush || protocol == relayproto.ProtoIDv2Stop {
			t.Fatalf("observation helper advertises a data or Identify service: %s", protocol)
		}
	}
	t.Logf("main TCP=%s, auxiliary QUIC=%s, main UDP=%s", connectedTCP(edge.mainHost, center.id).LocalMultiaddr(), observation.LocalMultiaddr(), edge.mainHost.Network().ListenAddresses())
}

func TestInfrastructureLegacyQUICPoolFailsClosedWithoutClosingIt(t *testing.T) {
	_, edge, infra, conn := infrastructureWithQUICConnection(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := edge.PrepareInfrastructure(ctx, infra); err == nil {
		t.Fatal("pre-existing wrong transport was reported as a prepared TCP relay")
	}
	if _, err := edge.ReserveRelay(ctx, infra); err == nil {
		t.Fatal("reservation reused a legacy QUIC connection")
	}
	if conn.IsClosed() {
		t.Fatal("rejecting a mismatched pool closed its live connection")
	}
}

func TestSelectedRelayHostRefusesQUICWithoutClosingIt(t *testing.T) {
	center, edge, _, conn := infrastructureWithQUICConnection(t)
	h := &connectionHost{Host: edge.mainHost, connection: func(context.Context, peer.ID) (network.Conn, error) { return conn, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if stream, err := h.NewStream(ctx, center.id, relayproto.ProtoIDv2Hop); err == nil || stream != nil {
		t.Fatal("selected relay host accepted a QUIC connection")
	}
	if conn.IsClosed() {
		t.Fatal("refusing the relay path closed an observation connection")
	}
}

func TestSelectedRelayHostNegotiatesOnItsTCPConnection(t *testing.T) {
	center := newTestRuntime(t, Config{ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"}})
	edge := newTestRuntime(t, Config{ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"}})
	center.SetAuthorizer(allowIDs(edge.PeerID()))
	edge.SetAuthorizer(allowIDs(center.PeerID()))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := edge.mainHost.Connect(ctx, peer.AddrInfo{ID: center.id, Addrs: center.mainHost.Addrs()}); err != nil {
		t.Fatal(err)
	}
	conn := connectedTCP(edge.mainHost, center.id)
	if conn == nil {
		t.Fatal("fixture never established its actual TCP connection")
	}
	used := make(chan network.Conn, 1)
	center.mainHost.SetStreamHandler(relayproto.ProtoIDv2Hop, func(stream network.Stream) {
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		used <- stream.Conn()
		_, _ = stream.Write([]byte("ok"))
	})
	h := &connectionHost{Host: edge.mainHost, connection: func(context.Context, peer.ID) (network.Conn, error) { return conn, nil }}
	stream, err := h.NewStream(ctx, center.id, relayproto.ProtoIDv2Hop)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if stream.Conn() != conn || stream.Protocol() != relayproto.ProtoIDv2Hop {
		t.Fatal("relay control stream did not use its selected connection and protocol")
	}
	select {
	case actual := <-used:
		if !isTCPConnection(actual) || actual.ConnState().Transport != "tcp" {
			t.Fatalf("selected stream reached the center over %s", actual.RemoteMultiaddr())
		}
	case <-ctx.Done():
		t.Fatal("actual relay handler did not accept the negotiated stream")
	}
}

func TestRelayReservationDoesNotReuseQUICObservationConnection(t *testing.T) {
	center, edge, infra, observation := preparedInfrastructure(t)
	used := make(chan network.Conn, 1)
	center.mainHost.SetStreamHandler(relayproto.ProtoIDv2Hop, func(stream network.Stream) {
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		var request relaypb.HopMessage
		if err := pbio.NewDelimitedReader(stream, 4096).ReadMsg(&request); err != nil || request.GetType() != relaypb.HopMessage_RESERVE {
			_ = stream.Reset()
			return
		}
		used <- stream.Conn()
		expires := uint64(time.Now().Add(time.Minute).Unix())
		reservation := &relaypb.Reservation{Expire: &expires}
		for _, address := range center.mainHost.Addrs() {
			reservation.Addrs = append(reservation.Addrs, address.Bytes())
		}
		response := &relaypb.HopMessage{Type: relaypb.HopMessage_STATUS.Enum(), Status: relaypb.Status_OK.Enum(), Reservation: reservation}
		_ = pbio.NewDelimitedWriter(stream).WriteMsg(response)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := edge.ReserveRelay(ctx, infra); err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-used:
		if !isTCPConnection(actual) || actual.ConnState().Transport != "tcp" {
			t.Fatalf("reservation used %s instead of the TCP baseline", actual.RemoteMultiaddr())
		}
	case <-ctx.Done():
		t.Fatal("reservation never reached the actual center handler")
	}
	if observation.IsClosed() || len(edge.observed.AddrsFor(observation.LocalMultiaddr())) == 0 {
		t.Fatal("selecting the TCP relay removed the live QUIC observation")
	}
}

func TestSelectedRelayTargetNoDialWithoutTCP(t *testing.T) {
	center, _, _, _ := infrastructureWithQUICConnection(t)
	remote := testPeerID(t)
	center.SetAuthorizer(allowIDs(remote.String()))
	ctx := network.WithNoDial(context.Background(), "relay connect")
	if conn, err := ensureTCP(ctx, center.mainHost, center.auth, remote); !errors.Is(err, network.ErrNoConn) || conn != nil {
		t.Fatalf("missing target TCP did not fail without dialing: conn=%v err=%v", conn, err)
	}
	if len(center.mainHost.Network().ConnsToPeer(remote)) != 0 {
		t.Fatal("NoDial target selection created a connection")
	}
}

func TestObservationCloseLeavesMainQUICDataListenerUsable(t *testing.T) {
	center, edge, _, observation := preparedInfrastructure(t)
	if err := edge.observationHost.Close(); err != nil {
		t.Fatal(err)
	}
	if !observation.IsClosed() || len(edge.observed.AddrsFor(observation.LocalMultiaddr())) != 0 {
		t.Fatal("closed auxiliary observer retained its candidate")
	}
	node := newTestRuntime(t, Config{ListenAddresses: []string{"/ip4/127.0.0.1/udp/0/quic-v1"}})
	node.SetAuthorizer(allowIDs(edge.PeerID()))
	edge.SetAuthorizer(allowIDs(center.PeerID(), node.PeerID()))
	listener, err := node.Listener()
	if err != nil {
		t.Fatal(err)
	}
	accepted := startAccept(t, listener)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := edge.Dial(ctx, endpointOf(node), peerauth.Infrastructure{}, peerhttp.PathDirect)
	if result.Err != nil {
		t.Fatalf("closing the auxiliary host shut down main QUIC: %v", result.Err)
	}
	defer result.Conn.Close()
	if result.Path != peerhttp.PathDirect || result.Fallback {
		t.Fatal("QUIC-only node data was not a real direct path")
	}
	_ = result.Conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := result.Conn.Write([]byte("main-udp")); err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-accepted:
		if actual == nil {
			t.Fatal("QUIC-only node did not accept data")
		}
		defer actual.Close()
		buffer := make([]byte, len("main-udp"))
		if _, err := io.ReadFull(actual, buffer); err != nil || string(buffer) != "main-udp" {
			t.Fatalf("direct QUIC data mismatch: %q err=%v", buffer, err)
		}
	case <-ctx.Done():
		t.Fatal("direct QUIC data listener did not receive the stream")
	}
}
