package peertransport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	relayproto "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	identifypb "github.com/libp2p/go-libp2p/p2p/protocol/identify/pb"
	"github.com/libp2p/go-msgio/pbio"
	ma "github.com/multiformats/go-multiaddr"
)

type relayControlEvents struct {
	mu     sync.Mutex
	events []RuntimeEvent
}

func (e *relayControlEvents) record(event RuntimeEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

func (e *relayControlEvents) snapshot() []RuntimeEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]RuntimeEvent(nil), e.events...)
}

func TestMixedInfrastructureRelayBothHopsUseTCP(t *testing.T) {
	var centerEvents, dialerEvents relayControlEvents
	listen := []string{"/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/udp/0/quic-v1"}
	center := newTestRuntime(t, Config{ListenAddresses: listen, Observe: centerEvents.record})
	target := newTestRuntime(t, Config{ListenAddresses: listen})
	dialer := newTestRuntime(t, Config{ListenAddresses: listen, Observe: dialerEvents.record})
	center.SetAuthorizer(allowIDs(target.PeerID(), dialer.PeerID()))
	target.SetAuthorizer(allowIDs(center.PeerID(), dialer.PeerID()))
	dialer.SetAuthorizer(allowIDs(center.PeerID(), target.PeerID()))
	infra := infraOf(center)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, runtime := range []*Runtime{target, dialer} {
		if err := runtime.SetDirectory(peerauth.Directory{Protocol: peerauth.Feature, Infrastructure: infra}); err != nil {
			t.Fatal(err)
		}
		if err := runtime.PrepareInfrastructure(ctx, infra); err != nil {
			t.Fatal(err)
		}
	}
	if err := center.EnableRelay(); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ReserveRelay(ctx, infra); err != nil {
		t.Fatal(err)
	}
	listener, err := target.Listener()
	if err != nil {
		t.Fatal(err)
	}
	accepted := startAccept(t, listener)
	result := dialer.Dial(ctx, endpointOf(target), infra, peerhttp.PathRelay)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	defer result.Conn.Close()
	if result.Path != peerhttp.PathRelay || result.Fallback {
		t.Fatal("strict circuit did not preserve its actual path")
	}
	_ = result.Conn.SetDeadline(time.Now().Add(5 * time.Second))
	const payload = "mixed-infrastructure-relay"
	if _, err := result.Conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	select {
	case conn := <-accepted:
		if conn == nil {
			t.Fatal("target did not accept the relayed object stream")
		}
		defer conn.Close()
		buffer := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != payload {
			t.Fatalf("relayed payload mismatch: %q err=%v", buffer, err)
		}
	case <-ctx.Done():
		t.Fatal("target did not receive the relayed payload")
	}
	assertHop := func(events []RuntimeEvent, local, remote string, protocol string) {
		t.Helper()
		for _, event := range events {
			if event.Kind != "relay_control_stream" || event.Protocol != protocol || event.LocalPeerID != local || event.RemotePeerID != remote || !event.Success {
				continue
			}
			if event.Transport != "tcp" || event.ConnectionID == "" || event.StreamID == "" || !tcpAddress(ma.StringCast(event.RemoteAddress)) {
				t.Fatalf("relay hop did not describe an actual TCP connection: %+v", event)
			}
			return
		}
		t.Fatalf("missing actual relay hop %s -> %s %s", local, remote, protocol)
	}
	assertHop(dialerEvents.snapshot(), dialer.PeerID(), center.PeerID(), string(relayproto.ProtoIDv2Hop))
	assertHop(centerEvents.snapshot(), center.PeerID(), target.PeerID(), string(relayproto.ProtoIDv2Stop))
	for _, runtime := range []*Runtime{target, dialer} {
		var observation network.Conn
		for _, conn := range runtime.observationHost.Network().ConnsToPeer(center.id) {
			if !conn.IsClosed() {
				observation = conn
				break
			}
		}
		if observation == nil || !sameUDPListener(observation, runtime.mainHost.Network().ListenAddresses()) || len(runtime.observed.AddrsFor(observation.LocalMultiaddr())) == 0 {
			t.Fatal("TCP relay damaged a separate shared-socket QUIC observation")
		}
	}
}

func TestMainInfrastructureQUICCallbackWaitsForTCPBaseline(t *testing.T) {
	center, edge, infra := mixedInfrastructure(t)
	if err := edge.SetDirectory(peerauth.Directory{Protocol: peerauth.Feature, Infrastructure: infra}); err != nil {
		t.Fatal(err)
	}
	gate := &mainGate{auth: edge.auth, network: edge.mainHost.Network()}
	address := ma.StringCast("/ip4/127.0.0.1/udp/1234/quic-v1")
	if gate.allowsInfrastructureTransport(network.DirInbound, center.id, address) {
		t.Fatal("QUIC callback may win the first infrastructure connection")
	}
	if !gate.allowsInfrastructureTransport(network.DirOutbound, testPeerID(t), address) {
		t.Fatal("infrastructure policy blocked another node's direct QUIC path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := edge.prepareTCPInfrastructure(ctx, infra); err != nil {
		t.Fatal(err)
	}
	if !gate.allowsInfrastructureTransport(network.DirInbound, center.id, address) || gate.allowsInfrastructureTransport(network.DirOutbound, center.id, address) {
		t.Fatal("prepared TCP baseline did not preserve inbound-only QUIC callbacks")
	}
}

func TestQUICObservationFirstFrameBoundsAndValidation(t *testing.T) {
	for _, name := range []string{"first-frame", "oversized", "empty", "dns", "circuit", "zero-port", "truncated"} {
		t.Run(name, func(t *testing.T) {
			center, edge, infra, conn := preparedInfrastructure(t)
			before := edge.observed.AddrsFor(conn.LocalMultiaddr())
			center.mainHost.SetStreamHandler(identify.ID, func(stream network.Stream) {
				defer stream.Close()
				_ = stream.SetDeadline(time.Now().Add(time.Second))
				var raw []byte
				switch name {
				case "first-frame":
					raw = ma.StringCast("/ip4/127.0.0.1/udp/45678/quic-v1").Bytes()
				case "empty":
				case "dns":
					raw = ma.StringCast("/dns4/example.test/udp/45678/quic-v1").Bytes()
				case "circuit":
					raw = ma.StringCast("/ip4/127.0.0.1/udp/45678/quic-v1/p2p-circuit").Bytes()
				case "zero-port":
					raw = ma.StringCast("/ip4/127.0.0.1/udp/0/quic-v1").Bytes()
				case "oversized", "truncated":
					var prefix [10]byte
					length := uint64(9 << 10)
					if name == "truncated" {
						length = 128
					}
					n := binary.PutUvarint(prefix[:], length)
					_, _ = stream.Write(prefix[:n])
					return
				}
				writer := pbio.NewDelimitedWriter(stream)
				_ = writer.WriteMsg(&identifypb.Identify{ObservedAddr: raw})
				if name == "first-frame" {
					_ = writer.WriteMsg(&identifypb.Identify{SignedPeerRecord: bytes.Repeat([]byte{7}, 9<<10)})
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			address, err := readQUICObservation(ctx, conn, false)
			if name == "first-frame" {
				if err != nil || address == nil || address.String() != "/ip4/127.0.0.1/udp/45678/quic-v1" {
					t.Fatalf("bounded base frame did not supply its address: %v err=%v", address, err)
				}
				return
			}
			if err == nil || address != nil {
				t.Fatalf("invalid observation accepted: %v err=%v", address, err)
			}
			ctx2, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := edge.observeQUICInfrastructure(ctx2, infra, edge.observed.fence()); err == nil {
				t.Fatal("invalid observation was recorded")
			}
			after := edge.observed.AddrsFor(conn.LocalMultiaddr())
			if len(after) != len(before) || len(after) == 0 || !after[0].Equal(before[0]) {
				t.Fatal("failed observation erased a still-valid candidate")
			}
		})
	}
}

func TestRuntimeCloseJoinsWaitingQUICObservation(t *testing.T) {
	center, edge, infra, _ := preparedInfrastructure(t)
	entered := make(chan struct{}, 1)
	center.mainHost.SetStreamHandler(identify.ID, func(stream network.Stream) {
		defer stream.Close()
		if !addressHasQUIC(stream.Conn().RemoteMultiaddr()) {
			_ = pbio.NewDelimitedWriter(stream).WriteMsg(&identifypb.Identify{ObservedAddr: stream.Conn().RemoteMultiaddr().Bytes()})
			return
		}
		select {
		case entered <- struct{}{}:
		default:
		}
		_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, stream)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- edge.PrepareInfrastructure(ctx, infra) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("preparation did not reach the waiting QUIC Identify stream")
	}
	closed := make(chan error, 1)
	go func() { closed <- edge.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel and join the pending observation")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed runtime reported successful preparation")
		}
	case <-time.After(time.Second):
		t.Fatal("Close returned before the pending preparation stopped")
	}
	if err := edge.PrepareInfrastructure(context.Background(), infra); !errors.Is(err, errRuntimeClosed) {
		t.Fatalf("closed runtime prepared new infrastructure: %v", err)
	}
}

func TestPreparedInfrastructureRefreshUsesFreshObservation(t *testing.T) {
	center, edge, infra, observation := preparedInfrastructure(t)
	baseline := connectedTCP(edge.mainHost, center.id)
	edge.observed.mu.Lock()
	edge.observed.until = time.Now().Add(-time.Second)
	edge.observed.mu.Unlock()
	if err := edge.SetDirectory(peerauth.Directory{Protocol: peerauth.Feature, Infrastructure: infra}); err != nil {
		t.Fatal(err)
	}
	edge.SetAuthorizer(allowIDs(center.PeerID()))
	if len(edge.observed.Addrs(1)) != 0 {
		t.Fatal("refresh revived observations without a new Identify exchange")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := edge.PrepareInfrastructure(ctx, infra); err != nil {
		t.Fatal(err)
	}
	if connectedTCP(edge.mainHost, center.id) != baseline || observation.IsClosed() {
		t.Fatal("refresh replaced or closed the existing transport connections")
	}
	if len(edge.observed.AddrsFor(observation.LocalMultiaddr())) == 0 {
		t.Fatal("fresh Identify did not restore the QUIC candidate")
	}
}

func TestQUICOnlyInfrastructureFailsClosedAsRelay(t *testing.T) {
	center := newTestRuntime(t, Config{ListenAddresses: []string{"/ip4/127.0.0.1/udp/0/quic-v1"}})
	edge := newTestRuntime(t, Config{})
	center.SetAuthorizer(allowIDs(edge.PeerID()))
	edge.SetAuthorizer(allowIDs(center.PeerID()))
	infra := infraOf(center)
	if _, err := edge.ReserveRelay(context.Background(), infra); !errors.Is(err, ErrInfrastructureInvalid) {
		t.Fatalf("QUIC-only reservation silently used QUIC: %v", err)
	}
	if _, err := circuitAddrInfo(infra, testPeerID(t)); !errors.Is(err, ErrInfrastructureInvalid) {
		t.Fatalf("QUIC-only circuit address escaped TCP policy: %v", err)
	}
	if len(edge.mainHost.Network().ConnsToPeer(peer.ID(center.id))) != 0 {
		t.Fatal("invalid TCP relay configuration still connected to QUIC")
	}
}
