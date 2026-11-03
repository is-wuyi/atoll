package peertransport

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2"
	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2/pb"
	"github.com/libp2p/go-msgio/pbio"
	ma "github.com/multiformats/go-multiaddr"
)

func realProbeRequest(t *testing.T, requester, server *Runtime, address ma.Multiaddr, nonce uint64) *pb.DialResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := requester.mainHost.Connect(ctx, peer.AddrInfo{ID: server.id, Addrs: server.mainHost.Addrs()}); err != nil {
		t.Fatal(err)
	}
	stream, err := requester.mainHost.NewStream(ctx, server.id, autonatv2.DialProtocol)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writer := pbio.NewDelimitedWriter(stream)
	request := &pb.Message{Msg: &pb.Message_DialRequest{DialRequest: &pb.DialRequest{Addrs: [][]byte{address.Bytes()}, Nonce: nonce}}}
	if err := writer.WriteMsg(request); err != nil {
		t.Fatal(err)
	}
	var response pb.Message
	if err := pbio.NewDelimitedReader(stream, 8192).ReadMsg(&response); err != nil {
		t.Fatal(err)
	}
	if response.GetDialDataRequest() != nil {
		amount := int(response.GetDialDataRequest().GetNumBytes())
		if amount > 100000 {
			t.Fatal("probe requested too much dial data")
		}
		for sent := 0; sent < amount; sent += 4000 {
			count := 4000
			if amount-sent < count {
				count = amount - sent
			}
			chunk := &pb.Message{Msg: &pb.Message_DialDataResponse{DialDataResponse: &pb.DialDataResponse{Data: make([]byte, count)}}}
			if err := writer.WriteMsg(chunk); err != nil {
				t.Fatal(err)
			}
		}
		if err := pbio.NewDelimitedReader(stream, 8192).ReadMsg(&response); err != nil {
			t.Fatal(err)
		}
	}
	result := response.GetDialResponse()
	if result == nil {
		t.Fatal("no AutoNAT response")
	}
	return result
}

func TestAuthorizedProbeCallbackUsesRegisteredIdentity(t *testing.T) {
	server := newTestRuntime(t, Config{ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"}})
	requester := newTestRuntime(t, Config{ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"}})
	server.SetAuthorizer(allowIDs(requester.PeerID()))
	requester.SetAuthorizer(allowIDs(server.PeerID()))
	h := server.mainHost.(*runtimeHost)
	if h.probe.ID() != server.id || h.probe.Peerstore() == server.mainHost.Peerstore() {
		t.Fatal("probe identity or peerstore isolation violated")
	}
	if len(h.probe.Network().ListenAddresses()) != 0 {
		t.Fatal("probe host must be dial-only")
	}
	received := make(chan string, 1)
	requester.mainHost.SetStreamHandler(autonatv2.DialBackProtocol, func(stream network.Stream) {
		defer stream.Close()
		stream.SetDeadline(time.Now().Add(5 * time.Second))
		var callback pb.DialBack
		if err := pbio.NewDelimitedReader(stream, 1024).ReadMsg(&callback); err != nil || callback.Nonce != 42 {
			stream.Reset()
			return
		}
		received <- stream.Conn().RemotePeer().String()
		_, _ = stream.Write([]byte{1})
	})
	response := realProbeRequest(t, requester, server, requester.mainHost.Addrs()[0], 42)
	if response.Status != pb.DialResponse_OK || response.DialStatus != pb.DialStatus_OK {
		t.Fatalf("registered callback failed: %v", response)
	}
	select {
	case id := <-received:
		if id != server.PeerID() {
			t.Fatal("callback used an unregistered identity")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("callback nonce did not arrive")
	}
	if len(h.probe.Network().Conns()) != 0 {
		t.Fatal("completed probe retained a peer connection")
	}
}

func TestProbeNeverClosesActiveDataConnection(t *testing.T) {
	server := newTestRuntime(t, Config{ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"}})
	requester := newTestRuntime(t, Config{ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"}})
	server.SetAuthorizer(allowIDs(requester.PeerID()))
	requester.SetAuthorizer(allowIDs(server.PeerID()))
	listener, err := requester.Listener()
	if err != nil {
		t.Fatal(err)
	}
	accepted := startAccept(t, listener)
	data := server.Dial(context.Background(), endpointOf(requester), peerauth.Infrastructure{}, peerhttp.PathDirect)
	if data.Err != nil {
		t.Fatal(data.Err)
	}
	defer data.Conn.Close()
	conn := <-accepted
	if conn == nil {
		t.Fatal("data stream missing")
	}
	defer conn.Close()
	requester.mainHost.SetStreamHandler(autonatv2.DialBackProtocol, func(stream network.Stream) {
		defer stream.Close()
		var callback pb.DialBack
		if err := pbio.NewDelimitedReader(stream, 1024).ReadMsg(&callback); err != nil {
			stream.Reset()
			return
		}
		_, _ = stream.Write([]byte{1})
	})
	response := realProbeRequest(t, requester, server, requester.mainHost.Addrs()[0], 99)
	if response.DialStatus != pb.DialStatus_OK {
		t.Fatalf("callback failed: %v", response)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	data.Conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := data.Conn.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "alive" {
		t.Fatalf("probe closed active stream: %q %v", buf, err)
	}
	if _, err := conn.Write([]byte("still")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(data.Conn, buf); err != nil || string(buf) != "still" {
		t.Fatalf("active response failed: %q %v", buf, err)
	}
}

func TestProbeGateRejectsUnknownPrivateAndInbound(t *testing.T) {
	g := newProtocolGate(context.Background())
	allowed := testPeerID(t)
	g.setAuthorizer(allowIDs(allowed.String()))
	gate := &probeGate{auth: g}
	public := ma.StringCast("/ip4/8.8.8.8/tcp/1234")
	if !gate.InterceptAddrDial(allowed, public) {
		t.Fatal("authorized public probe rejected")
	}
	for _, address := range []string{"/ip4/127.0.0.1/tcp/1234", "/ip4/192.168.0.1/tcp/1234", "/ip4/100.64.0.1/tcp/1234", "/dns4/localhost/tcp/1234", "/ip4/10.126.126.1/udp/1234/quic-v1"} {
		if gate.InterceptAddrDial(allowed, ma.StringCast(address)) {
			t.Fatalf("probe admitted nonpublic address %s", address)
		}
	}
	if gate.InterceptAddrDial(testPeerID(t), public) || gate.InterceptAccept(nil) {
		t.Fatal("probe admitted unknown peer or inbound connection")
	}
	g.setAuthorizer(func(context.Context, string) bool { return false })
	if gate.InterceptAddrDial(allowed, public) {
		t.Fatal("revoked probe admitted")
	}
}

func TestPrepareInfrastructureCancellationAndIdentity(t *testing.T) {
	center := newTestRuntime(t, Config{ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"}})
	edge := newTestRuntime(t, Config{ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"}})
	center.SetAuthorizer(allowIDs(edge.PeerID()))
	edge.SetAuthorizer(allowIDs(center.PeerID()))
	infra := infraOf(center)
	if err := edge.SetDirectory(peerauth.Directory{Protocol: peerauth.Feature, Infrastructure: infra}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := edge.PrepareInfrastructure(ctx, infra); err != nil {
		t.Fatal(err)
	}
	bad := infra
	bad.PublicKey = append([]byte(nil), bad.PublicKey...)
	bad.PublicKey[0] ^= 1
	if err := edge.PrepareInfrastructure(ctx, bad); !errors.Is(err, ErrInfrastructureInvalid) {
		t.Fatalf("wrong infrastructure accepted: %v", err)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := edge.PrepareInfrastructure(canceled, infra); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled prepare: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = edge.Close() }()
	}
	wg.Wait()
	if err := edge.PrepareInfrastructure(context.Background(), infra); !errors.Is(err, errRuntimeClosed) {
		t.Fatalf("closed prepare: %v", err)
	}
}
