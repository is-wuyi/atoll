package peertransport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
	"github.com/libp2p/go-libp2p/core/network"
	relaypb "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/pb"
	relayproto "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	"github.com/libp2p/go-msgio/pbio"
)

func TestRelayConnectHandshakeHonorsCallerBudget(t *testing.T) {
	for _, kind := range []string{"cancel", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			center := newTestRuntime(t, Config{})
			edge := newTestRuntime(t, Config{})
			target := newTestRuntime(t, Config{})
			center.SetAuthorizer(allowIDs(edge.PeerID()))
			edge.SetAuthorizer(allowIDs(center.PeerID(), target.PeerID()))
			entered := make(chan network.Conn, 1)
			handlerDone := make(chan struct{})
			center.mainHost.SetStreamHandler(relayproto.ProtoIDv2Hop, func(stream network.Stream) {
				defer close(handlerDone)
				defer stream.Close()
				_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
				var request relaypb.HopMessage
				if err := pbio.NewDelimitedReader(stream, 4096).ReadMsg(&request); err != nil || request.GetType() != relaypb.HopMessage_CONNECT {
					_ = stream.Reset()
					return
				}
				entered <- stream.Conn()
				_, _ = io.Copy(io.Discard, stream)
			})
			ctx, cancel := context.WithCancel(context.Background())
			if kind == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			}
			defer cancel()
			done := make(chan DialResult, 1)
			go func() { done <- edge.Dial(ctx, endpointOf(target), infraOf(center), peerhttp.PathRelay) }()
			var baseline network.Conn
			select {
			case baseline = <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("fixture never reached the actual CONNECT handshake")
			}
			if !isTCPConnection(baseline) {
				t.Fatal("CONNECT handshake did not use TCP")
			}
			started := time.Now()
			if kind == "cancel" {
				cancel()
			}
			select {
			case result := <-done:
				if result.Err == nil || result.Conn != nil {
					t.Fatal("silent relay handshake was reported as a successful connection")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("library relay handshake exceeded the caller's budget")
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Fatalf("handshake stopped too late: %v", elapsed)
			}
			select {
			case <-handlerDone:
			case <-time.After(time.Second):
				t.Fatal("cancellation left the actual control stream open")
			}
			if baseline.IsClosed() {
				t.Fatal("canceling the handshake closed the shared TCP peer connection")
			}
		})
	}
}

func TestRelayConnectionOutlivesCompletedDialContext(t *testing.T) {
	center := newTestRuntime(t, Config{})
	target := newTestRuntime(t, Config{})
	edge := newTestRuntime(t, Config{})
	center.SetAuthorizer(allowIDs(target.PeerID(), edge.PeerID()))
	target.SetAuthorizer(allowIDs(center.PeerID(), edge.PeerID()))
	edge.SetAuthorizer(allowIDs(center.PeerID(), target.PeerID()))
	if err := center.EnableRelay(); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ReserveRelay(context.Background(), infraOf(center)); err != nil {
		t.Fatal(err)
	}
	listener, err := target.Listener()
	if err != nil {
		t.Fatal(err)
	}
	accepted := startAccept(t, listener)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := edge.Dial(ctx, endpointOf(target), infraOf(center), peerhttp.PathRelay)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	defer result.Conn.Close()
	cancel()
	if result.Path != peerhttp.PathRelay || result.Fallback {
		t.Fatal("strict relay changed its path or fallback facts")
	}
	_ = result.Conn.SetDeadline(time.Now().Add(5 * time.Second))
	const payload = "payload-after-dial-cancel"
	if _, err := result.Conn.Write([]byte(payload)); err != nil {
		t.Fatalf("completed relay tunnel retained its dial cancellation: %v", err)
	}
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("target did not receive the surviving relay tunnel")
	}
	if conn == nil {
		t.Fatal("target listener closed without a stream")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != payload {
		t.Fatalf("relay tunnel payload mismatch after dial cancellation: %q err=%v", buffer, err)
	}
	if _, err := conn.Write(buffer); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(result.Conn, buffer); err != nil || string(buffer) != payload {
		t.Fatalf("relay tunnel response mismatch after dial cancellation: %q err=%v", buffer, err)
	}
}
