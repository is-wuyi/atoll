package peertransport

import (
	"context"
	"errors"
	"testing"
	"time"

	"atoll/pkg/peerauth"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2"
	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2/pb"
	"github.com/libp2p/go-msgio/pbio"
)

func nativeProbePair(t *testing.T) (*Runtime, *Runtime) {
	t.Helper()
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
	return center, edge
}

func nativeProbe(t *testing.T, edge *Runtime) (autonatv2.Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	service := edge.mainHost.(*runtimeHost).service
	for {
		result, err := service.GetReachability(ctx, []autonatv2.Request{{Addr: edge.mainHost.Addrs()[0], SendDialData: true}})
		if !errors.Is(err, autonatv2.ErrNoPeers) {
			return result, err
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestNativeAutoNATClientConfirmsRegisteredCallback(t *testing.T) {
	_, edge := nativeProbePair(t)
	result, err := nativeProbe(t, edge)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reachability != network.ReachabilityPublic || !result.Addr.Equal(edge.mainHost.Addrs()[0]) {
		t.Fatalf("native nonce/address verification did not confirm the callback: %+v", result)
	}
}

func TestNativeAutoNATClientRejectsWrongCallbackNonce(t *testing.T) {
	_, edge := nativeProbePair(t)
	entered := make(chan struct{}, 1)
	edge.mainHost.SetStreamHandler(autonatv2.DialBackProtocol, func(stream network.Stream) {
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		var received pb.DialBack
		if err := pbio.NewDelimitedReader(stream, 1024).ReadMsg(&received); err != nil {
			stream.Reset()
			return
		}
		entered <- struct{}{}
		// The server may report a successful dial, but the real client never
		// received its pending nonce. A transport success cannot override that.
		_, _ = stream.Write([]byte{1})
	})
	result, err := nativeProbe(t, edge)
	select {
	case <-entered:
	default:
		t.Fatal("the negative case never reached an actual callback stream")
	}
	if err == nil || result.Reachability == network.ReachabilityPublic {
		t.Fatalf("missing pending nonce was accepted: %+v %v", result, err)
	}
}
