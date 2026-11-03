package peertransport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	relayproto "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
)

func TestReservationCallerCancelStopsWaitingStream(t *testing.T) {
	center := newTestRuntime(t, Config{})
	edge := newTestRuntime(t, Config{})
	center.SetAuthorizer(allowIDs(edge.PeerID()))
	edge.SetAuthorizer(allowIDs(center.PeerID()))
	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	center.mainHost.SetStreamHandler(relayproto.ProtoIDv2Hop, func(stream network.Stream) {
		defer stream.Reset()
		close(entered)
		<-release
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := edge.ReserveRelay(ctx, infraOf(center)); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reservation did not open a real control stream")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel outcome: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("library deadline overrode caller cancellation")
	}
}

func TestReservationCallerDeadlineClampsLibraryDeadline(t *testing.T) {
	center := newTestRuntime(t, Config{})
	edge := newTestRuntime(t, Config{})
	center.SetAuthorizer(allowIDs(edge.PeerID()))
	edge.SetAuthorizer(allowIDs(center.PeerID()))
	center.mainHost.SetStreamHandler(relayproto.ProtoIDv2Hop, func(stream network.Stream) {
		defer stream.Reset()
		buf := make([]byte, 4096)
		_, _ = stream.Read(buf)
		_, _ = stream.Read(buf)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := edge.ReserveRelay(ctx, infraOf(center))
	if err == nil {
		t.Fatal("nonresponding relay granted a reservation")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("reservation exceeded caller bound: %v", elapsed)
	}
}
