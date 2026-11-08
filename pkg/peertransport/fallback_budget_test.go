package peertransport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
)

func TestNormalDialReservesCallerBudgetForRelayAfterSilentDirect(t *testing.T) {
	center := newTestRuntime(t, Config{})
	target := newTestRuntime(t, Config{})
	dialer := newTestRuntime(t, Config{})
	center.SetAuthorizer(allowIDs(target.PeerID(), dialer.PeerID()))
	target.SetAuthorizer(allowIDs(center.PeerID(), dialer.PeerID()))
	dialer.SetAuthorizer(allowIDs(center.PeerID(), target.PeerID()))
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
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	silentDone := make(chan struct{})
	silentEntered := make(chan struct{}, 1)
	go func() {
		defer close(silentDone)
		conn, err := silent.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		silentEntered <- struct{}{}
		<-release
	}()
	t.Cleanup(func() { close(release); _ = silent.Close(); <-silentDone })
	ep := endpointOf(target)
	ep.Addresses = []string{"/ip4/127.0.0.1/tcp/" + portOf(silent.Addr().String())}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := dialer.Dial(ctx, ep, infraOf(center), peerhttp.PathUnknown)
	if result.Err != nil {
		t.Fatalf("silent direct candidate consumed the whole caller budget before relay fallback: %v", result.Err)
	}
	defer result.Conn.Close()
	select {
	case <-silentEntered:
	default:
		t.Fatal("fixture did not reach its silent direct connection")
	}
	if !result.Fallback || result.Path != peerhttp.PathRelay {
		t.Fatalf("actual fallback facts differ: fallback=%v path=%s", result.Fallback, result.Path)
	}
	_ = result.Conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := result.Conn.Write([]byte("relay")); err != nil {
		t.Fatal(err)
	}
	select {
	case conn := <-accepted:
		if conn == nil {
			t.Fatal("target listener did not accept the fallback stream")
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, len("relay"))
		if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "relay" {
			t.Fatalf("fallback payload differs: %q err=%v", buffer, err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback never reached the real target")
	}
}

func portOf(address string) string {
	_, port, _ := net.SplitHostPort(address)
	return port
}
