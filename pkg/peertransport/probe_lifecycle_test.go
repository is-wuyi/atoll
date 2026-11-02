package peertransport

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"atoll/pkg/peerauth"
)

func TestRuntimeFailedListenClosesProbeAndObservations(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr)
	cfg := Config{ListenAddresses: []string{"/ip4/127.0.0.1/tcp/" + strconv.Itoa(address.Port)}}
	done := make(chan error, 1)
	go func() { _, err := New(context.Background(), cfg); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("occupied listener must fail runtime construction")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("failed runtime construction did not drain probe lifecycle")
	}
}

func TestPrepareInfrastructureNoAuthorizeFromWrongBinding(t *testing.T) {
	center := newTestRuntime(t, Config{})
	edge := newTestRuntime(t, Config{})
	edge.SetAuthorizer(allowIDs(center.PeerID()))
	infra := infraOf(center)
	if err := edge.SetDirectory(peerauth.Directory{Protocol: peerauth.Feature, Infrastructure: infra}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { done <- edge.PrepareInfrastructure(ctx, infra) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unauthorized center must not prepare")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("prepare exceeded caller deadline")
	}
}
