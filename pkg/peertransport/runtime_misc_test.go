package peertransport

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
)

// TestRuntimePublicOnly rejects a dial to a non-public (loopback) endpoint when
// PublicOnly is set: the public-only gate must refuse a private/loopback peer.
func TestRuntimePublicOnly(t *testing.T) {
	a := newTestRuntime(t, Config{})
	d := newTestRuntime(t, Config{PublicOnly: true})
	a.SetAuthorizer(allowIDs(d.PeerID()))
	d.SetAuthorizer(allowIDs(a.PeerID()))
	a.Listener()

	ep := endpointOf(a) // loopback addresses are not public
	res := d.Dial(context.Background(), ep, peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res.Err == nil {
		t.Fatalf("public-only dial to a loopback peer succeeded: path=%s", res.Path)
	}
}

// TestRuntimeUnauthorizedPeerRejected verifies a peer the authorizer rejects
// cannot open a ProtoID stream: the dial fails and the listener never serves it.
func TestRuntimeUnauthorizedPeerRejected(t *testing.T) {
	a := newTestRuntime(t, Config{})
	u := newTestRuntime(t, Config{})
	a.SetAuthorizer(func(context.Context, string) bool { return false }) // rejects everyone
	u.SetAuthorizer(allowIDs(a.PeerID()))

	la, err := a.Listener()
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	got := make(chan net.Conn, 1)
	go func() {
		c, err := la.Accept()
		if err != nil {
			got <- nil
			return
		}
		got <- c
	}()

	res := u.Dial(context.Background(), endpointOf(a), peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res.Err == nil {
		t.Fatal("unauthorized dial succeeded")
	}
	select {
	case c := <-got:
		if c != nil {
			c.Close()
			t.Fatal("listener served an unauthorized peer")
		}
	case <-time.After(200 * time.Millisecond):
		// No stream was accepted, which is the expected outcome.
	}
}

// TestRuntimeReconnectAfterNegativeCache covers the "first client registers
// after being cached as unknown" case: a peer rejected once becomes authorized
// and is admitted on a new connection once the negative cache window passes,
// without a long sleep masking the mechanism.
func TestRuntimeReconnectAfterNegativeCache(t *testing.T) {
	old := negCacheTTL
	negCacheTTL = 30 * time.Millisecond
	// Register the restore before the runtimes are created so it runs after
	// their Close (LIFO), never racing a live authorizer call.
	t.Cleanup(func() { negCacheTTL = old })

	a := newTestRuntime(t, Config{})
	u := newTestRuntime(t, Config{})

	var allowU atomic.Bool
	a.SetAuthorizer(func(_ context.Context, id string) bool {
		return allowU.Load() && id == u.PeerID()
	})
	u.SetAuthorizer(func(_ context.Context, id string) bool { return id == a.PeerID() })
	if _, err := a.Listener(); err != nil {
		t.Fatalf("listener: %v", err)
	}

	// First dial is rejected and cached.
	if res := u.Dial(context.Background(), endpointOf(a), peerauth.Infrastructure{}, peerhttp.PathDirect); res.Err == nil {
		t.Fatal("first dial should be rejected")
	}

	// The peer registers: the authorizer now admits it. Wait out the negative
	// cache window, then a fresh dial must succeed.
	allowU.Store(true)
	time.Sleep(40 * time.Millisecond)
	res := u.Dial(context.Background(), endpointOf(a), peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res.Err != nil {
		t.Fatalf("reconnect after registration failed: %v", res.Err)
	}
	res.Conn.Close()
}

// TestRuntimeDefaultDeny confirms a runtime with neither an authorizer nor a
// validated directory admits nobody: the default state is deny.
func TestRuntimeDefaultDeny(t *testing.T) {
	a := newTestRuntime(t, Config{})
	d := newTestRuntime(t, Config{}) // no authorizer, no SetDirectory
	a.SetAuthorizer(allowIDs(d.PeerID()))
	a.Listener()

	res := d.Dial(context.Background(), endpointOf(a), peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res.Err == nil {
		t.Fatal("default-deny runtime dialed an unauthorized peer")
	}
}

// TestRuntimeDialNotTrustStaleDirectory verifies a peer present in a valid but
// stale directory snapshot is refused when the online authorizer rejects it:
// the runtime must never rely on an expired allow-set for an authorization
// decision (the Master's relay/peer rights come from the live authorizer).
func TestRuntimeDialNotTrustStaleDirectory(t *testing.T) {
	a := newTestRuntime(t, Config{})
	d := newTestRuntime(t, Config{})

	infra, err := newEphemeralIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dir := peerauth.Directory{
		Protocol: peerauth.Feature,
		Infrastructure: peerauth.Infrastructure{
			PeerID:    infra.id.String(),
			PublicKey: infra.pub,
			Relay:     true,
		},
		Endpoints: []peerauth.Endpoint{{
			NodeID:          1,
			Addr:            "127.0.0.1:1",
			Role:            peerauth.RoleNode,
			PeerID:          a.PeerID(),
			PublicKey:       a.PublicKey(),
			BindingRevision: 1,
			Revision:        1,
			Addresses:       a.Addresses(),
			ValidUntil:      time.Now().Add(2 * time.Minute),
		}},
	}
	if err := d.SetDirectory(dir); err != nil {
		t.Fatalf("set directory: %v", err)
	}
	if !d.AllowedPeer(a.PeerID()) {
		t.Fatal("directory snapshot should admit the peer")
	}
	// The live authorizer revokes the peer; the stale allow-set must not win.
	d.SetAuthorizer(func(context.Context, string) bool { return false })

	res := d.Dial(context.Background(), endpointOf(a), peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res.Err == nil {
		t.Fatal("dial succeeded through a revoked stale-directory peer")
	}
}

// TestRuntimeConnContextTLSUnwrap verifies ConnContext extracts the verified
// source PeerID through a TLS wrapper (the shape http.Server.ServeTLS creates),
// never from an HTTP header.
func TestRuntimeConnContextTLSUnwrap(t *testing.T) {
	r := newTestRuntime(t, Config{})
	id := testPeerID(t)
	sc := &streamConn{
		peerID: id,
		local:  ma.StringCast("/ip4/127.0.0.1/tcp/1"),
		remote: ma.StringCast("/ip4/127.0.0.1/tcp/2"),
	}
	tc := tls.Server(sc, &tls.Config{InsecureSkipVerify: true})
	ctx := r.ConnContext(context.Background(), tc)
	if got := peerauth.SourcePeerID(ctx); got != id.String() {
		t.Fatalf("source peer = %q, want %q", got, id.String())
	}
}

// TestRelayLimitConfig checks the relay service budgets meet the stated
// requirements: per-direction data >= 64 MiB, finite reservation/circuit caps,
// and a legal 30 minute duration/TTL.
func TestRelayLimitConfig(t *testing.T) {
	if relayDataLimit < 64<<20 {
		t.Fatalf("relayDataLimit = %d, want >= 64 MiB", relayDataLimit)
	}
	if relayMaxReservations <= 0 || relayMaxCircuits <= 0 {
		t.Fatalf("relay caps must be positive: reservations=%d circuits=%d", relayMaxReservations, relayMaxCircuits)
	}
	if relayDuration <= 0 || relayReservationTTL <= 0 {
		t.Fatalf("relay duration/TTL must be positive")
	}
	if relayDuration > 30*time.Minute || relayReservationTTL > 30*time.Minute {
		t.Fatalf("relay duration/TTL exceeds 30 minutes: %v / %v", relayDuration, relayReservationTTL)
	}
	if listenerQueueSize <= 0 {
		t.Fatalf("listenerQueueSize must be positive")
	}
}
