package peertransport

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
)

func newTestRuntime(t *testing.T, cfg Config) *Runtime {
	t.Helper()
	r, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func allowIDs(ids ...string) func(context.Context, string) bool {
	return func(_ context.Context, id string) bool {
		for _, x := range ids {
			if x == id {
				return true
			}
		}
		return false
	}
}

func testPeerID(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRuntimeDirectDial(t *testing.T) {
	a := newTestRuntime(t, Config{})
	b := newTestRuntime(t, Config{})
	a.SetAuthorizer(allowIDs(b.PeerID()))
	b.SetAuthorizer(allowIDs(a.PeerID()))

	la, err := a.Listener()
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	type acceptRes struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptRes, 1)
	go func() {
		c, err := la.Accept()
		accepted <- acceptRes{c, err}
	}()

	ep := peerauth.Endpoint{PeerID: a.PeerID(), PublicKey: a.PublicKey(), Addresses: a.Addresses()}
	res := b.Dial(context.Background(), ep, peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res.Err != nil {
		t.Fatalf("dial: %v", res.Err)
	}
	if res.Conn == nil {
		t.Fatal("dial returned no connection")
	}
	defer res.Conn.Close()
	if res.Path != peerhttp.PathDirect {
		t.Fatalf("path = %q, want direct", res.Path)
	}
	if res.Fallback {
		t.Fatal("direct dial must not be a fallback")
	}

	if _, err := res.Conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	ar := <-accepted
	if ar.err != nil {
		t.Fatalf("accept: %v", ar.err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(ar.conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want ping", buf)
	}
	if _, err := ar.conn.Write([]byte("pong")); err != nil {
		t.Fatalf("write back: %v", err)
	}
	if _, err := io.ReadFull(res.Conn, buf); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("got %q, want pong", buf)
	}

	if got := peerauth.SourcePeerID(a.ConnContext(context.Background(), ar.conn)); got != b.PeerID() {
		t.Fatalf("source peer = %q, want %q", got, b.PeerID())
	}
}

func TestRuntimeConnOutlivesCallerCtx(t *testing.T) {
	a := newTestRuntime(t, Config{})
	b := newTestRuntime(t, Config{})
	a.SetAuthorizer(allowIDs(b.PeerID()))
	b.SetAuthorizer(allowIDs(a.PeerID()))

	la, err := a.Listener()
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	type acceptRes struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptRes, 1)
	go func() {
		c, err := la.Accept()
		accepted <- acceptRes{c, err}
	}()

	ep := peerauth.Endpoint{PeerID: a.PeerID(), PublicKey: a.PublicKey(), Addresses: a.Addresses()}
	ctx, cancel := context.WithCancel(context.Background())
	res := b.Dial(ctx, ep, peerauth.Infrastructure{}, peerhttp.PathDirect)
	cancel() // after Dial returns; the delivered conn must survive
	if res.Err != nil {
		t.Fatalf("dial: %v", res.Err)
	}
	defer res.Conn.Close()

	// The stream was fully negotiated inside Dial; after the caller cancelled
	// its context it still carries bytes end to end.
	if err := res.Conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := res.Conn.Write([]byte("after-cancel")); err != nil {
		t.Fatalf("write after cancel: %v", err)
	}
	ar := <-accepted
	if ar.err != nil {
		t.Fatalf("accept: %v", ar.err)
	}
	defer ar.conn.Close()
	if err := ar.conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, len("after-cancel"))
	if _, err := io.ReadFull(ar.conn, buf); err != nil {
		t.Fatalf("read after cancel: %v", err)
	}
	if string(buf) != "after-cancel" {
		t.Fatalf("got %q", buf)
	}
}

func TestRuntimeCloseIdempotent(t *testing.T) {
	r := newTestRuntime(t, Config{})
	infra, err := newEphemeralIdentity()
	if err != nil {
		t.Fatal(err)
	}
	u := newTestRuntime(t, Config{})
	dir := peerauth.Directory{
		Protocol: peerauth.Feature,
		Infrastructure: peerauth.Infrastructure{
			PeerID:    infra.id.String(),
			PublicKey: infra.pub,
		},
		Endpoints: []peerauth.Endpoint{{
			Role:       peerauth.RoleClient,
			PeerID:     u.PeerID(),
			PublicKey:  u.PublicKey(),
			Revision:   1,
			ValidUntil: time.Now().Add(2 * time.Minute),
		}},
	}
	if err := r.SetDirectory(dir); err != nil {
		t.Fatalf("set directory: %v", err)
	}
	member := u.PeerID()
	if !r.AllowedPeer(member) {
		t.Fatal("directory member should be admitted before close")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	// Listener and relay host creation after close must fail, not recreate.
	if _, err := r.Listener(); err == nil {
		t.Fatal("Listener after Close should fail")
	}
	if err := r.EnableRelay(); err == nil {
		t.Fatal("EnableRelay after Close should fail")
	}
	if _, err := r.relayHostFor(testPeerID(t)); err == nil {
		t.Fatal("relayHostFor after Close should fail")
	}
	// Authorization is closed too: the allow-set must not outlive the runtime.
	if r.AllowedPeer(member) {
		t.Fatal("AllowedPeer after Close must deny")
	}
}

func TestRuntimeNewCancelledCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(ctx, Config{}); err == nil {
		t.Fatal("New with a cancelled context must fail")
	}
}

// TestRuntimeDialCancelledCtx verifies a cancelled dial context fails fast and
// never reaches the connection gate or a network dial.
func TestRuntimeDialCancelledCtx(t *testing.T) {
	a := newTestRuntime(t, Config{})
	d := newTestRuntime(t, Config{})
	a.SetAuthorizer(allowIDs(d.PeerID()))
	d.SetAuthorizer(allowIDs(a.PeerID()))
	a.Listener()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := d.Dial(ctx, endpointOf(a), peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res.Err == nil {
		t.Fatal("dial with a cancelled context succeeded")
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("dial error = %v, want context.Canceled", res.Err)
	}
}

// TestOpenVerifiedStreamNoDial verifies the stream open never dials: even when
// the peer's addresses are known and reachable, a stream open with no existing
// connection fails fast instead of dialing, and no connection is created.
func TestOpenVerifiedStreamNoDial(t *testing.T) {
	a := newTestRuntime(t, Config{})
	b := newTestRuntime(t, Config{})
	a.SetAuthorizer(allowIDs(b.PeerID()))
	b.SetAuthorizer(allowIDs(a.PeerID()))
	target, err := peer.Decode(b.PeerID())
	if err != nil {
		t.Fatal(err)
	}
	// a knows b's addresses: a dialing open would connect and succeed.
	for _, s := range b.Addresses() {
		m, merr := ma.NewMultiaddr(s)
		if merr != nil {
			t.Fatal(merr)
		}
		a.mainHost.Peerstore().AddAddr(target, m, time.Hour)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = a.openVerifiedStream(ctx, a.mainHost, target, b.PublicKey(), connDirectOnly)
	if err == nil {
		t.Fatal("openVerifiedStream dialed the peer instead of using an existing connection")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("openVerifiedStream hung waiting for a dial instead of failing fast")
	}
	if n := len(a.mainHost.Network().Conns()); n != 0 {
		t.Fatalf("openVerifiedStream created %d connections", n)
	}
}

// TestRuntimeConcurrentClose races Close against Listener, EnableRelay and
// relayHostFor: creation happens under the lifecycle lock, so no half-created
// resource is torn down and no goroutine is leaked. Run under -race.
func TestRuntimeConcurrentClose(t *testing.T) {
	r := newTestRuntime(t, Config{})
	relays := make([]peer.ID, 8)
	for i := range relays {
		relays[i] = testPeerID(t)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(relay peer.ID) {
			defer wg.Done()
			_, _ = r.Listener()
			_ = r.EnableRelay()
			_, _ = r.relayHostFor(relay)
		}(relays[i])
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = r.Close()
	}()
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
}

// TestRuntimeListenerCloseRejectsAndDrains verifies that after Close an Accept
// returns net.ErrClosed rather than a connection queued before the close, and
// that the queue is drained (no stream is served or leaked after close).
func TestRuntimeListenerCloseRejectsAndDrains(t *testing.T) {
	a := newTestRuntime(t, Config{})
	b := newTestRuntime(t, Config{})
	a.SetAuthorizer(allowIDs(b.PeerID()))
	b.SetAuthorizer(allowIDs(a.PeerID()))
	la, err := a.Listener()
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	pl := la.(*peerListener)

	// Open a real stream and drive it so the handler queues the connection on
	// the listener (the stream handler is dispatched on first use).
	res := b.Dial(context.Background(), endpointOf(a), peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res.Err != nil {
		t.Fatalf("dial: %v", res.Err)
	}
	defer res.Conn.Close()
	if _, err := res.Conn.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(pl.ch) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("stream was never queued on the listener")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := la.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Accept after close must reject, never hand out the queued connection.
	if _, err := la.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}
	// The queue must be drained.
	select {
	case c := <-pl.ch:
		t.Fatalf("listener queue still holds a connection after Close: %v", c)
	default:
	}
}

func TestRuntimeAddressesCanonicalNoCircuit(t *testing.T) {
	r := newTestRuntime(t, Config{})
	addrs := r.Addresses()
	if len(addrs) == 0 {
		t.Fatal("no addresses")
	}
	seen := map[string]bool{}
	for i, a := range addrs {
		if strings.Contains(a, "/p2p-circuit") {
			t.Fatalf("address %s contains a circuit component", a)
		}
		if a != strings.TrimSpace(a) {
			t.Fatalf("address %q is not canonical", a)
		}
		if seen[a] {
			t.Fatalf("duplicate address %s", a)
		}
		seen[a] = true
		if i > 0 && addrs[i-1] > a {
			t.Fatalf("addresses not sorted: %v", addrs)
		}
	}
}

func TestRuntimeStringNoSecret(t *testing.T) {
	r := newTestRuntime(t, Config{})
	s := r.String()
	if !strings.HasPrefix(s, "peertransport.Runtime(") {
		t.Fatalf("String() = %q", s)
	}
	if !strings.Contains(s, r.PeerID()) {
		t.Fatalf("String() = %q does not contain the peer id", s)
	}
	// The private key must never appear in the formatted representation.
	for _, line := range []string{s, r.GoString(), "identity:" + r.ident.String()} {
		if strings.Contains(strings.ToLower(line), "priv") {
			t.Fatalf("formatted value leaks the private key: %q", line)
		}
	}
}

func TestRuntimeRelayHostCacheBound(t *testing.T) {
	r := newTestRuntime(t, Config{})
	// Fill the cache; once it is full a new relay host must be refused rather
	// than evicting one that may be serving active streams, so the cache stays
	// bounded and never grows with the directory.
	for i := 0; i < maxRelayHosts; i++ {
		id := testPeerID(t)
		if _, err := r.relayHostFor(id); err != nil {
			t.Fatalf("relayHostFor %d: %v", i, err)
		}
	}
	if _, err := r.relayHostFor(testPeerID(t)); err == nil {
		t.Fatal("relay host cache should refuse a new host when full")
	}
	r.lifeMu.Lock()
	n := len(r.relayHosts)
	order := len(r.relayOrder)
	r.lifeMu.Unlock()
	if n != maxRelayHosts {
		t.Fatalf("relay host cache = %d, want %d", n, maxRelayHosts)
	}
	if order != maxRelayHosts {
		t.Fatalf("relay order = %d, want %d", order, maxRelayHosts)
	}
}

// TestRuntimeRelayHostSingleflight creates the same relay concurrently and
// requires exactly one host to be retained (no duplicate creation, no eviction
// of a live host).
func TestRuntimeRelayHostSingleflight(t *testing.T) {
	r := newTestRuntime(t, Config{})
	relay := testPeerID(t)
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := r.relayHostFor(relay); err != nil {
				errs[i] = err
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("creator %d: %v", i, err)
		}
	}
	r.lifeMu.Lock()
	nHosts := len(r.relayHosts)
	r.lifeMu.Unlock()
	if nHosts != 1 {
		t.Fatalf("relay host cache = %d, want 1", nHosts)
	}
}

// TestRuntimeMaxConnections verifies the hard connection budget: a dial to a
// second peer is rejected while the first connection is alive, the active
// first stream keeps exchanging bytes (never reclaimed), and the budget frees
// up once the underlying connection is closed.
func TestRuntimeMaxConnections(t *testing.T) {
	d := newTestRuntime(t, Config{MaxConnections: 1})
	a := newTestRuntime(t, Config{})
	b := newTestRuntime(t, Config{})
	a.SetAuthorizer(allowIDs(d.PeerID()))
	b.SetAuthorizer(allowIDs(d.PeerID()))
	d.SetAuthorizer(allowIDs(a.PeerID(), b.PeerID()))
	la, err := a.Listener()
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	b.Listener()
	accept := startAccept(t, la)

	res := d.Dial(context.Background(), peerauth.Endpoint{PeerID: a.PeerID(), PublicKey: a.PublicKey(), Addresses: a.Addresses()}, peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res.Err != nil {
		t.Fatalf("first dial: %v", res.Err)
	}
	defer res.Conn.Close()

	// The active connection echoes.
	if err := res.Conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := res.Conn.Write([]byte("one")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var conn net.Conn
	select {
	case conn = <-accept:
	case <-time.After(5 * time.Second):
		t.Fatal("target did not accept the stream in time")
	}
	if conn == nil {
		t.Fatal("target did not accept the stream")
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "one" {
		t.Fatalf("got %q", buf)
	}

	// Budget full: the second dial is rejected, not trimmed into.
	res2 := d.Dial(context.Background(), peerauth.Endpoint{PeerID: b.PeerID(), PublicKey: b.PublicKey(), Addresses: b.Addresses()}, peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res2.Err == nil {
		res2.Conn.Close()
		t.Fatal("dial to a second peer succeeded with MaxConnections=1")
	}

	// The active echo is untouched by the rejected dial.
	if _, err := res.Conn.Write([]byte("two")); err != nil {
		t.Fatalf("write after refused dial: %v", err)
	}
	if _, err := conn.Write([]byte("two")); err != nil {
		t.Fatalf("echo after refused dial: %v", err)
	}
	if _, err := io.ReadFull(res.Conn, buf); err != nil {
		t.Fatalf("read after refused dial: %v", err)
	}
	if string(buf) != "two" {
		t.Fatalf("got %q", buf)
	}

	// Close the underlying connection; the budget frees up for the next peer.
	for _, c := range d.mainHost.Network().Conns() {
		_ = c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(d.mainHost.Network().Conns()) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("closed connection was never reaped")
		}
		time.Sleep(20 * time.Millisecond)
	}
	res3 := d.Dial(context.Background(), peerauth.Endpoint{PeerID: b.PeerID(), PublicKey: b.PublicKey(), Addresses: b.Addresses()}, peerauth.Infrastructure{}, peerhttp.PathDirect)
	if res3.Err != nil {
		t.Fatalf("dial after freeing the budget: %v", res3.Err)
	}
	defer res3.Conn.Close()
}
