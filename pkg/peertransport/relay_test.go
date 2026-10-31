package peertransport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
)

func infraOf(r *Runtime) peerauth.Infrastructure {
	return peerauth.Infrastructure{
		PeerID:    r.PeerID(),
		PublicKey: r.PublicKey(),
		Addresses: r.Addresses(),
		Relay:     true,
	}
}

func endpointOf(r *Runtime) peerauth.Endpoint {
	return peerauth.Endpoint{
		PeerID:    r.PeerID(),
		PublicKey: r.PublicKey(),
		Addresses: r.Addresses(),
	}
}

func startAccept(t *testing.T, l net.Listener) chan net.Conn {
	t.Helper()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			ch <- nil
			return
		}
		ch <- c
	}()
	return ch
}

// TestRuntimeRelayReserveAndDial exercises a real CircuitRelay v2 topology:
// target T reserves on relay R, dialer D reaches T through R over a circuit,
// exchanges bytes, and reports the circuit path.
func TestRuntimeRelayReserveAndDial(t *testing.T) {
	r := newTestRuntime(t, Config{})
	target := newTestRuntime(t, Config{})
	dialer := newTestRuntime(t, Config{})

	r.SetAuthorizer(allowIDs(target.PeerID(), dialer.PeerID()))
	target.SetAuthorizer(allowIDs(r.PeerID(), dialer.PeerID()))
	dialer.SetAuthorizer(allowIDs(r.PeerID(), target.PeerID()))

	if err := r.EnableRelay(); err != nil {
		t.Fatalf("enable relay: %v", err)
	}
	la, err := target.Listener()
	if err != nil {
		t.Fatalf("target listener: %v", err)
	}
	accept := startAccept(t, la)

	infraR := infraOf(r)
	exp, err := target.ReserveRelay(context.Background(), infraR)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if exp.IsZero() || !exp.After(time.Now()) {
		t.Fatalf("reservation expiry %v is not in the future", exp)
	}

	res := dialer.Dial(context.Background(), endpointOf(target), infraR, peerhttp.PathRelay)
	if res.Err != nil {
		t.Fatalf("relay dial: %v", res.Err)
	}
	defer res.Conn.Close()
	if res.Path != peerhttp.PathRelay {
		t.Fatalf("path = %q, want circuit", res.Path)
	}

	if _, err := res.Conn.Write([]byte("over-relay")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn := <-accept
	if conn == nil {
		t.Fatal("target did not accept the circuit stream")
	}
	buf := make([]byte, len("over-relay"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "over-relay" {
		t.Fatalf("got %q", buf)
	}
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatalf("write back: %v", err)
	}
	if _, err := io.ReadFull(res.Conn, buf[:2]); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf[:2]) != "ok" {
		t.Fatalf("got %q", buf[:2])
	}
}

// TestRuntimeRelayReserveAuthoritative proves the relay ACL consults the online
// authorizer rather than a stale directory allow-set: a peer the authorizer
// admits can reserve even though it was never in the directory snapshot.
func TestRuntimeRelayReserveAuthoritative(t *testing.T) {
	r := newTestRuntime(t, Config{})
	u := newTestRuntime(t, Config{})

	r.SetAuthorizer(allowIDs(u.PeerID())) // never calls SetDirectory
	u.SetAuthorizer(allowIDs(r.PeerID()))
	if err := r.EnableRelay(); err != nil {
		t.Fatalf("enable relay: %v", err)
	}
	exp, err := u.ReserveRelay(context.Background(), infraOf(r))
	if err != nil {
		t.Fatalf("authorized peer could not reserve: %v", err)
	}
	if exp.IsZero() {
		t.Fatal("reservation expiry is zero")
	}
}

// TestRuntimeReservationRefresh issues two reservations against the same relay
// and requires both to succeed (the second refreshes the existing one).
func TestRuntimeReservationRefresh(t *testing.T) {
	r := newTestRuntime(t, Config{})
	u := newTestRuntime(t, Config{})
	r.SetAuthorizer(allowIDs(u.PeerID()))
	u.SetAuthorizer(allowIDs(r.PeerID()))
	if err := r.EnableRelay(); err != nil {
		t.Fatalf("enable relay: %v", err)
	}
	infraR := infraOf(r)
	first, err := u.ReserveRelay(context.Background(), infraR)
	if err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	second, err := u.ReserveRelay(context.Background(), infraR)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second.Before(first) {
		t.Fatalf("refresh expiry %v before first %v", second, first)
	}
}

// TestRuntimeNormalFallbackRelay verifies the normal policy reports a relay
// attempt when the direct dial fails, without masking the failure.
func TestRuntimeNormalFallbackRelay(t *testing.T) {
	r := newTestRuntime(t, Config{})
	target := newTestRuntime(t, Config{})
	dialer := newTestRuntime(t, Config{})
	r.SetAuthorizer(allowIDs(target.PeerID(), dialer.PeerID()))
	target.SetAuthorizer(allowIDs(r.PeerID(), dialer.PeerID()))
	dialer.SetAuthorizer(allowIDs(r.PeerID(), target.PeerID()))
	if err := r.EnableRelay(); err != nil {
		t.Fatalf("enable relay: %v", err)
	}
	target.Listener()

	if _, err := target.ReserveRelay(context.Background(), infraOf(r)); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	la, err := target.Listener()
	if err != nil {
		t.Fatalf("target listener: %v", err)
	}
	accept := startAccept(t, la)

	// A direct endpoint that cannot be reached forces the relay fallback.
	ep := endpointOf(target)
	ep.Addresses = []string{"/ip4/127.0.0.1/tcp/1"}
	res := dialer.Dial(context.Background(), ep, infraOf(r), peerhttp.PathUnknown)
	if res.Err != nil {
		t.Fatalf("dial: %v", res.Err)
	}
	defer res.Conn.Close()
	if !res.Fallback {
		t.Fatal("normal policy did not mark the relay attempt as a fallback")
	}
	if res.Path != peerhttp.PathRelay {
		t.Fatalf("path = %q, want circuit fallback", res.Path)
	}

	// The fallback stream carries real bytes end to end.
	const msg = "fallback-bytes"
	if err := res.Conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := res.Conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	var conn net.Conn
	select {
	case conn = <-accept:
	case <-time.After(10 * time.Second):
		t.Fatal("target did not accept the fallback stream in time")
	}
	if conn == nil {
		t.Fatal("target did not accept the fallback stream")
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q, want %q", buf, msg)
	}
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	if _, err := io.ReadFull(res.Conn, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo got %q", buf)
	}
}

// TestRuntimeNormalDirectNoFallback verifies the normal policy uses a working
// direct connection even when a relay is available: it must not produce a false
// relay fallback. The direct connect succeeds, so the stream must open on the
// still-live direct context and be reported as PathDirect with Fallback=false.
func TestRuntimeNormalDirectNoFallback(t *testing.T) {
	r := newTestRuntime(t, Config{})
	target := newTestRuntime(t, Config{})
	dialer := newTestRuntime(t, Config{})
	r.SetAuthorizer(allowIDs(target.PeerID(), dialer.PeerID()))
	target.SetAuthorizer(allowIDs(r.PeerID(), dialer.PeerID()))
	dialer.SetAuthorizer(allowIDs(r.PeerID(), target.PeerID()))
	if err := r.EnableRelay(); err != nil {
		t.Fatalf("enable relay: %v", err)
	}
	la, err := target.Listener()
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	accept := startAccept(t, la)
	if _, err := target.ReserveRelay(context.Background(), infraOf(r)); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// The target is directly reachable AND relay-capable; the direct path must
	// win without an attempt at the relay.
	res := dialer.Dial(context.Background(), endpointOf(target), infraOf(r), peerhttp.PathUnknown)
	if res.Err != nil {
		t.Fatalf("normal direct dial: %v", res.Err)
	}
	defer res.Conn.Close()
	if res.Path != peerhttp.PathDirect {
		t.Fatalf("path = %q, want direct (no fake relay fallback)", res.Path)
	}
	if res.Fallback {
		t.Fatal("a successful direct dial must not be marked as a fallback")
	}

	if _, err := res.Conn.Write([]byte("direct-ok")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn := <-accept
	if conn == nil {
		t.Fatal("target did not accept the direct stream")
	}
	defer conn.Close()
	buf := make([]byte, len("direct-ok"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "direct-ok" {
		t.Fatalf("got %q", buf)
	}
}

// TestRuntimeInFlightDirectNotClosed dials the same target directly and then
// over a circuit, and requires the in-flight direct stream to remain usable:
// the isolated relay dial host must never close the main host's direct
// connection.
func TestRuntimeInFlightDirectNotClosed(t *testing.T) {
	r := newTestRuntime(t, Config{})
	target := newTestRuntime(t, Config{})
	dialer := newTestRuntime(t, Config{})
	r.SetAuthorizer(allowIDs(target.PeerID(), dialer.PeerID()))
	target.SetAuthorizer(allowIDs(r.PeerID(), dialer.PeerID()))
	dialer.SetAuthorizer(allowIDs(r.PeerID(), target.PeerID()))
	if err := r.EnableRelay(); err != nil {
		t.Fatalf("enable relay: %v", err)
	}
	la, err := target.Listener()
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	accept := startAccept(t, la)
	accept2 := startAccept(t, la)
	if _, err := target.ReserveRelay(context.Background(), infraOf(r)); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	direct := dialer.Dial(context.Background(), endpointOf(target), peerauth.Infrastructure{}, peerhttp.PathDirect)
	if direct.Err != nil {
		t.Fatalf("direct dial: %v", direct.Err)
	}
	defer direct.Conn.Close()
	if direct.Path != peerhttp.PathDirect {
		t.Fatalf("direct path = %q, want direct", direct.Path)
	}

	// Now dial the same target over the relay; the direct connection above must
	// survive this.
	circ := dialer.Dial(context.Background(), endpointOf(target), infraOf(r), peerhttp.PathRelay)
	if circ.Err != nil {
		t.Fatalf("circuit dial: %v", circ.Err)
	}
	defer circ.Conn.Close()
	if circ.Path != peerhttp.PathRelay {
		t.Fatalf("circuit path = %q, want relay", circ.Path)
	}
	if circ.Fallback {
		t.Fatal("a required relay dial must not be a fallback")
	}

	// Both paths to the same peer are alive at the same time: each stream
	// exchanges its own marker end to end and neither disturbs the other.
	const (
		directMsg  = "direct-payload-" // equal length
		circuitMsg = "circuit-payload"
	)
	for _, d := range []DialResult{direct, circ} {
		if err := d.Conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
	}
	if _, err := direct.Conn.Write([]byte(directMsg)); err != nil {
		t.Fatalf("direct stream was closed by the circuit dial: %v", err)
	}
	if _, err := circ.Conn.Write([]byte(circuitMsg)); err != nil {
		t.Fatalf("circuit write: %v", err)
	}
	conns := make([]net.Conn, 0, 2)
	for _, ch := range []chan net.Conn{accept, accept2} {
		var conn net.Conn
		select {
		case conn = <-ch:
		case <-time.After(10 * time.Second):
			t.Fatal("target did not accept a stream in time")
		}
		if conn == nil {
			t.Fatal("no accepted stream")
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		conns = append(conns, conn)
	}
	buf := make([]byte, len(directMsg))
	for _, conn := range conns {
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if _, err := conn.Write(buf); err != nil {
			t.Fatalf("echo write: %v", err)
		}
	}
	echo := make([]byte, len(directMsg))
	if _, err := io.ReadFull(direct.Conn, echo); err != nil {
		t.Fatalf("direct echo read: %v", err)
	}
	if string(echo) != directMsg {
		t.Fatalf("direct stream got %q, want %q", echo, directMsg)
	}
	if _, err := io.ReadFull(circ.Conn, echo); err != nil {
		t.Fatalf("circuit echo read: %v", err)
	}
	if string(echo) != circuitMsg {
		t.Fatalf("circuit stream got %q, want %q", echo, circuitMsg)
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// TestRuntimeRelayTwoConcurrentStreams exercises the strict relay path with
// two concurrent streams over the same circuit: both must be reported as
// relay, both exchange bytes end to end, and neither disturbs the other.
func TestRuntimeRelayTwoConcurrentStreams(t *testing.T) {
	r := newTestRuntime(t, Config{})
	target := newTestRuntime(t, Config{})
	dialer := newTestRuntime(t, Config{})
	r.SetAuthorizer(allowIDs(target.PeerID(), dialer.PeerID()))
	target.SetAuthorizer(allowIDs(r.PeerID(), dialer.PeerID()))
	dialer.SetAuthorizer(allowIDs(r.PeerID(), target.PeerID()))
	if err := r.EnableRelay(); err != nil {
		t.Fatalf("enable relay: %v", err)
	}
	la, err := target.Listener()
	if err != nil {
		t.Fatalf("target listener: %v", err)
	}
	accept1 := startAccept(t, la)
	accept2 := startAccept(t, la)
	if _, err := target.ReserveRelay(context.Background(), infraOf(r)); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	results := make([]DialResult, 2)
	for i := range results {
		res := dialer.Dial(context.Background(), endpointOf(target), infraOf(r), peerhttp.PathRelay)
		if res.Err != nil {
			t.Fatalf("relay dial %d: %v", i, res.Err)
		}
		if res.Path != peerhttp.PathRelay {
			t.Fatalf("relay dial %d path = %q, want circuit", i, res.Path)
		}
		if res.Fallback {
			t.Fatalf("relay dial %d must not be a fallback", i)
		}
		results[i] = res
		defer res.Conn.Close()
	}

	// Equal-length markers: each stream writes its own and must read back
	// exactly that marker, whichever accept goroutine picked it up.
	msgs := []string{"stream-one-aaaa", "stream-two-bbbb"}
	for i, res := range results {
		if err := res.Conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("stream %d deadline: %v", i, err)
		}
		if _, err := res.Conn.Write([]byte(msgs[i])); err != nil {
			t.Fatalf("stream %d write: %v", i, err)
		}
	}
	// Accept order is not deterministic: each accepted conn echoes whatever it
	// receives, so every stream verifies its own bytes by echo.
	conns := make([]net.Conn, 0, 2)
	for _, ch := range []chan net.Conn{accept1, accept2} {
		var conn net.Conn
		select {
		case conn = <-ch:
		case <-time.After(10 * time.Second):
			t.Fatal("target did not accept a stream in time")
		}
		if conn == nil {
			t.Fatal("target did not accept a stream")
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		conns = append(conns, conn)
	}
	buf := make([]byte, len(msgs[0]))
	for _, conn := range conns {
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if _, err := conn.Write(buf); err != nil {
			t.Fatalf("echo write: %v", err)
		}
	}
	for i, res := range results {
		if _, err := io.ReadFull(res.Conn, buf); err != nil {
			t.Fatalf("stream %d echo read: %v", i, err)
		}
		if string(buf) != msgs[i] {
			t.Fatalf("stream %d echo got %q, want %q", i, buf, msgs[i])
		}
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// TestRuntimeNormalFallbackAttemptMarkedOnFailure verifies a relay attempt
// that was really made but failed is still reported as a fallback: Fallback
// true, Conn nil, Path unknown, Err carrying both reasons.
func TestRuntimeNormalFallbackAttemptMarkedOnFailure(t *testing.T) {
	r := newTestRuntime(t, Config{})
	target := newTestRuntime(t, Config{})
	dialer := newTestRuntime(t, Config{})
	r.SetAuthorizer(allowIDs(target.PeerID(), dialer.PeerID()))
	target.SetAuthorizer(allowIDs(r.PeerID(), dialer.PeerID()))
	dialer.SetAuthorizer(allowIDs(r.PeerID(), target.PeerID()))
	target.Listener()

	// Direct endpoint and relay address both dead: the normal policy attempts
	// the relay fallback and must report the attempt even though it failed.
	infra := infraOf(r)
	infra.Addresses = []string{"/ip4/127.0.0.1/tcp/1"}
	ep := endpointOf(target)
	ep.Addresses = []string{"/ip4/127.0.0.1/tcp/1"}
	res := dialer.Dial(context.Background(), ep, infra, peerhttp.PathUnknown)
	if res.Err == nil {
		res.Conn.Close()
		t.Fatal("dial to dead endpoints must fail")
	}
	if !res.Fallback {
		t.Fatal("a failed relay attempt must still be reported as a fallback")
	}
	if res.Conn != nil {
		t.Fatal("a failed dial must not carry a connection")
	}
	if res.Path != peerhttp.PathUnknown {
		t.Fatalf("path = %q, want unknown on failure", res.Path)
	}
	if res.Identity != target.PeerID() {
		t.Fatalf("identity = %q, want %q", res.Identity, target.PeerID())
	}
}
