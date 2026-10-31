package peertransport

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ma "github.com/multiformats/go-multiaddr"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
)

// blockedStream is a negotiableStream whose reads never complete until reset,
// standing in for a peer that accepts the stream but never answers the
// multistream handshake.
type blockedStream struct {
	unblocked chan struct{}
	resetOnce sync.Once
}

func newBlockedStream() *blockedStream {
	return &blockedStream{unblocked: make(chan struct{})}
}

func (b *blockedStream) Read([]byte) (int, error) {
	<-b.unblocked
	return 0, errors.New("stream reset")
}

func (b *blockedStream) Write(p []byte) (int, error) { return len(p), nil }
func (b *blockedStream) Close() error                { return nil }
func (b *blockedStream) Reset() error {
	b.resetOnce.Do(func() { close(b.unblocked) })
	return nil
}

// TestNegotiateStreamHonorsCancel verifies a cancelled context fails the
// negotiation promptly by resetting the stream: a silent peer can never hang
// the open past the caller's context.
func TestNegotiateStreamHonorsCancel(t *testing.T) {
	s := newBlockedStream()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- negotiateStream(ctx, s, ProtoID) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("negotiate error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("negotiateStream did not honor a cancelled context")
	}
}

// TestOpenVerifiedStreamNegotiationRequired verifies the open really runs the
// multistream handshake: against a peer that never speaks ProtoID the open
// fails with a negotiation error instead of handing out an unverified stream,
// and against a real listener it completes with the negotiated protocol set.
func TestOpenVerifiedStreamNegotiationRequired(t *testing.T) {
	ctx := context.Background()

	// Phase 1: a plain libp2p host without a ProtoID handler.
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrs(ma.StringCast("/ip4/127.0.0.1/tcp/0")),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(libp2ptcp.NewTCPTransport),
	)
	if err != nil {
		t.Fatalf("plain host: %v", err)
	}
	t.Cleanup(func() { _ = plain.Close() })

	r := newTestRuntime(t, Config{})
	r.SetAuthorizer(allowIDs(plain.ID().String()))
	plainPub, err := priv.GetPublic().Raw()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.mainHost.Connect(ctx, peer.AddrInfo{ID: plain.ID(), Addrs: plain.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	stream, err := r.openVerifiedStream(ctx, r.mainHost, plain.ID(), plainPub, connDirectOnly)
	if err == nil {
		stream.Reset()
		t.Fatal("open succeeded against a peer that does not support ProtoID")
	}
	if !strings.Contains(err.Error(), "negotiate") {
		t.Fatalf("error = %v, want a negotiation failure", err)
	}

	// Phase 2: a real runtime listener completes the handshake.
	a := newTestRuntime(t, Config{})
	b := newTestRuntime(t, Config{})
	a.SetAuthorizer(allowIDs(b.PeerID()))
	b.SetAuthorizer(allowIDs(a.PeerID()))
	if _, err := a.Listener(); err != nil {
		t.Fatalf("listener: %v", err)
	}
	aID, err := peer.Decode(a.PeerID())
	if err != nil {
		t.Fatal(err)
	}
	var aAddrs []ma.Multiaddr
	for _, s := range a.Addresses() {
		m, merr := ma.NewMultiaddr(s)
		if merr != nil {
			t.Fatal(merr)
		}
		aAddrs = append(aAddrs, m)
	}
	if err := b.mainHost.Connect(ctx, peer.AddrInfo{ID: aID, Addrs: aAddrs}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	s, err := b.openVerifiedStream(ctx, b.mainHost, aID, a.PublicKey(), connDirectOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Reset()
	if s.Protocol() != ProtoID {
		t.Fatalf("protocol = %q, want %q", s.Protocol(), ProtoID)
	}
}

// TestRuntimeRepeatedDirectDialEcho dials the same target twice (the second
// time with the peer's protocols already identified and cached) and requires
// both streams to be direct, non-fallback and to really exchange bytes.
func TestRuntimeRepeatedDirectDialEcho(t *testing.T) {
	a := newTestRuntime(t, Config{})
	b := newTestRuntime(t, Config{})
	a.SetAuthorizer(allowIDs(b.PeerID()))
	b.SetAuthorizer(allowIDs(a.PeerID()))
	la, err := a.Listener()
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	// One accept loop serves both streams; the two concurrent Accepts of
	// separate goroutines could otherwise take each other's stream. Each
	// accepted conn echoes the equal-length marker it receives, so per-stream
	// verification is order-independent.
	accepted := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := la.Accept()
			if err != nil {
				accepted <- nil
				return
			}
			accepted <- c
		}
	}()

	const markerLen = len("echo-0")
	for i := 0; i < 2; i++ {
		res := b.Dial(context.Background(), endpointOf(a), peerauth.Infrastructure{}, peerhttp.PathDirect)
		if res.Err != nil {
			t.Fatalf("dial %d: %v", i, res.Err)
		}
		if res.Path != peerhttp.PathDirect {
			t.Fatalf("dial %d path = %q, want direct", i, res.Path)
		}
		if res.Fallback {
			t.Fatalf("dial %d must not be a fallback", i)
		}
		msg := fmt.Sprintf("echo-%d", i)
		if err := res.Conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("dial %d deadline: %v", i, err)
		}
		if _, err := res.Conn.Write([]byte(msg)); err != nil {
			t.Fatalf("dial %d write: %v", i, err)
		}
		var conn net.Conn
		select {
		case conn = <-accepted:
		case <-time.After(10 * time.Second):
			t.Fatalf("dial %d: target did not accept in time", i)
		}
		if conn == nil {
			t.Fatalf("dial %d: target did not accept", i)
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("dial %d deadline: %v", i, err)
		}
		buf := make([]byte, markerLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("dial %d read: %v", i, err)
		}
		if _, err := conn.Write(buf); err != nil {
			t.Fatalf("dial %d echo write: %v", i, err)
		}
		if _, err := io.ReadFull(res.Conn, buf); err != nil {
			t.Fatalf("dial %d echo read: %v", i, err)
		}
		if string(buf) != msg {
			t.Fatalf("dial %d echo got %q, want %q", i, buf, msg)
		}
		_ = res.Conn.Close()
		_ = conn.Close()
	}
}

// TestRuntimeListenerCloseJoinsBlockedHandler fills the listener queue and
// parks one handler on the full queue: Close must join it without hanging,
// refuse later Accepts and drain the queue.
func TestRuntimeListenerCloseJoinsBlockedHandler(t *testing.T) {
	a := newTestRuntime(t, Config{})
	b := newTestRuntime(t, Config{})
	a.SetAuthorizer(allowIDs(b.PeerID()))
	b.SetAuthorizer(allowIDs(a.PeerID()))
	la, err := a.Listener()
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	pl := la.(*peerListener)

	aID, err := peer.Decode(a.PeerID())
	if err != nil {
		t.Fatal(err)
	}
	var aAddrs []ma.Multiaddr
	for _, s := range a.Addresses() {
		m, merr := ma.NewMultiaddr(s)
		if merr != nil {
			t.Fatal(merr)
		}
		aAddrs = append(aAddrs, m)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := b.mainHost.Connect(ctx, peer.AddrInfo{ID: aID, Addrs: aAddrs}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	for i := 0; i < listenerQueueSize+1; i++ {
		s, serr := b.mainHost.NewStream(ctx, aID, ProtoID)
		if serr != nil {
			t.Fatalf("stream %d: %v", i, serr)
		}
		if _, err := s.Write([]byte("x")); err != nil {
			t.Fatalf("stream %d write: %v", i, err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		pl.mu.Lock()
		active, queued := pl.active, len(pl.ch)
		pl.mu.Unlock()
		if active >= 1 && queued == listenerQueueSize {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no handler parked on the full queue: active=%d queued=%d", active, queued)
		}
		time.Sleep(5 * time.Millisecond)
	}

	closed := make(chan struct{})
	go func() {
		_ = la.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return while a handler was parked on the full queue")
	}
	if _, err := la.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}
	select {
	case c := <-pl.ch:
		t.Fatalf("listener queue still holds a connection after Close: %v", c)
	default:
	}
}

// TestFilterPublishedAddrs verifies the published address set: public-only
// filtering drops loopback, private, CGNAT, DNS and circuit addresses,
// duplicates collapse, and the set is sorted and capped.
func TestFilterPublishedAddrs(t *testing.T) {
	id := testPeerID(t)
	circuit := ma.StringCast("/ip4/203.0.113.9/tcp/1/p2p/" + id.String() + "/p2p-circuit/p2p/" + id.String())
	raw := []ma.Multiaddr{
		ma.StringCast("/ip4/203.0.113.7/tcp/1"),
		ma.StringCast("/ip4/127.0.0.1/tcp/1"),
		ma.StringCast("/ip4/100.64.1.2/tcp/1"),
		ma.StringCast("/ip4/192.168.1.2/tcp/1"),
		ma.StringCast("/ip6/::1/tcp/1"),
		ma.StringCast("/dns4/example.com/tcp/1"),
		circuit,
		ma.StringCast("/ip4/203.0.113.7/tcp/1"),
	}
	got := filterPublishedAddrs(raw, true)
	if len(got) != 1 || got[0].String() != "/ip4/203.0.113.7/tcp/1" {
		t.Fatalf("public-only filter = %v, want only /ip4/203.0.113.7/tcp/1", got)
	}

	var many []ma.Multiaddr
	for i := 1; i <= 20; i++ {
		many = append(many, ma.StringCast(fmt.Sprintf("/ip4/203.0.113.%d/tcp/%d", i, i)))
	}
	got = filterPublishedAddrs(many, true)
	if len(got) != maxAdvertisedAddresses {
		t.Fatalf("capped set = %d, want %d", len(got), maxAdvertisedAddresses)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].String() >= got[i].String() {
			t.Fatalf("set not sorted and deduplicated: %v", got)
		}
	}
}

// TestNewRejectsInvalidConfigBeforeIdentity verifies every Config violation —
// budgets, timeouts, listen shape/duplicates, announce policy — fails New
// before an identity file is created.
func TestNewRejectsInvalidConfigBeforeIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	cases := []Config{
		{IdentityPath: path, MaxConnections: -1},
		{IdentityPath: path, MaxConnections: maxConfigMaxConns + 1},
		{IdentityPath: path, DirectTimeout: -time.Second},
		{IdentityPath: path, RelayTimeout: -time.Second},
		{IdentityPath: path, ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0/quic-v1"}},
		{IdentityPath: path, ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/tcp/0"}},
		{IdentityPath: path, PublicOnly: true, AnnounceAddresses: []string{"/ip4/127.0.0.1/tcp/1"}},
	}
	for i, cfg := range cases {
		if _, err := New(context.Background(), cfg); err == nil {
			t.Fatalf("case %d: invalid config accepted", i)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("identity file was created despite invalid config")
	}
}

// compile-time check that the stub really is a negotiable stream shape.
var _ negotiableStream = (*blockedStream)(nil)
var _ network.Stream = (*streamConn)(nil)
