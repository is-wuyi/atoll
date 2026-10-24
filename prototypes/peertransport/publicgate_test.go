package peertransport

import (
	"context"
	"crypto/rand"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
)

// The public-only gate is a route-proof tool: in that mode ONLY real public
// transport endpoints may be dialed or accepted. Every address class below is
// a fact the gate must get right on the connection, not on the probe's
// initial address list (identify/DCUtR re-learned endpoints hit the same
// gate). Loopback cannot be positively tested in public-only mode — the
// positive cases here are synthetic public/circuit inputs; the loopback
// negative is exercised against real hosts in
// TestPublicOnlyRefusesLoopbackEndpoints.

const (
	dnsRelayHop = "/dns4/relay.example.com/tcp/44001"
)

func mustPeerIDs(t *testing.T) (a, b peer.ID) {
	t.Helper()
	for _, dst := range []*peer.ID{&a, &b} {
		k, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		id, err := peer.IDFromPrivateKey(k)
		if err != nil {
			t.Fatalf("peer id: %v", err)
		}
		*dst = id
	}
	return a, b
}

func mustAddrs(t *testing.T, ss ...string) []ma.Multiaddr {
	t.Helper()
	out := make([]ma.Multiaddr, 0, len(ss))
	for _, s := range ss {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("multiaddr %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

// TestPublicOnlyDialClassification pins the address classes of the DIAL-side
// gate (InterceptAddrDial / the remote side of inbound conns).
func TestPublicOnlyDialClassification(t *testing.T) {
	id, other := mustPeerIDs(t)
	idS, otherS := id.String(), other.String()

	allow := []string{
		"/ip4/1.1.1.1/tcp/44010",
		"/ip4/8.8.8.8/udp/44010/quic-v1",
		"/ip6/2606:4700:4700::1111/tcp/44010",
		"/ip6/2001:4860:4860::8888/udp/44010/quic-v1",
		// CircuitRelay v2 over a PUBLIC relay hop: the dial address carries
		// the trailing /p2p/<target> virtual part; the first transport
		// component (the relay) is what gets judged.
		"/ip4/1.2.3.4/tcp/44001/p2p/" + idS + "/p2p-circuit/p2p/" + otherS,
		"/ip6/2606:4700::99/tcp/44001/p2p/" + idS + "/p2p-circuit/p2p/" + otherS,
	}
	reject := []string{
		// loopback
		"/ip4/127.0.0.1/tcp/44010",
		"/ip4/127.8.8.8/tcp/1",
		"/ip6/::1/tcp/44010",
		// RFC1918
		"/ip4/10.1.2.3/tcp/44010",
		"/ip4/172.16.0.9/tcp/1",
		"/ip4/172.31.255.254/tcp/1",
		"/ip4/192.168.1.1/tcp/44010",
		// CGNAT 100.64.0.0/10 (Tailscale / carrier NAT overlays)
		"/ip4/100.64.0.1/tcp/44010",
		"/ip4/100.127.255.254/tcp/44010",
		// link-local, unspecified, multicast
		"/ip4/169.254.3.4/tcp/1",
		"/ip4/0.0.0.0/tcp/1",
		"/ip6/::/tcp/1",
		"/ip4/224.0.0.5/tcp/1",
		"/ip6/ff02::1/tcp/1",
		// IPv6 ULA
		"/ip6/fd00::1/tcp/1",
		"/ip6/fdff:aaaa::1/tcp/1",
		// DNS names: judging them needs an implicit external resolution —
		// refused outright.
		dnsRelayHop + "/p2p/" + idS,
		"/dns/example.com/tcp/1",
		"/dnsaddr/example.com/p2p/" + idS,
		// no transport endpoint at all: nothing to enforce a class on
		"/p2p/" + idS,
		// circuit paths over non-public relays or without a transport hop
		"/ip4/127.0.0.1/tcp/44001/p2p/" + idS + "/p2p-circuit/p2p/" + otherS,
		"/ip4/100.64.0.1/tcp/44001/p2p/" + idS + "/p2p-circuit/p2p/" + otherS,
		"/ip4/192.168.1.1/tcp/44001/p2p/" + idS + "/p2p-circuit/p2p/" + otherS,
		"/p2p/" + idS + "/p2p-circuit/p2p/" + otherS,
	}

	for _, s := range allow {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("multiaddr %q: %v", s, err)
		}
		if !publicOnlyRemote(a) {
			t.Errorf("public-only rejected a public dial target: %s", s)
		}
	}
	for _, s := range reject {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("multiaddr %q: %v", s, err)
		}
		if publicOnlyRemote(a) {
			t.Errorf("public-only allowed a non-public dial target: %s", s)
		}
	}
}

// TestPublicOnlyLocalClassification pins the LOCAL side of accepted/upgraded
// conns: a port-forwarded WAN host legitimately shows a private LAN local
// address, so only loopback/unspecified are refused (plus the circuit virtual
// exemption).
func TestPublicOnlyLocalClassification(t *testing.T) {
	id, other := mustPeerIDs(t)

	allow := []string{
		"/ip4/192.168.8.5/tcp/51000", // NAT'd LAN interface under port forwarding
		"/ip4/10.0.0.7/tcp/51000",
		"/ip6/2606:4700::1/tcp/51000",
		// Circuit virtual local endpoint with no transport component: its real
		// endpoints were judged at dial/accept time; reading this as
		// "local-private" would break every relayed connection.
		"/p2p/" + id.String() + "/p2p-circuit/p2p/" + other.String(),
	}
	reject := []string{
		"/ip4/127.0.0.1/tcp/51000",
		"/ip6/::1/tcp/51000",
		"/ip4/0.0.0.0/tcp/51000",
		"/ip6/::/tcp/51000",
		"/p2p/" + id.String(), // no transport, no circuit: unknown shape
	}

	for _, s := range allow {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("multiaddr %q: %v", s, err)
		}
		if !publicOnlyLocal(a) {
			t.Errorf("public-only rejected a legitimate local endpoint: %s", s)
		}
	}
	for _, s := range reject {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("multiaddr %q: %v", s, err)
		}
		if publicOnlyLocal(a) {
			t.Errorf("public-only accepted a loopback/unknown local endpoint: %s", s)
		}
	}
}

// endpointPair is a minimal network.ConnMultiaddrs for gater unit tests.
type endpointPair struct{ local, remote ma.Multiaddr }

func (e endpointPair) LocalMultiaddr() ma.Multiaddr  { return e.local }
func (e endpointPair) RemoteMultiaddr() ma.Multiaddr { return e.remote }

func publicGater(t *testing.T, ids ...peer.ID) *ConnGater {
	t.Helper()
	g := NewConnGater(NewAllowlist(ids...))
	g.PublicOnly = true
	g.log = log.New(io.Discard, "", 0)
	return g
}

func pair(t *testing.T, local, remote string) endpointPair {
	t.Helper()
	return endpointPair{local: mustAddrs(t, local)[0], remote: mustAddrs(t, remote)[0]}
}

// TestConnGaterPublicOnlyIntercepts pins every intercept hook of the gate:
// PeerID allowlist first, then the endpoint class, with the circuit-virtual
// forms kept connectable.
func TestConnGaterPublicOnlyIntercepts(t *testing.T) {
	idA, idB := mustPeerIDs(t)
	g := publicGater(t, idA)
	loop := "/ip4/127.0.0.1/tcp/44010"
	pub := "/ip4/1.1.1.1/tcp/44010"
	natLocal := "/ip4/192.168.8.5/tcp/51000"
	circuitPub := "/ip4/1.2.3.4/tcp/44001/p2p/" + idA.String() + "/p2p-circuit/p2p/" + idB.String()
	circuitLoop := "/ip4/127.0.0.1/tcp/44001/p2p/" + idA.String() + "/p2p-circuit/p2p/" + idB.String()

	// Dial side: allowlist applies before the class check.
	if !g.InterceptPeerDial(idA) {
		t.Error("allowed peer refused at InterceptPeerDial")
	}
	if g.InterceptPeerDial(idB) {
		t.Error("unknown peer passed InterceptPeerDial")
	}
	if !g.InterceptAddrDial(idA, mustAddrs(t, pub)[0]) {
		t.Error("public dial target refused")
	}
	if g.InterceptAddrDial(idA, mustAddrs(t, loop)[0]) {
		t.Error("loopback dial target allowed")
	}
	if g.InterceptAddrDial(idB, mustAddrs(t, pub)[0]) {
		t.Error("unknown peer passed InterceptAddrDial on a public target")
	}

	// Accept side: pre-handshake, endpoint classes only.
	if !g.InterceptAccept(pair(t, natLocal, pub)) {
		t.Error("public remote with NAT'd private local refused (port-forwarded host must keep working)")
	}
	if g.InterceptAccept(pair(t, natLocal, loop)) {
		t.Error("loopback remote accepted")
	}
	if g.InterceptAccept(pair(t, natLocal, "/ip4/10.1.2.3/tcp/44010")) {
		t.Error("private remote accepted")
	}
	if g.InterceptAccept(pair(t, loop, pub)) {
		t.Error("loopback local accepted")
	}
	if !g.InterceptAccept(pair(t, natLocal, circuitPub)) {
		t.Error("circuit over a public relay hop refused")
	}
	if g.InterceptAccept(pair(t, natLocal, circuitLoop)) {
		t.Error("circuit over a loopback relay hop accepted")
	}

	// Secured: allowlist in both directions + endpoint class, circuit remote
	// over a public relay stays connectable (never misread as local-private).
	if !g.InterceptSecured(network.DirInbound, idA, pair(t, natLocal, pub)) {
		t.Error("allowed peer refused on inbound public connection")
	}
	if g.InterceptSecured(network.DirInbound, idB, pair(t, natLocal, pub)) {
		t.Error("unknown peer passed InterceptSecured")
	}
	if g.InterceptSecured(network.DirInbound, idA, pair(t, natLocal, loop)) {
		t.Error("inbound loopback connection accepted")
	}
	if !g.InterceptSecured(network.DirOutbound, idA, pair(t, natLocal, circuitPub)) {
		t.Error("outbound circuit connection over a public relay refused")
	}
	if g.InterceptSecured(network.DirOutbound, idA, pair(t, natLocal, loop)) {
		t.Error("outbound dial to loopback accepted")
	}
}

// TestConnGaterDefaultModeLoopbackUnchanged pins the default (PublicOnly
// false) behavior: loopback dials and accepts pass exactly as before, so the
// historical loopback suites are unaffected.
func TestConnGaterDefaultModeLoopbackUnchanged(t *testing.T) {
	idA, _ := mustPeerIDs(t)
	g := NewConnGater(NewAllowlist(idA))
	if g.PublicOnly {
		t.Fatal("PublicOnly must default to false")
	}
	loop := mustAddrs(t, "/ip4/127.0.0.1/tcp/44010")[0]
	if !g.InterceptAddrDial(idA, loop) {
		t.Error("default mode must keep allowing loopback dials")
	}
	if !g.InterceptAccept(pair(t, loop.String(), loop.String())) {
		t.Error("default mode must keep allowing loopback accepts")
	}
	if !g.InterceptSecured(network.DirInbound, idA, pair(t, loop.String(), loop.String())) {
		t.Error("default mode must keep allowing loopback secured conns")
	}
}

// outsiderGater is a non-*ConnGater ConnectionGater: HostOptions.PublicOnly
// must refuse it (fail closed) instead of silently running ungated.
type outsiderGater struct{}

func (outsiderGater) InterceptPeerDial(peer.ID) bool { return true }
func (outsiderGater) InterceptAddrDial(peer.ID, ma.Multiaddr) bool {
	return true
}
func (outsiderGater) InterceptAccept(network.ConnMultiaddrs) bool { return true }
func (outsiderGater) InterceptSecured(network.Direction, peer.ID, network.ConnMultiaddrs) bool {
	return true
}
func (outsiderGater) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

// TestNewHostPublicOnlyRequiresConnGater: PublicOnly flows HostOptions ->
// *ConnGater; anything that is not a *ConnGater is a configuration error.
func TestNewHostPublicOnlyRequiresConnGater(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if _, err := newHost(context.Background(), HostOptions{
		Priv: priv, ListenTCP: true, Gater: outsiderGater{}, PublicOnly: true,
	}); err == nil || !strings.Contains(err.Error(), "*ConnGater") {
		t.Fatalf("newHost with a non-*ConnGater and PublicOnly: got %v, want a *ConnGater error", err)
	}

	g := NewConnGater(NewAllowlist())
	h, err := newHost(context.Background(), HostOptions{
		Priv: priv, ListenTCP: true, Gater: g, PublicOnly: true,
	})
	if err != nil {
		t.Fatalf("newHost: %v", err)
	}
	defer h.Close()
	if !g.PublicOnly {
		t.Error("newHost did not enable PublicOnly on the provided *ConnGater")
	}
}

// TestPublicOnlyRefusesLoopbackEndpoints is the real-host negative: a
// public-only host on loopback must refuse to dial loopback endpoints and to
// accept loopback remotes, with no private dial side effects — while the
// default mode keeps working unchanged on the very same hosts. Each subtest
// uses a fresh dialer/target pair because a rejected dial puts the swarm's
// per-peer dial backoff on that pair, which would mask the gate under test.
func TestPublicOnlyRefusesLoopbackEndpoints(t *testing.T) {
	c := startCluster(t, 4, func(_ int, cfg *PeerConfig) {
		cfg.PublicOnly = true
		// The loopback relay is not dialable under public-only; skip the
		// startup reservation instead of relying on the background retry.
		cfg.SkipRelayReservation = true
	})
	assertNoConns := func(t *testing.T, src, dst *StoragePeer) {
		t.Helper()
		if n := len(src.Host.Network().ConnsToPeer(dst.ID)); n != 0 {
			t.Errorf("dialer kept %d connections to the target after rejection", n)
		}
		if n := len(dst.Host.Network().ConnsToPeer(src.ID)); n != 0 {
			t.Errorf("target saw %d inbound connections after rejection", n)
		}
	}

	// Outbound: the public-only DIALER refuses the loopback target address.
	t.Run("direct dial refused at the gate", func(t *testing.T) {
		src, dst := c.peers[0], c.peers[1]
		client, _ := src.Dial(dst.ID, PolicyDirect, c.Addrs(1))
		req, _ := http.NewRequestWithContext(c.ctx, http.MethodGet, "http://peer/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("public-only host connected over loopback: HTTP %d", resp.StatusCode)
		}
		if !strings.Contains(err.Error(), "gater") {
			t.Errorf("dial failed for a reason other than the gate: %v", err)
		}
		t.Logf("public-only direct dial rejected as expected: %v", err)
		assertNoConns(t, src, dst)
		if err := dst.Store.VerifyNoPartial(); err != nil {
			t.Errorf("target store was touched: %v", err)
		}
	})

	t.Run("relay fallback leg refused too", func(t *testing.T) {
		src, dst := c.peers[0], c.peers[1]
		client, _ := src.Dial(dst.ID, PolicyDirectThenRelay, c.Addrs(1))
		req, _ := http.NewRequestWithContext(c.ctx, http.MethodGet, "http://peer/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("public-only host fell back to a loopback relay: HTTP %d", resp.StatusCode)
		}
		t.Logf("public-only direct-then-relay rejected as expected: %v", err)
		assertNoConns(t, src, dst)
	})

	// Inbound: the public-only TARGET refuses the loopback remote even when
	// the dialer itself is in default mode — the gate is per connection,
	// checked again at InterceptAccept on the listening host.
	t.Run("inbound leg gated on the listener host", func(t *testing.T) {
		src, dst := c.peers[2], c.peers[1]
		src.gater.PublicOnly = false // fresh dialer pair, dialer in default mode
		client, _ := src.Dial(dst.ID, PolicyDirect, c.Addrs(1))
		req, _ := http.NewRequestWithContext(c.ctx, http.MethodGet, "http://peer/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("loopback remote was accepted by a public-only host: HTTP %d", resp.StatusCode)
		}
		t.Logf("public-only inbound rejection as expected: %v", err)
		assertNoConns(t, src, dst)
	})

	// Default mode is unchanged: the same cluster code path with the flag off
	// still transfers over loopback, and the actual endpoints are recorded.
	t.Run("default mode unchanged on the same hosts", func(t *testing.T) {
		src, dst := c.peers[3], c.peers[1]
		src.gater.PublicOnly = false // fresh dialer pair
		dst.gater.PublicOnly = false
		client, dc := src.Dial(dst.ID, PolicyDirect, c.Addrs(1))
		req, _ := http.NewRequestWithContext(c.ctx, http.MethodGet, "http://peer/healthz", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("default-mode loopback transfer broke: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("healthz: HTTP %d", resp.StatusCode)
		}
		st := dc.LastStats()
		if st.Effective != PathDirect {
			t.Errorf("effective = %q, want direct", st.Effective)
		}
		if !strings.Contains(st.RemoteMultiaddr, "127.0.0.1") {
			t.Errorf("remote_multiaddr = %q, want the loopback endpoint", st.RemoteMultiaddr)
		}
		if st.LocalMultiaddr == "" {
			t.Error("local_multiaddr not recorded on the transfer stats")
		}
	})
}
