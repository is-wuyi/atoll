package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	lpcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"

	pt "atoll/prototypes/peertransport"
)

// ============================ pure helpers ============================

func TestParsePolicy(t *testing.T) {
	ok := map[string]pt.DialPolicy{
		"direct":            pt.PolicyDirect,
		"forced-relay":      pt.PolicyForcedRelay,
		"direct-then-relay": pt.PolicyDirectThenRelay,
	}
	for in, want := range ok {
		got, err := parsePolicy(in)
		if err != nil {
			t.Errorf("parsePolicy(%q) = error %v, want %v", in, err, want)
			continue
		}
		if got != want {
			t.Errorf("parsePolicy(%q) = %v, want %v", in, got, want)
		}
	}
	// Typos must not silently downgrade: a mistyped forced relay must not be
	// measured as whichever path happens to be reachable.
	for _, bad := range []string{"", "direct-then-relay-v2", "DIRECT", "forced_relay", "relay", "direct then relay"} {
		if _, err := parsePolicy(bad); err == nil {
			t.Errorf("parsePolicy(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestValidatePerfFlags(t *testing.T) {
	direct := "/ip4/127.0.0.1/tcp/44010"
	relay := "/ip4/127.0.0.1/tcp/44001/p2p/" + peerID()

	cases := []struct {
		name       string
		target     string
		directAddr string
		relayAddr  string
		policy     string
		rounds     int
		bwBytes    int64
		timeout    time.Duration
		wantErr    string
		wantPolicy pt.DialPolicy
	}{
		{
			name:   "direct with a direct endpoint",
			target: peerID(), directAddr: direct, policy: "direct", rounds: 3, bwBytes: 2048, timeout: 3 * time.Second,
			wantPolicy: pt.PolicyDirect,
		},
		{
			name:   "forced relay with a relay endpoint",
			target: peerID(), relayAddr: relay, policy: "forced-relay", rounds: 3, bwBytes: 2048, timeout: 3 * time.Second,
			wantPolicy: pt.PolicyForcedRelay,
		},
		{
			name:   "direct-then-relay with both endpoints",
			target: peerID(), directAddr: direct, relayAddr: relay, policy: "direct-then-relay", rounds: 3, bwBytes: 0, timeout: 1 * time.Second,
			wantPolicy: pt.PolicyDirectThenRelay,
		},
		{
			name:   "forced relay without a relay endpoint",
			target: peerID(), directAddr: direct, policy: "forced-relay", rounds: 3, bwBytes: 2048, timeout: 3 * time.Second,
			wantErr:    "forced-relay requires -relay",
			wantPolicy: pt.PolicyForcedRelay,
		},
		{
			name:   "direct without a direct endpoint",
			target: peerID(), policy: "direct", rounds: 3, bwBytes: 2048, timeout: 3 * time.Second,
			wantErr:    "requires -direct-addr",
			wantPolicy: pt.PolicyDirect,
		},
		{
			name:   "unknown policy",
			target: peerID(), directAddr: direct, policy: "direct-first", rounds: 3, bwBytes: 2048, timeout: 3 * time.Second,
			wantErr:    "unknown -policy",
			wantPolicy: pt.PolicyDirectThenRelay,
		},
		{
			name:   "bad target",
			target: "not-a-peer-id", directAddr: direct, policy: "direct", rounds: 3, bwBytes: 2048, timeout: 3 * time.Second,
			wantErr:    "invalid -target",
			wantPolicy: pt.PolicyDirect,
		},
		{
			name:   "bad direct endpoint",
			target: peerID(), directAddr: "no-such-multiaddr", policy: "direct", rounds: 3, bwBytes: 2048, timeout: 3 * time.Second,
			wantErr:    "invalid -direct-addr",
			wantPolicy: pt.PolicyDirect,
		},
		{
			name:   "bad relay endpoint",
			target: peerID(), relayAddr: "/ip4/127.0.0.1/tcp/44001", policy: "forced-relay", rounds: 3, bwBytes: 2048, timeout: 3 * time.Second,
			wantErr:    "invalid -relay",
			wantPolicy: pt.PolicyForcedRelay,
		},
		{
			name:   "zero rounds",
			target: peerID(), directAddr: direct, policy: "direct", rounds: 0, bwBytes: 2048, timeout: 3 * time.Second,
			wantErr:    "-rounds must be >= 1",
			wantPolicy: pt.PolicyDirect,
		},
		{
			name:   "negative bw bytes",
			target: peerID(), directAddr: direct, policy: "direct", rounds: 3, bwBytes: -1, timeout: 3 * time.Second,
			wantErr:    "-bw-bytes must be >= 0",
			wantPolicy: pt.PolicyDirect,
		},
		{
			name:   "tiny bw payload",
			target: peerID(), directAddr: direct, policy: "direct", rounds: 3, bwBytes: 64, timeout: 3 * time.Second,
			wantErr:    "must be >= 1024",
			wantPolicy: pt.PolicyDirect,
		},
		{
			name:   "zero direct timeout",
			target: peerID(), directAddr: direct, policy: "direct", rounds: 3, bwBytes: 2048, timeout: 0,
			wantErr:    "-direct-timeout must be > 0",
			wantPolicy: pt.PolicyDirect,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			spec, err := validatePerfFlags(tc.target, tc.directAddr, tc.relayAddr, tc.policy, tc.rounds, tc.bwBytes, tc.timeout)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if spec.policy != tc.wantPolicy {
					t.Errorf("policy = %v, want %v", spec.policy, tc.wantPolicy)
				}
				if tc.relayAddr == "" && spec.relay != nil {
					t.Errorf("relay = %v, want none", spec.relay)
				}
				if tc.relayAddr != "" && spec.relay == nil {
					t.Errorf("relay = %v, want the configured relay", spec.relay)
				}
				if tc.directAddr == "" {
					if spec.directAddrs != nil {
						t.Errorf("directAddrs = %v, want none", spec.directAddrs)
					}
				} else if len(spec.directAddrs) != 1 {
					t.Errorf("directAddrs = %v, want exactly one", spec.directAddrs)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got nil (spec=%+v)", tc.wantErr, spec)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestIsOverlayRoutable(t *testing.T) {
	drop := []string{
		"127.0.0.1",
		"10.0.0.7",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.1",
		"192.168.1.1",
		"192.168.254.254",
		// Tailscale CGNAT range: two peers on the same VPN would otherwise
		// "direct connect" over the very overlay the mesh filter exists to
		// bypass.
		"100.64.0.1",
		"100.127.255.254",
		// unknown shapes are dropped conservatively rather than let through
		"10",
		"n.a.n.",
	}
	for _, ip := range drop {
		if !isOverlayRoutable(ip) {
			t.Errorf("isOverlayRoutable(%q) = false, want true", ip)
		}
	}
	keep := []string{
		"1.1.1.1",
		"172.15.0.1",
		"172.32.0.1",
		"100.63.255.255",
		"100.128.0.1",
		"8.8.8.8",
	}
	for _, ip := range keep {
		if isOverlayRoutable(ip) {
			t.Errorf("isOverlayRoutable(%q) = true, want false", ip)
		}
	}
}

func mustAddr(t *testing.T, s string) ma.Multiaddr {
	t.Helper()
	a, err := ma.NewMultiaddr(s)
	if err != nil {
		t.Fatalf("multiaddr %q: %v", s, err)
	}
	return a
}

func TestDropPrivate(t *testing.T) {
	in := []ma.Multiaddr{
		mustAddr(t, "/ip4/8.8.8.8/tcp/44010"),
		mustAddr(t, "/ip4/10.0.0.4/tcp/44010"),
		mustAddr(t, "/ip4/100.88.0.1/tcp/44010"),
		mustAddr(t, "/ip4/192.168.1.5/udp/44010/quic-v1"),
		mustAddr(t, "/ip6/::1/tcp/44010"),
	}
	out := dropPrivate(in)
	if len(out) != 2 {
		t.Fatalf("dropPrivate kept %d of %d, want 2: %v", len(out), len(in), out)
	}
	got := []string{}
	for _, a := range out {
		got = append(got, a.String())
	}
	if !strings.Contains(strings.Join(got, ","), "/ip4/8.8.8.8/tcp/44010") {
		t.Errorf("public endpoint dropped: %v", got)
	}
	// Non-IP endpoints (IPv6 here) are kept: they are not the overlay range
	// this filter exists to remove.
	if !strings.Contains(strings.Join(got, ","), "/ip6/") {
		t.Errorf("non-IP endpoint dropped: %v", got)
	}
}

func TestPeerAddrs(t *testing.T) {
	id := peerID()
	state := map[string]any{
		"peers": []map[string]any{
			{"peer_id": id, "addrs": []string{"/ip4/1.2.3.4/tcp/44010", "/ip4/1.2.3.4/udp/44010/quic-v1"}},
			{"peer_id": "not-a-peer-id", "addrs": []string{"/ip4/1.2.3.5/tcp/44010"}},
			{"peer_id": id, "addrs": []string{"garbage"}},
		},
	}
	out := peerAddrs(state)
	if len(out) != 1 {
		t.Fatalf("peerAddrs returned %d peers, want 1", len(out))
	}
	got, ok := out[mustPeerID(t, id)]
	if !ok {
		t.Fatalf("peerAddrs lost the peer: %v", out)
	}
	if len(got) != 2 {
		t.Fatalf("peerAddrs kept %d endpoints, want 2: %v", len(got), got)
	}

	// Absent or malformed registry sections yield an empty map, never a panic.
	if n := len(peerAddrs(map[string]any{})); n != 0 {
		t.Errorf("empty registry gave %d peers", n)
	}
	if n := len(peerAddrs(map[string]any{"peers": "nonsense"})); n != 0 {
		t.Errorf("malformed registry gave %d peers", n)
	}
}

func TestRelayAIString(t *testing.T) {
	var nilInfo *peer.AddrInfo
	if got := relayAIString(nilInfo); got != "" {
		t.Errorf("nil AddrInfo gave %q, want empty", got)
	}
	bare := &peer.AddrInfo{ID: mustPeerID(t, peerID())}
	if got := relayAIString(bare); got != "" {
		t.Errorf("AddrInfo without addresses gave %q, want empty", got)
	}
	info := &peer.AddrInfo{ID: mustPeerID(t, peerID()), Addrs: []ma.Multiaddr{mustAddr(t, "/ip4/1.2.3.4/tcp/44001")}}
	if got := relayAIString(info); got != "/ip4/1.2.3.4/tcp/44001/p2p/"+info.ID.String() {
		t.Errorf("relayAIString = %q, want /ip4/1.2.3.4/tcp/44001/p2p/<id>", got)
	}
}

func TestParseAddrInfo(t *testing.T) {
	id := peerID()
	ai, err := parseAddrInfo("/ip4/1.2.3.4/tcp/44001/p2p/" + id)
	if err != nil {
		t.Fatalf("parseAddrInfo: %v", err)
	}
	if ai.ID != mustPeerID(t, id) {
		t.Errorf("id = %v, want %v", ai.ID, id)
	}
	if len(ai.Addrs) != 1 {
		t.Fatalf("addrs = %v, want one", ai.Addrs)
	}

	for _, bad := range []string{"", "/ip4/1.2.3.4/tcp/44001", "not-a-multiaddr"} {
		if _, err := parseAddrInfo(bad); err == nil {
			t.Errorf("parseAddrInfo(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestLatencyMath(t *testing.T) {
	if got := ms(2500 * time.Microsecond); got != 2.5 {
		t.Errorf("ms = %v, want 2.5", got)
	}
	if got := mbps(1<<20, time.Second); got != 1 {
		t.Errorf("mbps(1 MiB, 1s) = %v, want 1 MiB/s", got)
	}
	if got := mbps(1<<20, 2*time.Second); got != 0.5 {
		t.Errorf("mbps(1 MiB, 2s) = %v, want 0.5", got)
	}
	if got := mbps(0, time.Second); got != 0 {
		t.Errorf("mbps(0 bytes) = %v, want 0", got)
	}
	if got := mbps(1<<20, 0); got != 0 {
		t.Errorf("mbps(0 duration) = %v, want 0", got)
	}
	if got := mbps(1<<20, -time.Second); got != 0 {
		t.Errorf("mbps(negative duration) = %v, want 0", got)
	}
}

func TestSetQuantiles(t *testing.T) {
	var empty perfResult
	setQuantiles(&empty, nil)
	if empty.N != 0 || empty.MinMS != 0 || empty.MaxMS != 0 {
		t.Errorf("empty phase reported %+v", empty)
	}

	// Unsorted input, unsorted quantiles out: N counts ONLY what was passed.
	var r perfResult
	setQuantiles(&r, []float64{40, 10, 20, 30})
	if r.N != 4 {
		t.Errorf("n = %d, want 4", r.N)
	}
	if r.MinMS != 10 || r.MaxMS != 40 {
		t.Errorf("min/max = %v/%v, want 10/40", r.MinMS, r.MaxMS)
	}
	// The median is the upper middle of the sorted sample (index N/2).
	if r.MedMS != 30 {
		t.Errorf("med = %v, want 30", r.MedMS)
	}

	// A single sample must not panic and must report itself on every axis.
	var one perfResult
	setQuantiles(&one, []float64{7})
	if one.N != 1 || one.MinMS != 7 || one.MedMS != 7 || one.P95MS != 7 || one.MaxMS != 7 {
		t.Errorf("single sample gave %+v", one)
	}
}

func TestPerfFailureMessage(t *testing.T) {
	f := &perfFailure{
		Phase: "down", Op: "get", Round: 2,
		Path: pt.PathCircuit, FallbackAttempted: true,
		Err: fmt.Errorf("HTTP 404: not found"),
	}
	got := f.Error()
	for _, want := range []string{"down", "get", "round 2", pt.PathCircuit, "fallback_attempted=true", "HTTP 404"} {
		if !strings.Contains(got, want) {
			t.Errorf("error %q does not mention %q", got, want)
		}
	}
	// A missing cause must still render, never a nil dereference.
	if got := (&perfFailure{Phase: "connect", Op: "dial", Round: 1}).Error(); !strings.Contains(got, "connect") {
		t.Errorf("nil-cause error did not name its phase: %q", got)
	}
}

// ============================ integration on loopback ============================

// peerID returns a valid PeerID string for tests that only need a well-formed
// value (they do not dial it).
func peerID() string {
	k, _, err := lpcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		panic(err)
	}
	id, err := peer.IDFromPrivateKey(k)
	if err != nil {
		panic(err)
	}
	return id.String()
}

func mustPeerID(t *testing.T, s string) peer.ID {
	t.Helper()
	id, err := peer.Decode(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return id
}

// perfCluster is the smallest topology the perf phases need: one real
// CircuitRelay v2 hop and n storage peers, all on loopback.
type perfCluster struct {
	ctx     context.Context
	cancel  context.CancelFunc
	base    string
	relay   *pt.RelayNode
	relayAI peer.AddrInfo
	peers   []*pt.StoragePeer
}

func (c *perfCluster) directAddrs(i int) []ma.Multiaddr { return c.peers[i].AddrInfo().Addrs }

func newPerfCluster(t *testing.T, n int, mutate ...func(i int, cfg *pt.PeerConfig)) *perfCluster {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &perfCluster{ctx: ctx, cancel: cancel, base: t.TempDir()}
	t.Cleanup(func() {
		cancel()
		for _, p := range c.peers {
			_ = p.Close()
		}
		if c.relay != nil {
			_ = c.relay.Close()
		}
	})

	ids := make([]peer.ID, 0, n)
	for i := 0; i < n; i++ {
		id, err := pt.LoadOrCreateIdentity(filepath.Join(c.base, fmt.Sprintf("peer%d", i+1)))
		if err != nil {
			t.Fatalf("identity peer%d: %v", i+1, err)
		}
		ids = append(ids, id.ID)
	}
	allow := pt.NewAllowlist(ids...)

	relay, err := pt.NewRelayNode(ctx, pt.RelayConfig{
		DataDir:         filepath.Join(c.base, "relay"),
		Allowlist:       allow,
		Limit:           pt.DefaultRelayLimit(),
		ReservationTTL:  30 * time.Minute,
		MaxReservations: 8,
		MaxCircuits:     4,
		Logger:          testLogger(),
	})
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	c.relay = relay
	c.relayAI = relay.AddrInfo()

	for i := 0; i < n; i++ {
		cfg := pt.PeerConfig{
			DataDir:    filepath.Join(c.base, fmt.Sprintf("peer%d", i+1)),
			Peers:      allow,
			Relay:      &c.relayAI,
			EnableQUIC: false,
			Logger:     testLogger(),
		}
		for _, m := range mutate {
			m(i, &cfg)
		}
		p, err := pt.NewStoragePeer(ctx, cfg)
		if err != nil {
			t.Fatalf("peer%d: %v", i+1, err)
		}
		c.peers = append(c.peers, p)
	}
	return c
}

func testLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func deadEndpoint(t *testing.T) []ma.Multiaddr {
	t.Helper()
	return []ma.Multiaddr{mustAddr(t, "/ip4/127.0.0.1/tcp/1")}
}

// TestPerfPhasesEnforceRequestedPolicy drives every supported policy through
// the connect phase and checks that the reported policy, fallback attempt, and
// actual path agree with what was requested — measured on loopback so the
// result is deterministic rather than network-dependent.
func TestPerfPhasesEnforceRequestedPolicy(t *testing.T) {
	c := newPerfCluster(t, 2)
	target := c.peers[1].ID
	direct := c.directAddrs(1)

	cases := []struct {
		name     string
		policy   pt.DialPolicy
		addrs    []ma.Multiaddr
		wantPath string
		wantFb   bool
	}{
		{"direct stays direct", pt.PolicyDirect, direct, pt.PathDirect, false},
		{"forced relay uses the circuit", pt.PolicyForcedRelay, nil, pt.PathCircuit, false},
		{"direct-then-relay prefers direct", pt.PolicyDirectThenRelay, direct, pt.PathDirect, false},
		{"direct-then-relay records the fallback", pt.PolicyDirectThenRelay, deadEndpoint(t), pt.PathCircuit, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r, err := phaseConnect(context.Background(), c.peers[0], target, tc.policy, tc.addrs, 3)
			if err != nil {
				t.Fatalf("phaseConnect: %v", err)
			}
			if r.Policy != string(tc.policy) {
				t.Errorf("policy = %q, want %q", r.Policy, tc.policy)
			}
			if r.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", r.Path, tc.wantPath)
			}
			if r.FallbackAttempted != tc.wantFb {
				t.Errorf("fallback_attempted = %v, want %v", r.FallbackAttempted, tc.wantFb)
			}
			// A fallback attempt whose path is direct must be labeled as an
			// upgrade, never as a bare direct measurement.
			if r.FallbackAttempted && r.Path == pt.PathDirect && !r.FallbackUpgraded {
				t.Errorf("direct path after a fallback attempt must set fallback_upgraded")
			}
			if r.FallbackUpgraded && (r.Path != pt.PathDirect || !r.FallbackAttempted) {
				t.Errorf("fallback_upgraded set without a fallback attempt to a direct path")
			}
			if r.N != 3 {
				t.Errorf("n = %d, want 3 (only successful dials count)", r.N)
			}
			if r.Endpoint == "" {
				t.Errorf("endpoint not reported")
			}
			if tc.wantPath == pt.PathCircuit && !strings.Contains(r.Endpoint, "/p2p-circuit") {
				t.Errorf("circuit path reported a non-circuit endpoint: %s", r.Endpoint)
			}
			if tc.wantPath == pt.PathDirect && strings.Contains(r.Endpoint, "/p2p-circuit") {
				t.Errorf("direct path reported a circuit endpoint: %s", r.Endpoint)
			}
		})
	}
}

// TestPerfPhasesFailExplicitly: a phase that cannot measure anything reports
// n=0, zero bytes, and a structured error that names phase, operation, path,
// and cause. Nothing is silently counted as success.
func TestPerfPhasesFailExplicitly(t *testing.T) {
	c := newPerfCluster(t, 2)
	target := c.peers[1].ID

	t.Run("unreachable target", func(t *testing.T) {
		// A target PeerID that belongs to no running host: the dial fails.
		ghost := mustPeerID(t, peerID())
		r, err := phaseConnect(context.Background(), c.peers[0], ghost, pt.PolicyDirect, deadEndpoint(t), 2)
		if err == nil {
			t.Fatalf("expected a failure, got %+v", r)
		}
		if r.N != 0 {
			t.Errorf("failed phase counted %d successful dials", r.N)
		}
		if r.Path != "" {
			t.Errorf("failed phase reported path %q", r.Path)
		}
		for _, want := range []string{`phase "connect"`, `op "dial"`, "round 1"} {
			if !strings.Contains(r.Err, want) {
				t.Errorf("error %q does not mention %q", r.Err, want)
			}
		}
	})

	t.Run("download of a missing object", func(t *testing.T) {
		r, err := phaseDownload(context.Background(), c.peers[0], target, pt.PolicyDirect, c.directAddrs(1),
			4096, newKey("perf-none"), "0000000000000000000000000000000000000000000000000000000000000000")
		if err == nil {
			t.Fatalf("expected a failure, got %+v", r)
		}
		if r.N != 0 || r.Bytes != 0 {
			t.Errorf("failed download counted n=%d bytes=%d", r.N, r.Bytes)
		}
		if r.Path != pt.PathDirect {
			t.Errorf("the attempt was made over a real direct connection; path must still be reported, got %q", r.Path)
		}
		if !strings.Contains(r.Err, `phase "down"`) || !strings.Contains(r.Err, `op "get"`) {
			t.Errorf("error %q does not name phase and operation", r.Err)
		}
	})
}

// TestPerfUploadDownloadAcknowledgeVerifiedBytes: upload bytes count only when
// the server confirms them, download bytes only when length and sha256 match
// the upload, and the payload generation time is outside every timer.
func TestPerfUploadDownloadAcknowledgeVerifiedBytes(t *testing.T) {
	c := newPerfCluster(t, 2)
	target := c.peers[1].ID
	direct := c.directAddrs(1)
	const size int64 = 1 << 20

	payload, want, err := makePayload(size)
	if err != nil {
		t.Fatalf("makePayload: %v", err)
	}
	key := newKey("perf-bw")

	up, err := phaseUpload(context.Background(), c.peers[0], target, pt.PolicyDirect, direct, size, key, payload, want)
	if err != nil {
		t.Fatalf("phaseUpload: %v", err)
	}
	if up.N != 1 || up.Bytes != size {
		t.Errorf("up: n=%d bytes=%d, want 1/%d", up.N, up.Bytes, size)
	}
	if up.Sha256 != want {
		t.Errorf("up sha = %s, want %s", up.Sha256, want)
	}
	if up.WireBytes < size {
		t.Errorf("up wire_bytes = %d, want >= %d (stream carries the payload)", up.WireBytes, size)
	}
	if up.MBps <= 0 || up.MaxMS <= 0 {
		t.Errorf("up reported no throughput/latency: %+v", up)
	}

	down, err := phaseDownload(context.Background(), c.peers[0], target, pt.PolicyDirect, direct, size, key, want)
	if err != nil {
		t.Fatalf("phaseDownload: %v", err)
	}
	if down.N != 1 || down.Bytes != size {
		t.Errorf("down: n=%d bytes=%d, want 1/%d", down.N, down.Bytes, size)
	}
	if down.Sha256 != want {
		t.Errorf("down sha = %s, want %s", down.Sha256, want)
	}
	if down.WireBytes < size {
		t.Errorf("down wire_bytes = %d, want >= %d", down.WireBytes, size)
	}
	if up.Path != down.Path {
		t.Errorf("up path %q != down path %q for one round trip", up.Path, down.Path)
	}

	// The same bytes over the relay hop must verify identically.
	downRelay, err := phaseDownload(context.Background(), c.peers[0], target, pt.PolicyForcedRelay, nil, size, key, want)
	if err != nil {
		t.Fatalf("phaseDownload forced-relay: %v", err)
	}
	if downRelay.N != 1 || downRelay.Bytes != size || downRelay.Sha256 != want {
		t.Errorf("down via relay: n=%d bytes=%d sha=%s", downRelay.N, downRelay.Bytes, downRelay.Sha256)
	}
	if downRelay.Path != pt.PathCircuit {
		t.Errorf("down via relay path = %q, want %q", downRelay.Path, pt.PathCircuit)
	}
}

// TestPerfDownloadRejectsWrongChecksum: a download whose length matches but
// whose content differs must fail rather than count as a verified download.
func TestPerfDownloadRejectsWrongChecksum(t *testing.T) {
	c := newPerfCluster(t, 2)
	target := c.peers[1].ID
	direct := c.directAddrs(1)
	const size int64 = 4096

	payload, want, err := makePayload(size)
	if err != nil {
		t.Fatalf("makePayload: %v", err)
	}
	key := newKey("perf-sha")
	if _, err := phaseUpload(context.Background(), c.peers[0], target, pt.PolicyDirect, direct, size, key, payload, want); err != nil {
		t.Fatalf("phaseUpload: %v", err)
	}

	r, err := phaseDownload(context.Background(), c.peers[0], target, pt.PolicyDirect, direct, size, key,
		"0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatalf("download with a wrong expected sha succeeded: %+v", r)
	}
	if r.Bytes != 0 {
		t.Errorf("unverified download counted %d bytes", r.Bytes)
	}
	if !strings.Contains(r.Err, "sha") {
		t.Errorf("error %q does not name the checksum mismatch", r.Err)
	}
}

// TestPhaseRequestSplitsConnectFromRequest: the request phase measures only
// request time over a kept-open connection — no dial inside the sample and no
// failed request inside N.
func TestPhaseRequestSplitsConnectFromRequest(t *testing.T) {
	c := newPerfCluster(t, 2)
	target := c.peers[1].ID
	direct := c.directAddrs(1)
	const rounds = 6

	r, err := phaseRequest(context.Background(), c.peers[0], target, pt.PolicyDirect, direct, rounds, 1024)
	if err != nil {
		t.Fatalf("phaseRequest: %v", err)
	}
	if r.N != rounds {
		t.Errorf("n = %d, want %d", r.N, rounds)
	}
	if r.Bytes != rounds*1024 {
		t.Errorf("bytes = %d, want %d (acknowledged only)", r.Bytes, rounds*1024)
	}
	if r.WireBytes <= 0 {
		t.Errorf("wire_bytes = %d, want > 0", r.WireBytes)
	}
	if r.MinMS <= 0 || r.MinMS > r.MaxMS {
		t.Errorf("min/max = %v/%v", r.MinMS, r.MaxMS)
	}
	if r.P95MS < r.MedMS || r.P95MS > r.MaxMS {
		t.Errorf("p95 = %v outside med/max %v/%v", r.P95MS, r.MedMS, r.MaxMS)
	}
	if r.Path != pt.PathDirect || r.FallbackAttempted {
		t.Errorf("path = %q fallback_attempted=%v", r.Path, r.FallbackAttempted)
	}
	if r.Policy != string(pt.PolicyDirect) {
		t.Errorf("policy = %q", r.Policy)
	}
}

// TestPhaseConnectMeasuresColdDials: every sample of the connect phase must be
// a real dial. Dialing into an already live connection would report ~0 ms and
// is what a cached first-touch measurement silently does without draining.
func TestPhaseConnectMeasuresColdDials(t *testing.T) {
	c := newPerfCluster(t, 2)
	target := c.peers[1].ID
	direct := c.directAddrs(1)

	first, err := phaseConnect(context.Background(), c.peers[0], target, pt.PolicyDirect, direct, 4)
	if err != nil {
		t.Fatalf("phaseConnect: %v", err)
	}
	if first.N != 4 {
		t.Fatalf("n = %d, want 4", first.N)
	}
	// A cold dial costs something measurable; a cached no-op would not.
	if first.MaxMS <= 0 {
		t.Errorf("max = %v, want > 0", first.MaxMS)
	}
	t.Logf("connect cold dials: min=%.3f med=%.3f max=%.3f ms over %s", first.MinMS, first.MedMS, first.MaxMS, first.Endpoint)
}

// TestClosePeerConnsDrains: the drain used by the connect phase must really
// leave no connection behind, otherwise the next sample is a cached connect.
func TestClosePeerConnsDrains(t *testing.T) {
	c := newPerfCluster(t, 2)
	target := c.peers[1].ID

	_, err := phaseConnect(context.Background(), c.peers[0], target, pt.PolicyDirect, c.directAddrs(1), 1)
	if err != nil {
		t.Fatalf("phaseConnect: %v", err)
	}
	// phaseConnect leaves the last dial open by closing its own conn, but the
	// dialer config may still hold the connection open via keep-alive.
	if n := len(c.peers[0].Host.Network().ConnsToPeer(target)); n == 0 {
		t.Log("no live connection to drain; drain is a no-op here")
	}
	closePeerConns(c.peers[0], target, 3*time.Second)
	if n := len(c.peers[0].Host.Network().ConnsToPeer(target)); n != 0 {
		t.Fatalf("closePeerConns left %d connections to %s", n, target)
	}
}

// TestProbeTransferAcknowledgesBothOperations: one probe emits a PUT and a GET
// line, both acknowledged, both reporting the same actual path and policy.
func TestProbeTransferAcknowledgesBothOperations(t *testing.T) {
	c := newPerfCluster(t, 2)
	target := c.peers[1].ID
	const size int64 = 64 << 10

	res, err := probeTransfer(context.Background(), c.peers[0], target, pt.PolicyDirect, c.directAddrs(1), size)
	if err != nil {
		t.Fatalf("probeTransfer: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("probe emitted %d results, want 2", len(res))
	}
	put, get := res[0], res[1]
	if put.Operation != "put" || get.Operation != "get" {
		t.Fatalf("operations = %s,%s, want put,get", put.Operation, get.Operation)
	}
	for _, r := range []probeResult{put, get} {
		if r.Err != "" {
			t.Fatalf("operation %s failed: %s", r.Operation, r.Err)
		}
		if r.Bytes != size {
			t.Errorf("%s bytes = %d, want %d (acknowledged only)", r.Operation, r.Bytes, size)
		}
		if r.Match == nil || !*r.Match {
			t.Errorf("%s match = %v, want true", r.Operation, r.Match)
		}
		if r.Policy != string(pt.PolicyDirect) {
			t.Errorf("%s policy = %q", r.Operation, r.Policy)
		}
		if r.Path != pt.PathDirect {
			t.Errorf("%s path = %q", r.Operation, r.Path)
		}
		if r.Fallback || r.FallbackUpgraded {
			t.Errorf("%s fallback=%v fallback_upgraded=%v", r.Operation, r.Fallback, r.FallbackUpgraded)
		}
		if r.LatencyMS <= 0 {
			t.Errorf("%s latency_ms = %v, want > 0", r.Operation, r.LatencyMS)
		}
		if r.WireBytes < size {
			t.Errorf("%s wire_bytes = %d, want >= %d", r.Operation, r.WireBytes, size)
		}
		// Route evidence: the ACTUAL endpoints of the connection that carried
		// the operation, recorded from the connection itself.
		if !strings.Contains(r.RemoteMultiaddr, "/ip4/127.0.0.1/tcp/") {
			t.Errorf("%s remote_multiaddr = %q, want the real loopback endpoint", r.Operation, r.RemoteMultiaddr)
		}
		if !strings.Contains(r.LocalMultiaddr, "/ip4/127.0.0.1/tcp/") {
			t.Errorf("%s local_multiaddr = %q, want the real local endpoint", r.Operation, r.LocalMultiaddr)
		}
	}
	if put.Sha256 != get.Sha256 || put.Sha256 == "" {
		t.Errorf("shas %q / %q", put.Sha256, get.Sha256)
	}
}

// TestProbeTransferReportsFailureWithoutCounting: a rejected upload (the
// destination caps objects at 100 bytes) must be emitted as a failure with
// zero acknowledged bytes and a skipped GET — the object does not exist, so
// there is nothing to verify.
func TestProbeTransferReportsFailureWithoutCounting(t *testing.T) {
	c := newPerfCluster(t, 2, func(i int, cfg *pt.PeerConfig) {
		if i == 1 {
			cfg.MaxObjectBytes = 100
		}
	})
	const size int64 = 1024

	res, err := probeTransfer(context.Background(), c.peers[0], c.peers[1].ID, pt.PolicyDirect, c.directAddrs(1), size)
	if err != nil {
		t.Fatalf("probeTransfer: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("probe emitted %d results, want 1 (GET must be skipped after a failed PUT)", len(res))
	}
	put := res[0]
	if put.Err == "" {
		t.Fatalf("rejected upload reported no error: %+v", put)
	}
	if put.Bytes != 0 {
		t.Errorf("rejected upload counted %d acknowledged bytes", put.Bytes)
	}
	if put.Match == nil || *put.Match {
		t.Errorf("rejected upload match = %v, want false", put.Match)
	}
	if put.Path != pt.PathDirect {
		t.Errorf("the attempt still used a real connection; path must be reported, got %q", put.Path)
	}
	if !strings.Contains(put.Err, "HTTP") {
		t.Errorf("error %q does not name the HTTP status", put.Err)
	}
	if got := c.peers[1].Store.Keys(); len(got) != 0 {
		t.Errorf("rejected probe left %d objects in the store", len(got))
	}
}

// TestProbeTransferFallsBackAndLabelsIt: the same probe over an unreachable
// direct endpoint falls back to the relay, and the line must say so without
// conflating the attempt with the actual path.
func TestProbeTransferFallsBackAndLabelsIt(t *testing.T) {
	c := newPerfCluster(t, 2)
	const size int64 = 4096

	res, err := probeTransfer(context.Background(), c.peers[0], c.peers[1].ID, pt.PolicyDirectThenRelay, deadEndpoint(t), size)
	if err != nil {
		t.Fatalf("probeTransfer: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("probe emitted %d results, want 2", len(res))
	}
	for _, r := range res {
		if r.Err != "" {
			t.Fatalf("operation %s failed: %s", r.Operation, r.Err)
		}
		if !r.Fallback {
			t.Errorf("%s fallback = false, want true", r.Operation)
		}
		if r.Path != pt.PathCircuit {
			t.Errorf("%s path = %q, want %q", r.Operation, r.Path, pt.PathCircuit)
		}
		if r.FallbackUpgraded {
			t.Errorf("%s fallback_upgraded = true for a circuit path", r.Operation)
		}
		if r.Bytes != size {
			t.Errorf("%s bytes = %d, want %d", r.Operation, r.Bytes, size)
		}
	}
}

// TestEmitProbeIsJSONStable: the probe line is machine-consumed, so its keys
// must stay explicit and stable.
func TestEmitProbeIsJSONStable(t *testing.T) {
	r := probeResult{
		Time: "2026-01-01T00:00:00Z", Operation: "get", Remote: "peer",
		Policy: "direct-then-relay", Path: pt.PathCircuit,
		Fallback: true, Bytes: 4096, WireBytes: 4120,
		Sha256: "ab", Match: boolPtr(true), LatencyMS: 1.25,
		RemoteMultiaddr: "/ip4/1.2.3.4/tcp/44001/p2p/relay/p2p-circuit",
		LocalMultiaddr:  "/ip4/192.168.8.5/tcp/51000",
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)
	for _, key := range []string{
		`"time"`, `"op"`, `"remote"`, `"policy"`, `"path"`, `"fallback"`,
		`"fallback_upgraded"`, `"bytes"`, `"wire_bytes"`, `"sha256"`, `"match"`, `"latency_ms"`,
		`"remote_multiaddr"`, `"local_multiaddr"`,
	} {
		if !strings.Contains(got, key) {
			t.Errorf("probe line lacks key %s: %s", key, got)
		}
	}
	if strings.Contains(got, `"err"`) {
		t.Errorf("probe line must omit an empty err: %s", got)
	}

	// Historical lines without the endpoint keys still decode (additive change).
	legacy := []byte(`{"time":"t","op":"put","remote":"peer","policy":"direct","path":"direct","fallback":false,"fallback_upgraded":false,"bytes":1,"wire_bytes":1,"sha256":"ab","match":true,"latency_ms":1}`)
	var back probeResult
	if err := json.Unmarshal(legacy, &back); err != nil {
		t.Fatalf("legacy line unmarshal: %v", err)
	}
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Bytes != 4096 || back.WireBytes != 4120 || back.Path != pt.PathCircuit {
		t.Errorf("round trip changed the result: %+v", back)
	}
	if back.RemoteMultiaddr == "" || back.LocalMultiaddr == "" {
		t.Errorf("round trip lost the endpoint keys: %+v", back)
	}
}

// TestEmitPerfResultIsJSONStable: same contract for the perf phase line. The
// historical `endpoint` key keeps its meaning (remote multiaddr); the local
// side is additive.
func TestEmitPerfResultIsJSONStable(t *testing.T) {
	r := perfResult{
		Phase: "down", Policy: "direct-then-relay", Path: pt.PathDirect,
		FallbackAttempted: true, FallbackUpgraded: true,
		Endpoint:       "/ip4/1.2.3.4/tcp/44010",
		LocalMultiaddr: "/ip4/192.168.8.5/tcp/51000",
		N:              1, Bytes: 4096, WireBytes: 4120,
		MinMS: 1, MedMS: 1, P95MS: 1, MaxMS: 1, MBps: 2, Sha256: "ab",
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)
	for _, key := range []string{
		`"phase"`, `"policy"`, `"path"`, `"fallback_attempted"`, `"fallback_upgraded"`, `"endpoint"`,
		`"n"`, `"bytes"`, `"wire_bytes"`, `"min_ms"`, `"med_ms"`, `"p95_ms"`, `"max_ms"`, `"mbps"`, `"sha256"`,
		`"local_multiaddr"`,
	} {
		if !strings.Contains(got, key) {
			t.Errorf("perf line lacks key %s: %s", key, got)
		}
	}
	if strings.Contains(got, `"err"`) {
		t.Errorf("perf line must omit an empty err: %s", got)
	}

	// Historical perf lines without local_multiaddr still decode.
	legacy := []byte(`{"phase":"down","policy":"direct","path":"direct","fallback_attempted":false,"fallback_upgraded":false,"endpoint":"/ip4/1.2.3.4/tcp/44010","n":1,"bytes":1,"wire_bytes":1,"min_ms":1,"med_ms":1,"p95_ms":1,"max_ms":1,"mbps":1}`)
	var back perfResult
	if err := json.Unmarshal(legacy, &back); err != nil {
		t.Fatalf("legacy line unmarshal: %v", err)
	}
	if back.Endpoint != "/ip4/1.2.3.4/tcp/44010" || back.LocalMultiaddr != "" {
		t.Errorf("legacy perf line changed meaning: %+v", back)
	}
}

// TestPublicOnlyFlagRoleScope pins which roles accept -public-only; every
// other role must reject it loudly instead of silently ignoring it.
func TestPublicOnlyFlagRoleScope(t *testing.T) {
	for _, role := range []string{"peer", "perf"} {
		if !publicOnlyRoleOK(role) {
			t.Errorf("publicOnlyRoleOK(%q) = false, want true", role)
		}
	}
	for _, role := range []string{"relay", "control", "identity", "", "unknown"} {
		if publicOnlyRoleOK(role) {
			t.Errorf("publicOnlyRoleOK(%q) = true, want false", role)
		}
	}
}

// TestPerfPublicOnlyRefusesLoopbackDirect: a perf run with -public-only
// against a loopback direct endpoint must fail as a MEASUREMENT FAILURE (n=0,
// no path) — the gate refuses the non-public dial instead of measuring an
// overlay connection and calling it direct.
func TestPerfPublicOnlyRefusesLoopbackDirect(t *testing.T) {
	c := newPerfCluster(t, 2, func(_ int, cfg *pt.PeerConfig) {
		cfg.PublicOnly = true
		// The loopback relay is not dialable under public-only either.
		cfg.SkipRelayReservation = true
	})
	r, err := phaseConnect(context.Background(), c.peers[0], c.peers[1].ID, pt.PolicyDirect, c.directAddrs(1), 2)
	if err == nil {
		t.Fatalf("public-only perf measured a loopback direct connection: %+v", r)
	}
	if r.N != 0 {
		t.Errorf("rejected dials counted n=%d", r.N)
	}
	if r.Path != "" {
		t.Errorf("rejected phase reported path %q", r.Path)
	}
	if !strings.Contains(r.Err, "dial") {
		t.Errorf("error %q does not name the dial failure", r.Err)
	}
}
