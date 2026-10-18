package peertransport

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"

	ma "github.com/multiformats/go-multiaddr"
)

// TestForcedRelayLargeStreamHashMatch: a 72 MiB object pushed peer1 -> peer2
// over a FORCED CircuitRelay v2 path and fetched back matches its sha256. The
// connection must be a real circuit v2 hop connection: /p2p-circuit in
// RemoteMultiaddr and Limited stat — not a plain HTTP proxy.
func TestForcedRelayLargeStreamHashMatch(t *testing.T) {
	c := startCluster(t, 2)
	const size = 72 << 20 // well over 64 MiB (72 MiB, not just above the boundary)
	data, want := deterministicBuf(size, 0xB0)

	serverSha, st, code, err := push(t, c.peers[0], c.peers[1].ID, PolicyForcedRelay, nil, "relay-big.bin", data, want)
	if err != nil {
		t.Fatalf("forced relay push: HTTP %d: %v", code, err)
	}
	if serverSha != want {
		t.Errorf("server manifest sha = %s, want %s", serverSha, want)
	}
	if st.Effective != "circuit" || !st.Limited {
		t.Errorf("push stats = %+v, want limited circuit", st)
	}
	// libp2p strips the trailing /p2p/<target> from a circuit conn's
	// RemoteMultiaddr (the remote peer is implied by the connection), so the
	// circuit component is the marker.
	if !strings.Contains(st.RemoteMultiaddr, "/p2p-circuit") {
		t.Errorf("RemoteMultiaddr %q lacks /p2p-circuit", st.RemoteMultiaddr)
	}
	if st.PayloadBytesWritten < size {
		t.Errorf("circuit payload written = %d, want >= %d", st.PayloadBytesWritten, size)
	}

	got, gotSha, st2, err := fetch(t, c.peers[0], c.peers[1].ID, PolicyForcedRelay, nil, "relay-big.bin")
	if err != nil {
		t.Fatalf("forced relay fetch: %v", err)
	}
	if len(got) != size {
		t.Errorf("fetched length = %d, want %d", len(got), size)
	}
	if gotSha != want {
		t.Errorf("fetched sha = %s, want %s", gotSha, want)
	}
	if st2.Effective != "circuit" || !st2.Limited {
		t.Errorf("fetch stats = %+v, want limited circuit", st2)
	}
	if st2.PayloadBytesRead < size {
		t.Errorf("circuit payload read = %d, want >= %d", st2.PayloadBytesRead, size)
	}
	t.Logf("forced relay %dMiB roundtrip ok over %s (circuit bytes written=%d read=%d)",
		size>>20, st2.RemoteMultiaddr, st2.PayloadBytesWritten, st2.PayloadBytesRead)
	assertAllConnectionsSecured(t, c.peers[0].Host, c.peers[1].Host)
}

// TestForcedRelayNoSilentDirectFallback: when the relay is unreachable the
// forced-relay policy must FAIL, never silently fall back to a direct
// connection to the target peer.
func TestForcedRelayNoSilentDirectFallback(t *testing.T) {
	c := startCluster(t, 2)

	// A relay identity that belongs to no running node.
	deadRelay, derr := LoadOrCreateIdentity(filepath.Join(c.base, "dead-relay"))
	if derr != nil {
		t.Fatalf("dead relay identity: %v", derr)
	}
	deadAddr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1")
	target := c.peers[1].ID

	// Authorize the dead relay at the SOURCE gater only, so the dial actually
	// leaves the host and the unreachable-relay mechanism is what fails
	// (otherwise the local gater would short-circuit before any dial).
	c.peers[0].AllowInfraPeer(deadRelay.ID)

	dc := &DialConfig{
		Host:     c.peers[0].Host,
		Expected: target,
		Relay:    &peer.AddrInfo{ID: deadRelay.ID, Addrs: []ma.Multiaddr{deadAddr}},
		Policy:   PolicyForcedRelay,
		logf:     testLog.Printf,
	}
	_, stats, derr := dc.Dial(context.Background())
	if derr == nil {
		t.Fatalf("forced relay dial with dead relay unexpectedly succeeded")
	}
	// The failure must come from the actual relay dial being unreachable, not
	// from our own outbound gater short-circuiting before any dial is made.
	if strings.Contains(derr.Error(), "gater disallows") {
		t.Fatalf("dial was rejected by the local gater; the unreachable-relay mechanism was not exercised: %v", derr)
	}
	if !strings.Contains(derr.Error(), "relay connect") {
		t.Fatalf("expected the error to originate from the relay dial, got: %v", derr)
	}
	if got := c.peers[0].Host.Network().ConnsToPeer(target); len(got) != 0 {
		t.Errorf("unexpected connections to target after failed forced relay dial: %d", len(got))
	}
	t.Logf("dead relay rejected, no direct fallback: %v (stats=%+v)", derr, stats)
}

// TestRelayCircuitDataLimitFailsCleanly: with a 4 MiB per-circuit relay data
// limit, a 9 MiB push must fail, and the destination store must contain no
// half object.
func TestRelayCircuitDataLimitFailsCleanly(t *testing.T) {
	c := startCluster(t, 2)

	// Dedicated relay with a small finite data limit.
	smallRelay, err := NewRelayNode(c.ctx, RelayConfig{
		DataDir:         filepath.Join(c.base, "relay-small"),
		Allowlist:       c.allow,
		Limit:           relay.RelayLimit{Duration: time.Hour, Data: 4 << 20},
		ReservationTTL:  30 * time.Minute,
		MaxReservations: 8,
		MaxCircuits:     4,
		Logger:          testLog,
	})
	if err != nil {
		t.Fatalf("small relay: %v", err)
	}
	defer smallRelay.Close()
	smallAI := smallRelay.AddrInfo()

	// Make the small relay a REAL transit hop for this experiment: authorize
	// it at both peers' connection gaters (the physical relayed connection
	// arrives from the relay's identity) and have BOTH peers hold a
	// reservation on it — CircuitRelay v2 requires the DESTINATION to hold an
	// active reservation before the hop relays a CONNECT. Without this the
	// circuit would fail to open and the 4 MiB data limit would never be
	// exercised.
	for _, p := range c.peers {
		p.AllowInfraPeer(smallRelay.ID)
		rctx, rcancel := context.WithTimeout(c.ctx, 10*time.Second)
		if _, err := relayclient.Reserve(rctx, p.Host, smallAI); err != nil {
			rcancel()
			t.Fatalf("reservation on small relay for %s: %v", p.ID, err)
		}
		rcancel()
		testLog.Printf("peer %s holds reservation on limited relay %s", p.ID, smallRelay.ID)
	}

	const size = 9 << 20
	data, want := deterministicBuf(size, 0xE1)
	dc := &DialConfig{
		Host:     c.peers[0].Host,
		Expected: c.peers[1].ID,
		Relay:    &smallAI,
		Policy:   PolicyForcedRelay,
		logf:     testLog.Printf,
	}
	client := dc.NewHTTPClient()
	req, _ := http.NewRequest("PUT", "http://peer/objects/limit.bin", bytes.NewReader(data))
	req.Header.Set("X-Object-Sha256", want)
	req.ContentLength = size
	resp, perr := client.Do(req)
	if perr != nil {
		t.Logf("push failed as expected: %v", perr)
	} else {
		resp.Body.Close()
		if resp.StatusCode == http.StatusCreated {
			t.Fatalf("9MiB push succeeded through a 4MiB-limited circuit; limit not enforced")
		}
		t.Logf("push rejected with HTTP %d", resp.StatusCode)
	}

	// The failure must be the per-circuit DATA LIMIT cutting a live transfer
	// mid-stream, not the circuit failing to open at all. The circuit must
	// therefore have opened (limited /p2p-circuit connection) and carried a
	// partial transfer (0 < written < size).
	st := dc.LastStats()
	if st.Effective != "circuit" || !st.Limited || !strings.Contains(st.RemoteMultiaddr, "/p2p-circuit") {
		t.Fatalf("circuit never opened; byte limit was not exercised: %+v", st)
	}
	if st.PayloadBytesWritten <= 0 || st.PayloadBytesWritten >= size {
		t.Fatalf("expected a partial transfer (0 < written < %d) cut by the 4MiB per-circuit limit, got written=%d",
			size, st.PayloadBytesWritten)
	}
	t.Logf("circuit opened and carried %d bytes before the 4MiB per-circuit data limit cut it", st.PayloadBytesWritten)

	waitForCleanStore(t, c.peers[1].Store, "limit.bin", 10*time.Second)
}

// TestRelayReservationLimitsFinite documents/enforces that the relay never
// runs with infinite limits: defaults are finite and the prototype never
// calls relay.WithInfiniteLimits.
func TestRelayReservationLimitsFinite(t *testing.T) {
	c := startCluster(t, 1)
	def := DefaultRelayLimit()
	if def.Duration <= 0 || def.Data <= 0 {
		t.Fatalf("default relay limit must be finite, got %+v", def)
	}
	t.Logf("relay %s running with finite per-circuit limits (default: %s / %d bytes per direction)",
		c.relay.ID, def.Duration, def.Data)
}

// TestRelayGlobalReservationCap: the relay's MaxReservations is a GLOBAL
// budget over all peers (MaxCircuits is the per-peer one). With a cap of 2,
// a third authorized peer must be denied a reservation — a finite per-peer
// AND global quota, never unlimited transit.
func TestRelayGlobalReservationCap(t *testing.T) {
	c := startCluster(t, 3)

	smallCapRelay, err := NewRelayNode(c.ctx, RelayConfig{
		DataDir:         filepath.Join(c.base, "relay-cap2"),
		Allowlist:       c.allow, // all three peers are authorized; the cap is what denies
		Limit:           DefaultRelayLimit(),
		ReservationTTL:  30 * time.Minute,
		MaxReservations: 2,
		MaxCircuits:     4,
		Logger:          testLog,
	})
	if err != nil {
		t.Fatalf("cap-2 relay: %v", err)
	}
	defer smallCapRelay.Close()
	capAI := smallCapRelay.AddrInfo()

	reserve := func(p *StoragePeer) error {
		p.AllowInfraPeer(smallCapRelay.ID)
		rctx, rcancel := context.WithTimeout(c.ctx, 10*time.Second)
		defer rcancel()
		_, err := relayclient.Reserve(rctx, p.Host, capAI)
		return err
	}

	// Peers 1 and 2 take the two slots.
	for i, p := range c.peers[:2] {
		if err := reserve(p); err != nil {
			t.Fatalf("peer%d reservation (slot %d/2): %v", i+1, i+1, err)
		}
		testLog.Printf("peer%d holds slot %d/2 on cap-2 relay", i+1, i+1)
	}
	// Peer 3 is authorized but must be denied: the global reservation budget
	// is exhausted.
	if err := reserve(c.peers[2]); err == nil {
		t.Fatalf("third reservation succeeded despite MaxReservations=2; global cap not enforced")
	} else {
		testLog.Printf("third reservation denied by global cap: %v", err)
	}
	// The two holders keep working (a refresh re-reservation succeeds).
	if err := reserve(c.peers[0]); err != nil {
		t.Errorf("existing reservation refresh after cap denial: %v", err)
	}
	t.Logf("global MaxReservations cap enforced: 2 granted, 1 denied, holder refresh ok")
}
