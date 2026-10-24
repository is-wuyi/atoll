package peertransport

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
)

// deadDirect is an unreachable direct endpoint: it makes the direct attempt
// fail deterministically without touching a real host or any remote address.
func deadDirect() []ma.Multiaddr {
	a, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1")
	if err != nil {
		panic(err)
	}
	return []ma.Multiaddr{a}
}

func dialWith(t *testing.T, p *StoragePeer, target peer.ID, policy DialPolicy, addrs []ma.Multiaddr) (TransferStats, error) {
	t.Helper()
	dc := &DialConfig{
		Host:          p.Host,
		Expected:      target,
		DirectAddrs:   addrs,
		Relay:         p.cfg.Relay,
		Policy:        policy,
		DirectTimeout: 2 * time.Second,
		logf:          testLog.Printf,
	}
	conn, st, err := dc.Dial(context.Background())
	if conn != nil {
		conn.Close()
	}
	return st, err
}

// resetPeerConns closes every connection from h to id and waits until none
// remain, so the next dial starts from a cold state. Policy dials otherwise
// inherit the previous subtest's live connection and "succeed" by reuse, which
// would hide a missing fallback.
func resetPeerConns(t *testing.T, h host.Host, id peer.ID) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conns := h.Network().ConnsToPeer(id)
		if len(conns) == 0 {
			return
		}
		for _, c := range conns {
			_ = c.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("connections to %s did not close", id)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestPolicyEnforcementLabelsAttemptAndPath separately: on loopback every policy
// must (a) establish the transport it was told to, (b) label the REQUESTED
// policy in Path, (c) record a relay attempt in FallbackUsed only when one
// happened, and (d) report the ACTUAL path in Effective.
func TestPolicyEnforcementLabelsAttemptAndPath(t *testing.T) {
	c := startCluster(t, 2)
	target := c.peers[1].ID
	direct := c.Addrs(1)

	t.Run("direct", func(t *testing.T) {
		resetPeerConns(t, c.peers[0].Host, target)
		st, err := dialWith(t, c.peers[0], target, PolicyDirect, direct)
		if err != nil {
			t.Fatalf("direct dial: %v", err)
		}
		assertPath(t, st, PolicyDirect, pathDirect, false, false)
		if strings.Contains(st.RemoteMultiaddr, "/p2p-circuit") {
			t.Errorf("direct path reported a circuit endpoint: %s", st.RemoteMultiaddr)
		}
	})

	t.Run("forced-relay", func(t *testing.T) {
		resetPeerConns(t, c.peers[0].Host, target)
		st, err := dialWith(t, c.peers[0], target, PolicyForcedRelay, nil)
		if err != nil {
			t.Fatalf("forced relay dial: %v", err)
		}
		// Forced relay makes no direct attempt, so FallbackUsed is false while
		// the path really is the circuit.
		assertPath(t, st, PolicyForcedRelay, pathCircuit, false, true)
		if !strings.Contains(st.RemoteMultiaddr, "/p2p-circuit") {
			t.Errorf("forced relay path lacks /p2p-circuit: %s", st.RemoteMultiaddr)
		}
	})

	t.Run("direct-then-relay prefers direct", func(t *testing.T) {
		resetPeerConns(t, c.peers[0].Host, target)
		st, err := dialWith(t, c.peers[0], target, PolicyDirectThenRelay, direct)
		if err != nil {
			t.Fatalf("direct-first dial: %v", err)
		}
		// The policy asked for a fallback option but none was needed.
		assertPath(t, st, PolicyDirectThenRelay, pathDirect, false, false)
	})

	t.Run("direct-then-relay records the fallback attempt", func(t *testing.T) {
		resetPeerConns(t, c.peers[0].Host, target)
		st, err := dialWith(t, c.peers[0], target, PolicyDirectThenRelay, deadDirect())
		if err != nil {
			t.Fatalf("fallback dial: %v", err)
		}
		// Attempt and path are distinct facts here: a relay attempt happened
		// AND the bytes really went over the circuit.
		assertPath(t, st, PolicyDirectThenRelay, pathCircuit, true, true)
	})
}

// assertPath checks the four independent facts a dial reports: requested policy,
// actual path, relay attempt, and whether the connection is Limited.
func assertPath(t *testing.T, st TransferStats, wantPolicy DialPolicy, wantEffective string, wantFallback, wantLimited bool) {
	t.Helper()
	if st.Path != string(wantPolicy) {
		t.Errorf("Path = %q, want the requested policy %q", st.Path, wantPolicy)
	}
	if st.Effective != wantEffective {
		t.Errorf("Effective = %q, want %q (stats=%+v)", st.Effective, wantEffective, st)
	}
	if st.FallbackUsed != wantFallback {
		t.Errorf("FallbackUsed = %v, want %v (stats=%+v)", st.FallbackUsed, wantFallback, st)
	}
	if st.Limited != wantLimited {
		t.Errorf("Limited = %v, want %v (stats=%+v)", st.Limited, wantLimited, st)
	}
}

// TestWrapStreamLabelsActualPathNotRequestedPath is the regression for the
// labeling defect: a relay dial must never report "circuit" for a connection
// that is actually direct. Observed on a real WAN run, the relay hop upgraded
// the circuit to a QUIC direct connection; on loopback that upgrade does not
// reproduce, so the label is asserted directly on a real upgraded-shaped stream
// instead of hoping a WAN timing shows up in CI.
func TestWrapStreamLabelsActualPathNotRequestedPath(t *testing.T) {
	c := startCluster(t, 2)
	target := c.peers[1].ID

	// A real DIRECT stream, wrapped as if it came from a relay attempt that
	// upgraded: this is exactly what dialRelay produces when the swarm
	// migrates the circuit to a direct connection.
	directDC := &DialConfig{
		Host: c.peers[0].Host, Expected: target, DirectAddrs: c.Addrs(1),
		Policy: PolicyDirect, logf: testLog.Printf,
	}
	directConn, _, err := directDC.Dial(context.Background())
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	defer directConn.Close()
	directStream := directConn.(*countingConn).Stream

	upgraded := wrapStream(directStream, PolicyDirectThenRelay, true)
	if upgraded.stats.Effective != pathDirect {
		t.Fatalf("upgraded direct connection labeled %q, want %q", upgraded.stats.Effective, pathDirect)
	}
	if !upgraded.stats.FallbackUsed {
		t.Errorf("relay attempt not recorded: %+v", upgraded.stats)
	}
	if upgraded.circuit {
		t.Errorf("upgraded connection must not be flagged as a circuit")
	}
	if upgraded.stats.Limited {
		t.Errorf("upgraded connection must not be flagged Limited: %+v", upgraded.stats)
	}

	// The other direction: a real CIRCUIT stream must not be relabeled "direct"
	// just because a policy asked for it.
	relayDC := &DialConfig{
		Host: c.peers[0].Host, Expected: target, Relay: &c.relayAI,
		Policy: PolicyForcedRelay, logf: testLog.Printf,
	}
	relayConn, _, err := relayDC.Dial(context.Background())
	if err != nil {
		t.Fatalf("relay dial: %v", err)
	}
	defer relayConn.Close()
	relayStream := relayConn.(*countingConn).Stream

	relabeled := wrapStream(relayStream, PolicyDirect, false)
	if relabeled.stats.Effective != pathCircuit {
		t.Fatalf("circuit connection labeled %q, want %q", relabeled.stats.Effective, pathCircuit)
	}
	if !relabeled.circuit {
		t.Errorf("circuit connection must be flagged as a circuit")
	}
	if !strings.Contains(relabeled.stats.RemoteMultiaddr, "/p2p-circuit") {
		t.Errorf("circuit endpoint lost its marker: %s", relabeled.stats.RemoteMultiaddr)
	}
}

// TestDirectPolicyNeverOpensACircuit: with only an unreachable direct endpoint
// the direct policy must fail, and it must not have opened a relay connection
// in the meantime. A failed direct measurement is a failure, not a circuit.
func TestDirectPolicyNeverOpensACircuit(t *testing.T) {
	c := startCluster(t, 2)
	target := c.peers[1].ID

	st, err := dialWith(t, c.peers[0], target, PolicyDirect, deadDirect())
	if err == nil {
		t.Fatalf("direct dial with an unreachable endpoint unexpectedly succeeded: %+v", st)
	}
	if st.Effective != "" {
		t.Errorf("failed dial must not report a path, got %q (stats=%+v)", st.Effective, st)
	}
	for _, conn := range c.peers[0].Host.Network().ConnsToPeer(target) {
		if hasCircuitComponent(conn.RemoteMultiaddr()) {
			t.Fatalf("direct policy opened a circuit connection: %s", conn.RemoteMultiaddr())
		}
	}
	if !strings.Contains(err.Error(), "direct") {
		t.Errorf("expected the error to name the direct attempt, got %v", err)
	}
}

// TestForcedRelayWithoutRelayIsExplicitError: a forced-relay policy without a
// relay endpoint fails with a cause that names the missing relay, never with a
// dial error that could be misread as a measurement.
func TestForcedRelayWithoutRelayIsExplicitError(t *testing.T) {
	c := startCluster(t, 2)
	dc := &DialConfig{
		Host: c.peers[0].Host, Expected: c.peers[1].ID,
		DirectAddrs: c.Addrs(1), Policy: PolicyForcedRelay, logf: testLog.Printf,
	}
	_, st, err := dc.Dial(context.Background())
	if err == nil {
		t.Fatalf("forced relay without a relay endpoint unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "relay endpoint not configured") {
		t.Errorf("expected the missing-relay cause, got %v", err)
	}
	if st.Effective != "" {
		t.Errorf("failed dial must not report a path: %+v", st)
	}
}

// TestLastStatsEmptyWhenNothingDialled: a DialConfig that never dialed reports
// an empty Effective. Measurement tooling must treat that as "nothing was
// transferred" rather than as a path — reading stats from an idle config is how
// a run can silently report empty paths and zero bytes as if it had measured.
func TestLastStatsEmptyWhenNothingDialled(t *testing.T) {
	c := startCluster(t, 2)
	dc := &DialConfig{
		Host: c.peers[0].Host, Expected: c.peers[1].ID,
		DirectAddrs: c.Addrs(1), Relay: &c.relayAI,
		Policy: PolicyDirectThenRelay, logf: testLog.Printf,
	}
	st := dc.LastStats()
	if st.Effective != "" {
		t.Fatalf("idle config reported path %q, want empty (stats=%+v)", st.Effective, st)
	}
	if st.Path != string(PolicyDirectThenRelay) {
		t.Errorf("idle config should still name the requested policy, got %q", st.Path)
	}
	if st.PayloadBytesWritten != 0 || st.PayloadBytesRead != 0 {
		t.Errorf("idle config reported traffic: written=%d read=%d", st.PayloadBytesWritten, st.PayloadBytesRead)
	}

	// ...and a real dial does fill it in.
	conn, _, err := dc.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	if got := dc.LastStats().Effective; got == "" {
		t.Errorf("dialled config still reports an empty path")
	}
}

// TestUnknownPolicyIsRejected: an unrecognised policy string is an error, not a
// silent downgrade to whichever path is reachable.
func TestUnknownPolicyIsRejected(t *testing.T) {
	c := startCluster(t, 2)
	dc := &DialConfig{
		Host: c.peers[0].Host, Expected: c.peers[1].ID,
		DirectAddrs: c.Addrs(1), Policy: DialPolicy("direct-then-relay-v2"), logf: testLog.Printf,
	}
	_, st, err := dc.Dial(context.Background())
	if err == nil {
		t.Fatalf("unknown policy unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "unknown dial policy") {
		t.Errorf("expected the unknown-policy cause, got %v", err)
	}
	if st.Effective != "" {
		t.Errorf("failed dial must not report a path: %+v", st)
	}
}
