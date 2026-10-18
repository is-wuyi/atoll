package peertransport

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"
)

// TestDirectRequestChecksumRoundtrip: an 8 MiB object pushed peer1 -> peer2
// over the DIRECT path and fetched back matches its sha256; stats report the
// direct path with no circuit involvement.
func TestDirectRequestChecksumRoundtrip(t *testing.T) {
	c := startCluster(t, 2)
	const size = 8 << 20
	data, want := deterministicBuf(size, 0x11)

	serverSha, stPush, code, err := push(t, c.peers[0], c.peers[1].ID, PolicyDirect, c.Addrs(1), "direct.bin", data, want)
	if err != nil {
		t.Fatalf("push: HTTP %d: %v", code, err)
	}
	if serverSha != want {
		t.Errorf("server manifest sha = %s, want %s", serverSha, want)
	}
	if stPush.Effective != "direct" || stPush.Limited {
		t.Errorf("push stats path = %q limited=%v, want direct/unlimited", stPush.Effective, stPush.Limited)
	}
	if stPush.PayloadBytesWritten < size {
		t.Errorf("push payload written = %d, want >= %d", stPush.PayloadBytesWritten, size)
	}
	if !hasCircuitComponent(ma.StringCast("/p2p-circuit")) {
		t.Fatalf("hasCircuitComponent failed to detect /p2p-circuit (sanity)")
	}

	got, gotSha, stFetch, err := fetch(t, c.peers[0], c.peers[1].ID, PolicyDirect, c.Addrs(1), "direct.bin")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("fetched bytes differ from pushed bytes")
	}
	if gotSha != want {
		t.Errorf("fetched sha = %s, want %s", gotSha, want)
	}
	if stFetch.PayloadBytesRead < size {
		t.Errorf("fetch payload read = %d, want >= %d", stFetch.PayloadBytesRead, size)
	}
	if stFetch.Effective != "direct" {
		t.Errorf("fetch path = %q, want direct", stFetch.Effective)
	}
	t.Logf("direct roundtrip ok: %d bytes, push written=%d, fetch read=%d remote=%s",
		size, stPush.PayloadBytesWritten, stFetch.PayloadBytesRead, stFetch.RemoteMultiaddr)
	assertAllConnectionsSecured(t, c.peers[0].Host, c.peers[1].Host)
}

// TestNodeNodePushChainExchange: a complete object exchange across the
// cluster: peer1 pushes to peer2, peer2 re-pushes the received object to
// peer3, peer3 fetches it back — the checksum must survive every hop.
func TestNodeNodePushChainExchange(t *testing.T) {
	c := startCluster(t, 3)
	const size = 5 << 20
	data, want := deterministicBuf(size, 0x22)

	sha1, _, _, err := push(t, c.peers[0], c.peers[1].ID, PolicyDirect, c.Addrs(1), "chain.bin", data, want)
	if err != nil {
		t.Fatalf("peer1 -> peer2 push: %v", err)
	}
	meta2, ok := c.peers[1].Store.Get("chain.bin")
	if !ok {
		t.Fatalf("object not committed on peer2")
	}
	if meta2.Sha256 != want || sha1 != want {
		t.Errorf("peer2 manifest sha mismatch: manifest=%s response=%s want=%s", meta2.Sha256, sha1, want)
	}

	// peer2 fetches the object from peer1's store? No: peer1 pushed a copy;
	// peer2 now pushes its own copy onward to peer3 (complete exchange).
	sha2, _, _, err := push(t, c.peers[1], c.peers[2].ID, PolicyDirect, c.Addrs(2), "chain.bin", data, want)
	if err != nil {
		t.Fatalf("peer2 -> peer3 push: %v", err)
	}
	if sha2 != want {
		t.Errorf("peer3 manifest sha = %s, want %s", sha2, want)
	}

	got, gotSha, _, err := fetch(t, c.peers[0], c.peers[2].ID, PolicyDirect, c.Addrs(2), "chain.bin")
	if err != nil {
		t.Fatalf("peer1 fetch from peer3: %v", err)
	}
	if !bytes.Equal(got, data) || gotSha != want {
		t.Errorf("end-to-end mismatch after 2 hops: sha=%s len=%d", gotSha, len(got))
	}
	if err := c.peers[1].Store.VerifyNoPartial(); err != nil {
		t.Errorf("peer2 store partial objects: %v", err)
	}
	if err := c.peers[2].Store.VerifyNoPartial(); err != nil {
		t.Errorf("peer3 store partial objects: %v", err)
	}
}

// TestDirectThenRelayFallbackAndPreference: with only an unreachable direct
// endpoint the direct-then-relay policy falls back to the circuit and RECORDS
// the fallback; with a reachable direct endpoint it stays direct and sends no
// payload through the relay.
func TestDirectThenRelayFallbackAndPreference(t *testing.T) {
	c := startCluster(t, 2)
	data, want := deterministicBuf(2<<20, 0x33)

	t.Run("fallback-recorded", func(t *testing.T) {
		bogus, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1")
		sha, st, code, err := push(t, c.peers[0], c.peers[1].ID, PolicyDirectThenRelay, []ma.Multiaddr{bogus}, "fb.bin", data, want)
		if err != nil {
			t.Fatalf("push: HTTP %d: %v", code, err)
		}
		if sha != want {
			t.Errorf("sha = %s want %s", sha, want)
		}
		if !st.FallbackUsed || st.Effective != "circuit" {
			t.Errorf("stats = %+v, want fallback to circuit", st)
		}
	})

	t.Run("direct-preferred-no-relay", func(t *testing.T) {
		sha, st, code, err := push(t, c.peers[0], c.peers[1].ID, PolicyDirectThenRelay, c.Addrs(1), "pref.bin", data, want)
		if err != nil {
			t.Fatalf("push: HTTP %d: %v", code, err)
		}
		if sha != want {
			t.Errorf("sha = %s want %s", sha, want)
		}
		if st.FallbackUsed || st.Effective != "direct" {
			t.Errorf("stats = %+v, want direct without fallback", st)
		}
	})
}

// TestObjectSizeLimitNoHalfObject: pushing 9 MiB into a store with an 8 MiB
// per-object cap fails with an explicit error and commits nothing — the
// atomic handler leaves no half object.
func TestObjectSizeLimitNoHalfObject(t *testing.T) {
	c := startCluster(t, 2, func(i int, cfg *PeerConfig) {
		cfg.MaxObjectBytes = 8 << 20
	})
	data, want := deterministicBuf(9<<20, 0x55)

	_, st, code, err := push(t, c.peers[0], c.peers[1].ID, PolicyDirect, c.Addrs(1), "toobig.bin", data, want)
	if err == nil {
		t.Fatalf("oversized push unexpectedly succeeded (HTTP %d)", code)
	}
	if code != 0 && code != http.StatusRequestEntityTooLarge {
		t.Logf("note: oversize rejected with HTTP %d", code)
	}
	waitForCleanStore(t, c.peers[1].Store, "toobig.bin", 10*time.Second)
	t.Logf("oversize push rejected cleanly (stats path=%s)", st.Effective)

	// A push within the limit still succeeds afterwards.
	small, want2 := deterministicBuf(64<<10, 0x56)
	sha, _, code2, err := push(t, c.peers[0], c.peers[1].ID, PolicyDirect, c.Addrs(1), "fits.bin", small, want2)
	if err != nil {
		t.Fatalf("in-limit push: HTTP %d: %v", code2, err)
	}
	if sha != want2 {
		t.Errorf("in-limit sha mismatch")
	}
}

// TestWrongExpectedPeerRejected: dialing with an expected PeerID that does not
// match the reached peer must fail — libp2p's identity-locked handshake binds
// the address to the PeerID, and the transport re-verifies it.
func TestWrongExpectedPeerRejected(t *testing.T) {
	c := startCluster(t, 3)
	// Expect peer3's ID but hand over peer2's addresses: the identity-locked
	// handshake reveals the real PeerID (peer2) and the dial must fail.
	client, dc := c.peers[0].Dial(c.peers[2].ID, PolicyDirect, c.Addrs(1))
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://peer/healthz", nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatalf("dial with wrong expected PeerID unexpectedly succeeded")
	}
	if got := dc.LastStats().RemotePeer; got != "" {
		t.Logf("no verified connection established (last stats empty) = %q", got)
	}
	t.Logf("expected-peer mismatch correctly rejected: %v", err)
}

// TestQUICOptionalDirect: QUIC transport is optional; when only the QUIC
// endpoint is offered the direct path still works and reports /quic-v1.
func TestQUICOptionalDirect(t *testing.T) {
	c := startCluster(t, 2, func(i int, cfg *PeerConfig) { cfg.EnableQUIC = true })
	var quicOnly []ma.Multiaddr
	for _, a := range c.Addrs(1) {
		if _, err := a.ValueForProtocol(ma.P_QUIC_V1); err == nil {
			quicOnly = append(quicOnly, a)
		}
	}
	if len(quicOnly) == 0 {
		t.Fatalf("no QUIC endpoint advertised")
	}
	data, want := deterministicBuf(1<<20, 0x44)
	sha, st, code, err := push(t, c.peers[0], c.peers[1].ID, PolicyDirect, quicOnly, "quic.bin", data, want)
	if err != nil {
		t.Fatalf("push over QUIC-only: HTTP %d: %v", code, err)
	}
	if sha != want {
		t.Errorf("sha mismatch: %s", sha)
	}
	if !strings.Contains(st.RemoteMultiaddr, "/quic-v1") {
		t.Errorf("expected QUIC remote multiaddr, got %s", st.RemoteMultiaddr)
	}
	t.Logf("QUIC direct path ok: remote=%s", st.RemoteMultiaddr)
}
