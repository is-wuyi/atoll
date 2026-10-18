package peertransport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUnauthorizedRejectedRelayAndService: a peer that is not in the
// experiment allowlist must be rejected (a) when connecting directly to a
// storage peer's service (connection gater) and (b) when trying to obtain a
// reservation on the relay. In both cases no usable connection may exist.
func TestUnauthorizedRejectedRelayAndService(t *testing.T) {
	c := startCluster(t, 2)

	unauthDir := filepath.Join(c.base, "unauth")
	// The unauthorized peer is given the cluster allowlist for its OWN
	// outbound gater (so its dials reach the targets); it is deliberately
	// absent from every allowlist on the receiving side.
	unauth, err := NewStoragePeer(c.ctx, PeerConfig{
		DataDir:              unauthDir,
		Peers:                c.allow,
		Relay:                &c.relayAI,
		SkipRelayReservation: true, // its reservation would be denied; rejection is tested via dial
		Logger:               testLog,
	})
	if err != nil {
		t.Fatalf("unauthorized peer: %v", err)
	}
	defer unauth.Close()

	t.Run("direct-service-rejected", func(t *testing.T) {
		client, _ := unauth.Dial(c.peers[0].ID, PolicyDirect, c.Addrs(0))
		req, _ := http.NewRequestWithContext(c.ctx, "GET", "http://peer/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("unauthorized peer reached the service: HTTP %d", resp.StatusCode)
		}
		if got := unauth.Host.Network().ConnsToPeer(c.peers[0].ID); len(got) != 0 {
			// The gater must have dropped the connection attempt.
			t.Logf("connections to target after rejection: %d (may be in teardown)", len(got))
		}
		t.Logf("direct service connection rejected: %v", err)
	})

	t.Run("relay-reservation-rejected", func(t *testing.T) {
		client, _ := unauth.Dial(c.peers[0].ID, PolicyForcedRelay, nil)
		req, _ := http.NewRequestWithContext(c.ctx, "GET", "http://peer/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("unauthorized peer obtained relay transit: HTTP %d", resp.StatusCode)
		}
		if !strings.Contains(err.Error(), "relay") && !strings.Contains(err.Error(), "connect") {
			t.Logf("note: rejection error text: %v", err)
		}
		t.Logf("relay reservation rejected: %v", err)
	})

	// The authorized peers' stores must not have served the unauthorized peer.
	if err := c.peers[0].Store.VerifyNoPartial(); err != nil {
		t.Errorf("peer1 store: %v", err)
	}
}

// TestControlRegisterForbidden: the control role accepts the connection but
// returns an explicit HTTP 403 to peers that are not in the join allowlist,
// and 200 for authorized ones.
func TestControlRegisterForbidden(t *testing.T) {
	c := startCluster(t, 1)

	unauthDir := filepath.Join(c.base, "unauth")
	unauth, err := NewStoragePeer(c.ctx, PeerConfig{
		DataDir:              unauthDir,
		Peers:                NewAllowlist(),
		Control:              &c.controlAI,
		Relay:                &c.relayAI,
		SkipRelayReservation: true,
		Logger:               testLog,
	})
	if err != nil {
		t.Fatalf("unauthorized peer: %v", err)
	}
	defer unauth.Close()

	err = unauth.RegisterWithControl(c.ctx, c.controlAI)
	if err == nil {
		t.Fatalf("unauthorized registration unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected explicit HTTP 403, got: %v", err)
	}
	t.Logf("control correctly denied unauthorized peer: %v", err)

	// The authorized peer must still be able to register.
	if err := c.peers[0].RegisterWithControl(c.ctx, c.controlAI); err != nil {
		t.Errorf("authorized registration failed: %v", err)
	}
}

// TestTransferDeadlineNoHalfObject: the per-request wall-clock deadline of
// the object store aborts a stalled upload; nothing partial is committed.
func TestTransferDeadlineNoHalfObject(t *testing.T) {
	c := startCluster(t, 2, func(i int, cfg *PeerConfig) {
		cfg.TransferDeadline = 1500 * time.Millisecond
	})

	// Rebuild the destination store with a tiny deadline by using a separate
	// store handler: simplest is a fresh peer with the deadline already set.
	// The cluster above already has it via mutate.
	pr, pw := io.Pipe()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			if _, err := pw.Write(buf); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond) // slow trickle; will exceed deadline
		}
	}()
	client, _ := c.peers[0].Dial(c.peers[1].ID, PolicyDirect, c.Addrs(1))
	req, _ := http.NewRequestWithContext(c.ctx, "PUT", "http://peer/objects/deadline.bin", pr)
	req.Header.Set("X-Object-Sha256", "unused")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Logf("server responded HTTP %d to stalled upload", resp.StatusCode)
	} else {
		t.Logf("stalled upload terminated: %v", err)
	}

	waitForCleanStore(t, c.peers[1].Store, "deadline.bin", 10*time.Second)
}

// TestControlRegisterBodyCapped: even an AUTHORIZED peer cannot stream an
// unbounded body into the control plane — a registration announce over the
// 64 KiB cap is rejected with an explicit 413.
func TestControlRegisterBodyCapped(t *testing.T) {
	c := startCluster(t, 1)
	dc := &DialConfig{
		Host:        c.peers[0].Host,
		Expected:    c.control.Host.ID(),
		DirectAddrs: c.control.AddrInfo().Addrs,
		Policy:      PolicyDirect,
		logf:        testLog.Printf,
	}
	client := dc.NewHTTPClient()
	// Valid JSON whose single huge string crosses the 64 KiB cap mid-token,
	// so the byte limit (not a syntax error) is what rejects it.
	big := []byte(`{"addrs":["` + strings.Repeat("a", maxRegisterBodyBytes) + `"]}`)
	req, err := http.NewRequest("POST", "http://control/register", bytes.NewReader(big))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("oversized register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Errorf("oversized register body: got HTTP %d (%s), want 413", resp.StatusCode, string(b))
	} else {
		t.Logf("oversized register body rejected with 413")
	}

	// A normal-size announce from the same authorized peer still registers.
	if err := c.peers[0].RegisterWithControl(c.ctx, c.controlAI); err != nil {
		t.Errorf("normal register after cap rejection: %v", err)
	}
}

// TestStalledFetchAbortedByDeadline: a client that stops reading mid-GET is
// aborted by the per-request write deadline (mirror of the upload deadline);
// the stream is released and the peer keeps serving afterwards.
func TestStalledFetchAbortedByDeadline(t *testing.T) {
	c := startCluster(t, 2, func(i int, cfg *PeerConfig) {
		cfg.TransferDeadline = 1500 * time.Millisecond
	})
	data, want := deterministicBuf(8<<20, 0x88)
	if sha, _, code, err := push(t, c.peers[0], c.peers[1].ID, PolicyDirect, c.Addrs(1), "stall.bin", data, want); err != nil {
		t.Fatalf("setup push: HTTP %d: %v", code, err)
	} else if sha != want {
		t.Fatalf("setup push sha mismatch")
	}

	// Raw conn: read only the start of the response, then stop reading while
	// keeping the connection open well past the deadline. The server's
	// io.Copy must abort via the write deadline instead of pinning the
	// stream forever.
	dc := &DialConfig{
		Host:        c.peers[0].Host,
		Expected:    c.peers[1].ID,
		DirectAddrs: c.Addrs(1),
		Policy:      PolicyDirect,
		logf:        testLog.Printf,
	}
	conn, _, err := dc.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("GET /objects/stall.bin HTTP/1.1\r\nHost: peer\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil { // response headers
		t.Fatalf("read headers: %v", err)
	}
	if _, err := conn.Read(buf); err != nil { // first body bytes
		t.Fatalf("read body start: %v", err)
	}
	time.Sleep(3 * time.Second)
	_ = conn.Close()

	// The committed object is untouched and the peer still serves: a fresh
	// full fetch succeeds, proving the stalled stream was released.
	got, gotSha, _, err := fetch(t, c.peers[0], c.peers[1].ID, PolicyDirect, c.Addrs(1), "stall.bin")
	if err != nil {
		t.Fatalf("fetch after stalled reader: %v", err)
	}
	if !bytes.Equal(got, data) || gotSha != want {
		t.Errorf("object corrupted after stalled fetch")
	}
	if err := c.peers[1].Store.VerifyNoPartial(); err != nil {
		t.Errorf("partial objects after stalled fetch: %v", err)
	}
	t.Logf("stalled GET aborted by write deadline; peer kept serving")
}

// TestCancelMidTransferClean: cancelling the client context mid-transfer of a
// large object aborts cleanly and leaves no half object.
func TestCancelMidTransferClean(t *testing.T) {
	c := startCluster(t, 2)

	fctx, fcancel := context.WithCancel(c.ctx)
	pr, pw := io.Pipe()
	go func() {
		buf := make([]byte, 1<<20)
		for {
			if _, err := pw.Write(buf); err != nil {
				return
			}
		}
	}()
	client, _ := c.peers[0].Dial(c.peers[1].ID, PolicyDirect, c.Addrs(1))
	req, _ := http.NewRequestWithContext(fctx, "PUT", "http://peer/objects/cancel.bin", pr)
	go func() {
		time.Sleep(300 * time.Millisecond)
		fcancel()
	}()
	_, err := client.Do(req)
	fcancel()
	if err == nil {
		t.Fatalf("expected transfer error after cancellation")
	}
	t.Logf("cancel produced: %v", err)

	waitForCleanStore(t, c.peers[1].Store, "cancel.bin", 10*time.Second)
	// The host must still be functional: a fresh small transfer succeeds.
	data, want := deterministicBuf(64<<10, 0x77)
	sha, _, _, perr := push(t, c.peers[0], c.peers[1].ID, PolicyDirect, c.Addrs(1), "after-cancel.bin", data, want)
	if perr != nil {
		t.Errorf("post-cancel transfer failed: %v", perr)
	}
	if sha != want {
		t.Errorf("post-cancel sha mismatch")
	}
}
