// Command demo runs the full phase-B network prototype topology on loopback:
//
//	1 control (bootstrap) role + 3 storage peers + 1 independent relay
//
// It exercises direct transport, forced CircuitRelay v2 transport
// (>64 MiB streams), direct-first-with-relay-fallback, authorization
// rejections (unauthorized peer on relay and service, wrong expected
// PeerID), transfer cancellation, and prints a JSON pass summary
// (path / checksums / counters — never keys or tokens).
//
// Everything runs on 127.0.0.1. WAN hole punching is NOT exercised.
package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"

	pt "atoll/prototypes/peertransport"
)

type Scenario struct {
	Name            string `json:"name"`
	Pass            bool   `json:"pass"`
	Transport       string `json:"transport,omitempty"`
	RemoteMultiaddr string `json:"remote_multiaddr,omitempty"`
	PayloadBytes    int64  `json:"payload_bytes,omitempty"`
	Sha256          string `json:"sha256,omitempty"`
	ExpectedSha256  string `json:"expected_sha256,omitempty"`
	Detail          string `json:"detail,omitempty"`
}

type PeerInfo struct {
	Role        string   `json:"role"`
	PeerID      string   `json:"peer_id"`
	Endpoints   []string `json:"endpoints"`
	IdentityDir string   `json:"identity_dir"`
}

type Summary struct {
	StartedAt string     `json:"started_at"`
	GoVersion string     `json:"go_version"`
	Libp2p    string     `json:"libp2p_version"`
	Peers     []PeerInfo `json:"peers"`
	Scenarios []Scenario `json:"scenarios"`
	Pass      bool       `json:"pass"`
}

func main() {
	fresh := flag.Bool("fresh", false, "wipe the demo state dir (new identities)")
	stateDir := flag.String("state", "", "identity + object state dir (default <logdir>/demo-state)")
	logDir := flag.String("logdir", "", "evidence log directory (default unique temp dir)")
	relayObjectBytes := flag.Int64("relay-object-bytes", 72<<20, "object size for the forced-relay scenario (>=70MiB, well over 64MiB)")
	flag.Parse()

	if *logDir == "" {
		created, err := os.MkdirTemp("", "atoll-peer-demo.XXXXXX")
		if err != nil {
			fatal("create log dir: %v", err)
		}
		*logDir = created
	}
	if *stateDir == "" {
		*stateDir = filepath.Join(*logDir, "demo-state")
	}
	if err := os.MkdirAll(*logDir, 0o755); err != nil {
		fatal("create log dir: %v", err)
	}
	logPath := filepath.Join(*logDir, "network-demo.log")
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fatal("open log: %v", err)
	}
	defer lf.Close()
	logger := log.New(io.MultiWriter(lf, os.Stderr), "[demo] ", log.LstdFlags|log.Lmicroseconds)
	logger.Printf("log dir %s", *logDir)
	logger.Printf("state dir %s", *stateDir)

	if *fresh {
		if err := os.RemoveAll(*stateDir); err != nil {
			fatal("wipe state: %v", err)
		}
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		fatal("create state dir: %v", err)
	}

	summary := Summary{
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		GoVersion: runtime.Version(),
		Libp2p:    moduleVersion("github.com/libp2p/go-libp2p"),
	}
	start := time.Now()
	defer func() {
		logger.Printf("demo finished in %s pass=%v", time.Since(start).Round(time.Millisecond), summary.Pass)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ---- identities (persisted; PeerIDs survive restarts) ----
	dirs := map[string]string{}
	for _, role := range []string{"relay", "control", "peer1", "peer2", "peer3", "peer4-unauth"} {
		dirs[role] = filepath.Join(*stateDir, role)
	}
	loadID := func(role string) *pt.Identity {
		i, err := pt.LoadOrCreateIdentity(dirs[role])
		if err != nil {
			fatal("identity %s: %v", role, err)
		}
		logger.Printf("role %s peer=%s identity=%s", role, i.ID, dirs[role])
		return i
	}
	idRelay, idControl := loadID("relay"), loadID("control")
	id1, id2, id3 := loadID("peer1"), loadID("peer2"), loadID("peer3")
	idUnauth := loadID("peer4-unauth") // created but intentionally not authorized

	// ---- relay (independent CircuitRelay v2 hop) ----
	relayNode, err := pt.NewRelayNode(ctx, pt.RelayConfig{
		DataDir:         dirs["relay"],
		Allowlist:       pt.NewAllowlist(id1.ID, id2.ID, id3.ID),
		Limit:           pt.DefaultRelayLimit(), // 1h / 256MiB per direction — finite, never WithInfiniteLimits
		ReservationTTL:  30 * time.Minute,
		MaxReservations: 16,
		MaxCircuits:     8,
		Logger:          logger,
	})
	if err != nil {
		fatal("relay: %v", err)
	}
	defer relayNode.Close()
	relayAI := relayNode.AddrInfo()
	logger.Printf("relay hop ready: %s", relayAI.ID)

	// ---- control / bootstrap role ----
	control, err := pt.NewControlNode(ctx, pt.ControlConfig{
		DataDir:       dirs["control"],
		Authorized:    pt.NewAllowlist(id1.ID, id2.ID, id3.ID),
		RelayAddrInfo: &relayAI,
		Logger:        logger,
	})
	if err != nil {
		fatal("control: %v", err)
	}
	defer control.Close()
	controlAI := control.AddrInfo()

	// ---- storage peers ----
	peerAllow := pt.NewAllowlist(id1.ID, id2.ID, id3.ID)
	mkPeer := func(name string) *pt.StoragePeer {
		p, err := pt.NewStoragePeer(ctx, pt.PeerConfig{
			DataDir:    dirs[name],
			EnableQUIC: true,
			Peers:      peerAllow,
			Control:    &controlAI,
			Relay:      &relayAI,
			Logger:     logger,
		})
		if err != nil {
			fatal("peer %s: %v", name, err)
		}
		if err := p.RegisterWithControl(ctx, controlAI); err != nil {
			fatal("peer %s register: %v", name, err)
		}
		return p
	}
	p1, p2, p3 := mkPeer("peer1"), mkPeer("peer2"), mkPeer("peer3")
	defer p1.Close()
	defer p2.Close()
	defer p3.Close()

	summary.Peers = append(summary.Peers,
		PeerInfo{Role: "relay", PeerID: idRelay.ID.String(), Endpoints: addrsOf(relayNode.Host), IdentityDir: dirs["relay"]},
		PeerInfo{Role: "control", PeerID: idControl.ID.String(), Endpoints: addrsOf(control.Host), IdentityDir: dirs["control"]},
		PeerInfo{Role: "peer1", PeerID: id1.ID.String(), Endpoints: p1.Endpoints(), IdentityDir: dirs["peer1"]},
		PeerInfo{Role: "peer2", PeerID: id2.ID.String(), Endpoints: p2.Endpoints(), IdentityDir: dirs["peer2"]},
		PeerInfo{Role: "peer3", PeerID: id3.ID.String(), Endpoints: p3.Endpoints(), IdentityDir: dirs["peer3"]},
	)
	_ = idUnauth

	// Endpoint registry as announced to control (PeerID -> mutable endpoints).
	reg := map[peer.ID][]ma.Multiaddr{}
	for _, p := range []struct {
		id   peer.ID
		peer *pt.StoragePeer
	}{{id1.ID, p1}, {id2.ID, p2}, {id3.ID, p3}} {
		reg[p.id] = p.peer.AddrInfo().Addrs
	}

	// ================= Scenario A: direct roundtrip =================
	{
		const size = 8 << 20
		data, want := deterministicBuf(size, 0xA1)
		client, dc := p1.Dial(id2.ID, pt.PolicyDirect, reg[id2.ID])
		sc := Scenario{Name: "direct-roundtrip-8MiB"}
		pushed, err := pushObject(ctx, client, "direct-a.bin", data, want)
		if err == nil {
			var got []byte
			var sha string
			got, sha, err = fetchObject(ctx, client, "direct-a.bin")
			if err == nil {
				err = compare(got, data)
				sc.Sha256, sc.ExpectedSha256 = sha, want
				if pushed != "" && pushed != want {
					err = fmt.Errorf("server-side sha %q != expected %q", pushed, want)
				}
				st := dc.LastStats()
				sc.Transport, sc.RemoteMultiaddr, sc.PayloadBytes = st.Effective, st.RemoteMultiaddr, st.PayloadBytesWritten+st.PayloadBytesRead
				if st.Effective != "direct" || st.Limited {
					err = fmt.Errorf("expected direct path, got %q limited=%v", st.Effective, st.Limited)
				}
			}
		}
		sc.Pass, sc.Detail = finish(err)
		summary.Scenarios = append(summary.Scenarios, sc)
	}

	// ================= Scenario B: forced relay, >64MiB =================
	{
		data, want := deterministicBuf(*relayObjectBytes, 0xB7)
		client, dc := p1.Dial(id3.ID, pt.PolicyForcedRelay, nil)
		sc := Scenario{Name: fmt.Sprintf("forced-relay-%dMiB", (*relayObjectBytes)>>20)}
		pushed, err := pushObject(ctx, client, "relay-b.bin", data, want)
		if err == nil {
			var got []byte
			var sha string
			got, sha, err = fetchObject(ctx, client, "relay-b.bin")
			if err == nil {
				err = compare(got, data)
				sc.Sha256, sc.ExpectedSha256 = sha, want
				if pushed != "" && pushed != want {
					err = fmt.Errorf("server-side sha %q != expected %q", pushed, want)
				}
				st := dc.LastStats()
				sc.Transport, sc.RemoteMultiaddr, sc.PayloadBytes = st.Effective, st.RemoteMultiaddr, st.PayloadBytesWritten+st.PayloadBytesRead
				// Must be a REAL CircuitRelay v2 connection: /p2p-circuit in
				// RemoteMultiaddr and Limited stat — not an HTTP proxy.
				if st.Effective != "circuit" || !st.Limited {
					err = fmt.Errorf("expected limited circuit path, got %q limited=%v", st.Effective, st.Limited)
				}
			}
		}
		sc.Pass, sc.Detail = finish(err)
		summary.Scenarios = append(summary.Scenarios, sc)
	}

	// ================= Scenario C: direct first, relay fallback =================
	{
		bogus, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1")
		data, want := deterministicBuf(2<<20, 0xC3)
		client, dc := p2.Dial(id3.ID, pt.PolicyDirectThenRelay, []ma.Multiaddr{bogus})
		sc := Scenario{Name: "direct-then-relay-fallback-2MiB"}
		_, err := pushObject(ctx, client, "fallback-c.bin", data, want)
		if err == nil {
			st := dc.LastStats()
			sc.Transport, sc.RemoteMultiaddr, sc.PayloadBytes = st.Effective, st.RemoteMultiaddr, st.PayloadBytesWritten
			if !st.FallbackUsed || st.Effective != "circuit" {
				err = fmt.Errorf("expected recorded fallback to circuit, got path=%q effective=%q fallback=%v",
					st.Path, st.Effective, st.FallbackUsed)
			}
		}
		sc.Pass, sc.Detail = finish(err)
		summary.Scenarios = append(summary.Scenarios, sc)

		// Direct reachable => stays direct (payload must not detour via relay).
		client2, dc2 := p2.Dial(id1.ID, pt.PolicyDirectThenRelay, reg[id1.ID])
		sc2 := Scenario{Name: "direct-first-preferred-2MiB"}
		_, err = pushObject(ctx, client2, "direct-first-c.bin", data, want)
		if err == nil {
			st := dc2.LastStats()
			sc2.Transport, sc2.RemoteMultiaddr, sc2.PayloadBytes = st.Effective, st.RemoteMultiaddr, st.PayloadBytesWritten
			if st.FallbackUsed || st.Effective != "direct" {
				err = fmt.Errorf("expected direct preferred, got path=%q effective=%q fallback=%v",
					st.Path, st.Effective, st.FallbackUsed)
			}
		}
		sc2.Pass, sc2.Detail = finish(err)
		summary.Scenarios = append(summary.Scenarios, sc2)
	}

	// ================= Scenario D: unauthorized peer rejected =================
	{
		sc := Scenario{Name: "unauthorized-peer-rejected"}
		var msgs []string
		unauth, err := pt.NewStoragePeer(ctx, pt.PeerConfig{
			DataDir: dirs["peer4-unauth"],
			// Outbound gater of the unauthorized peer lets it dial cluster
			// peers; it is deliberately absent from every RECEIVING allowlist.
			Peers:                peerAllow,
			Control:              &controlAI,
			Relay:                &relayAI,
			SkipRelayReservation: true, // its reservation would be denied anyway
			Logger:               logger,
		})
		if err != nil {
			fatal("unauth peer: %v", err)
		}

		// D1: registration at control => explicit 403.
		err = unauth.RegisterWithControl(ctx, controlAI)
		msgs = append(msgs, "register="+short(err))
		d1 := err != nil

		// D2: direct service connection => rejected by connection gater.
		c1, dc1 := unauth.Dial(id1.ID, pt.PolicyDirect, reg[id1.ID])
		_, derr := c1.Get("http://peer/healthz")
		_ = dc1
		msgs = append(msgs, "direct-service="+short(derr))
		d2 := derr != nil

		// D3: relay reservation => rejected (relay ACL + connection gater).
		c2, _ := unauth.Dial(id2.ID, pt.PolicyForcedRelay, nil)
		_, rerr := c2.Get("http://peer/healthz")
		msgs = append(msgs, "relay-reserve="+short(rerr))
		d3 := rerr != nil

		if d1 && d2 && d3 {
			sc.Pass, sc.Detail = true, "all rejected: "+strings.Join(msgs, "; ")
		} else {
			sc.Pass, sc.Detail = false, "unauthorized access unexpectedly succeeded: "+strings.Join(msgs, "; ")
		}
		_ = unauth.Close()
		summary.Scenarios = append(summary.Scenarios, sc)
	}

	// ================= Scenario E: wrong expected PeerID =================
	{
		sc := Scenario{Name: "wrong-expected-peerid-rejected"}
		client, _ := p1.Dial(id3.ID, pt.PolicyDirect, reg[id2.ID]) // expects p3, dials p2
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://peer/healthz", nil)
		_, err := client.Do(req)
		// The dial MUST fail: the identity-locked handshake binds the
		// address to peer2, so expecting peer3 is a hard rejection.
		if err != nil {
			sc.Pass, sc.Detail = true, "rejected as required: "+err.Error()
		} else {
			sc.Pass, sc.Detail = false, "dial with wrong expected PeerID unexpectedly succeeded"
		}
		summary.Scenarios = append(summary.Scenarios, sc)
	}

	// ================= Scenario F: cancellation leaves no half object =================
	{
		const size = 66 << 20
		fctx, fcancel := context.WithCancel(ctx)
		client, _ := p1.Dial(id2.ID, pt.PolicyDirect, reg[id2.ID])
		pr, pw := io.Pipe()
		firstWritten := make(chan struct{}, 1)
		go func() {
			buf := make([]byte, 1<<20)
			for i := 0; i < size>>20; i++ {
				if _, err := crand.Read(buf); err != nil {
					pw.CloseWithError(err)
					return
				}
				if _, err := pw.Write(buf); err != nil {
					pw.CloseWithError(err)
					return
				}
				if i == 0 {
					firstWritten <- struct{}{}
				}
			}
			pw.Close()
		}()
		req, _ := http.NewRequestWithContext(fctx, "PUT", "http://peer/objects/cancel-f.bin", pr)
		go func() {
			<-firstWritten
			fcancel() // abort mid-transfer, long before 66 MiB can complete
		}()
		_, err := client.Do(req)
		sc := Scenario{Name: "cancel-mid-transfer-clean"}
		// The destination cleans up asynchronously when the stream breaks;
		// give it a short grace period before asserting the invariant.
		clean := false
		for i := 0; i < 100; i++ {
			_, has := p2.Store.Get("cancel-f.bin")
			if !has && p2.Store.VerifyNoPartial() == nil {
				clean = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err == nil {
			sc.Pass, sc.Detail = false, "expected transfer error after cancel"
		} else if !clean {
			sc.Pass, sc.Detail = false, "half object stayed visible or uncommitted temp file remained"
		} else {
			sc.Pass, sc.Detail = true, "transfer aborted, no half object, store clean"
		}
		summary.Scenarios = append(summary.Scenarios, sc)
	}

	summary.Pass = true
	for _, s := range summary.Scenarios {
		if !s.Pass {
			summary.Pass = false
		}
	}

	out, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(out))
	if sf, err := os.OpenFile(filepath.Join(*logDir, "network-demo-summary.json"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
		_, _ = sf.Write(out)
		_ = sf.Close()
	}
	logger.Printf("summary written to %s", filepath.Join(*logDir, "network-demo-summary.json"))
	if !summary.Pass {
		os.Exit(1)
	}
}

// ===================== helpers =====================

func addrsOf(h host.Host) []string {
	out := []string{}
	for _, a := range h.Addrs() {
		out = append(out, a.String())
	}
	return out
}

func moduleVersion(mod string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, d := range bi.Deps {
		if d.Path == mod {
			return d.Version
		}
	}
	return "unknown"
}

// deterministicBuf builds n bytes of reproducible content (no crypto/rand, so
// runs and CI are comparable) plus its sha256.
func deterministicBuf(n int64, seed byte) ([]byte, string) {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = seed ^ byte(i*2654435761>>24)
	}
	sum := sha256.Sum256(buf)
	return buf, hex.EncodeToString(sum[:])
}

func pushObject(ctx context.Context, c *http.Client, key string, data []byte, sha string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "PUT", "http://peer/objects/"+key, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	if sha != "" {
		req.Header.Set("X-Object-Sha256", sha)
	}
	req.ContentLength = int64(len(data))
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("PUT %s: HTTP %d: %s", key, resp.StatusCode, string(body))
	}
	var meta struct {
		Sha256 string `json:"sha256"`
	}
	_ = json.Unmarshal(body, &meta)
	return meta.Sha256, nil
}

func fetchObject(ctx context.Context, c *http.Client, key string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://peer/objects/"+key, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("GET %s: HTTP %d: %s", key, resp.StatusCode, string(b))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

func compare(got, want []byte) error {
	if len(got) != len(want) {
		return fmt.Errorf("length mismatch: got %d want %d", len(got), len(want))
	}
	gs, ws := sha256.Sum256(got), sha256.Sum256(want)
	if gs != ws {
		return fmt.Errorf("sha256 mismatch: got %s want %s", hex.EncodeToString(gs[:]), hex.EncodeToString(ws[:]))
	}
	return nil
}

func finish(err error) (bool, string) {
	if err != nil {
		return false, err.Error()
	}
	return true, ""
}

func short(err error) string {
	if err == nil {
		return "<unexpectedly succeeded>"
	}
	s := err.Error()
	if len(s) > 140 {
		s = s[:140] + "..."
	}
	return s
}

func fatal(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "demo: "+f+"\n", args...)
	os.Exit(1)
}
