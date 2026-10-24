// Command wanrunner runs ONE prototype role as a single long-lived process for
// cross-machine WAN verification — unlike cmd/demo (all roles in one process,
// loopback only).
//
// Roles:
//
//	wanrunner relay   -state DIR -announce /ip4/<public>/tcp/4001 [-allow-peer ID]...
//	wanrunner control -state DIR -announce /ip4/<public>/tcp/4000 [-relay /ip4/.../p2p/<relayID>]
//	wanrunner peer    -state DIR [-announce ...] -control <multiaddr-with-p2p>
//	                    [-relay <multiaddr-with-p2p>] [-allow-peer ID]... [-probe-every 30s]
//	                    [-no-mesh-direct] [-public-only]
//	wanrunner perf    -state DIR -target <peerID> [-direct-addr <multiaddr>]
//	                    [-relay <multiaddr-with-p2p>] [-policy direct|forced-relay|direct-then-relay]
//	                    [-rounds 20] [-bw-bytes N] [-direct-timeout 3s] [-public-only]
//
// Every role prints one JSON line on stdout at startup:
//
//	{"role":"peer","peer_id":"12D3...","addresses":["/ip4/.../tcp/..."],"public_only":true}
//
// (public_only is present only when -public-only is enabled.)
//
// The peer role registers with control, fetches the authorized peer list, then
// every -probe-every interval runs a transfer probe against each peer it can
// reach: PUT then GET of a small + a large probe object, direct-first with
// relay fallback, recording one JSON result line per probe (policy, path,
// fallback attempt, bytes, checksum match, and the ACTUAL remote/local
// multiaddr of the connection that carried the operation). Never prints keys
// or tokens.
//
// -public-only (peer/perf) enables the peertransport public-endpoint
// connection gate: dials and accepts are limited to real public IP endpoints
// (loopback, RFC1918, CGNAT 100.64/10, link-local, IPv6 ULA/link-local and DNS
// names are refused in every direction; a circuit path is judged by its first
// public relay endpoint). Endpoints re-learned by identify or dialed by DCUtR
// hit the same gate, so no private dial side effects exist. It proves the
// route stayed on public endpoints — it does NOT by itself prove a direct
// (non-circuit) connection succeeded; the actual non-circuit path and OS route
// are only what the recorded connection endpoints of a run show.
//
// The perf role measures ONE target on ONE explicitly requested policy and
// exits. Four phases, one JSON line each: connect (first-touch path cost, cold
// dial every round), request (steady-state request latency over a kept-open
// connection), up (one acknowledged upload), down (one checksum-verified
// download). An operation counts only when it is acknowledged: an upload needs
// HTTP 201 plus a server manifest whose sha256 and size match what was sent;
// a download needs a length and sha256 that match the upload. Payload
// generation and the warm-up request are outside every timer. Any failure is
// reported with a structured error and the process exits non-zero, so a failed
// run can never be read as a successful one.
//
// Path labels are facts about a connection, not about intent, and the three
// must not be collapsed: `policy` is what was requested, `fallback_attempted`
// records that a relay hop was tried, and `path` is what the connection
// actually was ("direct" or "circuit"). A relay attempt whose connection
// upgraded to a direct one reports path="direct" with fallback_attempted=true
// (fallback_upgraded=true). "direct" proves only non-circuit — it is NOT proof of
// a non-overlay link, because a direct connection can still ride an overlay
// network (LAN mesh, VPN).
//
// This is still the PROTOTYPE module — no production wiring, no deployment.
// The numbers it prints are only as strong as the loopback regression that
// exercises the same code paths; no real WAN/NAT traversal result is claimed
// here.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"

	pt "atoll/prototypes/peertransport"
)

type roleInfo struct {
	Role      string   `json:"role"`
	PeerID    string   `json:"peer_id"`
	Addresses []string `json:"addresses"`
	// PublicOnly is true when the role started with the public-endpoint
	// connection gate enabled (-public-only). Omitted when false so the
	// historical identity line is byte-for-byte unchanged.
	PublicOnly bool `json:"public_only,omitempty"`
}

func announceJSON(role string, id peer.ID, addrs []ma.Multiaddr, publicOnly bool) {
	out := roleInfo{Role: role, PeerID: id.String(), Addresses: make([]string, 0, len(addrs)), PublicOnly: publicOnly}
	for _, a := range addrs {
		out.Addresses = append(out.Addresses, a.String())
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func parseMultiaddr(s string) (ma.Multiaddr, error) {
	return ma.NewMultiaddr(s)
}

func parseAddrInfo(s string) (peer.AddrInfo, error) {
	a, err := parseMultiaddr(s)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("invalid multiaddr %q: %w", s, err)
	}
	ai, err := peer.AddrInfoFromP2pAddr(a)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("multiaddr %q has no /p2p/ peer: %w", s, err)
	}
	return *ai, nil
}

// parsePolicy maps the -policy flag to a DialPolicy. An unknown value is a
// hard error: silently downgrading a typo to direct-then-relay would make a
// forced-relay measurement report whichever path happened to be reachable.
func parsePolicy(s string) (pt.DialPolicy, error) {
	switch s {
	case "direct":
		return pt.PolicyDirect, nil
	case "forced-relay":
		return pt.PolicyForcedRelay, nil
	case "direct-then-relay":
		return pt.PolicyDirectThenRelay, nil
	}
	return "", fmt.Errorf("unknown -policy %q (want direct, forced-relay or direct-then-relay)", s)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wanrunner relay|control|peer|perf [flags]")
		os.Exit(2)
	}
	role := os.Args[1]
	fs := flag.NewFlagSet("wanrunner "+role, flag.ExitOnError)
	state := fs.String("state", "", "identity + object state dir (required)")
	listenIP := fs.String("listen-ip", "0.0.0.0", "listen IP")
	listenPort := fs.Int("listen-port", 0, "listen port (0 = random; must match the announced port unless NAT port-forwarding maps it)")
	var announce []ma.Multiaddr
	fs.Var(&multiaddrSlice{&announce}, "announce", "public multiaddr to announce (repeatable)")
	quic := fs.Bool("quic", true, "also listen on QUIC")
	// 各角色的专属 flags 都在这里注册（ExitOnError 在第一遍 Parse 时就要认识它们）。
	relayAddr := addrInfoFlag(fs, "relay", "relay multiaddr with /p2p/<relayID> (control advertises it)")
	controlAddr := addrInfoFlag(fs, "control", "control multiaddr with /p2p/<controlID> (peer role)")
	allowed := peerIDSliceFlag(fs, "allow-peer", "authorized PeerID (repeatable)")
	probeEvery := fs.Duration("probe-every", 30*time.Second, "probe interval; 0 = register and idle")
	noMesh := fs.Bool("no-mesh-direct", false, "drop overlay-routable endpoints from probe direct dials (force the relay path on an overlaid mesh)")
	publicOnly := fs.Bool("public-only", false, "仅允许公网端点建连（peer/perf 专用）：拒绝 loopback/RFC1918/CGNAT 100.64/10/链路本地/IPv6 ULA/DNS 的拨号与入站，circuit 按 relay 首个公网端点判定；默认 false 保持历史行为")
	perfTarget := fs.String("target", "", "perf: target PeerID")
	perfDirect := fs.String("direct-addr", "", "perf: target direct multiaddr")
	perfPolicy := fs.String("policy", "direct-then-relay", "perf: direct|forced-relay|direct-then-relay (enforced, never downgraded)")
	perfRounds := fs.Int("rounds", 20, "perf: latency rounds per phase")
	perfBW := fs.Int64("bw-bytes", 16<<20, "perf: bandwidth payload size (bytes); 0 skips the up/down phases")
	perfDirectTimeout := fs.Duration("direct-timeout", 3*time.Second, "perf: bound on each direct dial attempt (direct-then-relay)")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if *state == "" {
		fmt.Fprintln(os.Stderr, "wanrunner: -state is required")
		os.Exit(2)
	}
	// -public-only 是端到端验证用的门，不是各角色通用开关：relay/control 的
	// 连接策略不同（relay 必须接受保留请求），误用直接拒绝，绝不静默忽略。
	if *publicOnly && !publicOnlyRoleOK(role) {
		fmt.Fprintf(os.Stderr, "wanrunner %s: -public-only 仅支持 peer/perf 角色\n", role)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if role == "perf" {
		// Latency + bandwidth measurement against one target, one explicitly
		// requested policy, four phases with acknowledged-byte accounting.
		// Emits one JSON line per phase and exits non-zero on any failure.
		runPerf(ctx, *state, *listenIP, *listenPort, announce, *perfTarget, *perfDirect,
			relayAIString(relayAddr), *perfPolicy, *perfRounds, *perfBW, *perfDirectTimeout, *publicOnly)
		return
	}

	if role == "identity" {
		// Offline helper: print the PeerID stored in -state without networking
		// (operator workflow: create identity first, share PeerID, then the
		// admin authorizes it before the role starts).
		if *state == "" {
			fmt.Fprintln(os.Stderr, "wanrunner identity: -state is required")
			os.Exit(2)
		}
		id, err := pt.LoadOrCreateIdentity(*state)
		if err != nil {
			log.Fatalf("identity: %v", err)
		}
		announceJSON("identity", id.ID, nil, false)
		return
	}

	switch role {
	case "relay":
		runRelay(ctx, *state, *listenIP, *listenPort, announce, *quic, *allowed)
	case "control":
		runControl(ctx, *state, *listenIP, *listenPort, announce, *quic, relayAddr, *allowed)
	case "peer":
		runPeer(ctx, *state, *listenIP, *listenPort, announce, *quic, controlAddr, relayAddr, *allowed, *probeEvery, *noMesh, *publicOnly)
	default:
		fmt.Fprintf(os.Stderr, "wanrunner: unknown role %q\n", role)
		os.Exit(2)
	}
}

// publicOnlyRoleOK pins which roles accept -public-only (peer/perf); every
// other role must reject the flag loudly instead of silently ignoring it.
func publicOnlyRoleOK(role string) bool { return role == "peer" || role == "perf" }

type multiaddrSlice struct{ list *[]ma.Multiaddr }

func (m multiaddrSlice) String() string { return "" }
func (m multiaddrSlice) Set(s string) error {
	a, err := parseMultiaddr(s)
	if err != nil {
		return fmt.Errorf("-announce: %w", err)
	}
	*m.list = append(*m.list, a)
	return nil
}

func peerIDSliceFlag(fs *flag.FlagSet, name, usage string) *[]peer.ID {
	out := new([]peer.ID)
	fs.Var(&peerIDSlice{out}, name, usage)
	return out
}

type peerIDSlice struct{ list *[]peer.ID }

func (m peerIDSlice) String() string { return "" }
func (m peerIDSlice) Set(s string) error {
	id, err := peer.Decode(s)
	if err != nil {
		return fmt.Errorf("invalid PeerID %q: %w", s, err)
	}
	*m.list = append(*m.list, id)
	return nil
}

func addrInfoFlag(fs *flag.FlagSet, name, usage string) *peer.AddrInfo {
	out := new(peer.AddrInfo)
	fs.Var(&addrInfoValue{out}, name, usage)
	return out
}

type addrInfoValue struct{ ai *peer.AddrInfo }

func (v addrInfoValue) String() string { return "" }
func (v addrInfoValue) Set(s string) error {
	ai, err := parseAddrInfo(s)
	if err != nil {
		return fmt.Errorf("%s: %w", "multiaddr with /p2p/", err)
	}
	*v.ai = ai
	return nil
}

// relayAIString flattens a parsed -relay flag to <addr>/p2p/<relayID>.
func relayAIString(ai *peer.AddrInfo) string {
	if ai == nil || ai.ID == "" || len(ai.Addrs) == 0 {
		return ""
	}
	return ai.Addrs[0].String() + "/p2p/" + ai.ID.String()
}

// ============================ perf role ============================

// perfFailure is one structured measurement failure: which phase, which
// operation, which round, which path was in effect, and why. It never
// contains payloads, object keys, or credentials.
type perfFailure struct {
	Phase             string
	Op                string
	Round             int
	Path              string
	FallbackAttempted bool
	Err               error
}

func (f *perfFailure) Error() string {
	return fmt.Sprintf("perf phase %q op %q round %d (path=%q fallback_attempted=%v): %v",
		f.Phase, f.Op, f.Round, f.Path, f.FallbackAttempted, f.Err)
}

// perfResult is one JSON line per measurement phase on stdout.
type perfResult struct {
	// Phase is connect | request | up | down.
	Phase string `json:"phase"`
	// Policy is the REQUESTED dial policy.
	Policy string `json:"policy"`
	// Path is the path the used connection really was: "direct" or "circuit".
	// It is derived from the connection, never from the policy.
	Path string `json:"path"`
	// FallbackAttempted is true when a relay (circuit) attempt was made.
	FallbackAttempted bool `json:"fallback_attempted"`
	// FallbackUpgraded is true when a relay attempt connected but the connection
	// ended up direct; then path is "direct" and fallback_attempted is true.
	FallbackUpgraded bool `json:"fallback_upgraded"`
	// Endpoint is the used connection's remote multiaddr (a public endpoint,
	// not a secret). Kept as-is for JSON compatibility with existing perf
	// records; the local side was added as local_multiaddr below.
	Endpoint string `json:"endpoint,omitempty"`
	// LocalMultiaddr is the used connection's actual local endpoint (route
	// evidence alongside endpoint). Additive: omitted when unset.
	LocalMultiaddr string `json:"local_multiaddr,omitempty"`
	// N counts ONLY successful operations; failures are excluded from N and
	// from the latency distribution.
	N int `json:"n"`
	// Bytes are acknowledged bytes: the server-confirmed upload size, or the
	// checksum-verified download length. Zero when nothing succeeded.
	Bytes int64 `json:"bytes"`
	// WireBytes is what the transport counted on the stream (payload plus HTTP
	// framing), so protocol overhead stays visible next to the payload.
	WireBytes int64   `json:"wire_bytes"`
	MinMS     float64 `json:"min_ms"`
	MedMS     float64 `json:"med_ms"`
	P95MS     float64 `json:"p95_ms"`
	MaxMS     float64 `json:"max_ms"`
	// MBps is MiB/s over the measured window.
	MBps float64 `json:"mbps"`
	// Sha256 is the verified content hash (up and down phases).
	Sha256 string `json:"sha256,omitempty"`
	// Err is set when the phase had failures.
	Err string `json:"err,omitempty"`
}

// perfSpec is one validated perf run.
type perfSpec struct {
	target        peer.ID
	policy        pt.DialPolicy
	directAddrs   []ma.Multiaddr
	relay         *peer.AddrInfo
	rounds        int
	bwBytes       int64
	directTimeout time.Duration
}

// validatePerfFlags turns the raw perf flags into a spec, rejecting anything
// that would make a dial error look like a measurement. It is pure (no host is
// started) so it can be tested directly.
func validatePerfFlags(targetID, directAddr, relayAddr, policy string, rounds int, bwBytes int64, directTimeout time.Duration) (perfSpec, error) {
	spec := perfSpec{rounds: rounds, bwBytes: bwBytes, directTimeout: directTimeout}
	tid, err := peer.Decode(targetID)
	if err != nil {
		return spec, fmt.Errorf("invalid -target %q: %w", targetID, err)
	}
	pol, err := parsePolicy(policy)
	if err != nil {
		return spec, err
	}
	if rounds < 1 {
		return spec, fmt.Errorf("-rounds must be >= 1 (got %d)", rounds)
	}
	if bwBytes < 0 {
		return spec, fmt.Errorf("-bw-bytes must be >= 0 (got %d)", bwBytes)
	}
	if bwBytes > 0 && bwBytes < 1024 {
		return spec, fmt.Errorf("-bw-bytes must be >= 1024, or 0 to skip the up/down phases")
	}
	if directTimeout <= 0 {
		return spec, fmt.Errorf("-direct-timeout must be > 0 (got %s)", directTimeout)
	}
	if directAddr != "" {
		a, err := ma.NewMultiaddr(directAddr)
		if err != nil {
			return spec, fmt.Errorf("invalid -direct-addr %q: %w", directAddr, err)
		}
		spec.directAddrs = []ma.Multiaddr{a}
	}
	if relayAddr != "" {
		ai, err := parseAddrInfo(relayAddr)
		if err != nil {
			return spec, fmt.Errorf("invalid -relay %q: %w", relayAddr, err)
		}
		spec.relay = &ai
	}
	// A policy is only meaningful together with the endpoint it needs; refusing
	// here keeps an operator from reading a dial error as a measurement.
	if pol == pt.PolicyForcedRelay && spec.relay == nil {
		return spec, fmt.Errorf("-policy forced-relay requires -relay")
	}
	if pol != pt.PolicyForcedRelay && spec.directAddrs == nil {
		return spec, fmt.Errorf("-policy %s requires -direct-addr", policy)
	}
	spec.target, spec.policy = tid, pol
	return spec, nil
}

// runPerf validates the flags, then runs the four phases in order. It is the
// only function that exits: usage and validation errors exit 2, measurement
// failures exit 1 via log.Fatalf.
func runPerf(ctx context.Context, state, listenIP string, listenPort int, announce []ma.Multiaddr, targetID, directAddr, relayAddr, policy string, rounds int, bwBytes int64, directTimeout time.Duration, publicOnly bool) {
	if publicOnly {
		log.Printf("public-only 已启用：仅公网端点可建连；非公网直连端点（loopback/私网/CGNAT/DNS）会在连接门处被拒绝并计为失败，绝不产生私网拨号")
	}
	spec, err := validatePerfFlags(targetID, directAddr, relayAddr, policy, rounds, bwBytes, directTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wanrunner perf: %v\n", err)
		os.Exit(2)
	}
	p, err := pt.NewStoragePeer(ctx, pt.PeerConfig{
		DataDir:       state,
		EnableQUIC:    true,
		Peers:         pt.NewAllowlist(spec.target),
		Control:       nil,
		Relay:         spec.relay,
		ListenIP:      listenIP,
		ListenPort:    listenPort,
		AnnounceAddrs: announce,
		DirectTimeout: spec.directTimeout,
		PublicOnly:    publicOnly,
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatalf("perf: %v", err)
	}
	defer p.Close()

	emitPhase := func(r *perfResult, err error) {
		if err != nil {
			r.Err = err.Error()
		}
		_ = json.NewEncoder(os.Stdout).Encode(r)
	}

	// Phase 1: connect. First-touch path cost, measured on a torn-down
	// connection set so every sample is a real dial rather than a cached
	// no-op connect. No HTTP request is made here.
	r, err := phaseConnect(ctx, p, spec.target, spec.policy, spec.directAddrs, spec.rounds)
	emitPhase(&r, err)
	if err != nil {
		log.Fatalf("perf: %v", err)
	}

	// Phase 2: request. Steady-state request latency over one kept-open
	// connection; the dial cost is already measured by phase 1 and the first
	// request is a discarded warm-up.
	r, err = phaseRequest(ctx, p, spec.target, spec.policy, spec.directAddrs, spec.rounds, 1024)
	emitPhase(&r, err)
	if err != nil {
		log.Fatalf("perf: %v", err)
	}

	if spec.bwBytes == 0 {
		log.Printf("perf complete: policy=%s rounds=%d bw_bytes=0 (up/down phases skipped)", spec.policy, spec.rounds)
		return
	}

	// The payload is generated BEFORE any timer starts: entropy cost is not
	// upload throughput. The same key and bytes are uploaded then downloaded,
	// so the download can be verified against the upload.
	payload, want, err := makePayload(spec.bwBytes)
	if err != nil {
		log.Fatalf("perf: %v", err)
	}
	key := newKey("perf-bw")

	// Phase 3: up. One upload, counted only if the server acknowledges those
	// exact bytes.
	r, err = phaseUpload(ctx, p, spec.target, spec.policy, spec.directAddrs, spec.bwBytes, key, payload, want)
	emitPhase(&r, err)
	if err != nil {
		log.Fatalf("perf: %v", err)
	}

	// Phase 4: down. One download, counted only if length and sha256 match
	// the upload. A wrong or truncated body is a failure, not a download.
	r, err = phaseDownload(ctx, p, spec.target, spec.policy, spec.directAddrs, spec.bwBytes, key, want)
	emitPhase(&r, err)
	if err != nil {
		log.Fatalf("perf: %v", err)
	}
	log.Printf("perf complete: policy=%s rounds=%d bw_bytes=%d path=%s", spec.policy, spec.rounds, spec.bwBytes, r.Path)
}

// phaseConnect measures path establishment for the requested policy. Every
// round starts from a torn-down connection set, so each sample is a real
// first-touch dial.
func phaseConnect(ctx context.Context, p *pt.StoragePeer, tid peer.ID, policy pt.DialPolicy, addrs []ma.Multiaddr, rounds int) (perfResult, error) {
	res := perfResult{Phase: "connect", Policy: string(policy)}
	lat := make([]float64, 0, rounds)
	var firstErr error
	for i := 0; i < rounds; i++ {
		closePeerConns(p, tid, 5*time.Second)
		_, dc := p.Dial(tid, policy, addrs)
		start := time.Now()
		conn, st, err := dc.Dial(ctx)
		if err != nil {
			if firstErr == nil {
				firstErr = &perfFailure{Phase: res.Phase, Op: "dial", Round: i + 1, Path: st.Effective, FallbackAttempted: st.FallbackUsed, Err: err}
			}
			continue
		}
		if st.Effective == "" {
			if firstErr == nil {
				firstErr = &perfFailure{Phase: res.Phase, Op: "dial", Round: i + 1, Err: errors.New("dialer recorded no connection")}
			}
			if conn != nil {
				_ = conn.Close()
			}
			continue
		}
		_ = conn.Close()
		lat = append(lat, ms(time.Since(start)))
		refreshPath(&res, st)
	}
	setQuantiles(&res, lat)
	if firstErr != nil {
		res.Err = firstErr.Error()
	}
	return res, firstErr
}

// phaseRequest measures small-object REQUEST latency over one kept-open
// connection (HTTP keep-alive). The first PUT opens the connection and is
// discarded as a warm-up, so the reported distribution is steady-state
// request time with no dial cost.
func phaseRequest(ctx context.Context, p *pt.StoragePeer, tid peer.ID, policy pt.DialPolicy, addrs []ma.Multiaddr, rounds int, size int64) (perfResult, error) {
	res := perfResult{Phase: "request", Policy: string(policy)}
	client, dc := p.Dial(tid, policy, addrs)

	warm, want, err := makePayload(size)
	if err != nil {
		return res, err
	}
	if _, err := putVerified(ctx, client, dc, newKey("perf-req-warm"), warm, want); err != nil {
		st := dc.LastStats()
		return res, &perfFailure{Phase: res.Phase, Op: "put(warmup)", Round: 0, Path: st.Effective, FallbackAttempted: st.FallbackUsed, Err: err}
	}
	refreshPath(&res, dc.LastStats())
	warmBytes := dc.LastStats().PayloadBytesWritten

	lat := make([]float64, 0, rounds)
	ack := int64(0)
	var firstErr error
	for i := 0; i < rounds; i++ {
		payload, sha, err := makePayload(size)
		if err != nil {
			return res, err
		}
		start := time.Now()
		if _, err := putVerified(ctx, client, dc, newKey("perf-req"), payload, sha); err != nil {
			if firstErr == nil {
				st := dc.LastStats()
				firstErr = &perfFailure{Phase: res.Phase, Op: "put", Round: i + 1, Path: st.Effective, FallbackAttempted: st.FallbackUsed, Err: err}
			}
			continue
		}
		lat = append(lat, ms(time.Since(start)))
		ack += size
	}
	setQuantiles(&res, lat)
	st := dc.LastStats()
	refreshPath(&res, st)
	res.Bytes = ack
	res.WireBytes = st.PayloadBytesWritten - warmBytes
	if firstErr != nil {
		res.Err = firstErr.Error()
	}
	return res, firstErr
}

// phaseUpload measures one upload of `size` bytes. The bytes are counted only
// when the server acknowledges exactly them (HTTP 201 + matching manifest).
func phaseUpload(ctx context.Context, p *pt.StoragePeer, tid peer.ID, policy pt.DialPolicy, addrs []ma.Multiaddr, size int64, key string, payload []byte, want string) (perfResult, error) {
	res := perfResult{Phase: "up", Policy: string(policy)}
	client, dc := p.Dial(tid, policy, addrs)
	start := time.Now()
	st, err := putVerified(ctx, client, dc, key, payload, want)
	elapsed := time.Since(start)
	refreshPath(&res, st)
	res.WireBytes = st.PayloadBytesWritten
	if err != nil {
		f := &perfFailure{Phase: res.Phase, Op: "put", Round: 1, Path: st.Effective, FallbackAttempted: st.FallbackUsed, Err: err}
		res.Err = f.Error()
		return res, f
	}
	res.N = 1
	res.Bytes = size
	res.MinMS, res.MedMS, res.P95MS, res.MaxMS = ms(elapsed), ms(elapsed), ms(elapsed), ms(elapsed)
	res.MBps = mbps(size, elapsed)
	res.Sha256 = want
	return res, nil
}

// phaseDownload measures one download of the object just uploaded and counts
// the bytes only when the downloaded length AND sha256 match it.
func phaseDownload(ctx context.Context, p *pt.StoragePeer, tid peer.ID, policy pt.DialPolicy, addrs []ma.Multiaddr, size int64, key, want string) (perfResult, error) {
	res := perfResult{Phase: "down", Policy: string(policy)}
	client, dc := p.Dial(tid, policy, addrs)
	start := time.Now()
	n, st, err := getVerified(ctx, client, dc, key, want, size)
	elapsed := time.Since(start)
	refreshPath(&res, st)
	res.WireBytes = st.PayloadBytesRead
	if err != nil {
		f := &perfFailure{Phase: res.Phase, Op: "get", Round: 1, Path: st.Effective, FallbackAttempted: st.FallbackUsed, Err: err}
		res.Err = f.Error()
		return res, f
	}
	res.N = 1
	res.Bytes = n
	res.MinMS, res.MedMS, res.P95MS, res.MaxMS = ms(elapsed), ms(elapsed), ms(elapsed), ms(elapsed)
	res.MBps = mbps(n, elapsed)
	res.Sha256 = want
	return res, nil
}

// closePeerConns tears down every connection to tid and waits until the host
// reports none. A first-touch measurement needs a genuinely cold dial: dialing
// into an already live connection is a cached no-op and would report ~0 ms.
func closePeerConns(p *pt.StoragePeer, tid peer.ID, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		conns := p.Host.Network().ConnsToPeer(tid)
		if len(conns) == 0 {
			return
		}
		for _, c := range conns {
			_ = c.Close()
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ============================ shared helpers ============================

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

// mbps returns MiB/s. It is deliberately MiB, matching the historical `mbps`
// field of the perf output.
func mbps(bytes int64, d time.Duration) float64 {
	if d <= 0 || bytes <= 0 {
		return 0
	}
	return float64(bytes) / 1024 / 1024 / d.Seconds()
}

// setQuantiles sets N and the latency distribution of a phase. lat must hold
// ONLY successful operations.
func setQuantiles(res *perfResult, lat []float64) {
	if len(lat) == 0 {
		res.N = 0
		return
	}
	sort.Float64s(lat)
	res.N = len(lat)
	res.MinMS = lat[0]
	res.MedMS = lat[len(lat)/2]
	res.P95MS = lat[len(lat)*95/100]
	res.MaxMS = lat[len(lat)-1]
}

// refreshPath copies the transport facts of the connection a phase used into
// its result line. An empty Effective means the dialer never connected, which
// is a failure and is never reported as a path.
func refreshPath(res *perfResult, st pt.TransferStats) {
	if st.Effective == "" {
		return
	}
	res.Path = st.Effective
	res.FallbackAttempted = st.FallbackUsed
	res.FallbackUpgraded = st.FallbackUsed && st.Effective == pt.PathDirect
	res.Endpoint = st.RemoteMultiaddr
	res.LocalMultiaddr = st.LocalMultiaddr
}

func objectURL(key string) string { return "http://peer/objects/" + key }

func newKey(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// makePayload builds incompressible payload plus its sha256. Random bytes are
// deliberate: a repeating pattern could be deduplicated or compressed by a
// middlebox and inflate the measured throughput.
func makePayload(size int64) ([]byte, string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, "", fmt.Errorf("random payload: %w", err)
	}
	sum := sha256.Sum256(buf)
	return buf, hex.EncodeToString(sum[:]), nil
}

// putVerified uploads payload under key and requires the server to confirm
// exactly those bytes: HTTP 201 plus a manifest whose sha256 and size match
// what was sent. Only then are the bytes acknowledged. It returns the stats of
// the connection that carried the request.
func putVerified(ctx context.Context, client *http.Client, dc *pt.DialConfig, key string, payload []byte, want string) (pt.TransferStats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, objectURL(key), bytes.NewReader(payload))
	if err != nil {
		return dc.LastStats(), err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Object-Sha256", want)
	resp, err := client.Do(req)
	if err != nil {
		return dc.LastStats(), err
	}
	defer resp.Body.Close()
	st := dc.LastStats()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return st, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var meta pt.ObjectMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		return st, fmt.Errorf("malformed manifest: %w", err)
	}
	if meta.Sha256 != want {
		return st, fmt.Errorf("server manifest sha %s != uploaded %s", meta.Sha256, want)
	}
	if meta.Size != int64(len(payload)) {
		return st, fmt.Errorf("server manifest size %d != uploaded %d", meta.Size, len(payload))
	}
	return st, nil
}

// getVerified downloads key and requires BOTH the length and the sha256 to
// match the uploaded object. A truncated or altered body is a failure, not a
// download. It returns the number of bytes read plus the connection stats.
func getVerified(ctx context.Context, client *http.Client, dc *pt.DialConfig, key, want string, wantLen int64) (int64, pt.TransferStats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, objectURL(key), nil)
	if err != nil {
		return 0, dc.LastStats(), err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, dc.LastStats(), err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, dc.LastStats(), fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	st := dc.LastStats()
	if err != nil {
		return n, st, fmt.Errorf("read body: %w", err)
	}
	if n != wantLen {
		return n, st, fmt.Errorf("downloaded %d bytes, want %d", n, wantLen)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return n, st, fmt.Errorf("downloaded sha %s != uploaded %s", got, want)
	}
	return n, st, nil
}

func boolPtr(b bool) *bool { return &b }

// ============================ relay role ============================

func runRelay(ctx context.Context, state, listenIP string, listenPort int, announce []ma.Multiaddr, quic bool, allowed []peer.ID) {
	if len(announce) == 0 {
		fmt.Fprintln(os.Stderr, "wanrunner relay: -announce is required (public address for reservations)")
		os.Exit(2)
	}
	allow := pt.NewAllowlist(allowed...)
	r, err := pt.NewRelayNode(ctx, pt.RelayConfig{
		DataDir:       state,
		Allowlist:     allow,
		ListenIP:      listenIP,
		ListenPort:    listenPort,
		AnnounceAddrs: announce,
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatalf("relay: %v", err)
	}
	announceJSON("relay", r.ID, r.Host.Addrs(), false)
	log.Printf("relay running addrs=%v", r.Host.Addrs())
	<-ctx.Done()
	_ = r.Close()
}

func runControl(ctx context.Context, state, listenIP string, listenPort int, announce []ma.Multiaddr, quic bool, relay *peer.AddrInfo, controlAllowed []peer.ID) {
	// wanrunner 不做加入授权的动态管理：-allow-peer 传入的 PeerID 集合就是
	// 可注册集合；空集合 = 拒绝一切（fail-closed）。
	allow := pt.NewAllowlist(controlAllowed...)
	c, err := pt.NewControlNode(ctx, pt.ControlConfig{
		DataDir:       state,
		Authorized:    allow,
		RelayAddrInfo: relayPtr(relay),
		ListenIP:      listenIP,
		ListenPort:    listenPort,
		AnnounceAddrs: announce,
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatalf("control: %v", err)
	}
	announceJSON("control", c.Host.ID(), c.Host.Addrs(), false)
	addrs := c.Host.Addrs()
	if len(announce) > 0 {
		addrs = announce
	}
	log.Printf("control running addrs=%v relay=%v", addrs, relay)
	<-ctx.Done()
	_ = c.Close()
}

func relayPtr(ai *peer.AddrInfo) *peer.AddrInfo {
	if ai == nil || ai.ID == "" {
		return nil
	}
	return ai
}

// ============================ peer role ============================

func runPeer(ctx context.Context, state, listenIP string, listenPort int, announce []ma.Multiaddr, quic bool, control, relay *peer.AddrInfo, allowed []peer.ID, probeEvery time.Duration, noMesh bool, publicOnly bool) {
	if control == nil || control.ID == "" {
		fmt.Fprintln(os.Stderr, "wanrunner peer: -control is required")
		os.Exit(2)
	}
	if publicOnly {
		log.Printf("public-only 已启用：仅公网端点可建连；identify/DCUtR 再学习到的私网端点会被连接门拦截，不会产生私网拨号副作用")
	}
	allow := pt.NewAllowlist(allowed...)
	p, err := pt.NewStoragePeer(ctx, pt.PeerConfig{
		DataDir:       state,
		EnableQUIC:    quic,
		Peers:         allow,
		Control:       control,
		Relay:         relayPtr(relay),
		ListenIP:      listenIP,
		ListenPort:    listenPort,
		AnnounceAddrs: announce,
		PublicOnly:    publicOnly,
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatalf("peer: %v", err)
	}
	defer p.Close()
	announceJSON("peer", p.ID, p.Host.Addrs(), publicOnly)
	log.Printf("peer running addrs=%v control=%s relay=%s", p.Host.Addrs(), control.ID, relay.ID)

	if err := p.RegisterWithControl(ctx, *control); err != nil {
		log.Fatalf("register with control: %v", err)
	}
	log.Printf("registered with control")

	if probeEvery <= 0 {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(probeEvery)
	defer t.Stop()
	runProbeRound(ctx, p, control, allowed, noMesh)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runProbeRound(ctx, p, control, allowed, noMesh)
		}
	}
}

// probeResult is one JSON line per transfer probe on stdout. Path, Fallback
// and FallbackUpgraded are three separate facts: the requested policy, whether a
// relay attempt was made, and the path the connection really was.
type probeResult struct {
	Time      string `json:"time"`
	Operation string `json:"op"`
	Remote    string `json:"remote"`
	Policy    string `json:"policy"`
	Path      string `json:"path"`
	Fallback  bool   `json:"fallback"`
	// FallbackUpgraded: a relay attempt connected but the connection is direct.
	FallbackUpgraded bool `json:"fallback_upgraded"`
	// Bytes are acknowledged bytes only: zero when the operation failed.
	Bytes     int64   `json:"bytes"`
	WireBytes int64   `json:"wire_bytes"`
	Sha256    string  `json:"sha256"`
	Match     *bool   `json:"match,omitempty"`
	LatencyMS float64 `json:"latency_ms"`
	// 实际端点（route 证明用）：本操作真正使用的连接端点，取自连接本身而
	// 非策略。remote_multiaddr 对 circuit 连接是 /ip4/<relay>/.../p2p-circuit
	// 形态（首个 IP 为 relay 跳），local_multiaddr 是本侧真实传输地址。历史
	// 行没有这两个键；omitempty 保证旧字段顺序与默认输出不破坏。
	RemoteMultiaddr string `json:"remote_multiaddr,omitempty"`
	LocalMultiaddr  string `json:"local_multiaddr,omitempty"`
	Err             string `json:"err,omitempty"`
}

func runProbeRound(ctx context.Context, p *pt.StoragePeer, control *peer.AddrInfo, targets []peer.ID, noMesh bool) {
	if control == nil || control.ID == "" {
		log.Printf("probe: no control configured; skipping round")
		return
	}
	state, err := p.FetchControlState(ctx, *control)
	if err != nil {
		log.Printf("probe: fetch control state: %v", err)
		return
	}
	peers := peerAddrs(state)
	for _, id := range targets {
		if id == p.ID {
			continue
		}
		direct := peers[id]
		if noMesh {
			direct = dropPrivate(direct)
		}
		for _, size := range []int64{64 << 10, 32 << 20} {
			probeOnce(ctx, p, id, pt.PolicyDirectThenRelay, direct, size)
		}
	}
}

// dropPrivate removes overlay-routable components from the direct endpoint
// set: RFC1918/loopback (EasyTier/LAN mesh) AND 100.64.0.0/10 CGNAT
// (Tailscale uses this range; two NAS with Tailscale would otherwise "direct
// connect" through the very overlay this flag exists to bypass, hiding the
// public relay path under test).
func dropPrivate(addrs []ma.Multiaddr) []ma.Multiaddr {
	var out []ma.Multiaddr
	for _, a := range addrs {
		ip, err := a.ValueForProtocol(ma.P_IP4)
		if err != nil {
			out = append(out, a)
			continue
		}
		if isOverlayRoutable(ip) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func isOverlayRoutable(ip string) bool {
	if ip == "127.0.0.1" {
		return true
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return true // unknown shape: drop conservatively
	}
	oct := make([]int, 4)
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return true
		}
		oct[i] = v
	}
	return (oct[0] == 10) ||
		(oct[0] == 172 && oct[1] >= 16 && oct[1] <= 31) ||
		(oct[0] == 192 && oct[1] == 168) ||
		(oct[0] == 100 && oct[1] >= 64 && oct[1] <= 127)
}

// peerAddrs extracts {peerID: direct multiaddrs} from the control registry.
func peerAddrs(state map[string]any) map[peer.ID][]ma.Multiaddr {
	out := map[peer.ID][]ma.Multiaddr{}
	raw, _ := json.Marshal(state["peers"])
	var entries []struct {
		PeerID string   `json:"peer_id"`
		Addrs  []string `json:"addrs"`
	}
	if json.Unmarshal(raw, &entries) != nil {
		return out
	}
	for _, e := range entries {
		id, err := peer.Decode(e.PeerID)
		if err != nil {
			continue
		}
		for _, s := range e.Addrs {
			a, err := ma.NewMultiaddr(s)
			if err != nil {
				continue
			}
			out[id] = append(out[id], a)
		}
	}
	return out
}

// probeOnce runs one verified transfer probe on the SELECTED policy: a PUT of
// `size` bytes followed by a GET of that same object. It emits one JSON line
// per operation. Only acknowledged operations count: a PUT counts when the
// server answers 201 with a matching manifest sha; a GET counts when the
// downloaded length AND sha match the upload. Failures are emitted with their
// error AND logged to stderr — they are never counted as successes.
func probeOnce(ctx context.Context, p *pt.StoragePeer, target peer.ID, policy pt.DialPolicy, directAddrs []ma.Multiaddr, size int64) {
	res, err := probeTransfer(ctx, p, target, policy, directAddrs, size)
	if err != nil {
		log.Printf("probe %s: %v", target, err)
		return
	}
	for _, r := range res {
		if r.Err != "" {
			log.Printf("probe %s %s failed: %s", target, r.Operation, r.Err)
		}
		emitProbe(r)
	}
}

// probeTransfer is probeOnce without the stdout emission, so the same logic can
// be asserted on. Every returned result carries either acknowledged Bytes or an
// Err, never an unqualified success. The GET is skipped when the PUT was not
// acknowledged — the object does not exist and there is nothing to verify.
func probeTransfer(ctx context.Context, p *pt.StoragePeer, target peer.ID, policy pt.DialPolicy, directAddrs []ma.Multiaddr, size int64) ([]probeResult, error) {
	payload, want, err := makePayload(size)
	if err != nil {
		return nil, err
	}
	key := newKey("probe-" + strconv.FormatInt(size, 10))

	pctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	client, dc := p.Dial(target, policy, directAddrs)

	// PUT: acknowledged only on 201 + matching manifest sha and size.
	start := time.Now()
	st, err := putVerified(pctx, client, dc, key, payload, want)
	put := probeResult{
		Time:      time.Now().Format(time.RFC3339Nano),
		Operation: "put",
		Remote:    target.String(),
		Policy:    string(policy),
		Sha256:    want,
		Match:     boolPtr(err == nil),
		LatencyMS: ms(time.Since(start)),
	}
	refreshProbePath(&put, st)
	put.WireBytes = st.PayloadBytesWritten
	if err != nil {
		put.Err = err.Error()
		return []probeResult{put}, nil
	}
	put.Bytes = size

	// GET: acknowledged only when length and sha256 match the upload.
	start = time.Now()
	n, st2, err := getVerified(pctx, client, dc, key, want, size)
	get := probeResult{
		Time:      time.Now().Format(time.RFC3339Nano),
		Operation: "get",
		Remote:    target.String(),
		Policy:    string(policy),
		Sha256:    want,
		Match:     boolPtr(err == nil),
		LatencyMS: ms(time.Since(start)),
	}
	refreshProbePath(&get, st2)
	get.WireBytes = st2.PayloadBytesRead
	if err != nil {
		get.Err = err.Error()
		return []probeResult{put, get}, nil
	}
	get.Bytes = n
	return []probeResult{put, get}, nil
}

func refreshProbePath(r *probeResult, st pt.TransferStats) {
	r.Path = st.Effective
	r.Fallback = st.FallbackUsed
	r.FallbackUpgraded = st.FallbackUsed && st.Effective == pt.PathDirect
	// The endpoints come from the connection that actually carried the
	// operation — they are the route evidence, never the requested policy.
	r.RemoteMultiaddr = st.RemoteMultiaddr
	r.LocalMultiaddr = st.LocalMultiaddr
}

func emitProbe(r probeResult) {
	_ = json.NewEncoder(os.Stdout).Encode(r)
}
