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
//
// Every role prints one JSON line on stdout at startup:
//
//	{"role":"peer","peer_id":"12D3...","addresses":["/ip4/.../tcp/..."]}
//
// The peer role registers with control, fetches the authorized peer list, then
// every -probe-every interval runs a transfer probe against each peer it can
// reach: PUT then GET of a small + a large probe object, direct-first with
// relay fallback, recording one JSON result line per probe (path, fallback,
// bytes, checksum match). Never prints keys or tokens.
//
// This is still the PROTOTYPE module — no production wiring. The point is to
// gather real WAN/NAT/relay/hole-punch measurements before deciding how to
// wire peer transport into production.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
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
}

func announceJSON(role string, id peer.ID, addrs []ma.Multiaddr) {
	out := roleInfo{Role: role, PeerID: id.String(), Addresses: make([]string, 0, len(addrs))}
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

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wanrunner relay|control|peer [flags]")
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
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if *state == "" {
		fmt.Fprintln(os.Stderr, "wanrunner: -state is required")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch role {
	case "relay":
		runRelay(ctx, *state, *listenIP, *listenPort, announce, *quic, *allowed)
	case "control":
		runControl(ctx, *state, *listenIP, *listenPort, announce, *quic, relayAddr, *allowed)
	case "peer":
		runPeer(ctx, *state, *listenIP, *listenPort, announce, *quic, controlAddr, relayAddr, *allowed, *probeEvery)
	default:
		fmt.Fprintf(os.Stderr, "wanrunner: unknown role %q\n", role)
		os.Exit(2)
	}
}

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
		AnnounceAddrs: announce,
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatalf("relay: %v", err)
	}
	announceJSON("relay", r.ID, r.Host.Addrs())
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
		Authorized:   allow,
		RelayAddrInfo: relayPtr(relay),
		ListenIP:      listenIP,
		ListenPort:    listenPort,
		AnnounceAddrs: announce,
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatalf("control: %v", err)
	}
	announceJSON("control", c.Host.ID(), c.Host.Addrs())
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

func runPeer(ctx context.Context, state, listenIP string, listenPort int, announce []ma.Multiaddr, quic bool, control, relay *peer.AddrInfo, allowed []peer.ID, probeEvery time.Duration) {
	if control == nil || control.ID == "" {
		fmt.Fprintln(os.Stderr, "wanrunner peer: -control is required")
		os.Exit(2)
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
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatalf("peer: %v", err)
	}
	defer p.Close()
	announceJSON("peer", p.ID, p.Host.Addrs())
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
	runProbeRound(ctx, p, control, allowed)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runProbeRound(ctx, p, control, allowed)
		}
	}
}

// probeResult is one JSON line per transfer probe on stdout.
type probeResult struct {
	Time      string `json:"time"`
	Operation string `json:"op"`
	Remote    string `json:"remote"`
	Path      string `json:"path"`
	Fallback  bool   `json:"fallback"`
	Bytes     int64  `json:"bytes"`
	Sha256    string `json:"sha256"`
	Match     *bool  `json:"match,omitempty"`
	Err       string `json:"err,omitempty"`
}

func runProbeRound(ctx context.Context, p *pt.StoragePeer, control *peer.AddrInfo, targets []peer.ID) {
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
		for _, size := range []int64{64 << 10, 32 << 20} {
			probeOnce(ctx, p, id, peers[id], size)
		}
	}
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

func probeOnce(ctx context.Context, p *pt.StoragePeer, target peer.ID, directAddrs []ma.Multiaddr, size int64) {
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		return
	}
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])
	key := fmt.Sprintf("probe-%d-%d", size, time.Now().UnixNano())

	put := func() *probeResult {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		client, dial := p.Dial(target, pt.PolicyDirectThenRelay, directAddrs)
		keyURL := fmt.Sprintf("http://peer/objects/%s", key)
		req, err := newPutRequest(pctx, keyURL, payload, want)
		if err != nil {
			return &probeResult{Time: time.Now().Format(time.RFC3339Nano), Operation: "put", Remote: target.String(), Err: err.Error()}
		}
		resp, err := client.Do(req)
		if err != nil {
			return &probeResult{Time: time.Now().Format(time.RFC3339Nano), Operation: "put", Remote: target.String(), Err: err.Error()}
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		st := dial.LastStats()
		r := &probeResult{Time: time.Now().Format(time.RFC3339Nano), Operation: "put", Remote: target.String(), Path: st.Effective, Fallback: st.FallbackUsed, Bytes: size, Sha256: want}
		if resp.StatusCode != 201 {
			r.Err = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))
		}
		return r
	}
	res := put()
	emit(res)
	if res.Err != "" {
		return
	}

	get := func() *probeResult {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		client, dial := p.Dial(target, pt.PolicyDirectThenRelay, directAddrs)
		req, err := newGetRequest(pctx, fmt.Sprintf("http://peer/objects/%s", key))
		if err != nil {
			return &probeResult{Time: time.Now().Format(time.RFC3339Nano), Operation: "get", Remote: target.String(), Err: err.Error()}
		}
		resp, err := client.Do(req)
		if err != nil {
			return &probeResult{Time: time.Now().Format(time.RFC3339Nano), Operation: "get", Remote: target.String(), Err: err.Error()}
		}
		defer resp.Body.Close()
		h := sha256.New()
		n, err := io.Copy(h, resp.Body)
		if err != nil {
			return &probeResult{Time: time.Now().Format(time.RFC3339Nano), Operation: "get", Remote: target.String(), Err: err.Error()}
		}
		st := dial.LastStats()
		got := hex.EncodeToString(h.Sum(nil))
		match := got == want
		return &probeResult{Time: time.Now().Format(time.RFC3339Nano), Operation: "get", Remote: target.String(), Path: st.Effective, Fallback: st.FallbackUsed, Bytes: n, Sha256: got, Match: &match}
	}
	emit(get())
}

func emit(r *probeResult) {
	_ = json.NewEncoder(os.Stdout).Encode(r)
}

func newPutRequest(ctx context.Context, url string, body []byte, sha string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Object-Sha256", sha)
	return req, nil
}

func newGetRequest(ctx context.Context, url string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
}
