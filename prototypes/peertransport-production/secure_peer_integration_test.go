//go:build integration

// The resolver uses a fixture-only address-to-PeerID mapping; device and
// libp2p identities are not yet bound by production discovery. Data requests
// must carry access tickets over real TLS, while health probes are anonymous.
// The advertised listener may serve health checks but never object payload.
// All secrets and nodes are isolated to this loopback test.
package peerproduction

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/client"
	"atoll/master"
	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/auth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
	pt "atoll/prototypes/peertransport"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
)

// accessTicketPrefix is the only credential the node is allowed to see. Anything
// else belongs to a different hop.
const accessTicketPrefix = "at1_"

// loopbackHost builds a TCP-only libp2p host: this suite is about credentials
// and TLS, not transport negotiation, so no QUIC endpoint is created.
func loopbackHost(t *testing.T, allow *pt.Allowlist) host.Host {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.ConnectionGater(pt.NewConnGater(allow)))
	if err != nil {
		t.Fatalf("libp2p.New: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// hit is one request the node handler saw.
type hit struct {
	method string
	path   string
	authz  string
	hasTLS bool
	ver    uint16
}

type hits struct {
	mu  sync.Mutex
	out []hit
}

func (h *hits) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ver := uint16(0)
		if r.TLS != nil {
			ver = r.TLS.Version
		}
		h.mu.Lock()
		h.out = append(h.out, hit{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.TLS != nil, ver})
		h.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (h *hits) snapshot() []hit {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]hit(nil), h.out...)
}

// dialFact is what the resolver's dialer verified for one request.
type dialFact struct {
	target    string
	effective string
	peer      string
	ok        bool
}

type dials struct {
	mu  sync.Mutex
	out []dialFact
}

func (d *dials) add(f dialFact) {
	d.mu.Lock()
	d.out = append(d.out, f)
	d.mu.Unlock()
}

func (d *dials) snapshot() []dialFact {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dialFact(nil), d.out...)
}

// dialResolver is the production seam: a registered node address becomes a peer
// dialer, and every dial's verified outcome is recorded.
func dialResolver(rec *dials, dc *pt.DialConfig) peerhttp.Resolver {
	return func(_ context.Context, addr string) (peerhttp.PeerDialer, error) {
		return func(ctx context.Context) peerhttp.PeerDial {
			conn, st, err := dc.Dial(ctx)
			rec.add(dialFact{target: addr, effective: st.Effective, peer: st.RemotePeer, ok: conn != nil})
			if conn == nil {
				return peerhttp.PeerDial{Err: err, Identity: st.RemotePeer, Path: peerPath(st.Effective)}
			}
			return peerhttp.PeerDial{Conn: conn, Identity: st.RemotePeer, Path: peerPath(st.Effective)}
		}, nil
	}
}

// randSecret returns n random bytes as unpadded base64url. Callers never print
// the value.
func randSecret(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// shape reports a credential's prefix and length without printing it.
func shape(v string) string {
	tok := strings.TrimPrefix(v, "Bearer ")
	head := tok
	if len(head) > 4 {
		head = head[:4]
	}
	return fmt.Sprintf("%q (len %d)", head, len(tok))
}

// secureCluster is the fixture shared by the direct and relayed variants.
type secureCluster struct {
	store        *meta.Store
	adminPass    string
	controlToken string

	clientTLS *tls.Config
	serverTLS func() *tls.Config
	masterURL string
	advertise string

	nodeHost     host.Host
	clientHost   host.Host
	nodeAllow    *pt.Allowlist
	clientAllow  *pt.Allowlist
	nodeEndpoint peer.AddrInfo  // nodeHost's endpoints, as identify populated them
	relayAI      *peer.AddrInfo // nil in the direct-only fixture

	dataRec *hits // the bridge: the data plane under test
	ctlRec  *hits // the advertise address: the master's health probe only

	client  *client.Client
	session client.LoginResult
}

// secureOpts selects the fixture variants. relay stands up a CircuitRelay v2
// hop; transfer enables master-side transfer planning and wires the three
// transfer budgets (node, master profile, client).
type secureOpts struct {
	relay    bool
	transfer bool
}

func newSecureCluster(t *testing.T, opts secureOpts) *secureCluster {
	t.Helper()

	// Every credential below is generated in this process and never printed.
	c := &secureCluster{adminPass: randSecret(t, 24), controlToken: randSecret(t, 40)}

	var err error
	c.store, err = meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { _ = c.store.Close() })
	if _, _, err := c.store.BootstrapSecurity("admin", c.adminPass, time.Now()); err != nil {
		t.Fatalf("BootstrapSecurity: %v", err)
	}

	certT, leaf := cert(t)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	// No ServerName: peerhttp refuses one, so the handshake binds to the request
	// host, as it does in production.
	c.clientTLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	// Each server builds its own TLSConfig: net/http's h2 setup mutates
	// TLSConfig.NextProtos lazily on the first Serve, so sharing a config
	// between concurrently serving servers is a data race.
	c.serverTLS = func() *tls.Config {
		return &tls.Config{Certificates: []tls.Certificate{certT}, MinVersion: tls.VersionTLS12}
	}

	srv := master.NewServer(c.store, time.Hour)
	srv.SetTLS(c.clientTLS) // node reachability probing goes to https
	if err := srv.EnableSecurity(master.SecurityConfig{ControlToken: auth.Token(c.controlToken), AllowInsecure: false}); err != nil {
		t.Fatalf("master EnableSecurity: %v", err)
	}
	if err := srv.EnableWritePlanning(master.WritePlanningConfig{MaxReplicas: 1, TransferPlanning: opts.transfer}); err != nil {
		t.Fatalf("EnableWritePlanning: %v", err)
	}
	srv.AttachSecureTransports()
	masterSrv := httptest.NewUnstartedServer(srv.Handler())
	masterSrv.TLS = c.serverTLS()
	masterSrv.StartTLS()
	t.Cleanup(masterSrv.Close)
	c.masterURL = masterSrv.URL

	// The advertised address is a real listener, so the master's /healthz probe
	// succeeds and write planning has a node to place the replica on. The data
	// plane must never use it; that is asserted by the variants.
	adv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("advertise listen: %v", err)
	}
	c.advertise = adv.Addr().String()

	invite, err := c.store.CreateDeviceInvite(time.Now().Add(time.Hour), time.Now())
	if err != nil {
		t.Fatalf("CreateDeviceInvite: %v", err)
	}

	c.nodeAllow = pt.NewAllowlist()
	c.clientAllow = pt.NewAllowlist()
	c.nodeHost = loopbackHost(t, c.nodeAllow)
	c.clientHost = loopbackHost(t, c.clientAllow)
	c.clientAllow.Add(c.nodeHost.ID())
	c.nodeAllow.Add(c.clientHost.ID())

	// The relay is authorized to reach both peers, and both peers accept it.
	var relayAllow *pt.Allowlist
	if opts.relay {
		relayAllow = pt.NewAllowlist(c.clientHost.ID(), c.nodeHost.ID())
		relay, rerr := pt.NewRelayNode(context.Background(), pt.RelayConfig{
			DataDir:         t.TempDir(),
			Allowlist:       relayAllow,
			Limit:           pt.DefaultRelayLimit(),
			ReservationTTL:  30 * time.Minute,
			MaxReservations: 16,
			MaxCircuits:     8,
			Logger:          log.New(io.Discard, "", 0),
		})
		if rerr != nil {
			t.Fatalf("NewRelayNode: %v", rerr)
		}
		t.Cleanup(func() { _ = relay.Host.Close() })
		ai := relay.AddrInfo()
		c.relayAI = &ai
		c.clientAllow.Add(relay.ID)
		c.nodeAllow.Add(relay.ID)
		// CircuitRelay v2 contract: the destination must hold a live
		// reservation at the hop, which is also how the hop learns the
		// destination's addresses (the CONNECT carries only the PeerID).
		rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
		if _, rerr := relayclient.Reserve(rctx, c.nodeHost, ai); rerr != nil {
			rcancel()
			t.Fatalf("node relay reservation at %s: %v", relay.ID, rerr)
		}
		rcancel()
	}

	bridge, _, err := pt.NewHTTPListener(context.Background(), c.nodeHost, c.nodeAllow)
	if err != nil {
		t.Fatalf("NewHTTPListener: %v", err)
	}

	dir := t.TempDir()
	n := node.New(dir, c.masterURL, c.advertise, 1<<30)
	if opts.transfer {
		// Must precede EnableSecurity/Register: budgets are configured once,
		// before registration, and handlePut refuses a planned PUT whose leg
		// carries a rate the node cannot bound.
		if err := n.ConfigureTransferBudget(transferBudget); err != nil {
			t.Fatalf("node ConfigureTransferBudget: %v", err)
		}
	}
	n.SetTLS(c.clientTLS)
	// The edge identity (a persistent Ed25519 key here) is unrelated to
	// c.nodeHost.ID(); nothing in this suite binds the two.
	if err := n.EnableSecurity(filepath.Join(dir, "identity.key"), invite, false); err != nil {
		t.Fatalf("node EnableSecurity: %v", err)
	}

	h := n.Handler()
	c.dataRec = &hits{}
	c.ctlRec = &hits{}
	dataSrv := &http.Server{Handler: c.dataRec.handler(h), TLSConfig: c.serverTLS(), ReadHeaderTimeout: 10 * time.Second}
	ctlSrv := &http.Server{Handler: c.ctlRec.handler(h), TLSConfig: c.serverTLS(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = dataSrv.ServeTLS(bridge, "", "") }()
	go func() { _ = ctlSrv.ServeTLS(adv, "", "") }()
	t.Cleanup(func() {
		_ = dataSrv.Close()
		_ = ctlSrv.Close()
	})
	if err := n.Register(); err != nil {
		t.Fatalf("node Register: %v", err)
	}
	if opts.transfer {
		// The planner refuses to plan unless every eligible node carries a
		// finite profile, so the master side learns the same budgets.
		if err := c.store.SetNodePlacementProfile(meta.NodePlacementProfile{
			NodeID: n.NodeIDForTest(), UploadBPS: transferBudget.UploadBPS,
			DownloadBPS: transferBudget.DownloadBPS, MaxTransferConcurrency: transferBudget.MaxConcurrent,
		}); err != nil {
			t.Fatalf("SetNodePlacementProfile: %v", err)
		}
	}

	targets := []peer.AddrInfo{{ID: c.nodeHost.ID(), Addrs: c.nodeHost.Addrs()}}
	if c.relayAI != nil {
		targets = append(targets, *c.relayAI)
	}
	for _, ti := range targets {
		if err := c.clientHost.Connect(context.Background(), ti); err != nil {
			t.Fatalf("peer connect %s: %v", ti.ID, err)
		}
	}
	c.nodeEndpoint = peer.AddrInfo{ID: c.nodeHost.ID(), Addrs: c.clientHost.Peerstore().Addrs(c.nodeHost.ID())}
	if len(c.nodeEndpoint.Addrs) == 0 {
		t.Fatal("identify did not populate an endpoint for the node")
	}

	c.client, err = client.NewSecure(c.masterURL, c.clientTLS, false)
	if err != nil {
		t.Fatalf("NewSecure: %v", err)
	}
	c.session, err = c.client.Login(context.Background(), "admin", c.adminPass)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := c.client.Mkdir("/docs"); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if opts.transfer {
		if err := c.client.SetTransferBudget(transferBudget); err != nil {
			t.Fatalf("client SetTransferBudget: %v", err)
		}
	}
	return c
}

// transferBudget is the one budget every participant in the transfer variant
// agrees on: generous enough that a 128 KiB upload is not throttled, finite so
// the planner accepts it.
var transferBudget = types.TransferBudget{UploadBPS: 64 << 20, DownloadBPS: 64 << 20, MaxConcurrent: 2}

// dialConfig builds the fixture's peer dial config toward the node: direct uses
// the endpoints identify populated, forced relay uses only the circuit.
func (c *secureCluster) dialConfig(expected peer.ID, policy pt.DialPolicy) *pt.DialConfig {
	dc := &pt.DialConfig{
		Host:           c.clientHost,
		Expected:       expected,
		DirectAddrs:    c.nodeEndpoint.Addrs,
		Policy:         policy,
		DirectTimeout:  5 * time.Second,
		ConnectTimeout: 10 * time.Second,
	}
	if c.relayAI != nil {
		dc.Relay = c.relayAI
	}
	return dc
}

// putGet runs the real planned write and the real read through the secure
// client over the given dial config, and returns the uploaded payload.
func putGet(t *testing.T, c *secureCluster, dc *pt.DialConfig, rec *dials) []byte {
	t.Helper()
	if err := c.client.SetPeerResolver(dialResolver(rec, dc)); err != nil {
		t.Fatalf("SetPeerResolver: %v", err)
	}
	payload := make([]byte, 128<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	in, err := c.client.PutSmall("/docs/peer.bin", payload, 1, false)
	if err != nil {
		t.Fatalf("planned put: %v", err)
	}
	if in.Size != int64(len(payload)) {
		t.Fatalf("committed size = %d, want %d", in.Size, len(payload))
	}
	outPath := filepath.Join(t.TempDir(), "peer.out")
	if err := c.client.Get("/docs/peer.bin", outPath); err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("downloaded content differs from what was uploaded")
	}
	return payload
}

// assertDataPlane checks what the node handler saw over the data plane. A data
// request carries only access tickets and only over TLS; /healthz is the node's
// deliberately public endpoint, so the transfer planner may measure it over the
// same peer transport, but such a probe must still be an unauthenticated GET.
// The prefix check rules out user sessions, device sessions (nd1_) and
// control/admin credentials at once.
func assertDataPlane(t *testing.T, c *secureCluster) []hit {
	t.Helper()
	data := c.dataRec.snapshot()
	if len(data) == 0 {
		t.Fatal("the node handler served no data plane request")
	}
	credentialed := 0
	for i, h := range data {
		if !h.hasTLS {
			t.Fatalf("request %d (%s %s) reached the node without TLS", i, h.method, h.path)
		}
		if h.ver < tls.VersionTLS12 {
			t.Fatalf("request %d was served over TLS %x", i, h.ver)
		}
		if h.path == "/healthz" {
			if h.method != http.MethodGet {
				t.Fatalf("health probe was %s, want GET", h.method)
			}
			if h.authz != "" {
				t.Fatalf("the health probe carried %s", shape(h.authz))
			}
			continue
		}
		credentialed++
		if !strings.HasPrefix(h.authz, "Bearer "+accessTicketPrefix) {
			t.Fatalf("request %d (%s %s) carried %s instead of an access ticket", i, h.method, h.path, shape(h.authz))
		}
		if h.authz == "Bearer "+c.session.Token {
			t.Fatalf("the user session reached the node (%s)", shape(h.authz))
		}
	}
	if credentialed == 0 {
		t.Fatal("the node handler served no credentialed data plane request")
	}
	return data
}

// assertControlPlane checks that the advertised address answered only the
// master's anonymous health probe, so no request took a plain TCP fallback to
// the same address.
func assertControlPlane(t *testing.T, c *secureCluster) {
	t.Helper()
	ctl := c.ctlRec.snapshot()
	if len(ctl) == 0 {
		t.Fatal("the master never probed the advertised address; planning would have had no live node")
	}
	assertNoDirectDataPlane(t, c)
}

func assertNoDirectDataPlane(t *testing.T, c *secureCluster) {
	t.Helper()
	for _, h := range c.ctlRec.snapshot() {
		if h.path != "/healthz" {
			t.Fatalf("advertised address served %s %s; the data plane must stay on the peer transport", h.method, h.path)
		}
		if h.authz != "" {
			t.Fatalf("the health probe carried %s", shape(h.authz))
		}
		if !h.hasTLS {
			t.Fatalf("advertised address served plaintext %s %s", h.method, h.path)
		}
	}
}

// assertDials checks that every dial was bound to the advertised address, the
// expected PeerID and the expected path.
func assertDials(t *testing.T, rec *dials, wantPeer peer.ID, advertise, wantPath string, min int) {
	t.Helper()
	facts := rec.snapshot()
	if len(facts) < min {
		t.Fatalf("only %d peer dials for a put and a get: %+v", len(facts), facts)
	}
	for i, f := range facts {
		if !f.ok || f.effective != wantPath || f.peer != wantPeer.String() || f.target != advertise {
			t.Fatalf("dial %d was not the %s path to the expected peer: %+v", i, wantPath, f)
		}
	}
}

// denyCredential sends a credential for another hop straight to the node: the
// node's online check must refuse it (it does not pattern-match prefixes
// locally, it defers to the master).
func denyCredential(t *testing.T, c *secureCluster, dc *pt.DialConfig, cred, what string) {
	t.Helper()
	req, err := http.NewRequestWithContext(peerhttp.WithPath(context.Background(), peerhttp.PathDirect),
		http.MethodGet, nodeURL+"/objects/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+cred)
	resp, err := peerClient(t, dc, c.clientTLS, nil).HTTP.Do(req)
	if err != nil {
		t.Fatalf("%s probe never reached the node: %v", what, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the node accepted %s (status %d)", what, resp.StatusCode)
	}
}

func TestSecureClusterOverTLSPeerStream(t *testing.T) {
	c := newSecureCluster(t, secureOpts{})
	dc := c.dialConfig(c.nodeHost.ID(), pt.PolicyDirect)
	rec := &dials{}
	putGet(t, c, dc, rec)

	assertDataPlane(t, c)
	assertDials(t, rec, c.nodeHost.ID(), c.advertise, pt.PathDirect, 2)
	st := dc.LastStats()
	if st.Effective != pt.PathDirect || st.RemotePeer != c.nodeHost.ID().String() {
		t.Fatalf("dial reported path=%q peer=%s", st.Effective, st.RemotePeer)
	}
	if st.RemoteMultiaddr == "" || strings.Contains(st.RemoteMultiaddr, "p2p-circuit") {
		t.Fatalf("dial reported multiaddr %q", st.RemoteMultiaddr)
	}
	assertControlPlane(t, c)

	// Negatives.
	denied := len(c.dataRec.snapshot())

	// Plaintext on the bridge dies at the TLS layer, before the node handler.
	// net/http answers a plaintext-to-HTTPS attempt with its own 400 on the raw
	// connection, so the only thing that matters is that the handler never ran.
	plain, err := dc.DialContext(context.Background(), "tcp4", "")
	if err != nil {
		t.Fatalf("raw peer dial: %v", err)
	}
	if _, err := plain.Write([]byte("GET /objects/1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")); err != nil {
		t.Fatalf("plaintext write: %v", err)
	}
	plainResp, _ := http.ReadResponse(bufio.NewReader(plain), nil)
	_ = plain.Close()
	if plainResp != nil {
		plainResp.Body.Close()
		if plainResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext attempt got status %d, want the TLS layer's 400", plainResp.StatusCode)
		}
	}

	// Same endpoint, different Expected PeerID: the dial is bound, so a receipt
	// from another peer is refused.
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := peer.IDFromPublicKey(priv.GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	c.clientAllow.Add(wrong)
	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	wreq, err := http.NewRequestWithContext(wctx, http.MethodGet, nodeURL+"/objects/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peerClient(t, c.dialConfig(wrong, pt.PolicyDirect), c.clientTLS, nil).HTTP.Do(wreq); err == nil {
		t.Fatal("a request to an unexpected PeerID succeeded")
	}

	if got := len(c.dataRec.snapshot()); got != denied {
		t.Fatalf("a refused attempt reached the node handler (%d -> %d)", denied, got)
	}

	denyCredential(t, c, dc, c.session.Token, "a user session")
	denyCredential(t, c, dc, c.controlToken, "the master control token")
	denyCredential(t, c, dc, accessTicketPrefix+randSecret(t, 32), "a forged access ticket")
}

// TestSecureClusterOverRelayedTLSPeerStream runs the same secure flow through a
// real CircuitRelay v2 hop. A live direct endpoint is available and refused: the
// forced policy dials only the circuit, and the node still sees a TLS request
// carrying only an access ticket.
func TestSecureClusterOverRelayedTLSPeerStream(t *testing.T) {
	c := newSecureCluster(t, secureOpts{relay: true})
	if c.relayAI == nil {
		t.Fatal("relay fixture missing")
	}
	dc := c.dialConfig(c.nodeHost.ID(), pt.PolicyForcedRelay)
	rec := &dials{}
	putGet(t, c, dc, rec)

	assertDataPlane(t, c)
	assertDials(t, rec, c.nodeHost.ID(), c.advertise, pt.PathCircuit, 2)
	st := dc.LastStats()
	if st.Effective != pt.PathCircuit {
		t.Fatalf("effective path = %q, want %q", st.Effective, pt.PathCircuit)
	}
	if st.RemoteMultiaddr == "" || !strings.Contains(st.RemoteMultiaddr, "p2p-circuit") {
		t.Fatalf("relayed dial reported multiaddr %q, want a /p2p-circuit endpoint", st.RemoteMultiaddr)
	}
	assertControlPlane(t, c)
}

// TestSecureClusterOverPlannedTLSPeerStream runs the secure flow with transfer
// planning enabled. A planned put here can only succeed through the whole
// transfer chain: the client probes each planned node's /healthz over the peer
// transport, reports the measured link, the master plans a leg carrying that
// path and a rate, the client pins the leg path on the PUT and both ends bound
// it with the configured budgets. A successful planned put therefore proves the
// plan was executed, not that an unpinned connection happened to work.
func TestSecureClusterOverPlannedTLSPeerStream(t *testing.T) {
	c := newSecureCluster(t, secureOpts{transfer: true})
	dc := c.dialConfig(c.nodeHost.ID(), pt.PolicyDirect)
	rec := &dials{}
	putGet(t, c, dc, rec)

	data := assertDataPlane(t, c)
	// The planner's own measurement rode the peer transport as well: the node
	// handler saw the client's unauthenticated /healthz probe over the bridge,
	// never over the advertised address.
	probes := 0
	for _, h := range data {
		if h.path == "/healthz" {
			probes++
		}
	}
	if probes == 0 {
		t.Fatal("the transfer planner never measured the node over the peer transport")
	}
	assertDials(t, rec, c.nodeHost.ID(), c.advertise, pt.PathDirect, 2)
	st := dc.LastStats()
	if st.Effective != pt.PathDirect {
		t.Fatalf("effective path = %q, want %q", st.Effective, pt.PathDirect)
	}
	if st.RemoteMultiaddr == "" || strings.Contains(st.RemoteMultiaddr, "p2p-circuit") {
		t.Fatalf("planned dial reported multiaddr %q", st.RemoteMultiaddr)
	}
	assertNoDirectDataPlane(t, c)
}
