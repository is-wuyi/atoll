//go:build integration

// Package peerproduction is a LOCAL-ONLY integration harness. It wires the
// production storage-node HTTP handler onto the peertransport prototype's
// libp2p stream listener, in front of a real TLS handshake, and drives it with
// the production client HTTP stack through the production peerhttp transport
// adapter.
//
// Wiring under test:
//
//	server:  pt.NewHTTPListener(host, allow)  ->  http.Server.ServeTLS(raw, "", "")
//	client:  pt.DialConfig.Dial  ->  peerhttp.Resolver  ->  peerhttp.Transport
//	         ->  auth.Transport  ->  client.Client.HTTP
//
// What it asserts, and nothing more:
//
//   - a production object receipt (PUT -> 201 {"size":N}) and a byte-exact GET
//     round trip work over a libp2p peer stream with ordinary TLS in front;
//   - the handler only ever sees requests whose r.TLS is populated, i.e. the
//     bridge cannot bypass the node's TLS gate by presenting the peer channel
//     as an already-secured connection;
//   - a plaintext attempt on the same stream reaches no handler at all;
//   - no Authorization credential crosses the bridge to the node (the bridge
//     authenticates the peer via the libp2p identity, it forwards no device or
//     session credential);
//   - the path a request took is reported as direct, and the peer identity is
//     bound: a receipt is never accepted from a different peer, even when
//     that peer's endpoint is dialed.
//
// Loopback only; no remote host is contacted. The production write APIs
// (client.Put/Get) are master-driven and their node-data-plane helpers are
// unexported, so the requests here go through the client's own HTTP transport
// chain exactly as client.putObject would. Wiring master into the bridge is
// out of scope for this test.
//
// Run with: go test -tags=integration ./...
package peerproduction

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/client"
	"atoll/node"
	"atoll/pkg/auth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
	pt "atoll/prototypes/peertransport"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

const nodeURL = "https://127.0.0.1"

// seen is what the production node handler observed, for the assertions above.
type seen struct {
	mu      sync.Mutex
	calls   int
	authz   []string
	tlsVers []uint16
	untls   []string
}

func (s *seen) record(method, path, authz string, hasTLS bool, ver uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.authz = append(s.authz, authz)
	s.tlsVers = append(s.tlsVers, ver)
	if !hasTLS {
		s.untls = append(s.untls, method+" "+path)
	}
}

func (s *seen) snapshot() (calls int, authz, untls []string, vers []uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls,
		append([]string(nil), s.authz...),
		append([]string(nil), s.untls...),
		append([]uint16(nil), s.tlsVers...)
}

// peerPath maps the prototype's verified effective path onto the adapter's.
// An empty effective path is not guessed as direct.
func peerPath(effective string) peerhttp.Path {
	switch effective {
	case pt.PathDirect:
		return peerhttp.PathDirect
	case pt.PathCircuit:
		return peerhttp.PathRelay
	default:
		return peerhttp.PathUnknown
	}
}

// peerClient builds the production client's HTTP stack over the prototype's
// peer dialer. peerhttp.NewTransport supplies the base transport and the peer
// routing (fresh connection per request, so a reported path is always the path
// that request took); auth.Transport is the production client's own credential
// wrapper; DialConfig.NewHTTPClient supplies the base transport whose
// DialContext opens a libp2p stream.
func peerClient(t *testing.T, dc *pt.DialConfig, tlsCfg *tls.Config, paths *[]peerhttp.Observation) *client.Client {
	t.Helper()
	base := dc.NewHTTPClient().Transport.(*http.Transport)
	base.TLSClientConfig = tlsCfg
	rt, err := peerhttp.NewTransport(base, peerhttp.WithResolver(func(ctx context.Context, _ string) (peerhttp.PeerDialer, error) {
		return func(ctx context.Context) peerhttp.PeerDial {
			conn, st, err := dc.Dial(ctx)
			if conn == nil {
				return peerhttp.PeerDial{Err: err, Identity: st.RemotePeer, Path: peerPath(st.Effective)}
			}
			return peerhttp.PeerDial{Conn: conn, Identity: st.RemotePeer, Path: peerPath(st.Effective)}
		}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	rt.SetReporter(&peerhttp.Reporter{Observe: func(o peerhttp.Observation) {
		if paths == nil {
			return
		}
		*paths = append(*paths, o)
	}})
	return &client.Client{
		MasterURL: "http://127.0.0.1:1",
		HTTP:      &http.Client{Transport: &auth.Transport{Fallback: rt}},
	}
}

func TestProductionNodeHandlerOverTLSPeerStream(t *testing.T) {
	// Loopback TCP only: this test is about the bridge, not about transport
	// negotiation, so no QUIC endpoint is created.
	nodeAllow := pt.NewAllowlist()
	clientAllow := pt.NewAllowlist()
	mk := func(allow *pt.Allowlist) host.Host {
		t.Helper()
		h, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.ConnectionGater(pt.NewConnGater(allow)),
		)
		if err != nil {
			t.Fatalf("libp2p.New: %v", err)
		}
		t.Cleanup(func() { _ = h.Close() })
		return h
	}
	nodeHost := mk(nodeAllow)
	clientHost := mk(clientAllow)
	clientAllow.Add(nodeHost.ID())
	nodeAllow.Add(clientHost.ID())

	// The bridge: the production handler served over the prototype's peer
	// stream listener, with the TLS handshake performed by http.Server on the
	// raw stream listener.
	lis, _, err := pt.NewHTTPListener(context.Background(), nodeHost, nodeAllow)
	if err != nil {
		t.Fatalf("NewHTTPListener: %v", err)
	}
	rec := &seen{}
	prod := node.New(t.TempDir(), "", "", 1<<30)
	handled := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ver := uint16(0)
		if r.TLS != nil {
			ver = r.TLS.Version
		}
		rec.record(r.Method, r.URL.Path, r.Header.Get("Authorization"), r.TLS != nil, ver)
		prod.Handler().ServeHTTP(w, r)
	})
	certT, leaf := cert(t)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	// No ServerName: peerhttp refuses one, so the handshake binds to the
	// request host (127.0.0.1) as it would in production.
	clientTLS := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	srv := &http.Server{
		Handler:           handled,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{certT}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.ServeTLS(lis, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	// Establish the peer channel once so identify populates the peerstore,
	// then take the endpoint the peer actually advertises.
	if err := clientHost.Connect(context.Background(),
		peer.AddrInfo{ID: nodeHost.ID(), Addrs: nodeHost.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	directAddrs := clientHost.Peerstore().Addrs(nodeHost.ID())
	if len(directAddrs) == 0 {
		t.Fatal("peerstore has no endpoint for the node; identify did not complete")
	}

	dc := &pt.DialConfig{
		Host:           clientHost,
		Expected:       nodeHost.ID(),
		DirectAddrs:    directAddrs,
		Policy:         pt.PolicyDirect,
		DirectTimeout:  5 * time.Second,
		ConnectTimeout: 10 * time.Second,
	}
	var paths []peerhttp.Observation
	c := peerClient(t, dc, clientTLS, &paths)

	payload := make([]byte, 512<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	// Verified receipt: the node recomputes CRC32C of the body and refuses a
	// mismatched digest, so the 201 is an integrity statement, not an ACK.
	req, err := http.NewRequestWithContext(peerhttp.WithPath(context.Background(), peerhttp.PathDirect),
		http.MethodPut, nodeURL+"/objects/1", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", types.CRC32C(payload)))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatalf("put over TLS peer stream: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("put status = %d, body %s", resp.StatusCode, body)
	}
	var receipt struct {
		Size *int64 `json:"size"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil || receipt.Size == nil || *receipt.Size != int64(len(payload)) {
		t.Fatalf("receipt = %s (json err %v), want size %d", body, err, len(payload))
	}

	get, err := http.NewRequestWithContext(peerhttp.WithPath(context.Background(), peerhttp.PathDirect),
		http.MethodGet, nodeURL+"/objects/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	gresp, err := c.HTTP.Do(get)
	if err != nil {
		t.Fatalf("get over TLS peer stream: %v", err)
	}
	got, err := io.ReadAll(gresp.Body)
	gresp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if gresp.StatusCode != http.StatusOK || !bytes.Equal(got, payload) {
		t.Fatalf("get status = %d, body matches = %v", gresp.StatusCode, bytes.Equal(got, payload))
	}

	// The dial reported the path it actually took and the peer it verified.
	st := dc.LastStats()
	if st.Effective != pt.PathDirect {
		t.Fatalf("effective path = %q, want %q", st.Effective, pt.PathDirect)
	}
	if st.RemotePeer != nodeHost.ID().String() {
		t.Fatalf("remote peer = %s, want %s", st.RemotePeer, nodeHost.ID().String())
	}
	if st.RemoteMultiaddr == "" || strings.Contains(st.RemoteMultiaddr, "p2p-circuit") {
		t.Fatalf("remote multiaddr = %q", st.RemoteMultiaddr)
	}
	if len(paths) != 2 {
		t.Fatalf("path observations = %d, want 2: %v", len(paths), paths)
	}
	for _, o := range paths {
		if o.Path != peerhttp.PathDirect || o.Scheme != "https" {
			t.Fatalf("observation %v, want scheme=https path=direct", o)
		}
	}

	calls0, authz, untls, vers := rec.snapshot()
	if len(untls) != 0 || len(authz) != calls0 || len(vers) != calls0 {
		t.Fatalf("handler calls %d, tls-version samples %d, auth samples %d, non-TLS %v",
			calls0, len(vers), len(authz), untls)
	}
	for _, v := range vers {
		if v < tls.VersionTLS12 {
			t.Fatalf("handler served TLS %x, below 1.2", v)
		}
	}
	for _, a := range authz {
		if a != "" {
			t.Fatalf("credential leaked to the node over the bridge: Authorization=%q", a)
		}
	}

	// Plaintext on the same stream: the handshake must fail before the node
	// handler runs. net/http answers a plaintext-to-HTTPS attempt with its own
	// 400 written on the raw connection (net/http server.go:1921), so the only
	// thing that matters here is that the handler never saw the request.
	plainConn, err := dc.DialContext(context.Background(), "tcp4", "")
	if err != nil {
		t.Fatalf("raw peer dial: %v", err)
	}
	if _, err := plainConn.Write([]byte("GET /objects/1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")); err != nil {
		t.Fatalf("plaintext write: %v", err)
	}
	plainResp, _ := http.ReadResponse(bufio.NewReader(plainConn), nil)
	_ = plainConn.Close()
	if plainResp != nil {
		plainResp.Body.Close()
		if plainResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext attempt got status %d, want the TLS layer's 400", plainResp.StatusCode)
		}
	}
	if calls, _, untls, _ := rec.snapshot(); calls != calls0 || len(untls) != 0 {
		t.Fatalf("plaintext attempt reached the node handler (calls %d -> %d, non-TLS %v)",
			calls0, calls, untls)
	}

	// The receipt is bound to the expected PeerID: dialing the same endpoint
	// with a different Expected must fail rather than accept the peer that
	// answers.
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unexpectedID, err := peer.IDFromPublicKey(priv.GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	clientAllow.Add(unexpectedID)
	wrong := &pt.DialConfig{
		Host:           clientHost,
		Expected:       unexpectedID,
		DirectAddrs:    directAddrs,
		Policy:         pt.PolicyDirect,
		DirectTimeout:  3 * time.Second,
		ConnectTimeout: 5 * time.Second,
	}
	wctx, cancel := context.WithTimeout(peerhttp.WithPath(context.Background(), peerhttp.PathDirect), time.Second)
	defer cancel()
	wreq, err := http.NewRequestWithContext(wctx, http.MethodGet, nodeURL+"/objects/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peerClient(t, wrong, clientTLS, nil).HTTP.Do(wreq); err == nil {
		t.Fatal("request to an unexpected PeerID succeeded; the dial is not bound to Expected")
	}
	if calls, _, untls, _ := rec.snapshot(); calls != calls0 || len(untls) != 0 {
		t.Fatalf("unexpected-PeerID dial reached the node handler (calls %d -> %d)", calls0, calls)
	}
}

// cert returns a self-signed certificate for 127.0.0.1, valid for one hour. It
// is generated per test so the suite cannot ship a long-lived key.
func cert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "atoll-peer-bridge-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"127.0.0.1"},
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, leaf
}
