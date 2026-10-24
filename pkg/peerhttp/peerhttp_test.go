package peerhttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- helpers ----

// testCert returns a self-signed RSA certificate for the loopback addresses.
func testCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{cn, "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	return pair
}

// testPool trusts only the given certificate. tls.Certificate.Certificate holds
// raw DER, while x509.CertPool wants PEM, so re-encode.
func testPool(t *testing.T, cert tls.Certificate) *x509.CertPool {
	t.Helper()
	der := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(der) {
		t.Fatal("append certificate")
	}
	return p
}

// tlsConfig returns a client TLS config that trusts only cert.
func tlsConfig(t *testing.T, cert tls.Certificate) *tls.Config {
	return &tls.Config{RootCAs: testPool(t, cert), MinVersion: tls.VersionTLS12}
}

// getWith sends one GET on the given context.
func getWith(ctx context.Context, client *http.Client, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

// listen returns a TCP listener that stands in for a peer transport's
// accepted-stream source.
func listen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return l
}

// serve runs srv on lis and stops it when the test ends.
func serve(t *testing.T, srv *http.Server, lis net.Listener) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(lis) }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
}

// serveTLS runs srv on lis with a real TLS handshake performed server-side.
func serveTLS(t *testing.T, lis net.Listener, cert tls.Certificate, h http.Handler) {
	t.Helper()
	sec, err := SecureListener(lis, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("SecureListener: %v", err)
	}
	serve(t, &http.Server{Handler: h}, sec)
}

// countingClose counts Close calls on a connection.
type countingClose struct {
	net.Conn
	closes *atomic.Int64
}

func (c *countingClose) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// dialCounter counts the dials and closes an http.Transport makes.
type dialCounter struct {
	dials  atomic.Int64
	closes atomic.Int64
}

func (d *dialCounter) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.dials.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &countingClose{Conn: conn, closes: &d.closes}, nil
}

// dialScript resolves one address and drives what every dial reports.
type dialScript struct {
	addr     string
	resolves atomic.Int64
	dials    atomic.Int64
	pathAt   func(n int) Path
	wrap     func(n int, conn net.Conn) net.Conn
}

func (s *dialScript) Resolver() Resolver {
	return Resolver(func(ctx context.Context, nodeAddr string) (PeerDialer, error) {
		s.resolves.Add(1)
		if nodeAddr != s.addr {
			return nil, nil
		}
		return func(ctx context.Context) PeerDial {
			n := int(s.dials.Add(1))
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", s.addr)
			if err != nil {
				return PeerDial{Err: err}
			}
			if s.wrap != nil {
				conn = s.wrap(n, conn)
			}
			pd := PeerDial{Conn: conn, Identity: "peer-a"}
			if s.pathAt != nil {
				pd.Path = s.pathAt(n)
			}
			return pd
		}, nil
	})
}

var directPath = func(int) Path { return PathDirect }

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok"))
})

// ---- tests ----

// TestHTTPSOverPeerStream is the core end-to-end check: https traffic goes over
// a peer stream with a genuine TLS handshake, the server sees a populated
// r.TLS, and the pinned master keeps its own dial path.
func TestHTTPSOverPeerStream(t *testing.T) {
	cert := testCert(t, "peer.test")
	pool := testPool(t, cert)

	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	sec, err := SecureListener(peerLis, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("SecureListener: %v", err)
	}
	var peerServed, unsecured atomic.Int64
	serve(t, &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerServed.Add(1)
		if r.TLS == nil {
			unsecured.Add(1)
			http.Error(w, "plaintext connections are rejected", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("peer-ok"))
	})}, sec)

	masterLis := listen(t)
	masterAddr := masterLis.Addr().String()
	serveTLS(t, masterLis, cert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("master-ok"))
	}))

	script := &dialScript{addr: peerAddr, pathAt: directPath}
	var obsMu sync.Mutex
	var obs []Observation
	base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, MaxIdleConnsPerHost: 1}
	tr, err := NewTransport(base, WithResolver(script.Resolver()), WithMaster("https://"+masterAddr))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	tr.SetReporter(&Reporter{Observe: func(o Observation) {
		obsMu.Lock()
		obs = append(obs, o)
		obsMu.Unlock()
	}})
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	// 1. Peer: https over a peer stream, with a real handshake.
	res, err := client.Get("https://" + peerAddr + "/")
	if err != nil {
		t.Fatalf("peer https: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || string(body) != "peer-ok" {
		t.Fatalf("peer https: status %d body %q", res.StatusCode, body)
	}
	if got := unsecured.Load(); got != 0 {
		t.Fatalf("server saw %d unsecured request(s); the r.TLS gate must not be bypassed", got)
	}
	if got := peerServed.Load(); got != 1 {
		t.Fatalf("peer requests served = %d, want 1", got)
	}
	if got := script.dials.Load(); got != 1 {
		t.Fatalf("peer dials = %d, want 1", got)
	}
	if got := script.resolves.Load(); got != 1 {
		t.Fatalf("resolves = %d, want 1", got)
	}

	// 2. Master: the same client, but the dial goes through the base transport
	// and the resolver is never asked about the master.
	res, err = client.Get("https://" + masterAddr + "/")
	if err != nil {
		t.Fatalf("master https: %v", err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || string(body) != "master-ok" {
		t.Fatalf("master https: status %d body %q", res.StatusCode, body)
	}
	if got := script.resolves.Load(); got != 1 {
		t.Fatalf("resolves = %d after the master request, want 1: the master must not be resolved as a peer", got)
	}
	if got := script.dials.Load(); got != 1 {
		t.Fatalf("peer dials = %d after the master request, want 1", got)
	}

	// 3. http to a peer is refused before anything is dialed.
	if _, err = client.Get("http://" + peerAddr + "/"); err == nil {
		t.Fatal("http to a peer must be refused")
	} else if !strings.Contains(err.Error(), "http is not permitted") {
		t.Fatalf("unexpected error for an http peer: %v", err)
	}
	if got := script.dials.Load(); got != 1 {
		t.Fatalf("a dial happened for a refused http peer: %d", got)
	}

	// 4. No peer dialer and nothing pinned: the request falls back to plain TCP
	// and fails on the connection, without being dialed as a peer.
	if _, err = client.Get("https://127.0.0.1:1/"); err == nil {
		t.Fatal("an unreachable address must fail")
	}
	if got := script.resolves.Load(); got != 2 {
		t.Fatalf("resolves = %d, want 2: the address was resolved once and had no dialer", got)
	}
	if got := script.dials.Load(); got != 1 {
		t.Fatalf("peer dials = %d, want 1: the fallback must not use the peer dialer", got)
	}

	// 5. The same address with a pinned peer path fails closed.
	_, err = getWith(WithPath(context.Background(), PathDirect), client, "https://127.0.0.1:1/")
	if err == nil {
		t.Fatal("a pinned peer path must not fall back to plain TCP")
	} else if !strings.Contains(err.Error(), "requires the direct peer path") {
		t.Fatalf("unexpected error: %v", err)
	}

	obsMu.Lock()
	gotObs := append([]Observation(nil), obs...)
	obsMu.Unlock()
	wantObs := []Observation{
		{Scheme: "https", Target: peerAddr, Path: PathDirect},
		{Scheme: "https", Target: masterAddr, Path: PathHTTPS, Master: true},
	}
	if !reflect.DeepEqual(gotObs, wantObs) {
		t.Fatalf("observations = %v, want %v", gotObs, wantObs)
	}
}

// TestTLSIsVerified proves the handshake really binds the request to the
// advertised address: a certificate the client does not trust is rejected.
func TestTLSIsVerified(t *testing.T) {
	server := testCert(t, "peer.test")
	foreign := testCert(t, "foreign.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, server, okHandler)

	script := &dialScript{addr: peerAddr, pathAt: directPath}
	base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: testPool(t, foreign)}}
	tr, err := NewTransport(base, WithResolver(script.Resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	_, err = (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://" + peerAddr + "/")
	if err == nil {
		t.Fatal("a certificate the client does not trust must be rejected")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("the failure must be a certificate verification failure, got: %v", err)
	}
	if got := script.dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1: the dial succeeded and the handshake failed", got)
	}
}

// TestPlainStreamCannotCarryHTTPS proves there is no silent downgrade: https
// over a plaintext stream fails the handshake, and http is refused outright.
func TestPlainStreamCannotCarryHTTPS(t *testing.T) {
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	var served atomic.Int64
	serve(t, &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		_, _ = w.Write([]byte("ok"))
	})}, peerLis)

	script := &dialScript{addr: peerAddr, pathAt: directPath}
	tr, err := NewTransport(&http.Transport{}, WithResolver(script.Resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	if _, err = client.Get("https://" + peerAddr + "/"); err == nil {
		t.Fatal("https over a plaintext peer stream must fail")
	}
	if got := served.Load(); got != 0 {
		t.Fatalf("a plaintext stream served %d request(s); it must not satisfy https", got)
	}
	if _, err = client.Get("http://" + peerAddr + "/"); err == nil || !strings.Contains(err.Error(), "http is not permitted") {
		t.Fatalf("http over a peer stream must be refused, got: %v", err)
	}
}

// TestMasterOriginGuard proves the master match is exact: scheme is part of it,
// paths and queries are not, and default ports are filled in before matching.
func TestMasterOriginGuard(t *testing.T) {
	cert := testCert(t, "peer.test")
	pool := testPool(t, cert)

	masterLis := listen(t)
	masterAddr := masterLis.Addr().String()
	serveTLS(t, masterLis, cert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("master"))
	}))
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("peer"))
	}))

	script := &dialScript{addr: peerAddr, pathAt: directPath}
	base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	tr, err := NewTransport(base, WithResolver(script.Resolver()), WithMaster("https://"+masterAddr))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	get := func(target string) (string, error) {
		res, err := client.Get(target)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return string(body), nil
	}

	if body, err := get("https://" + masterAddr + "/"); err != nil || body != "master" {
		t.Fatalf("pinned master: body=%q err=%v", body, err)
	}
	if body, err := get("https://" + masterAddr + "/meta/writes"); err != nil || body != "master" {
		t.Fatalf("a path does not change the origin: body=%q err=%v", body, err)
	}
	if body, err := get("https://" + masterAddr + "/?x=1"); err != nil || body != "master" {
		t.Fatalf("a query does not change the origin: body=%q err=%v", body, err)
	}
	if _, err := get("http://" + masterAddr + "/"); err == nil || !strings.Contains(err.Error(), "http is not permitted") {
		t.Fatalf("a different scheme must not match the master origin, got: %v", err)
	}
	if body, err := get("https://" + peerAddr + "/"); err != nil || body != "peer" {
		t.Fatalf("a non-master address: body=%q err=%v", body, err)
	}

	// https://host:443 and https://host both canonicalize to host:443.
	other := &dialScript{addr: peerAddr, pathAt: directPath}
	tr2, err := NewTransport(base, WithResolver(other.Resolver()), WithMaster("https://127.0.0.1:443"))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	if _, err := (&http.Client{Transport: tr2, Timeout: 10 * time.Second}).Get("https://127.0.0.1/"); err == nil {
		t.Fatal("nothing listens on loopback 443")
	}
	if got := other.resolves.Load(); got != 0 {
		t.Fatalf("resolves = %d, want 0: a default-port master origin must match before the resolver is asked", got)
	}
}

// TestPathMismatchClosesConn proves a connection whose path does not meet the
// requirement is closed and never handed to net/http.
func TestPathMismatchClosesConn(t *testing.T) {
	cert := testCert(t, "peer.test")
	pool := testPool(t, cert)
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	var served atomic.Int64
	serveTLS(t, peerLis, cert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))

	var rejected atomic.Int64
	script := &dialScript{
		addr:   peerAddr,
		pathAt: func(int) Path { return PathRelay },
		// Count only the second dial's connection: net/http never owns it, so
		// the close count is exactly what peerDial did.
		wrap: func(n int, conn net.Conn) net.Conn {
			if n == 2 {
				return &countingClose{Conn: conn, closes: &rejected}
			}
			return conn
		},
	}
	tr, err := NewTransport(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, WithResolver(script.Resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	target := "https://" + peerAddr + "/"

	// Nothing pinned: the relay path is accepted and served.
	res, err := client.Get(target)
	if err != nil {
		t.Fatalf("unpinned request: %v", err)
	}
	res.Body.Close()
	if got := served.Load(); got != 1 {
		t.Fatalf("served = %d, want 1", got)
	}

	// Pinned direct: the connection is closed before the handshake.
	_, err = getWith(WithPath(context.Background(), PathDirect), client, target)
	if err == nil {
		t.Fatal("a path that does not meet the requirement must fail")
	} else if !strings.Contains(err.Error(), "took the circuit path, direct was required") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rejected.Load(); got != 1 {
		t.Fatalf("rejected connection closes = %d, want 1", got)
	}
	if got := served.Load(); got != 1 {
		t.Fatalf("served = %d, want 1: the rejected connection must not reach the handler", got)
	}
	if got := script.dials.Load(); got != 2 {
		t.Fatalf("dials = %d, want 2", got)
	}
}

// TestPathReuseNeverCrosses proves pooled connections cannot carry one request's
// path to another: every peer request dials fresh, the reported path is the
// path it actually took, and a mismatch is closed.
func TestPathReuseNeverCrosses(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	var served atomic.Int64
	serveTLS(t, peerLis, cert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))

	script := &dialScript{addr: peerAddr, pathAt: func(n int) Path {
		if n%2 == 1 {
			return PathDirect
		}
		return PathRelay
	}}
	var obsMu sync.Mutex
	var obs []Path
	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)}, WithResolver(script.Resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	tr.SetReporter(&Reporter{Observe: func(o Observation) {
		obsMu.Lock()
		obs = append(obs, o.Path)
		obsMu.Unlock()
	}})
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	target := "https://" + peerAddr + "/"
	req := func(p Path) error {
		_, err := getWith(WithPath(context.Background(), p), client, target)
		return err
	}

	if err := req(PathDirect); err != nil {
		t.Fatalf("direct: %v", err)
	}
	if err := req(PathRelay); err != nil {
		t.Fatalf("circuit: %v", err)
	}
	if err := req(PathDirect); err != nil {
		t.Fatalf("direct again: %v", err)
	}
	if err := req(PathRelay); err != nil {
		t.Fatalf("circuit again: %v", err)
	}
	// The fifth dial is direct, so a pinned circuit path cannot be met.
	if err := req(PathRelay); err == nil {
		t.Fatal("the fifth dial took the direct path, so a pinned circuit path must fail")
	}

	if got := script.dials.Load(); got != 5 {
		t.Fatalf("dials = %d, want 5: every peer request must get its own connection", got)
	}
	if got := served.Load(); got != 4 {
		t.Fatalf("served = %d, want 4: the mismatched connection must not be served", got)
	}
	want := []Path{PathDirect, PathRelay, PathDirect, PathRelay}
	obsMu.Lock()
	got := append([]Path(nil), obs...)
	obsMu.Unlock()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reported paths = %v, want %v", got, want)
	}
}

// TestNoPeerPathFallsBack proves the fallback rules: a nil resolver or a nil
// dialer falls back to plain TCP only when nothing pinned a peer path.
func TestNoPeerPathFallsBack(t *testing.T) {
	cert := testCert(t, "peer.test")
	pool := testPool(t, cert)
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)
	target := "https://" + peerAddr + "/"
	base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}

	// 1. No resolver at all: an https peer request goes over plain TCP.
	tr, err := NewTransport(base)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	res, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get(target)
	if err != nil {
		t.Fatalf("pass-through without a resolver: %v", err)
	}
	res.Body.Close()

	// 2. A resolver with no dialer for the address: the same fallback.
	script := &dialScript{addr: "127.0.0.1:1"}
	tr2, err := NewTransport(base, WithResolver(script.Resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	client2 := &http.Client{Transport: tr2, Timeout: 10 * time.Second}
	res, err = client2.Get(target)
	if err != nil {
		t.Fatalf("pass-through with no dialer: %v", err)
	}
	res.Body.Close()
	if got := script.resolves.Load(); got != 1 {
		t.Fatalf("resolves = %d, want 1", got)
	}
	if got := script.dials.Load(); got != 0 {
		t.Fatalf("peer dials = %d, want 0", got)
	}

	// 3. A pinned peer path never falls back.
	_, err = getWith(WithPath(context.Background(), PathDirect), client2, target)
	if err == nil {
		t.Fatal("a pinned peer path must not fall back")
	} else if !strings.Contains(err.Error(), "requires the direct peer path") {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = getWith(WithPath(context.Background(), PathDirect), &http.Client{Transport: tr, Timeout: 10 * time.Second}, target)
	if err == nil {
		t.Fatal("a pinned peer path must not fall back without a resolver")
	} else if !strings.Contains(err.Error(), "no resolver is configured") {
		t.Fatalf("unexpected error: %v", err)
	}

	// 4. A resolver error is not swallowed by the fallback.
	wanted := errors.New("registry unavailable")
	tr3, err := NewTransport(base, WithResolver(Resolver(func(context.Context, string) (PeerDialer, error) {
		return nil, wanted
	})))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	if _, err := (&http.Client{Transport: tr3, Timeout: 10 * time.Second}).Get(target); !errors.Is(err, wanted) {
		t.Fatalf("a resolver error must surface, got: %v", err)
	}
}

// TestPeerDialChecked proves the dialer's reported identity and path are
// verified and that an ambiguous report fails closed.
func TestPeerDialChecked(t *testing.T) {
	cert := testCert(t, "peer.test")
	pool := testPool(t, cert)
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	var served atomic.Int64
	var closes atomic.Int64
	serveTLS(t, peerLis, cert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	conn := func() net.Conn {
		c, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", peerAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return &countingClose{Conn: c, closes: &closes}
	}
	withDial := func(pd PeerDial) *http.Client {
		tr, err := NewTransport(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
			WithResolver(Resolver(func(context.Context, string) (PeerDialer, error) {
				return func(context.Context) PeerDial { return pd }, nil
			})))
		if err != nil {
			t.Fatalf("NewTransport: %v", err)
		}
		return &http.Client{Transport: tr, Timeout: 10 * time.Second}
	}
	target := "https://" + peerAddr + "/"

	for _, c := range []struct {
		name string
		pd   PeerDial
		want string
	}{
		{"no verified identity", PeerDial{Conn: conn(), Path: PathDirect}, "no verified identity"},
		{"unrecognized path", PeerDial{Conn: conn(), Identity: "peer-a", Path: "bogus"}, `unrecognized peer path "bogus"`},
		{"not a peer path", PeerDial{Conn: conn(), Identity: "peer-a", Path: PathHTTPS}, "not a peer path"},
		{"connection and error", PeerDial{Conn: conn(), Identity: "peer-a", Path: PathDirect, Err: errors.New("half open")}, "both a connection and an error"},
		{"no connection", PeerDial{}, "no connection returned"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := withDial(c.pd).Get(target)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	if got := closes.Load(); got != 4 {
		t.Fatalf("rejected connection closes = %d, want 4", got)
	}
	if got := served.Load(); got != 0 {
		t.Fatalf("served = %d, want 0: a rejected dial must not reach the handler", got)
	}

	// An honest PathUnknown is accepted when nothing is pinned and reported as
	// unknown, but it never satisfies a pinned peer path.
	round := func(require Path) error {
		tr, err := NewTransport(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
			WithResolver(Resolver(func(context.Context, string) (PeerDialer, error) {
				return func(context.Context) PeerDial { return PeerDial{Conn: conn(), Identity: "peer-a", Path: PathUnknown} }, nil
			})))
		if err != nil {
			return err
		}
		var mu sync.Mutex
		var got Path
		tr.SetReporter(&Reporter{Observe: func(o Observation) { mu.Lock(); got = o.Path; mu.Unlock() }})
		ctx := context.Background()
		if require != "" {
			ctx = WithPath(ctx, require)
		}
		resp, err := getWith(ctx, &http.Client{Transport: tr, Timeout: 10 * time.Second}, target)
		if err != nil {
			return err
		}
		resp.Body.Close()
		mu.Lock()
		defer mu.Unlock()
		if got != PathUnknown {
			return fmt.Errorf("reported %s, want %s", got, PathUnknown)
		}
		return nil
	}
	if err := round(""); err != nil {
		t.Fatalf("an unexposed path must be accepted and reported honestly: %v", err)
	}
	if err := round(PathDirect); err == nil {
		t.Fatal("an unexposed path must not satisfy a pinned direct path")
	}
}

// TestRoundTripRejectsAmbiguousURLs proves malformed requests are refused before
// anything is dialed.
func TestRoundTripRejectsAmbiguousURLs(t *testing.T) {
	script := &dialScript{addr: "127.0.0.1:1"}
	tr, err := NewTransport(&http.Transport{}, WithResolver(script.Resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	must := func(name string, req *http.Request) {
		t.Helper()
		if _, err := tr.RoundTrip(req); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	must("nil request", nil)
	must("nil URL", &http.Request{Method: "GET"})
	must("hostless URL", &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Path: "/x"}})
	must("unsupported scheme", &http.Request{Method: "GET", URL: &url.URL{Scheme: "ftp", Host: "peer:1"}})
	must("opaque and host", &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Host: "peer:1", Opaque: "x"}})
	forced := &url.URL{Scheme: "https", Host: "peer:1"}
	forced.ForceQuery = true
	must("forced query", &http.Request{Method: "GET", URL: forced})
	must("disagreeing RawPath", &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Host: "peer:1", Path: "/a b", RawPath: "/x"}})
	must("bare IPv6 literal", &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Host: "::1"}})
	must("peer userinfo", &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Host: "peer:443", User: url.UserPassword("a", "b")}})
	if script.resolves.Load() != 0 || script.dials.Load() != 0 {
		t.Fatal("a refused request must not resolve or dial")
	}
}

// TestRequestHeadersAreNotSecurityFlags proves caller-controlled headers can
// never stand in for TLS or for a path.
func TestRequestHeadersAreNotSecurityFlags(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)
	script := &dialScript{addr: peerAddr, pathAt: func(int) Path { return PathRelay }}
	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)}, WithResolver(script.Resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}

	req, err := http.NewRequest("GET", "http://"+peerAddr+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Peer-Path", "direct")
	req.Header.Set("X-Forwarded-Proto", "https")
	if _, err := tr.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "http is not permitted") {
		t.Fatalf("a forged header must not make an http request secure, got: %v", err)
	}
	if got := script.dials.Load(); got != 0 {
		t.Fatalf("dials = %d, want 0", got)
	}

	req, err = http.NewRequestWithContext(WithPath(context.Background(), PathDirect), "GET", "https://"+peerAddr+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Peer-Path", "direct")
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("a forged path header must not satisfy a pinned direct path")
	}
}

// TestPeerRequestsBypassProxy proves the base transport's proxy can never carry
// a peer request somewhere else.
func TestPeerRequestsBypassProxy(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)

	var proxied atomic.Int64
	base := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: testPool(t, cert)},
		Proxy: func(*http.Request) (*url.URL, error) {
			proxied.Add(1)
			return &url.URL{Scheme: "http", Host: "127.0.0.1:1"}, nil
		},
	}
	script := &dialScript{addr: peerAddr, pathAt: directPath}
	tr, err := NewTransport(base, WithResolver(script.Resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	res, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://" + peerAddr + "/")
	if err != nil {
		t.Fatalf("peer https: %v", err)
	}
	res.Body.Close()
	if got := proxied.Load(); got != 0 {
		t.Fatalf("a peer request went through the proxy %d time(s)", got)
	}
}

// TestCloseIdleConnections proves idle connections are closed and that the
// master path keeps the pooling the caller configured.
func TestCloseIdleConnections(t *testing.T) {
	cert := testCert(t, "peer.test")
	masterLis := listen(t)
	masterAddr := masterLis.Addr().String()
	serveTLS(t, masterLis, cert, okHandler)

	d := &dialCounter{}
	base := &http.Transport{TLSClientConfig: tlsConfig(t, cert), DialContext: d.DialContext}
	tr, err := NewTransport(base, WithMaster("https://"+masterAddr))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	target := "https://" + masterAddr + "/"
	get := func() {
		res, err := client.Get(target)
		if err != nil {
			t.Fatalf("master https: %v", err)
		}
		// Drain before closing: an undrained body makes net/http close the
		// connection instead of returning it to the pool.
		if _, err := io.Copy(io.Discard, res.Body); err != nil {
			t.Fatalf("drain: %v", err)
		}
		res.Body.Close()
	}
	get()
	get()
	if got := d.dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1: the master path must keep its pooling", got)
	}
	tr.CloseIdleConnections()
	if got := d.closes.Load(); got != 1 {
		t.Fatalf("closes = %d, want 1", got)
	}
	get()
	if got := d.dials.Load(); got != 2 {
		t.Fatalf("dials = %d, want 2", got)
	}
}

// TestReporterPrecedence proves a context reporter wins over the Transport's.
func TestReporterPrecedence(t *testing.T) {
	cert := testCert(t, "peer.test")
	masterLis := listen(t)
	masterAddr := masterLis.Addr().String()
	serveTLS(t, masterLis, cert, okHandler)

	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)}, WithMaster("https://"+masterAddr))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	var mu sync.Mutex
	count := map[string]int{}
	tr.SetReporter(&Reporter{Observe: func(Observation) {
		mu.Lock()
		count["transport"]++
		mu.Unlock()
	}})

	req, err := http.NewRequest("GET", "https://"+masterAddr+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req = req.WithContext(WithReporter(req.Context(), &Reporter{Observe: func(Observation) {
		mu.Lock()
		count["context"]++
		mu.Unlock()
	}}))
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if count["context"] != 1 || count["transport"] != 0 {
		t.Fatalf("reports = %v, want the context reporter to win", count)
	}
}

// TestServeTLSOverStream checks the equivalent server spelling: ServeTLS over a
// raw peer-stream listener performs the handshake itself.
func TestServeTLSOverStream(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	var served, unsecured atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		if r.TLS == nil {
			unsecured.Add(1)
			http.Error(w, "plaintext connections are rejected", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	done := make(chan error, 1)
	go func() { done <- srv.ServeTLS(peerLis, "", "") }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})

	script := &dialScript{addr: peerAddr, pathAt: directPath}
	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)}, WithResolver(script.Resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	res, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://" + peerAddr + "/")
	if err != nil {
		t.Fatalf("peer https: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if got := served.Load(); got != 1 {
		t.Fatalf("served = %d, want 1", got)
	}
	if got := unsecured.Load(); got != 0 {
		t.Fatalf("server saw %d unsecured request(s)", got)
	}
}

// TestSecureListenerValidation checks the wiring-time checks.
func TestSecureListenerValidation(t *testing.T) {
	cert := testCert(t, "peer.test")
	lis := listen(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	if _, err := SecureListener(nil, cfg); err == nil {
		t.Error("nil listener accepted")
	}
	if _, err := SecureListener(lis, nil); err == nil {
		t.Error("nil config accepted")
	}
	if _, err := SecureListener(lis, &tls.Config{}); err == nil {
		t.Error("a certless config accepted")
	}
	if _, err := SecureListener(lis, &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate}}}); err == nil {
		t.Error("a keyless certificate accepted")
	}
	// GetCertificate is a valid way to hand out a certificate.
	if _, err := SecureListener(lis, &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &cert, nil
	}}); err != nil {
		t.Fatalf("a GetCertificate config rejected: %v", err)
	}
	if _, err := SecureListener(lis, cfg); err != nil {
		t.Fatalf("a valid config rejected: %v", err)
	}
}

// TestNewTransportValidation checks the transport's configuration checks.
func TestNewTransportValidation(t *testing.T) {
	base := &http.Transport{}
	for _, master := range []string{
		"https:",
		"https:127.0.0.1:9",
		"https://127.0.0.1:9/path",
		"https://user:pass@127.0.0.1:9",
		"https://127.0.0.1:9?x=1",
		"https://127.0.0.1:9#f",
		"https:/127.0.0.1",
		"127.0.0.1:9",
		"ftp://127.0.0.1:9",
		"::1",
		"https://[::1",
	} {
		if _, err := NewTransport(base, WithMaster(master)); err == nil {
			t.Errorf("master %q accepted", master)
		}
	}
	for _, master := range []string{
		"",
		"https://127.0.0.1",
		"https://127.0.0.1:8443",
		"http://master.example",
		"https://[::1]:8443",
	} {
		if _, err := NewTransport(base, WithMaster(master)); err != nil {
			t.Errorf("master %q rejected: %v", master, err)
		}
	}
	if _, err := NewTransport(nil); err == nil {
		t.Error("nil base accepted")
	}
	if _, err := NewTransport(&http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, nil },
	}); err == nil {
		t.Error("a DialTLSContext base accepted")
	}
	if _, err := NewTransport(&http.Transport{
		DialTLS: func(string, string) (net.Conn, error) { return nil, nil },
	}); err == nil {
		t.Error("a DialTLS base accepted")
	}
	skip := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	if _, err := NewTransport(skip); err == nil {
		t.Error("InsecureSkipVerify accepted without opt-in")
	}
	if _, err := NewTransport(skip, AllowInsecureTLS()); err != nil {
		t.Fatalf("opted-in InsecureSkipVerify rejected: %v", err)
	}
	if _, err := NewTransport(&http.Transport{TLSClientConfig: &tls.Config{ServerName: "example"}}); err == nil {
		t.Error("a preset ServerName accepted")
	}
}
