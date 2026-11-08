package peertransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
)

func TestHTTPNormalDialReservesRequestBudgetAfterSilentDirect(t *testing.T) {
	center := newTestRuntime(t, Config{})
	target := newTestRuntime(t, Config{})
	dialer := newTestRuntime(t, Config{})
	center.SetAuthorizer(allowIDs(target.PeerID(), dialer.PeerID()))
	target.SetAuthorizer(allowIDs(center.PeerID(), dialer.PeerID()))
	dialer.SetAuthorizer(allowIDs(center.PeerID(), target.PeerID()))
	if err := center.EnableRelay(); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ReserveRelay(context.Background(), infraOf(center)); err != nil {
		t.Fatal(err)
	}
	listener, err := target.Listener()
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "peer.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"peer.test"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	secured, err := peerhttp.SecureListener(listener, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "real TLS required", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "relay-health")
	})}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(secured) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Error("peer HTTP server did not stop")
		}
	})
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release, entered := make(chan struct{}), make(chan struct{}, 1)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				select {
				case entered <- struct{}{}:
				default:
				}
				<-release
			}()
		}
	}()
	t.Cleanup(func() { _ = silent.Close(); close(release); workers.Wait() })
	ep := endpointOf(target)
	ep.Addresses = []string{"/ip4/127.0.0.1/tcp/" + portOf(silent.Addr().String())}
	tr, err := peerhttp.NewTransport(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, peerhttp.WithResolver(func(ctx context.Context, addr string) (peerhttp.PeerDialer, error) {
		return func(ctx context.Context) peerhttp.PeerDial {
			return dialer.Dial(ctx, ep, infraOf(center), peerhttp.PathUnknown).PeerDial
		}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr}
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var mu sync.Mutex
		var observations []peerhttp.Observation
		ctx = peerhttp.WithReporter(ctx, &peerhttp.Reporter{Observe: func(o peerhttp.Observation) {
			mu.Lock()
			observations = append(observations, o)
			mu.Unlock()
		}})
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://peer.test/healthz", nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		response, err := cl.Do(request)
		if err != nil {
			cancel()
			t.Fatalf("HTTP attempt %d missed the original request budget before relay: %v", attempt, err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		cancel()
		if err != nil || response.StatusCode != http.StatusOK || string(body) != "relay-health" {
			t.Fatalf("HTTP attempt %d body=%q status=%d err=%v", attempt, body, response.StatusCode, err)
		}
		mu.Lock()
		var completed bool
		for _, observation := range observations {
			usable := observation.Path == peerhttp.PathRelay || observation.Path == peerhttp.PathDirect
			if observation.Phase == peerhttp.PhaseResponse && usable && observation.Identity == target.PeerID() && observation.ErrorKind == peerhttp.ErrorNone && observation.ConnectionID != "" && observation.StreamID != "" {
				completed = attempt > 0 || observation.Fallback
			}
		}
		mu.Unlock()
		if !completed {
			t.Fatalf("HTTP attempt %d has no complete actual peer response within the request budget: %+v", attempt, observations)
		}
	}
	select {
	case <-entered:
	default:
		t.Fatal("test did not reach the silent direct candidate")
	}
}
