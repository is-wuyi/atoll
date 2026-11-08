package peerhttp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPRequestDeadlineStopsPendingPeerDial(t *testing.T) {
	observed := make(chan time.Time, 1)
	tr, err := NewTransport(&http.Transport{}, WithResolver(Resolver(func(ctx context.Context, addr string) (PeerDialer, error) {
		return func(dial context.Context) PeerDial {
			deadline, _ := dial.Deadline()
			observed <- deadline
			if deadline.IsZero() {
				return PeerDial{Err: errors.New("request deadline missing from peer dial")}
			}
			<-dial.Done()
			return PeerDial{Err: dial.Err()}
		}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr}
	for _, path := range []Path{PathUnknown, PathDirect, PathRelay} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		want, _ := ctx.Deadline()
		if path != PathUnknown {
			ctx = WithPath(ctx, path)
		}
		_, err = getWith(ctx, cl, "https://peer.test/healthz")
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s request error = %v, want deadline", path, err)
		}
		if got := <-observed; got != want {
			t.Fatalf("%s peer dial deadline = %v, want caller deadline %v", path, got, want)
		}
	}
}

func TestHTTPResolverDeadlineReachesPeerDial(t *testing.T) {
	observed := make(chan time.Time, 1)
	resolverExited := make(chan struct{})
	tr, err := NewTransport(&http.Transport{}, WithResolver(Resolver(func(ctx context.Context, addr string) (PeerDialer, error) {
		defer close(resolverExited)
		deadline, _ := ctx.Deadline()
		observed <- deadline
		if deadline.IsZero() {
			return nil, errors.New("request deadline missing from resolver")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	want, _ := ctx.Deadline()
	_, err = getWith(ctx, &http.Client{Transport: tr}, "https://peer.test/healthz")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request error = %v, want deadline", err)
	}
	if got := <-observed; got != want {
		t.Fatalf("resolver deadline = %v, want caller deadline %v", got, want)
	}
	select {
	case <-resolverExited:
	case <-time.After(time.Second):
		t.Fatal("peer resolver did not exit at the original deadline")
	}
}

func TestHTTPRequestCancellationStopsPendingPeerDial(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	tr, err := NewTransport(&http.Transport{}, WithResolver(Resolver(func(ctx context.Context, addr string) (PeerDialer, error) {
		return func(dial context.Context) PeerDial {
			defer close(exited)
			close(entered)
			<-dial.Done()
			return PeerDial{Err: dial.Err()}
		}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := getWith(ctx, &http.Client{Transport: tr}, "https://peer.test/healthz")
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("pending peer dial did not enter")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("request error = %v, want canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled HTTP request did not exit")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		tr.CloseIdleConnections()
		t.Fatal("canceled HTTP request left a peer dial pending")
	}
}

func TestHTTPDialContextCleanupDoesNotCloseEstablishedPeerConnection(t *testing.T) {
	cert := testCert(t, "peer.test")
	listener := listen(t)
	serveTLS(t, listener, cert, okHandler)
	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)}, WithResolver((&dialScript{addr: listener.Addr().String(), pathAt: directPath}).Resolver()))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := tr.dialPeerTLS(ctx, "tcp", listener.Addr().String())
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET /healthz HTTP/1.1\r\nHost: "+listener.Addr().String()+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "ok" || response.StatusCode != http.StatusOK {
		t.Fatalf("established TLS body = %q, status %d, error %v", body, response.StatusCode, err)
	}
}

func TestHTTPRequestKeepsShorterTLSHandshakeTimeout(t *testing.T) {
	server, raw := net.Pipe()
	defer server.Close()
	tr, err := NewTransport(&http.Transport{TLSHandshakeTimeout: 150 * time.Millisecond}, WithResolver(Resolver(func(ctx context.Context, addr string) (PeerDialer, error) {
		return func(dial context.Context) PeerDial {
			return PeerDial{Conn: raw, Identity: "peer-a", Path: PathDirect}
		}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	_, err = getWith(ctx, &http.Client{Transport: tr}, "https://peer.test/healthz")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second || ctx.Err() != nil {
		t.Fatalf("configured TLS timeout lost: err=%v elapsed=%v caller=%v", err, time.Since(started), ctx.Err())
	}
}

func TestHTTPRequestDeadlineBoundsPeerTLSHandshake(t *testing.T) {
	entered := make(chan struct{})
	server, raw := net.Pipe()
	defer server.Close()
	tr, err := NewTransport(&http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}, WithResolver(Resolver(func(ctx context.Context, addr string) (PeerDialer, error) {
		return func(dial context.Context) PeerDial {
			close(entered)
			return PeerDial{Conn: raw, Identity: "peer-a", Path: PathDirect}
		}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = getWith(ctx, &http.Client{Transport: tr}, "https://peer.test/healthz")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request error = %v, want deadline", err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("TLS peer dial never entered")
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4096)
	for {
		_, err = server.Read(buffer)
		if err != nil {
			break
		}
	}
	if err != io.EOF {
		t.Fatalf("silent TLS peer read = %v, want EOF after original deadline", err)
	}
}
