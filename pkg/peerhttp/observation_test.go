package peerhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- helpers ----

// observationSink collects observations in arrival order. Its reporter is
// installed per request or per transport; Observe must synchronize itself,
// exactly as the Reporter contract demands.
type observationSink struct {
	mu  sync.Mutex
	obs []Observation
}

func (s *observationSink) reporter() *Reporter {
	return &Reporter{Observe: func(o Observation) {
		s.mu.Lock()
		s.obs = append(s.obs, o)
		s.mu.Unlock()
	}}
}

func (s *observationSink) snapshot() []Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Observation(nil), s.obs...)
}

// scriptedPeer dials a real TLS server but reports scripted dial facts, and
// records every dial context so tests can assert on the private request meta.
type scriptedPeer struct {
	t    *testing.T
	addr string
	// script may replace the default accepted-dial report; a replacement
	// without a connection counts as a failed dial.
	script func(n int, pd PeerDial) PeerDial

	mu   sync.Mutex
	ctxs []context.Context
}

func (s *scriptedPeer) resolver() Resolver {
	return Resolver(func(ctx context.Context, nodeAddr string) (PeerDialer, error) {
		if nodeAddr != s.addr {
			return nil, nil
		}
		return s.dial, nil
	})
}

func (s *scriptedPeer) dial(ctx context.Context) PeerDial {
	s.mu.Lock()
	s.ctxs = append(s.ctxs, ctx)
	n := len(s.ctxs)
	s.mu.Unlock()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return PeerDial{Err: err, Identity: "peer-a", Path: PathUnknown}
	}
	pd := PeerDial{
		Conn:          conn,
		Identity:      "peer-a",
		Path:          PathDirect,
		ConnectionID:  fmt.Sprintf("conn-%d", n),
		StreamID:      fmt.Sprintf("stream-%d", n),
		LocalAddress:  "local-peer-addr",
		RemoteAddress: "remote-peer-addr",
	}
	if s.script != nil {
		base := pd
		pd = s.script(n, pd)
		if pd.Conn == nil && base.Conn != nil {
			_ = base.Conn.Close() // a script that reports failure abandons the connection
		}
	}
	return pd
}

func (s *scriptedPeer) dialContexts() []context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]context.Context(nil), s.ctxs...)
}

// peerTransport wires a transport and client to the scripted peer, with sink
// as the transport-level reporter when it is not nil.
func peerTransport(t *testing.T, cert tls.Certificate, peer *scriptedPeer, sink *observationSink) (*Transport, *http.Client) {
	t.Helper()
	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)}, WithResolver(peer.resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	if sink != nil {
		tr.SetReporter(sink.reporter())
	}
	return tr, &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// readAll drains a response to EOF and closes it.
func readAll(t *testing.T, res *http.Response) {
	t.Helper()
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// assertNoSecret fails if raw error material leaked into any observation.
func assertNoSecret(t *testing.T, secret string, obs []Observation) {
	t.Helper()
	for i, o := range obs {
		if strings.Contains(fmt.Sprintf("%+v", o), secret) {
			t.Fatalf("observation %d carries raw error material: %+v", i, o)
		}
	}
}

// ---- tests ----

// TestAutoRequestIDOptIn proves the automatic request ID is opt-in: a reporter
// on the request or the transport allocates one per request, a caller-set ID is
// reported verbatim, and with no observer nothing is allocated at all.
func TestAutoRequestIDOptIn(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)
	peer := &scriptedPeer{t: t, addr: peerAddr}

	// 1. A transport reporter opts every peer request in: one ID per request,
	// shared by its dial report and its completion report.
	sink := &observationSink{}
	_, client := peerTransport(t, cert, peer, sink)
	for i := 0; i < 2; i++ {
		res, err := client.Get("https://" + peerAddr + "/")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		readAll(t, res)
	}
	obs := sink.snapshot()
	if len(obs) != 4 {
		t.Fatalf("observations = %d, want a dial and a completion per request", len(obs))
	}
	if obs[0].RequestID == "" || obs[0].RequestID == obs[2].RequestID {
		t.Fatalf("auto IDs must exist and differ per request: %q vs %q", obs[0].RequestID, obs[2].RequestID)
	}
	if obs[0].RequestID != obs[1].RequestID {
		t.Fatal("the dial and the completion of one request must share its ID")
	}
	// The auto ID goes back into the request context, so the runtime behind the
	// resolver reads from the dial context the same ID the reports carry and can
	// correlate it with ConnectionID without any side channel.
	dialCtxs := peer.dialContexts()
	if len(dialCtxs) != 2 {
		t.Fatalf("dials = %d, want 2", len(dialCtxs))
	}
	if RequestID(dialCtxs[0]) != obs[0].RequestID || RequestID(dialCtxs[1]) != obs[2].RequestID {
		t.Fatalf("dial context IDs = %q, %q, want the reports' IDs", RequestID(dialCtxs[0]), RequestID(dialCtxs[1]))
	}

	// 2. A caller-set ID is reported verbatim, not replaced.
	ctx := WithRequestID(context.Background(), "caller-id-1")
	res, err := getWith(ctx, client, "https://"+peerAddr+"/")
	if err != nil {
		t.Fatalf("request with ID: %v", err)
	}
	readAll(t, res)
	obs = sink.snapshot()
	if obs[len(obs)-2].RequestID != "caller-id-1" || obs[len(obs)-1].RequestID != "caller-id-1" {
		t.Fatalf("caller ID reports = %q, %q", obs[len(obs)-2].RequestID, obs[len(obs)-1].RequestID)
	}

	// 3. A request-level reporter opts in even without a transport reporter.
	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)}, WithResolver(peer.resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	requestSink := &observationSink{}
	req, err := http.NewRequest("GET", "https://"+peerAddr+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req = req.WithContext(WithReporter(req.Context(), requestSink.reporter()))
	res, err = (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request-level reporter: %v", err)
	}
	res.Body.Close()
	if got := len(requestSink.snapshot()); got == 0 {
		t.Fatal("a request-level reporter must opt the request in")
	}

	// 4. Nothing observes: the request stays fully uninstrumented — no meta, no
	// trace, no body wrapper, no ID — exactly the request net/http would make.
	unobserved := &scriptedPeer{t: t, addr: peerAddr}
	tr2, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)}, WithResolver(unobserved.resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	res, err = (&http.Client{Transport: tr2, Timeout: 10 * time.Second}).Get("https://" + peerAddr + "/")
	if err != nil {
		t.Fatalf("unobserved request: %v", err)
	}
	readAll(t, res)
	if _, ok := res.Body.(*observedBody); ok {
		t.Fatal("an unobserved request must not get a body wrapper")
	}
	ctxs := unobserved.dialContexts()
	if len(ctxs) != 1 {
		t.Fatalf("dials = %d, want 1", len(ctxs))
	}
	if meta := metaFrom(ctxs[0]); meta != nil {
		t.Fatalf("an unobserved request must carry no meta, got %+v", meta)
	}
}

// TestObservationCarriesDialFacts proves the dial report and the response
// completion describe the same request and the same connection, and that a
// query never enters a report.
func TestObservationCarriesDialFacts(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)
	peer := &scriptedPeer{t: t, addr: peerAddr}
	sink := &observationSink{}
	_, client := peerTransport(t, cert, peer, sink)

	req, err := http.NewRequest("GET", "https://"+peerAddr+"/data/x?q=1", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	readAll(t, res)

	obs := sink.snapshot()
	if len(obs) != 2 {
		t.Fatalf("observations = %+v, want a dial and a completion", obs)
	}
	dial, done := obs[0], obs[1]
	if dial.Phase != PhaseDial || done.Phase != PhaseResponse {
		t.Fatalf("phases = %q, %q", dial.Phase, done.Phase)
	}
	if dial.Path != PathDirect || dial.Identity != "peer-a" || dial.Master {
		t.Fatalf("dial report = %+v", dial)
	}
	if dial.ConnectionID == "" || dial.StreamID == "" || dial.LocalAddress == "" || dial.RemoteAddress == "" {
		t.Fatalf("dial report = %+v: the dial facts must be reported", dial)
	}
	if dial.Method != "GET" || dial.RequestPath != "/data/x" {
		t.Fatalf("dial request facts = %+v", dial)
	}
	if done.Status != http.StatusOK || done.ErrorKind != ErrorNone {
		t.Fatalf("completion = %+v", done)
	}
	// The completion describes the connection that served the response.
	if done.Identity != dial.Identity || done.ConnectionID != dial.ConnectionID || done.StreamID != dial.StreamID {
		t.Fatalf("completion = %+v, dial = %+v", done, dial)
	}
	// The request path is the path alone: the query stays out of every report.
	if done.RequestPath != "/data/x" {
		t.Fatalf("completion = %+v", done)
	}
	if leaked := fmt.Sprintf("%+v", obs); strings.Contains(leaked, "q=1") {
		t.Fatalf("a query leaked into the reports: %s", leaked)
	}
}

// TestFallbackFacts proves FallbackUpgraded is derived from the dial's own
// facts: a fallback that landed on the direct path is upgraded, any other
// fallback is not, and the plain-TCP fallback reports itself honestly.
func TestFallbackFacts(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)
	target := "https://" + peerAddr + "/"

	for _, c := range []struct {
		name     string
		script   func(n int, pd PeerDial) PeerDial
		fallback bool
		path     Path
		upgraded bool
	}{
		{"fallback upgraded to direct", func(_ int, pd PeerDial) PeerDial { pd.Fallback = true; return pd }, true, PathDirect, true},
		{"fallback stayed on the relay", func(_ int, pd PeerDial) PeerDial { pd.Fallback = true; pd.Path = PathRelay; return pd }, true, PathRelay, false},
		{"no fallback", func(_ int, pd PeerDial) PeerDial { return pd }, false, PathDirect, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			peer := &scriptedPeer{t: t, addr: peerAddr, script: c.script}
			sink := &observationSink{}
			_, client := peerTransport(t, cert, peer, sink)
			res, err := client.Get(target)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			readAll(t, res)
			obs := sink.snapshot()
			if len(obs) != 2 {
				t.Fatalf("observations = %+v", obs)
			}
			for i, o := range obs {
				if o.Fallback != c.fallback || o.FallbackUpgraded != c.upgraded || o.Path != c.path {
					t.Fatalf("report %d = %+v", i, o)
				}
			}
		})
	}

	// The plain-TCP fallback is a fallback on the ordinary path, never an
	// upgraded one, and its addresses are the socket's own facts.
	sink := &observationSink{}
	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)},
		WithResolver(Resolver(func(context.Context, string) (PeerDialer, error) { return nil, nil })))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	tr.SetReporter(sink.reporter())
	res, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get(target)
	if err != nil {
		t.Fatalf("fallback get: %v", err)
	}
	readAll(t, res)
	obs := sink.snapshot()
	if len(obs) != 2 {
		t.Fatalf("observations = %+v", obs)
	}
	for i, o := range obs {
		if o.Path != PathHTTPS || !o.Fallback || o.FallbackUpgraded {
			t.Fatalf("report %d = %+v", i, o)
		}
		if o.LocalAddress == "" || o.RemoteAddress != peerAddr {
			t.Fatalf("report %d = %+v: the addresses must be the socket facts", i, o)
		}
	}
}

// TestDialFailureReportsKindWithoutRawError proves a failed dial is reported
// once, with a bounded kind and no identity, and that the raw error text stays
// on the returned error where the caller can act on it.
func TestDialFailureReportsKindWithoutRawError(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)
	secret := "SECRET-raw-error-material"

	peer := &scriptedPeer{t: t, addr: peerAddr, script: func(_ int, _ PeerDial) PeerDial {
		return PeerDial{Err: fmt.Errorf("dial refused: %s", secret), Identity: "peer-a", Path: PathUnknown}
	}}
	sink := &observationSink{}
	_, client := peerTransport(t, cert, peer, sink)
	_, err := client.Get("https://" + peerAddr + "/")
	if err == nil || !strings.Contains(err.Error(), secret) {
		t.Fatalf("the caller must still see the raw error, got: %v", err)
	}
	obs := sink.snapshot()
	if len(obs) != 1 {
		t.Fatalf("observations = %+v, want exactly the dial failure", obs)
	}
	if obs[0].Phase != PhaseDial || obs[0].ErrorKind != ErrorConnect || obs[0].Path != PathUnknown {
		t.Fatalf("dial failure = %+v", obs[0])
	}
	if obs[0].Identity != "" {
		t.Fatalf("dial failure = %+v: nothing was verified about a failed dial", obs[0])
	}
	assertNoSecret(t, secret, obs)

	// A resolver failure is reported with its own kind.
	sink2 := &observationSink{}
	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)},
		WithResolver(Resolver(func(context.Context, string) (PeerDialer, error) {
			return nil, fmt.Errorf("registry unavailable: %s", secret)
		})))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	tr.SetReporter(sink2.reporter())
	if _, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://" + peerAddr + "/"); err == nil {
		t.Fatal("a resolver failure must fail the request")
	}
	obs = sink2.snapshot()
	if len(obs) != 1 || obs[0].ErrorKind != ErrorResolve || obs[0].Path != PathUnknown {
		t.Fatalf("resolver failure = %+v", obs)
	}
	assertNoSecret(t, secret, obs)
}

// TestResponseFailureAfterAcceptedDial proves a failure after the dial was
// accepted is reported once as a response failure: a TLS handshake failure
// happens before GotConn, so its connection stays unknown, while a response
// header timeout happens after it, so its report carries the facts of the
// connection net/http committed the request to.
func TestResponseFailureAfterAcceptedDial(t *testing.T) {
	cert := testCert(t, "peer.test")
	foreign := testCert(t, "foreign.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)
	target := "https://" + peerAddr + "/"

	// Handshake failure after an accepted dial: no GotConn, no connection facts.
	peer := &scriptedPeer{t: t, addr: peerAddr}
	sink := &observationSink{}
	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, foreign)}, WithResolver(peer.resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	tr.SetReporter(sink.reporter())
	if _, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get(target); err == nil {
		t.Fatal("an untrusted certificate must fail the handshake")
	}
	obs := sink.snapshot()
	if len(obs) != 2 {
		t.Fatalf("observations = %+v, want the dial acceptance and one response failure", obs)
	}
	if obs[0].Phase != PhaseDial || obs[0].ErrorKind != ErrorNone {
		t.Fatalf("dial report = %+v", obs[0])
	}
	failure := obs[1]
	if failure.Phase != PhaseResponse || failure.ErrorKind != ErrorTLS || failure.Status != 0 {
		t.Fatalf("response failure = %+v, want one TLS response failure", failure)
	}
	if failure.Path != PathUnknown || failure.Identity != "" || failure.ConnectionID != "" {
		t.Fatalf("response failure = %+v: GotConn never fired, so the connection stays unknown", failure)
	}

	// Response header timeout after GotConn: the facts of the serving
	// connection are known and reported.
	stall := listen(t)
	stallAddr := stall.Addr().String()
	serveTLS(t, stall, cert, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	stalled := &scriptedPeer{t: t, addr: stallAddr}
	timeoutSink := &observationSink{}
	tr2, err := NewTransport(&http.Transport{
		TLSClientConfig:       tlsConfig(t, cert),
		ResponseHeaderTimeout: 50 * time.Millisecond,
	}, WithResolver(stalled.resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	tr2.SetReporter(timeoutSink.reporter())
	if _, err := (&http.Client{Transport: tr2, Timeout: 10 * time.Second}).Get("https://" + stallAddr + "/"); err == nil {
		t.Fatal("a stalled response must time out")
	}
	obs = timeoutSink.snapshot()
	if len(obs) != 2 {
		t.Fatalf("observations = %+v, want the dial acceptance and one response failure", obs)
	}
	if obs[0].Phase != PhaseDial || obs[0].ErrorKind != ErrorNone {
		t.Fatalf("dial report = %+v", obs[0])
	}
	failure = obs[1]
	if failure.Phase != PhaseResponse || failure.ErrorKind != ErrorTimeout || failure.Status != 0 {
		t.Fatalf("response failure = %+v, want one timeout response failure", failure)
	}
	if failure.Identity != "peer-a" || failure.Path != PathDirect || failure.ConnectionID == "" {
		t.Fatalf("response failure = %+v: GotConn identified the serving connection", failure)
	}
}

// TestResponseCompletionOnEOF proves a response read to EOF reports exactly one
// proven completion, and that Close and later reads cannot report again.
func TestResponseCompletionOnEOF(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)
	peer := &scriptedPeer{t: t, addr: peerAddr}
	sink := &observationSink{}
	_, client := peerTransport(t, cert, peer, sink)

	res, err := client.Get("https://" + peerAddr + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, _ = res.Body.Read(make([]byte, 1)) // a late read must not report again

	obs := sink.snapshot()
	if len(obs) != 2 {
		t.Fatalf("observations = %+v, want a dial and one completion", obs)
	}
	done := obs[1]
	if done.Phase != PhaseResponse || done.Status != http.StatusOK || done.ErrorKind != ErrorNone {
		t.Fatalf("completion = %+v", done)
	}
}

// TestResponseCompletionOnEarlyClose proves a body closed before a proven EOF
// is reported as body_closed, exactly once, no matter what happens after.
func TestResponseCompletionOnEarlyClose(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "65536")
		_, _ = w.Write(make([]byte, 65536))
	}))
	peer := &scriptedPeer{t: t, addr: peerAddr}
	sink := &observationSink{}
	_, client := peerTransport(t, cert, peer, sink)

	res, err := client.Get("https://" + peerAddr + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := res.Body.Read(make([]byte, 1)); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	_ = res.Body.Close()                  // idempotent: still one report
	_, _ = res.Body.Read(make([]byte, 1)) // a read after close: still one report

	obs := sink.snapshot()
	if len(obs) != 2 {
		t.Fatalf("observations = %+v, want a dial and one completion", obs)
	}
	done := obs[1]
	if done.Phase != PhaseResponse || done.Status != http.StatusOK || done.ErrorKind != ErrorBodyClosed {
		t.Fatalf("completion = %+v, want one body_closed", done)
	}
}

// TestResponseCompleteWithoutBody proves a response that cannot carry body
// bytes is complete when closed unread, not mislabeled body_closed.
func TestResponseCompleteWithoutBody(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	peer := &scriptedPeer{t: t, addr: peerAddr}
	sink := &observationSink{}
	_, client := peerTransport(t, cert, peer, sink)

	// 204: no body can follow the headers.
	res, err := client.Get("https://" + peerAddr + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// HEAD: the method itself proves no body can follow.
	head, err := client.Head("https://" + peerAddr + "/")
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if err := head.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	obs := sink.snapshot()
	if len(obs) != 4 {
		t.Fatalf("observations = %+v, want dial and completion per request", obs)
	}
	for _, i := range []int{1, 3} {
		if obs[i].Phase != PhaseResponse || obs[i].ErrorKind != ErrorNone {
			t.Fatalf("completion = %+v, want a proven completion", obs[i])
		}
	}
}

// TestConcurrentReporterSwap proves reporter swaps and concurrent requests do
// not race: every request still succeeds and every report is well-formed. Run
// with -race; the sink's own mutex is part of the contract under test.
func TestConcurrentReporterSwap(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)

	script := &dialScript{addr: peerAddr, pathAt: directPath}
	tr, err := NewTransport(&http.Transport{TLSClientConfig: tlsConfig(t, cert)}, WithResolver(script.Resolver()))
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	sinkA, sinkB := &observationSink{}, &observationSink{}
	tr.SetReporter(sinkA.reporter())
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	stop := make(chan struct{})
	var swapper sync.WaitGroup
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			switch i % 3 {
			case 0:
				tr.SetReporter(nil)
			case 1:
				tr.SetReporter(sinkA.reporter())
			case 2:
				tr.SetReporter(sinkB.reporter())
			}
		}
	}()

	var requests sync.WaitGroup
	for i := 0; i < 8; i++ {
		requests.Add(1)
		go func() {
			defer requests.Done()
			for j := 0; j < 5; j++ {
				res, err := client.Get("https://" + peerAddr + "/")
				if err != nil {
					t.Errorf("request: %v", err)
					return
				}
				if _, err := io.Copy(io.Discard, res.Body); err != nil {
					t.Errorf("read: %v", err)
					_ = res.Body.Close()
					return
				}
				if err := res.Body.Close(); err != nil {
					t.Errorf("close: %v", err)
					return
				}
			}
		}()
	}
	requests.Wait()
	close(stop)
	swapper.Wait()

	if got := script.dials.Load(); got != 40 {
		t.Fatalf("dials = %d, want 40", got)
	}
	for _, s := range []*observationSink{sinkA, sinkB} {
		for _, o := range s.snapshot() {
			if o.Phase != PhaseDial && o.Phase != PhaseResponse {
				t.Fatalf("malformed report = %+v", o)
			}
		}
	}
}

// TestControlRequestStaysUnobserved proves a control request end to end: it
// dials normally, produces no report on any sink, and allocates no request ID,
// so control traffic can never be attributed to a data request.
func TestControlRequestStaysUnobserved(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, okHandler)
	peer := &scriptedPeer{t: t, addr: peerAddr}
	sink := &observationSink{}
	_, client := peerTransport(t, cert, peer, sink)

	ctx := ControlContext(WithRequestID(context.Background(), "data-request-1"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+peerAddr+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("control request: %v", err)
	}
	res.Body.Close()
	if obs := sink.snapshot(); len(obs) != 0 {
		t.Fatalf("control request observations = %+v, want none", obs)
	}
	ctxs := peer.dialContexts()
	if len(ctxs) != 1 {
		t.Fatalf("dials = %d, want 1", len(ctxs))
	}
	if meta := metaFrom(ctxs[0]); meta != nil {
		t.Fatal("a control request must stay uninstrumented, so it can never be attributed to a data request")
	}
}

// TestSwitchingProtocolsTunnel proves a 101 upgrade keeps working through the
// completion wrapper: the body stays a ReadWriteCloser tunnel that carries
// bytes after the headers, and an early Close is body_closed, never a proven
// completion, even though the response carries no ContentLength.
func TestSwitchingProtocolsTunnel(t *testing.T) {
	cert := testCert(t, "peer.test")
	peerLis := listen(t)
	peerAddr := peerLis.Addr().String()
	serveTLS(t, peerLis, cert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, err = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
		if err == nil {
			err = buf.Flush()
		}
		if err != nil {
			return
		}
		_, _ = io.Copy(conn, buf) // echo the tunnel until the client closes
	}))
	peer := &scriptedPeer{t: t, addr: peerAddr}
	sink := &observationSink{}
	tr, _ := peerTransport(t, cert, peer, sink)

	req, err := http.NewRequest("GET", "https://"+peerAddr+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// The transport only leaves the connection to the caller when the request
	// itself announces the switch; without it, DisableKeepAlives would inject
	// Connection: close. RoundTrip is driven directly: an http.Client would
	// wrap the body itself and drop Write above this layer.
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "test")
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("upgrade request: %v", err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", res.StatusCode)
	}
	rwc, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("a switched protocol body must stay a ReadWriteCloser, got %T", res.Body)
	}
	if _, err := rwc.Write([]byte("ping")); err != nil {
		t.Fatalf("tunnel write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(res.Body, got); err != nil {
		t.Fatalf("tunnel read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("tunnel read = %q, want ping", got)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatalf("tunnel close: %v", err)
	}
	obs := sink.snapshot()
	if len(obs) != 2 {
		t.Fatalf("observations = %+v, want the dial acceptance and one completion", obs)
	}
	done := obs[1]
	if done.Phase != PhaseResponse || done.Status != http.StatusSwitchingProtocols || done.ErrorKind != ErrorBodyClosed {
		t.Fatalf("completion = %+v, want one body_closed for the closed tunnel", done)
	}
}

// TestProvenCompletionRequiresCleanClose proves the proven-empty shortcut is
// exact: a switched protocol is never proven by its headers, and a Close that
// fails is never reported as success.
func TestProvenCompletionRequiresCleanClose(t *testing.T) {
	tr, err := NewTransport(&http.Transport{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	sink := &observationSink{}
	tr.SetReporter(sink.reporter())
	meta := &requestMeta{scheme: "https", target: "peer.test:443", requestID: "id", method: "GET", requestPath: "/"}

	// A 101 tunnel at ContentLength 0: closing it unread is body_closed.
	body101 := struct {
		io.Reader
		io.Writer
		io.Closer
	}{
		Reader: strings.NewReader("tunnel"),
		Writer: writerFunc(func([]byte) (int, error) { return 0, nil }),
		Closer: closerFunc(func() error { return nil }),
	}
	res := &http.Response{StatusCode: http.StatusSwitchingProtocols, ContentLength: 0, Body: body101}
	b := tr.observeBody(res, meta, &http.Request{Method: http.MethodGet})
	if _, ok := b.(io.ReadWriteCloser); !ok {
		t.Fatal("a 101 body must stay a ReadWriteCloser")
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	obs := sink.snapshot()
	if len(obs) != 1 || obs[0].Phase != PhaseResponse || obs[0].Status != http.StatusSwitchingProtocols || obs[0].ErrorKind != ErrorBodyClosed {
		t.Fatalf("completion = %+v, want body_closed for an unread tunnel", obs)
	}

	// A proven-empty body whose Close fails is a failure, never a success, and
	// the caller still sees the underlying close error.
	boom := errors.New("close failed")
	res2 := &http.Response{StatusCode: http.StatusNoContent, ContentLength: 0, Body: struct {
		io.Reader
		io.Closer
	}{strings.NewReader(""), closerFunc(func() error { return boom })}}
	b2 := tr.observeBody(res2, meta, &http.Request{Method: http.MethodGet})
	if err := b2.Close(); !errors.Is(err, boom) {
		t.Fatalf("close = %v, want the underlying error", err)
	}
	_ = b2.Close() // a repeated Close must not report again
	obs = sink.snapshot()
	if len(obs) != 2 {
		t.Fatalf("reports = %d, want one per body", len(obs))
	}
	if obs[1].ErrorKind != ErrorRead {
		t.Fatalf("completion = %+v, want the close error classified, not a success", obs[1])
	}
}

// TestObserveBodyPreservesReadWriteCloser proves the completion wrapper keeps
// the original body's interfaces and always reaches its Close.
func TestObserveBodyPreservesReadWriteCloser(t *testing.T) {
	tr, err := NewTransport(&http.Transport{})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	sink := &observationSink{}
	tr.SetReporter(sink.reporter())
	meta := &requestMeta{scheme: "https", target: "peer.test:443", requestID: "id", method: "GET", requestPath: "/"}

	type rwcBody struct {
		io.Reader
		io.Writer
		io.Closer
	}
	var writes []byte
	closed := false
	orig := &rwcBody{
		Reader: strings.NewReader("ok"),
		Writer: writerFunc(func(p []byte) (int, error) {
			writes = append(writes, p...)
			return len(p), nil
		}),
		Closer: closerFunc(func() error { closed = true; return nil }),
	}
	res := &http.Response{StatusCode: http.StatusOK, ContentLength: 2, Body: orig}
	body := tr.observeBody(res, meta, &http.Request{Method: http.MethodGet})
	observing, ok := body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("an io.ReadWriteCloser body must stay one under the wrapper")
	}
	if _, err := observing.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if string(writes) != "ping" {
		t.Fatalf("writes = %q, want %q", writes, "ping")
	}
	if _, err := io.ReadAll(body); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !closed {
		t.Fatal("the original body's Close must be reached")
	}
	obs := sink.snapshot()
	if len(obs) != 1 || obs[0].ErrorKind != ErrorNone || obs[0].Status != http.StatusOK || obs[0].RequestID != "id" {
		t.Fatalf("completion = %+v, want one proven completion", obs)
	}

	// A plain ReadCloser gains nothing it did not have.
	plain := &http.Response{StatusCode: http.StatusOK, ContentLength: 1, Body: io.NopCloser(strings.NewReader("x"))}
	wrapped := tr.observeBody(plain, meta, &http.Request{Method: http.MethodGet})
	if _, ok := wrapped.(io.Writer); ok {
		t.Fatal("a plain body must not grow a Write method")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
