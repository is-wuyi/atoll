package peertrace

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync/atomic"
	"time"
)

const Header = "X-Atoll-Diagnostic-ID"

type Event struct {
	ID      string        `json:"id"`
	Side    string        `json:"side"`
	Method  string        `json:"method"`
	Path    string        `json:"path"`
	Phase   string        `json:"phase"`
	Elapsed time.Duration `json:"elapsed_ns"`
	Status  int           `json:"status,omitempty"`
	Error   string        `json:"error,omitempty"`
	Reused  bool          `json:"reused,omitempty"`
}

// Observers must be concurrency-safe and nonblocking. Events contain no query,
// request body, credentials, certificate contents or raw error strings.
type Observer func(Event)

type observerKey struct{}
type requestKey struct{}

var sequence atomic.Uint64

func WithObserver(ctx context.Context, observe Observer) context.Context {
	return context.WithValue(ctx, observerKey{}, observe)
}

type Request struct {
	observe Observer
	started time.Time
	event   Event
}

func (r *Request) emit(phase string, status int, err error, reused bool) {
	if r == nil {
		return
	}
	event := r.event
	event.Phase = phase
	event.Elapsed = time.Since(r.started)
	event.Status, event.Error, event.Reused = status, errorKind(err), reused
	r.observe(event)
}

func (r *Request) Mark(phase string) { r.emit(phase, 0, nil, false) }

func (r *Request) Finish(status int, err error) { r.emit("done", status, err, false) }

func StartClient(req *http.Request) (*http.Request, *Request) {
	observe, _ := req.Context().Value(observerKey{}).(Observer)
	if observe == nil {
		return req, nil
	}
	r := &Request{observe: observe, started: time.Now(), event: Event{
		ID: strconv.FormatUint(sequence.Add(1), 10), Side: "client", Method: req.Method, Path: req.URL.Path,
	}}
	trace := &httptrace.ClientTrace{
		GetConn:              func(string) { r.Mark("get_connection") },
		GotConn:              func(info httptrace.GotConnInfo) { r.emit("got_connection", 0, nil, info.Reused) },
		DNSStart:             func(httptrace.DNSStartInfo) { r.Mark("dns_start") },
		DNSDone:              func(info httptrace.DNSDoneInfo) { r.emit("dns_done", 0, info.Err, false) },
		ConnectStart:         func(string, string) { r.Mark("connect_start") },
		ConnectDone:          func(_, _ string, err error) { r.emit("connect_done", 0, err, false) },
		TLSHandshakeStart:    func() { r.Mark("tls_start") },
		TLSHandshakeDone:     func(_ tls.ConnectionState, err error) { r.emit("tls_done", 0, err, false) },
		WroteHeaders:         func() { r.Mark("wrote_headers") },
		WroteRequest:         func(info httptrace.WroteRequestInfo) { r.emit("wrote_request", 0, info.Err, false) },
		GotFirstResponseByte: func() { r.Mark("first_response_byte") },
	}
	copy := req.Clone(httptrace.WithClientTrace(req.Context(), trace))
	copy.Header.Set(Header, r.event.ID)
	r.Mark("start")
	return copy, r
}

// Handler is opt-in instrumentation, not an authorization boundary. The ID only
// correlates timing events and must never be used as an authenticated identity.
func Handler(next http.Handler, observe Observer) http.Handler {
	if observe == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		id := req.Header.Get(Header)
		if !validID(id) {
			next.ServeHTTP(w, req)
			return
		}
		r := &Request{observe: observe, started: time.Now(), event: Event{
			ID: id, Side: "server", Method: req.Method, Path: req.URL.Path,
		}}
		r.Mark("start")
		defer r.Finish(0, nil)
		next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), requestKey{}, r)))
	})
}

func Mark(ctx context.Context, phase string) {
	r, _ := ctx.Value(requestKey{}).(*Request)
	r.Mark(phase)
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 20 {
		return false
	}
	value, err := strconv.ParseUint(id, 10, 64)
	return err == nil && value != 0 && strconv.FormatUint(value, 10) == id
}

func errorKind(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "network_timeout"
	}
	return "request_error"
}
