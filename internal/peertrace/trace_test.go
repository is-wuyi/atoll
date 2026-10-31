package peertrace

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *eventLog) observe(e Event) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *eventLog) snapshot() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.events...)
}

func TestClientServerTraceUsesActualTLSPhases(t *testing.T) {
	var log eventLog
	server := httptest.NewTLSServer(Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Mark(r.Context(), "authorization_done")
		Mark(r.Context(), "directory_read_start")
		_, _ = io.WriteString(w, "{}")
		Mark(r.Context(), "directory_read_done")
	}), log.observe))
	defer server.Close()
	req, err := http.NewRequestWithContext(WithObserver(context.Background(), log.observe), http.MethodGet, server.URL+"/peers/directory?secret=not-for-trace", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer not-for-trace")
	traced, trace := StartClient(req)
	if req.Header.Get(Header) != "" || !validID(traced.Header.Get(Header)) {
		t.Fatal("tracing mutated the caller's header or omitted its correlation ID")
	}
	resp, err := server.Client().Do(traced)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	trace.Mark("response_body")
	trace.Finish(resp.StatusCode, err)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, event := range log.snapshot() {
		if event.ID != traced.Header.Get(Header) || event.Path != "/peers/directory" {
			t.Fatalf("trace identity or safe path changed: %+v", event)
		}
		seen[event.Side+":"+event.Phase] = true
	}
	for _, phase := range []string{"client:start", "client:get_connection", "client:connect_done", "client:tls_start", "client:tls_done", "client:wrote_request", "client:first_response_byte", "client:response_body", "client:done", "server:start", "server:authorization_done", "server:directory_read_start", "server:directory_read_done", "server:done"} {
		if !seen[phase] {
			t.Errorf("missing actual phase %s", phase)
		}
	}
	raw, _ := json.Marshal(log.snapshot())
	if strings.Contains(string(raw), "not-for-trace") || strings.Contains(string(raw), "Authorization") {
		t.Fatal("trace leaked request secrets")
	}
}

func TestTracingIsOptInAndRejectsAmbiguousIDs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://master.test/peers/directory", nil)
	copy, trace := StartClient(req)
	if copy != req || trace != nil || req.Header.Get(Header) != "" {
		t.Fatal("uninstrumented request changed")
	}
	trace.Mark("unused")
	trace.Finish(0, nil)
	for _, id := range []string{"", "0", "01", "-1", "+1", "18446744073709551616", "client-secret"} {
		var log eventLog
		called := false
		handler := Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), log.observe)
		req := httptest.NewRequest(http.MethodGet, "/peers/directory", nil)
		req.Header.Set(Header, id)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		if !called || len(log.snapshot()) != 0 {
			t.Fatalf("invalid diagnostic ID affected service or emitted events: %q", id)
		}
	}
}

func TestTraceDistinguishesHandlerWaitFromConnectionWait(t *testing.T) {
	var log eventLog
	entered := make(chan struct{})
	server := httptest.NewTLSServer(Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Mark(r.Context(), "directory_read_start")
		close(entered)
		<-r.Context().Done()
	}), log.observe))
	defer server.Close()
	ctx, cancel := context.WithCancel(WithObserver(context.Background(), log.observe))
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/peers/directory", nil)
	req, trace := StartClient(req)
	done := make(chan error, 1)
	go func() {
		resp, err := server.Client().Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		trace.Finish(0, err)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach the real handler")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation changed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not cancel")
	}
	seenRead, seenCancel := false, false
	for _, event := range log.snapshot() {
		seenRead = seenRead || event.Side == "server" && event.Phase == "directory_read_start"
		seenCancel = seenCancel || event.Side == "client" && event.Phase == "done" && event.Error == "canceled"
		if event.Side == "client" && event.Phase == "first_response_byte" {
			t.Fatal("request waiting in handler falsely reported response bytes")
		}
	}
	if !seenRead || !seenCancel {
		t.Fatal("trace did not distinguish server work from response arrival")
	}
	if got := errorKind(errors.New("secret-token")); got != "request_error" {
		t.Fatalf("raw error was not redacted: %q", got)
	}
}
