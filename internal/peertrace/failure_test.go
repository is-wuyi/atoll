package peertrace

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTraceFailureBeforeHandlerIsVisible(t *testing.T) {
	for _, tc := range []struct {
		name string
		tls  bool
	}{
		{name: "connection"},
		{name: "certificate", tls: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events eventLog
			var url string
			if tc.tls {
				server := httptest.NewTLSServer(Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.WriteString(w, "unexpected")
				}), events.observe))
				defer server.Close()
				url = server.URL
			} else {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				url = "https://" + ln.Addr().String()
				ln.Close()
			}
			ctx, cancel := context.WithTimeout(WithObserver(context.Background(), events.observe), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/peers/directory", nil)
			if err != nil {
				t.Fatal(err)
			}
			req, trace := StartClient(req)
			transport := http.DefaultTransport.(*http.Transport).Clone()
			defer transport.CloseIdleConnections()
			resp, err := transport.RoundTrip(req)
			trace.Finish(0, err)
			if resp != nil {
				resp.Body.Close()
			}
			if err == nil {
				t.Fatal("expected rejection before the handler")
			}
			failedPhase := "connect_done"
			if tc.tls {
				failedPhase = "tls_done"
			}
			found := false
			for _, event := range events.snapshot() {
				if event.Side == "server" || event.Phase == "first_response_byte" {
					t.Fatalf("failure before handler produced a server response event: %+v", event)
				}
				found = found || event.Phase == failedPhase && event.Error != ""
			}
			if !found {
				t.Fatalf("did not record the actual failed phase %q", failedPhase)
			}
		})
	}
}
