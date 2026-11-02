package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"

	"atoll/pkg/peerhttp"
)

func TestPeerDiagnosticsCanonicalMasterStaysUnobserved(t *testing.T) {
	for _, tc := range []struct {
		name, master, request string
	}{
		{"case", "https://Master.Example", "https://master.example/meta"},
		{"default port", "https://master.example", "https://MASTER.EXAMPLE:443/meta"},
		{"implicit port", "https://MASTER.EXAMPLE:443", "https://master.example/meta"},
		{"explicit port", "https://Master.Example:9420", "https://master.example:9420/meta"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := mustSink(t, filepath.Join(t.TempDir(), "diagnostics.json"))
			baseErr := errors.New("base dial sentinel")
			var baseCalls, peerCalls atomic.Int64
			peer, err := peerhttp.NewTransport(&http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
				baseCalls.Add(1)
				return nil, baseErr
			}}, peerhttp.WithMaster(tc.master), peerhttp.WithResolver(func(context.Context, string) (peerhttp.PeerDialer, error) {
				peerCalls.Add(1)
				return nil, errors.New("unexpected peer resolver")
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer peer.CloseIdleConnections()
			wrapper := newPeerDiagnosticsRoundTripper(peer, tc.master, sink.reporter())
			req, err := http.NewRequest(http.MethodGet, tc.request, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wrapper.RoundTrip(req); !errors.Is(err, baseErr) {
				t.Fatalf("same origin left base transport: %v", err)
			}
			if baseCalls.Load() != 1 || peerCalls.Load() != 0 {
				t.Fatalf("control request reached peer resolver: base=%d peer=%d", baseCalls.Load(), peerCalls.Load())
			}
			sink.mu.Lock()
			records := len(sink.records)
			sink.mu.Unlock()
			if records != 0 || wrapper.nextID.Load() != 0 {
				t.Fatalf("control request gained diagnostics: records=%d ids=%d", records, wrapper.nextID.Load())
			}
			for _, target := range []string{"https://master.example:444/objects/1", "https://other.example/objects/1"} {
				r, err := http.NewRequest(http.MethodGet, target, nil)
				if err != nil {
					t.Fatal(err)
				}
				if wrapper.isMaster(r) {
					t.Fatalf("different origin was classified as master: %s", target)
				}
			}
		})
	}
}

func TestPeerDiagnosticsInvalidOriginStaysUnobserved(t *testing.T) {
	for _, origin := range []string{"", "not-an-origin", "http://master.example", "https://master.example/path", "https://master.example/?query=1"} {
		wrapper := newPeerDiagnosticsRoundTripper(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if peerhttp.RequestID(req.Context()) != "" {
				t.Fatal("invalid pinned origin injected diagnostics")
			}
			return nil, errors.New("inner sentinel")
		}), origin, &peerhttp.Reporter{})
		req, err := http.NewRequest(http.MethodGet, "https://node.example/objects/1", nil)
		if err != nil {
			t.Fatal(err)
		}
		if !wrapper.isMaster(req) {
			t.Fatalf("invalid origin must disable classification: %q", origin)
		}
		_, _ = wrapper.RoundTrip(req)
	}
}
