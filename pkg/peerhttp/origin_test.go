package peerhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestMasterCanonicalOriginUsesBaseTransport(t *testing.T) {
	for _, tc := range []struct {
		name, master, request string
	}{
		{"lowercase request", "https://Master.Example", "https://master.example/meta"},
		{"uppercase request", "https://master.example", "https://MASTER.EXAMPLE/meta"},
		{"explicit default port", "https://Master.Example", "https://master.example:443/meta"},
		{"implicit default port", "https://master.example:443", "https://MASTER.EXAMPLE/meta"},
		{"nondefault port", "https://Master.Example:9420", "https://master.example:9420/meta"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseErr := errors.New("base dial sentinel")
			peerErr := errors.New("peer resolver sentinel")
			var baseCalls, peerCalls atomic.Int64
			base := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
				baseCalls.Add(1)
				return nil, baseErr
			}}
			tr, err := NewTransport(base, WithMaster(tc.master), WithResolver(func(context.Context, string) (PeerDialer, error) {
				peerCalls.Add(1)
				return nil, peerErr
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer tr.CloseIdleConnections()
			var observations []Observation
			tr.SetReporter(&Reporter{Observe: func(o Observation) { observations = append(observations, o) }})
			req, err := http.NewRequest(http.MethodGet, tc.request, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tr.RoundTrip(req); !errors.Is(err, baseErr) {
				t.Fatalf("same origin did not retain the base transport: %v", err)
			}
			if baseCalls.Load() != 1 || peerCalls.Load() != 0 {
				t.Fatalf("same origin crossed peer resolver: base=%d peer=%d", baseCalls.Load(), peerCalls.Load())
			}
			if len(observations) != 1 || !observations[0].Master {
				t.Fatalf("same origin lost its master classification: %+v", observations)
			}
			if _, err := tr.RoundTrip(req.WithContext(WithPath(req.Context(), PathDirect))); err == nil {
				t.Fatal("same origin accepted a required peer path")
			}
			if baseCalls.Load() != 1 || peerCalls.Load() != 0 {
				t.Fatal("required peer path reached a dialer for the master")
			}
		})
	}
}

func TestMasterCanonicalOriginKeepsOtherOriginsSeparate(t *testing.T) {
	var baseCalls, peerCalls atomic.Int64
	peerErr := errors.New("peer resolver sentinel")
	tr, err := NewTransport(&http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		baseCalls.Add(1)
		return nil, errors.New("unexpected base dial")
	}}, WithMaster("https://Master.Example"), WithResolver(func(context.Context, string) (PeerDialer, error) {
		peerCalls.Add(1)
		return nil, peerErr
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	for _, address := range []string{"https://master.example:444/meta", "https://other.example/meta"} {
		req, err := http.NewRequest(http.MethodGet, address, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tr.RoundTrip(req); !errors.Is(err, peerErr) {
			t.Fatalf("different origin took master settings: %s: %v", address, err)
		}
	}
	if baseCalls.Load() != 0 || peerCalls.Load() != 2 {
		t.Fatalf("different origin classification: base=%d peer=%d", baseCalls.Load(), peerCalls.Load())
	}
}

func TestMasterDialGuardRejectsCaseVariants(t *testing.T) {
	tr, err := NewTransport(&http.Transport{}, WithMaster("https://Master.Example"), WithResolver(func(context.Context, string) (PeerDialer, error) {
		return nil, errors.New("unexpected peer resolver")
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"master.example", "MASTER.EXAMPLE", "master.example:443", "MASTER.EXAMPLE:443"} {
		if _, _, err := tr.dialConn(context.Background(), "tcp", host); !errors.Is(err, errMasterViaPeer) {
			t.Fatalf("peer dial guard missed %q: %v", host, err)
		}
	}
}
