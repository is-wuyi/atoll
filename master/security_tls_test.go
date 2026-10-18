package master

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestSecureMasterDefaultsToHTTPSWithoutCustomCA(t *testing.T) {
	c := newSecureCluster(t, 0)
	srv := NewServer(c.store, time.Hour)
	scanner := NewScanner(c.store, time.Hour, time.Minute, time.Hour)
	autonomy, err := NewAutonomy(c.store, time.Hour, AutonomyConfig{Mode: AutonomyObserve})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetScanner(scanner)
	srv.SetAutonomy(autonomy)
	if err := srv.EnableSecurity(SecurityConfig{ControlToken: secControlToken}); err != nil {
		t.Fatal(err)
	}
	srv.AttachSecureTransports()
	if srv.nodeScheme() != "https" || scanner.scheme != "https" || autonomy.scheme != "https" {
		t.Errorf("secure schemes: server=%q scanner=%q autonomy=%q", srv.nodeScheme(), scanner.scheme, autonomy.scheme)
	}
	if srv.tlsCfg == nil || srv.tlsCfg.InsecureSkipVerify {
		t.Error("secure mode must use verified TLS with system roots when no custom CA is supplied")
	}
	sent := 0
	transport := srv.secureControlTransport(securityRoundTripFunc(func(*http.Request) (*http.Response, error) {
		sent++
		return nil, context.Canceled
	}))
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:59821/healthz", nil)
	if _, err := transport.RoundTrip(req); err == nil || sent != 0 {
		t.Fatalf("secure control transport sent plaintext: sends=%d error=%v", sent, err)
	}
}

func TestSecureControlRejectsAmbiguousDestinations(t *testing.T) {
	c := newSecureCluster(t, 0)
	cases := map[string]func(*http.Request){
		"host":         func(r *http.Request) { r.Host = "other.example:9421" },
		"userinfo":     func(r *http.Request) { r.URL.User = url.User("other") },
		"opaque":       func(r *http.Request) { r.URL.Opaque = "//other.example/healthz" },
		"escaped-path": func(r *http.Request) { r.URL.RawPath = "/%68ealthz" },
		"fragment":     func(r *http.Request) { r.URL.Fragment = "fragment" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			sent := 0
			transport := c.srv.secureControlTransport(securityRoundTripFunc(func(*http.Request) (*http.Response, error) {
				sent++
				return nil, context.Canceled
			}))
			req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:59822/healthz", nil)
			if err != nil {
				t.Fatal(err)
			}
			mutate(req)
			if _, err := transport.RoundTrip(req); err == nil || sent != 0 {
				t.Fatalf("ambiguous control request sent=%d error=%v", sent, err)
			}
		})
	}
}

func TestSecureMasterInsecureOptInRetainsHTTP(t *testing.T) {
	c := newSecureCluster(t, 0)
	if c.srv.nodeScheme() != "http" {
		t.Fatalf("isolated HTTP opt-in changed scheme: %s", c.srv.nodeScheme())
	}
	if enabled, err := c.store.SecurityEnabled(); err != nil || !enabled {
		t.Fatalf("initialized state: %v %v", enabled, err)
	}
	if _, err := c.store.ListAliveNodes(time.Hour); err != nil {
		t.Fatal(err)
	}
}
