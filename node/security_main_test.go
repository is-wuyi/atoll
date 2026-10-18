package node

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"atoll/pkg/edgeidentity"
)

type deviceDeniedBody struct{ closes int }

func (b *deviceDeniedBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *deviceDeniedBody) Close() error             { b.closes++; return nil }

func TestDeviceTransportDenialClosesBody(t *testing.T) {
	for _, mode := range []string{"origin", "host", "no-session", "nil-url"} {
		t.Run(mode, func(t *testing.T) {
			body := &deviceDeniedBody{}
			req, err := http.NewRequest(http.MethodPost, "https://master.example/nodes/heartbeat", body)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "origin":
				req.URL.Host = "other.example"
				req.Host = req.URL.Host
			case "host":
				req.Host = "other.example"
			case "nil-url":
				req.URL = nil
			}
			tr := &deviceTransport{sec: &nodeSecurity{masterScheme: "https", masterHost: "master.example"}}
			if _, err := tr.RoundTrip(req); err == nil {
				t.Fatal("invalid device request was accepted")
			}
			if body.closes != 1 {
				t.Fatalf("denied body closed %d times, want 1", body.closes)
			}
		})
	}
}

func TestSecurityMarkerRejectsTruncatedValidPrefix(t *testing.T) {
	dir := t.TempDir()
	id, err := edgeidentity.LoadOrCreate(filepath.Join(t.TempDir(), "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	u := &url.URL{Scheme: "https", Host: "master.example"}
	if err := writeSecurityMarker(dir, id, u); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, securityMarkerName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for len(raw) < maxMarkerBytes {
		raw = append(raw, ' ')
	}
	raw = append(raw, []byte("invalid trailing bytes")...)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSecurityMarker(path, id.NodeID().String(), u.String()); err == nil {
		t.Fatal("oversized marker was accepted by parsing only its valid prefix")
	}
}
