package master

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

func TestPutSmallReusesNodeConnections(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "http"
		if secure {
			name = "https"
		}
		t.Run(name, func(t *testing.T) {
			store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })

			token := auth.Token("small-connection-test")
			var connections, puts atomic.Int64
			nodeServer := httptest.NewUnstartedServer(auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.Method != http.MethodPut {
					http.Error(w, "unexpected request", http.StatusMethodNotAllowed)
					return
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					http.Error(w, "read failed", http.StatusBadRequest)
					return
				}
				if got, want := r.Header.Get(types.ChecksumHeader), fmt.Sprintf("%08x", types.CRC32C(data)); got != want {
					t.Errorf("checksum header=%q, want %q", got, want)
				}
				if puts.Add(1) == 2 {
					http.Error(w, "injected write failure", http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, "stored")
			}), token))
			nodeServer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			if secure {
				nodeServer.StartTLS()
			} else {
				nodeServer.Start()
			}
			t.Cleanup(nodeServer.Close)
			if _, err := store.RegisterNode(nodeServer.Listener.Addr().String(), 1<<30); err != nil {
				t.Fatal(err)
			}

			srv := NewServer(store, time.Hour)
			srv.SetToken(token)
			if secure {
				roots := x509.NewCertPool()
				roots.AddCert(nodeServer.Certificate())
				srv.SetTLS(&tls.Config{RootCAs: roots})
			}
			handler := srv.Handler()
			for i := range 4 {
				data := []byte(fmt.Sprintf("small payload %d", i))
				path := fmt.Sprintf("/file-%d", i)
				req := httptest.NewRequest(http.MethodPost,
					fmt.Sprintf("/files/small?path=%s&replicas=1&op_id=connection-%d", path, i), bytes.NewReader(data))
				req.Header.Set(types.FeaturesHeader, types.ObjectIDFeature)
				token.Set(req)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if i == 1 {
					if rec.Code != http.StatusServiceUnavailable {
						t.Fatalf("failed write status=%d: %s", rec.Code, rec.Body.String())
					}
					if _, err := store.ResolvePath(path); err != meta.ErrNotExist {
						t.Fatalf("failed write published metadata: %v", err)
					}
					continue
				}
				if rec.Code != http.StatusCreated {
					t.Fatalf("small write status=%d: %s", rec.Code, rec.Body.String())
				}
				var out struct {
					Inode types.Inode `json:"inode"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				if out.Inode.Size != int64(len(data)) || out.Inode.Checksum != types.CRC32C(data) || out.Inode.Generation != 1 {
					t.Fatalf("incorrect committed metadata: %+v", out.Inode)
				}
			}
			if got := puts.Load(); got != 4 {
				t.Errorf("node PUTs=%d, want 4", got)
			}
			if got := connections.Load(); got != 1 {
				t.Errorf("node connections=%d, want 1 shared by probes and sequential writes, including a failed write", got)
			}
		})
	}
}
