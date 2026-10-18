package master

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"atoll/master/meta"
	bolt "go.etcd.io/bbolt"
)

func TestSecureCorruptConfigCannotReopenLegacyEndpoints(t *testing.T) {
	for _, state := range []string{"broken-json", "null", "missing"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metadata.db")
			store, err := meta.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.BootstrapSecurity("admin", secAdminPassword, time.Now()); err != nil {
				store.Close()
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := bolt.Open(path, 0o600, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("security"))
				if state == "missing" {
					return b.Delete([]byte("cfg/security"))
				}
				return b.Put([]byte("cfg/security"), []byte(state))
			})
			if closeErr := db.Close(); err != nil || closeErr != nil {
				t.Fatalf("corrupt database: %v, close: %v", err, closeErr)
			}
			store, err = meta.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			srv := NewServer(store, time.Hour)
			if err := srv.EnableSecurity(SecurityConfig{ControlToken: secControlToken, AllowInsecure: true}); err == nil {
				t.Fatal("corrupt configuration allowed secure startup")
			}
			handler := srv.Handler()
			for _, target := range []string{"/meta?path=/", "/dirs/children?path=/", "/admin/nodes"} {
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, target, nil))
				if res.Code != http.StatusServiceUnavailable {
					t.Errorf("%s reopened without authentication: %d", target, res.Code)
				}
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if res.Code != http.StatusOK {
				t.Fatalf("health check: %d", res.Code)
			}
		})
	}
}
