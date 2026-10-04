package master

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryManifest404RequiresEmptyBackupInventory(t *testing.T) {
	for _, body := range []string{"null", `[{"key":"snapshot-5-0","size":16384}]`, "not json"} {
		t.Run(body, func(t *testing.T) {
			seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/meta-backup" {
					io.WriteString(w, body)
					return
				}
				http.NotFound(w, r)
			}))
			defer seed.Close()
			recoverMissingLocalMustFailStop(t, []string{httptestSeedAddr(seed)}, t.TempDir())
		})
	}
	t.Run("unimplemented_endpoint", func(t *testing.T) {
		seed := newFixedStatusSeed(http.StatusNotFound)
		defer seed.Close()
		recoverMissingLocalMustFailStop(t, []string{httptestSeedAddr(seed)}, t.TempDir())
	})
}
