package node

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestTransferObservationsNeverDelayHeartbeat(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int64
	ms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nodes/transfer-peers" {
			calls.Add(1)
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
			w.WriteHeader(http.StatusConflict)
			return
		}
		io.WriteString(w, `{}`)
	}))
	defer ms.Close()
	defer close(release)
	n := New(t.TempDir(), ms.URL, "", 10000)
	if err := n.ConfigureTransferBudget(types.TransferBudget{UploadBPS: 1000, DownloadBPS: 2000, MaxConcurrent: 2}); err != nil {
		t.Fatal(err)
	}
	n.SetNodeIDForTest(1)
	before := time.Now()
	if err := n.heartbeatOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if time.Since(before) > time.Second {
		t.Fatal("heartbeat waited for slow peer discovery")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("observation did not start")
	}
	for i := 0; i < 10; i++ {
		if err := n.heartbeatOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("unbounded observation workers: %d", calls.Load())
	}
}
