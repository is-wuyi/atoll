package mount

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"atoll/client"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type lifecycleTransport func(*http.Request) (*http.Response, error)

func (f lifecycleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPlannedWriteErrorIsRetainedOnSameHandle(t *testing.T) {
	withChunkSize(t, 4096)
	cl := newPlannedMountCluster(t)
	cl.mount.NoSmallPath = true
	base := cl.client.HTTP.Transport
	var fail atomic.Bool
	fail.Store(true)
	cl.client.HTTP.Transport = lifecycleTransport(func(r *http.Request) (*http.Response, error) {
		if fail.Load() && r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			r.Body.Close()
			return &http.Response{StatusCode: http.StatusInsufficientStorage, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"injected full node"}`)), Request: r}, nil
		}
		return base.RoundTrip(r)
	})
	_, raw := namespaceFS(cl.mount)
	f := createNamespaceFile(t, raw, "shared")
	payload := bytes.Repeat([]byte{0x7a}, 8192)
	f.write(t, payload, 0)
	cl.mount.mu.Lock()
	w := cl.mount.writes["/shared"]
	cl.mount.mu.Unlock()
	w.mu.Lock()
	stream := w.stream
	w.mu.Unlock()
	if stream == nil {
		t.Fatal("stream was not started")
	}
	deadline := time.Now().Add(5 * time.Second)
	for stream.Err() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !client.IsPlannedWriteError(stream.Err()) {
		t.Fatalf("expected background plan failure, got %v", stream.Err())
	}
	fail.Store(false)

	shared, err := cl.mount.newWriteHandle("/shared", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shared.Release(context.Background()) })
	if shared != w {
		t.Fatal("writer did not share the original handle")
	}
	got := make([]byte, len(payload))
	if _, err := shared.f.ReadAt(got, 0); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("shared open changed contents: %v", err)
	}
	status := f.flush()
	cl.mu.Lock()
	begins := cl.calls["POST /writes"]
	cl.mu.Unlock()
	if begins != 1 {
		t.Errorf("failed plan silently replaced: Begin calls=%d", begins)
	}
	if status == fuse.OK {
		t.Error("Flush hid the original planned write failure")
	}
	if _, _, err := cl.client.Lookup("/shared"); err == nil {
		t.Error("failed upload was silently published")
	}
	cl.assertPlanned(t)
}
