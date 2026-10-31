package node

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestVerifiedReplayAtFullCapacity(t *testing.T) {
	data := []byte{0xab, 0x9b, 0xe0, 0x9b}
	n := New(t.TempDir(), "", "", int64(len(data)))
	crc := types.CRC32C(data)
	if _, _, err := n.storeVerifiedObject(8, bytes.NewReader(data), &crc, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if size, got, err := n.storeVerifiedObject(8, bytes.NewReader(data), &crc, int64(len(data))); err != nil || size != int64(len(data)) || got != crc {
			t.Fatalf("same immutable object retry needs no extra capacity: size=%d crc=%x err=%v", size, got, err)
		}
	}
	if n.used.Load() != int64(len(data)) || n.inflightForTest() != 0 {
		t.Fatalf("retry changed accounting: used=%d inflight=%d", n.used.Load(), n.inflightForTest())
	}
	for _, body := range [][]byte{data[:2], append(append([]byte(nil), data...), 1), []byte("bad!")} {
		if _, _, err := n.storeVerifiedObject(8, bytes.NewReader(body), &crc, int64(len(data))); err == nil {
			t.Fatal("invalid retry payload accepted")
		}
	}
	got, err := os.ReadFile(n.objectPath(8))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("failed retry changed old object: %x %v", got, err)
	}
}

type replayBlockingReader struct {
	reader  *bytes.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *replayBlockingReader) Read(dst []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return r.reader.Read(dst)
}

func TestVerifiedReplayAllowsDeleteDuringSlowBody(t *testing.T) {
	data := []byte("full")
	n := New(t.TempDir(), "", "", 4)
	crc := types.CRC32C(data)
	if _, _, err := n.storeVerifiedObject(8, bytes.NewReader(data), &crc, 4); err != nil {
		t.Fatal(err)
	}
	body := &replayBlockingReader{reader: bytes.NewReader(data), started: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(body.release) }) }
	defer unblock()
	done := make(chan error, 1)
	go func() {
		_, _, err := n.storeVerifiedObject(8, body, &crc, 4)
		done <- err
	}()
	select {
	case <-body.started:
	case <-time.After(3 * time.Second):
		t.Fatal("retry body was not read")
	}
	deleted := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		n.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/objects/8", nil))
		deleted <- w.Code
	}()
	select {
	case status := <-deleted:
		if status != http.StatusOK {
			t.Fatalf("delete status=%d", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("slow retry held object lock during body transfer")
	}
	unblock()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("deleted object was acknowledged by a late retry")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retry did not finish")
	}
}

func TestUsageSnapshotsShareMonotonicSequence(t *testing.T) {
	n := New(t.TempDir(), "", "", 100)
	n.SetNodeIDForTest(2)
	var mu sync.Mutex
	var reports []types.NodeUsage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Usage *types.NodeUsage `json:"usage"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Usage == nil {
			t.Errorf("missing usage snapshot: %v", err)
		} else {
			mu.Lock()
			reports = append(reports, *body.Usage)
			mu.Unlock()
		}
		io.WriteString(w, "{}")
	}))
	defer srv.Close()
	n.masterURL = srv.URL
	if err := n.heartbeatOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	data := []byte("abc")
	crc := types.CRC32C(data)
	if _, _, err := n.storeVerifiedObject(8, bytes.NewReader(data), &crc, 3); err != nil {
		t.Fatal(err)
	}
	if err := n.reportStored(t.Context(), types.ObjectIntegrity{ObjectID: 8, Size: 3, ChecksumKnown: true}); err != nil {
		t.Fatal(err)
	}
	if err := n.heartbeatOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 3 {
		t.Fatalf("reports=%d", len(reports))
	}
	for i, r := range reports {
		if r.Epoch == "" || r.Epoch != reports[0].Epoch || r.Sequence == 0 || (i > 0 && r.Sequence <= reports[i-1].Sequence) {
			t.Fatalf("unsequenced usage: %+v", reports)
		}
	}
	if reports[0].UsedBytes != 0 || reports[1].UsedBytes != 3 || reports[2].UsedBytes != 3 {
		t.Fatalf("usage=%+v", reports)
	}
}
