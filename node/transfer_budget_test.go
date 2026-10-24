package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestWriteTransferReadDeadlineReleasesStalledIngress(t *testing.T) {
	object := types.ChunkID(types.StagingInodeBase+100, 0)
	expires := time.Now().Add(300 * time.Millisecond)
	plan := types.ReplicationPlan{Protocol: types.IntegrityProtocol, Object: types.ObjectIntegrity{ObjectID: object, InodeID: types.StagingInodeBase + 100, Chunked: true, ChunkIndex: 0, Size: 100, ChecksumKnown: true, Checksum: types.CRC32C(make([]byte, 100)), Replicas: []uint64{1}}, WriteTransfer: &types.WriteTransferPlan{UploadTargets: []uint64{1}, ExpiresAt: expires, Legs: []types.WriteTransferLeg{{ToNodeID: 1, Path: "http", BPS: 1000}}}}
	ms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(plan) }))
	defer ms.Close()
	dir := t.TempDir()
	n := New(dir, ms.URL, "", 10000)
	if err := n.ConfigureTransferBudget(types.TransferBudget{UploadBPS: 1000, DownloadBPS: 1000, MaxConcurrent: 1}); err != nil {
		t.Fatal(err)
	}
	n.SetNodeIDForTest(1)
	s := httptest.NewServer(n.Handler())
	defer s.Close()
	conn, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "PUT /objects/%d HTTP/1.1\r\nHost: %s\r\nContent-Length: 100\r\n\r\nx", object, s.Listener.Addr()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	time.Sleep(50 * time.Millisecond)
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer shortCancel()
	if release, err := n.downloadBudget.Acquire(shortCtx); err == nil {
		release()
		t.Fatal("stalled upload did not hold budget")
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	release, err := n.downloadBudget.Acquire(ctx)
	if err != nil {
		t.Fatalf("expired upload retained slot: %v", err)
	}
	release()
	if _, err := os.Stat(n.objectPath(object)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial object published: %v", err)
	}
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Errorf("temporary object retained: %s", path)
		}
		return err
	})
}

func TestTransferBudgetRequiresConfiguredLocalRate(t *testing.T) {
	n := New(t.TempDir(), "http://127.0.0.1:1", "", 10000)
	if _, _, err := n.receiveWithBudget(context.Background(), strings.NewReader("x"), 100); err == nil {
		t.Fatal("claimed rate without local budget")
	}
	if err := n.ConfigureTransferBudget(types.TransferBudget{UploadBPS: 1000, DownloadBPS: 4000, MaxConcurrent: 2}); err != nil {
		t.Fatal(err)
	}
	body, release, err := n.receiveWithBudget(context.Background(), strings.NewReader("x"), 100)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := io.ReadAll(body); err != nil {
		t.Fatal(err)
	}
}
