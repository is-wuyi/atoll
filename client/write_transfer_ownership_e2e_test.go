package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master"
	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/types"
)

type ownedWriteBody struct {
	io.ReadCloser
	ctx     context.Context
	entered chan struct{}
	release <-chan struct{}
	first   bool
}

func (b *ownedWriteBody) Read(p []byte) (int, error) {
	if !b.first {
		b.first = true
		if len(p) > 32 {
			p = p[:32]
		}
		n, err := b.ReadCloser.Read(p)
		if n > 0 {
			close(b.entered)
			select {
			case <-b.release:
			case <-b.ctx.Done():
				return n, b.ctx.Err()
			}
		}
		return n, err
	}
	return b.ReadCloser.Read(p)
}

func TestRecoveryDirectWriteHasSingleOwnerDuringSlowReceive(t *testing.T) {
	withChunkSize(t, 128<<10)
	store, err := meta.Open(filepath.Join(t.TempDir(), "metadata.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := master.NewServer(store, time.Hour)
	if err := srv.EnableWritePlanning(master.WritePlanningConfig{MaxReplicas: 2}); err != nil {
		t.Fatal(err)
	}
	var primary atomic.Uint64
	var object atomic.Uint64
	primaryPlanned := make(chan struct{})
	var plannedOnce sync.Once
	handler := srv.Handler()
	masterHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		if r.Method == http.MethodGet && r.URL.Path == "/files/replication" && r.URL.Query().Get("node_id") == strconv.FormatUint(primary.Load(), 10) {
			id, _ := strconv.ParseUint(r.URL.Query().Get("object_id"), 10, 64)
			if d, err := store.ObjectIntegrity(id); err == nil && types.ContainsUint64(d.Done, primary.Load()) {
				plannedOnce.Do(func() { close(primaryPlanned) })
			}
		}
	}))
	t.Cleanup(masterHTTP.Close)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var duplicatePull, duplicatePush atomic.Int32
	var nodeIDs []uint64
	for i := 0; i < 2; i++ {
		n := node.New(filepath.Join(t.TempDir(), "objects"), masterHTTP.URL, "", 1<<30)
		n.SetWriteProgressIntervalForTest(100 * time.Millisecond)
		nodeHandler := n.Handler()
		slow := i == 1
		nodeHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slow {
				if r.Method == http.MethodPost && r.URL.Path == "/pull" {
					duplicatePull.Add(1)
				}
				if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/replicate/") {
					duplicatePush.Add(1)
				}
				if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
					r.Body = &ownedWriteBody{ReadCloser: r.Body, ctx: r.Context(), entered: entered, release: release}
				}
			}
			nodeHandler.ServeHTTP(w, r)
		}))
		t.Cleanup(nodeHTTP.Close)
		info, err := store.RegisterNode(nodeHTTP.Listener.Addr().String(), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		n.SetNodeIDForTest(info.ID)
		if err := store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: info.ID, FailureDomains: map[string]string{"zone": strconv.Itoa(i)}}); err != nil {
			t.Fatal(err)
		}
		nodeIDs = append(nodeIDs, info.ID)
	}
	primary.Store(nodeIDs[0])
	c := New(masterHTTP.URL)
	if _, err := c.SetProtection("/", types.ProtectionSecurity); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	c.HTTP.Transport = anchoredTransport{base: c.HTTP.Transport, ctx: ctx}
	done := make(chan struct{})
	result := make(chan error, 1)
	t.Cleanup(func() { unblock(); cancel(); <-done })
	data := bytes.Repeat([]byte("single-owned-write"), 4096)
	go func() {
		defer close(done)
		_, err := c.putPlannedReader(ctx, "/owned-write", int64(len(data)), bytes.NewReader(data), false)
		result <- err
	}()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("upload ended before the real receive barrier: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("slow target never consumed a positive byte")
	}
	var staging types.Inode
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := store.ForEachStaging(func(in types.Inode) error { staging = in; return nil })
		if err != nil {
			t.Fatal(err)
		}
		if len(staging.Chunks) == 1 && types.ContainsUint64(staging.Chunks[0].Done, primary.Load()) {
			object.Store(staging.Chunks[0].ID)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fast target never produced its verified confirmation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	before, err := store.WriteProgressState(object.Load(), nodeIDs[1], 1, time.Now())
	if err != nil || before == nil || before.Attempt != 1 {
		t.Fatalf("direct stream did not own the initial progress attempt: %+v %v", before, err)
	}
	// Wait for the fast node's actual post-receipt replication-plan query.
	select {
	case <-primaryPlanned:
	case <-ctx.Done():
		t.Fatal("post-receipt plan query did not finish")
	}
	scanner := master.NewScanner(store, time.Hour, time.Second, time.Hour)
	scanner.RepairScanOnce()
	if duplicatePull.Load() != 0 || duplicatePush.Load() != 0 {
		t.Fatalf("active target received duplicate data paths: pull=%d push=%d", duplicatePull.Load(), duplicatePush.Load())
	}
	after, err := store.WriteProgressState(object.Load(), nodeIDs[1], 1, time.Now())
	if err != nil || after == nil || after.Attempt != before.Attempt {
		t.Fatalf("direct receive attempt was replaced: before=%+v after=%+v err=%v", before, after, err)
	}
	unblock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("direct write did not complete after the barrier was released")
	}
	<-done
	in, _, err := c.Lookup("/owned-write")
	if err != nil || len(in.Chunks) != 1 || len(in.Chunks[0].Done) != 2 || len(in.Chunks[0].Replicas) != 2 {
		t.Fatalf("published confirmation set changed: %+v %v", in, err)
	}
	if duplicatePull.Load() != 0 || duplicatePush.Load() != 0 {
		t.Fatalf("duplicate transfers appeared before publication: pull=%d push=%d", duplicatePull.Load(), duplicatePush.Load())
	}
	out := filepath.Join(t.TempDir(), "readback")
	if err := c.Get("/owned-write", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("confirmed content differs from the original bytes")
	}
}
