package master

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"atoll/client"
	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/types"
)

func TestWriteTransferIngressReplicationEndToEnd(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(fmt.Sprintf("multichunk=%v", multi), func(t *testing.T) { testWriteTransferIngress(t, multi) })
	}
}

func testWriteTransferIngress(t *testing.T, multi bool) {
	if multi {
		previous := types.ChunkSize
		types.ChunkSize = 1024
		defer func() { types.ChunkSize = previous }()
	}
	store, err := meta.Open(filepath.Join(t.TempDir(), "master.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := NewServer(store, time.Hour)
	if err := srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 2, TransferPlanning: true}); err != nil {
		t.Fatal(err)
	}
	srv.SetHealthProbe(func(string) bool { return false })
	var payloadToMaster atomic.Int64
	handler := srv.Handler()
	ms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/objects/") || strings.HasPrefix(r.URL.Path, "/replicate/") {
			payloadToMaster.Add(r.ContentLength)
		}
		handler.ServeHTTP(w, r)
	}))
	defer ms.Close()
	var servers []*httptest.Server
	var ids []uint64
	var dirs []string
	for i := 0; i < 2; i++ {
		dir := filepath.Join(t.TempDir(), "data")
		n := node.New(dir, ms.URL, "", 1<<30)
		if err := n.ConfigureTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 4}); err != nil {
			t.Fatal(err)
		}
		ns := httptest.NewServer(n.Handler())
		defer ns.Close()
		reg, err := store.RegisterNode(ns.Listener.Addr().String(), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		n.SetNodeIDForTest(reg.ID)
		if err := store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: reg.ID, FailureDomains: map[string]string{"zone": fmt.Sprint(i)}, UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxTransferConcurrency: 4}); err != nil {
			t.Fatal(err)
		}
		servers = append(servers, ns)
		ids = append(ids, reg.ID)
		dirs = append(dirs, dir)
	}
	if err := srv.RecordTransferObservation(types.TransferObservation{FromNodeID: ids[0], ToNodeID: ids[1], Path: "http", Available: true, RTTMs: 2, ObservedAt: time.Now()}, time.Now()); err != nil {
		t.Fatal(err)
	}
	c := client.New(ms.URL)
	if err := c.SetTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetProtection("/", types.ProtectionSecurity); err != nil {
		t.Fatal(err)
	}
	base := c.HTTP.Transport
	var writesToSecond atomic.Int64
	var plan types.WriteChunkPlan
	c.HTTP.Transport = writeTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == servers[1].Listener.Addr().String() {
			if r.Method == http.MethodPut {
				writesToSecond.Add(1)
			}
			if r.Body != nil {
				r.Body.Close()
			}
			return nil, fmt.Errorf("client cannot reach second node")
		}
		response, err := base.RoundTrip(r)
		if err == nil && r.URL.Path == "/writes/chunks" && response.StatusCode == http.StatusOK {
			raw, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			var out types.PlanWriteChunkResponse
			if err := json.Unmarshal(raw, &out); err != nil {
				return nil, err
			}
			plan = out.Plan
			response.Body = io.NopCloser(bytes.NewReader(raw))
		}
		return response, err
	})
	data := bytes.Repeat([]byte("encrypted-or-plain-object-test"), 100)
	in, err := c.PutSmall("/transfer", data, 99, false)
	if err != nil {
		t.Fatal(err)
	}
	if writesToSecond.Load() != 0 || payloadToMaster.Load() != 0 {
		t.Fatalf("unexpected client leg or master payload: %d %d", writesToSecond.Load(), payloadToMaster.Load())
	}
	if plan.Transfer == nil || len(plan.Transfer.UploadTargets) != 1 || plan.Transfer.UploadTargets[0] != ids[0] || plan.RequiredConfirmations != 2 {
		t.Fatalf("wrong plan: %+v", plan)
	}
	for i, id := range ids {
		var offset int64
		for _, chunk := range in.Chunks {
			if !types.ContainsUint64(chunk.Done, id) {
				t.Fatalf("node %d not confirmed", id)
			}
			objectID := chunk.ID
			raw, err := os.ReadFile(filepath.Join(dirs[i], "objects", fmt.Sprintf("%02x", objectID%256), fmt.Sprint(objectID)))
			logical := chunk.LogicalSize
			if logical == 0 {
				logical = chunk.Size
			}
			if err != nil || !bytes.Equal(raw, data[offset:offset+logical]) {
				t.Fatalf("node %d object mismatch: %v", id, err)
			}
			offset += logical
		}
	}
}
