package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	"atoll/master"
	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/types"
)

func configureTransferCluster(t *testing.T, cl *plannedCluster) {
	t.Helper()
	if err := cl.store.EnableTransferPlanning(); err != nil {
		t.Fatal(err)
	}
	if err := cl.client.SetTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 2}); err != nil {
		t.Fatal(err)
	}
	for i, server := range cl.nodes {
		reg, err := cl.store.RegisterNode(server.Listener.Addr().String(), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		if err := cl.store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: reg.ID, FailureDomains: map[string]string{"zone": fmt.Sprint(i)}, UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxTransferConcurrency: 4}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPlannedClientTransferRejectsMissingBudget(t *testing.T) {
	cl := newPlannedCluster(t, 1)
	cl.client.transferEnabled = true
	u, err := cl.client.beginPlannedWrite(context.Background(), "/transfer", 4, false, "transfer")
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.client.uploadPlannedChunk(context.Background(), u, 0, []byte("data")); err == nil || !strings.Contains(err.Error(), "configured") {
		t.Fatal(err)
	}
}

func TestPlannedClientOnlyUploadsIngressAndRetainsCommitGate(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "metadata.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := master.NewServer(store, time.Hour)
	if err := srv.EnableWritePlanning(master.WritePlanningConfig{MaxReplicas: 2, TransferPlanning: true}); err != nil {
		t.Fatal(err)
	}
	masterHTTP := httptest.NewServer(srv.Handler())
	t.Cleanup(masterHTTP.Close)
	var nodes []types.NodeInfo
	var replicas atomic.Int64
	for i := 0; i < 2; i++ {
		n := node.New(filepath.Join(t.TempDir(), "objects"), masterHTTP.URL, "", 1<<30)
		if err := n.ConfigureTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 4}); err != nil {
			t.Fatal(err)
		}
		handler := n.Handler()
		nodeHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/replicate/") {
				replicas.Add(1)
			}
			handler.ServeHTTP(w, r)
		}))
		t.Cleanup(nodeHTTP.Close)
		info, err := store.RegisterNode(nodeHTTP.Listener.Addr().String(), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		n.SetNodeIDForTest(info.ID)
		if err := store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: info.ID, FailureDomains: map[string]string{"zone": fmt.Sprint(i)}, UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxTransferConcurrency: 4}); err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, info)
	}
	for _, from := range nodes {
		for _, to := range nodes {
			if from.ID != to.ID {
				if err := srv.RecordTransferObservation(types.TransferObservation{FromNodeID: from.ID, ToNodeID: to.ID, Available: true, Path: "http", RTTMs: 2, ObservedAt: time.Now()}, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	c := New(masterHTTP.URL)
	if err := c.SetTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetProtection("/", types.ProtectionSecurity); err != nil {
		t.Fatal(err)
	}
	u, err := c.beginPlannedWrite(context.Background(), "/transfer", 4, false, "transfer")
	if err != nil {
		t.Fatal(err)
	}
	base := c.HTTP.Transport
	var uploads atomic.Int64
	c.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			uploads.Add(1)
			// The client must obey the persisted graph, not a rewritten response.
			persisted, err := store.GetPlannedWrite(meta.WriteActor{}, plannedBinding(u), time.Now())
			if err != nil || len(persisted.Chunks) != 1 || persisted.Chunks[0].Transfer == nil || len(persisted.Chunks[0].Transfer.UploadTargets) != 1 {
				r.Body.Close()
				return nil, errors.New("persisted single-ingress plan missing")
			}
			ingress := persisted.Chunks[0].Transfer.UploadTargets[0]
			for _, target := range nodes {
				if target.ID != ingress && r.URL.Host == target.Addr {
					r.Body.Close()
					return nil, errors.New("client touched non-ingress replica")
				}
			}
		}
		return base.RoundTrip(r)
	})
	if err := c.uploadPlannedChunk(context.Background(), u, 0, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if uploads.Load() != 1 || replicas.Load() != 1 {
		t.Fatalf("unexpected transfer graph execution: client PUTs=%d replica PUTs=%d", uploads.Load(), replicas.Load())
	}
	persisted, err := store.GetPlannedWrite(meta.WriteActor{}, plannedBinding(u), time.Now())
	if err != nil || len(persisted.Chunks) != 1 || persisted.Chunks[0].Transfer == nil || persisted.Chunks[0].RequiredConfirmations != 2 {
		t.Fatalf("persisted confirmation graph invalid: %+v %v", persisted, err)
	}
	plan := persisted.Chunks[0]
	if len(plan.Transfer.UploadTargets) != 1 || len(plan.Transfer.Legs) != 2 {
		t.Fatalf("single-ingress graph differs from expected: %+v", plan.Transfer)
	}
	status, err := store.PlannedWriteStatus(meta.WriteActor{}, plannedBinding(u), time.Hour, time.Now())
	if err != nil || len(status.Chunks) != 1 || !status.Chunks[0].Ready || len(status.Chunks[0].Done) != 2 {
		t.Fatalf("node replica did not satisfy both confirmations: %+v %v", status, err)
	}
	request := types.CommitWriteRequest{WriteBinding: plannedBinding(u), OpID: "transfer-commit", Size: 4, ChunkCount: 1}
	if _, _, _, err := store.CommitPlannedWrite(meta.WriteActor{}, request, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "readback")
	if err := c.Get("/transfer", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, []byte("data")) {
		t.Fatal("persisted transfer graph returned different content")
	}
}

func plannedJSONResponse(r *http.Request, value any) *http.Response {
	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(value)
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(&b), Request: r}
}
