package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master/meta"
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
	cl := newPlannedCluster(t, 2)
	c := cl.client
	if _, err := c.SetProtection("/", types.ProtectionSecurity); err != nil {
		t.Fatal(err)
	}
	u, err := c.beginPlannedWrite(context.Background(), "/transfer", 4, false, "transfer")
	if err != nil {
		t.Fatal(err)
	}
	req := types.PlanWriteChunkRequest{WriteBinding: plannedBinding(u), Index: 0, LogicalSize: 4, StoredSize: 4, Encoding: types.PlainEncoding, Checksum: types.CRC32C([]byte("data"))}
	var response types.PlanWriteChunkResponse
	if err := c.writeJSON(context.Background(), http.MethodPost, "/writes/chunks", req, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Plan.Confirmations) < 2 {
		t.Fatalf("fixture needs two confirmations: %+v", response.Plan)
	}
	ingress := response.Plan.Confirmations[0]
	response.Plan.Transfer = &types.WriteTransferPlan{UploadTargets: []uint64{ingress}, ExpiresAt: time.Now().Add(time.Minute)}
	for _, target := range response.Plan.Layout.Nodes {
		from := ingress
		if target == ingress {
			from = 0
		}
		response.Plan.Transfer.Legs = append(response.Plan.Transfer.Legs, types.WriteTransferLeg{FromNodeID: from, ToNodeID: target, Path: "http", BPS: 1 << 20})
	}
	base := c.HTTP.Transport
	var uploads atomic.Int64
	c.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/writes/chunks" {
			return plannedJSONResponse(r, response), nil
		}
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/") {
			uploads.Add(1)
			for _, node := range response.Nodes {
				if node.ID != ingress && r.URL.Host == node.Addr {
					return nil, errors.New("client touched non-ingress replica")
				}
			}
		}
		return base.RoundTrip(r)
	})
	if err := c.uploadPlannedChunk(context.Background(), u, 0, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if uploads.Load() != 1 {
		t.Fatalf("uploads=%d", uploads.Load())
	}
	// Commit still checks the persisted full confirmation set, regardless of the client's upload list.
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		_, _, _, err := cl.store.CommitPlannedWrite(meta.WriteActor{}, types.CommitWriteRequest{WriteBinding: plannedBinding(u), OpID: "transfer-commit", Size: 4, ChunkCount: 1}, time.Hour, time.Now())
		if err == nil {
			return
		}
		if !errors.Is(err, meta.ErrWriteNotReady) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("node replication did not satisfy both confirmations")
}

func plannedJSONResponse(r *http.Request, value any) *http.Response {
	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(value)
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(&b), Request: r}
}
