package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func TestUploadRecoverableChunkNoCircuitContinuesOriginalPlan(t *testing.T) {
	c := New("http://master.test")
	c.SetPutTimeout(40 * time.Millisecond)
	c.writePathRecovery = true
	upload := types.WriteUpload{ID: types.StagingInodeBase + 7, PlanID: "path-fallback", Revision: 1}
	data := bytes.Repeat([]byte("p"), 1024)
	hardUntil := time.Now().Add(5 * time.Second)
	initial := pathRecoveryFlowPlan(upload, data, peerhttp.PathDirect, hardUntil, 1, 0, "")
	chunk := types.ChunkInfo{ID: initial.Object.ID, Index: 0, Size: initial.Object.StoredSize, Checksum: initial.Object.Checksum, ChecksumKnown: true, Replicas: []uint64{1, 2}, Done: []uint64{1}}
	nodes := []types.NodeInfo{{ID: 1, Addr: "node1.test:80"}, {ID: 2, Addr: "node2.test:80"}}
	var statusCalls atomic.Int64
	var rejected atomic.Bool
	var afterReject atomic.Int64
	var mu sync.Mutex
	var requests []types.RecoverWriteChunkRequest
	c.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/"):
			if r.Body != nil {
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
			}
			return pathRecoveryFlowResponse(r, http.StatusCreated, map[string]int64{"size": int64(len(data))})
		case r.URL.Path == "/writes/status":
			bytesReceived := statusCalls.Add(1)
			chunkStatus := types.WriteChunkStatus{Index: 0, Epoch: 1}
			if rejected.Load() && afterReject.Add(1) >= 2 {
				chunkStatus.Ready = true
				chunkStatus.Done = []uint64{1, 2}
			} else {
				chunkStatus.Progress = []types.WriteNodeProgress{{NodeID: 1, Attempt: 1, Bytes: bytesReceived, UpdatedAt: time.Now()}, {NodeID: 2, Attempt: 1, Bytes: bytesReceived, UpdatedAt: time.Now()}}
			}
			return pathRecoveryFlowResponse(r, http.StatusOK, types.WriteStatus{UploadID: upload.ID, Chunks: []types.WriteChunkStatus{chunkStatus}})
		case r.URL.Path == "/writes/chunks/recover":
			var req types.RecoverWriteChunkRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				return nil, err
			}
			mu.Lock()
			requests = append(requests, req)
			mu.Unlock()
			rejected.Store(true)
			return pathRecoveryFlowResponse(r, http.StatusUnprocessableEntity, types.WriteError{Error: "no circuit available", Code: types.WriteNoFeasible})
		default:
			return nil, fmt.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		}
	})
	geometry := types.PlanWriteChunkRequest{WriteBinding: plannedBinding(upload), LogicalSize: int64(len(data)), StoredSize: int64(len(data)), Encoding: types.PlainEncoding, Checksum: types.CRC32C(data)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.uploadRecoverableChunk(ctx, upload, geometry, types.PlanWriteChunkResponse{Plan: initial, Chunk: chunk, Nodes: nodes}, data); err != nil {
		t.Fatalf("no-circuit fallback abandoned a progressing original plan: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 1 || len(requests[0].FailedNodes) != 0 || len(requests[0].AvoidPaths) != 1 || requests[0].AvoidPaths[0] != "direct" {
		t.Fatalf("path recovery was retried or changed into node exclusion: %+v", requests)
	}
}
