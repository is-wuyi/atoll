package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func pathRecoveryFlowPlan(upload types.WriteUpload, data []byte, path peerhttp.Path, hardUntil time.Time, epoch uint64, attempts uint32, op string) types.WriteChunkPlan {
	recovery := &types.WriteRecovery{Epoch: epoch, Attempts: attempts, HardUntil: hardUntil}
	if attempts > 0 {
		recovery.OperationID = op
		recovery.RequestHash = strings.Repeat("0", 64)
		recovery.AvoidPaths = []string{string(peerhttp.PathDirect)}
	}
	return types.WriteChunkPlan{Index: 0, Object: types.ContentObject{ID: types.ChunkID(upload.ID, 0), Version: 1, LogicalSize: int64(len(data)), StoredSize: int64(len(data)), Encoding: types.PlainEncoding, Checksum: types.CRC32C(data), ChecksumKnown: true}, Layout: types.ReplicaLayout{ObjectID: types.ChunkID(upload.ID, 0), Epoch: epoch, Scheme: "replicate", Nodes: []uint64{1, 2}}, Confirmations: []uint64{1, 2}, RequiredConfirmations: 2, Recovery: recovery, Transfer: &types.WriteTransferPlan{UploadTargets: []uint64{1}, ExpiresAt: hardUntil, Legs: []types.WriteTransferLeg{{ToNodeID: 1, Path: string(path), BPS: 1}, {FromNodeID: 1, ToNodeID: 2, Path: string(path), BPS: 1}}}}
}

func pathRecoveryFlowResponse(r *http.Request, status int, value any) (*http.Response, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw)), Request: r}, nil
}

func TestUploadRecoverableChunkUsesAvoidDirect(t *testing.T) {
	c := New("http://master.test")
	c.SetPutTimeout(40 * time.Millisecond)
	c.writePathRecovery = true
	upload := types.WriteUpload{ID: types.StagingInodeBase + 7, PlanID: "path-flow", Revision: 1}
	data := bytes.Repeat([]byte("p"), 64)
	hardUntil := time.Now().Add(5 * time.Second)
	initial := pathRecoveryFlowPlan(upload, data, peerhttp.PathDirect, hardUntil, 1, 0, "")
	// The ingress replica is complete; only its direct replication leg is slow.
	chunk := types.ChunkInfo{ID: initial.Object.ID, Index: 0, Size: initial.Object.StoredSize, Checksum: initial.Object.Checksum, ChecksumKnown: true, Replicas: []uint64{1, 2}, Done: []uint64{1}}
	nodes := []types.NodeInfo{{ID: 1, Addr: "node1.test:80"}, {ID: 2, Addr: "node2.test:80"}}
	var epoch atomic.Uint64
	epoch.Store(1)
	var statusCalls atomic.Int64
	var mu sync.Mutex
	var requests []types.RecoverWriteChunkRequest
	var putEpochs []uint64
	c.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/objects/"):
			if r.Body != nil {
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
			}
			var value uint64
			_, _ = fmt.Sscanf(r.Header.Get(types.WriteEpochHeader), "%d", &value)
			mu.Lock()
			putEpochs = append(putEpochs, value)
			mu.Unlock()
			return pathRecoveryFlowResponse(r, http.StatusCreated, map[string]int64{"size": int64(len(data))})
		case r.URL.Path == "/writes/status":
			current := epoch.Load()
			status := types.WriteStatus{UploadID: upload.ID}
			chunkStatus := types.WriteChunkStatus{Index: 0, Epoch: current}
			if current == 2 {
				chunkStatus.Ready = true
				chunkStatus.Done = []uint64{1, 2}
			} else {
				bytesReceived := statusCalls.Add(1)
				chunkStatus.Progress = []types.WriteNodeProgress{{NodeID: 1, Attempt: 1, Bytes: bytesReceived, UpdatedAt: time.Now()}, {NodeID: 2, Attempt: 1, Bytes: bytesReceived, UpdatedAt: time.Now()}}
			}
			status.Chunks = []types.WriteChunkStatus{chunkStatus}
			return pathRecoveryFlowResponse(r, http.StatusOK, status)
		case r.URL.Path == "/writes/chunks/recover":
			var req types.RecoverWriteChunkRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				return nil, err
			}
			mu.Lock()
			requests = append(requests, req)
			mu.Unlock()
			next := pathRecoveryFlowPlan(upload, data, peerhttp.PathRelay, hardUntil, 2, 1, req.OpID)
			epoch.Store(2)
			return pathRecoveryFlowResponse(r, http.StatusOK, types.PlanWriteChunkResponse{Plan: next, Chunk: chunk, Nodes: nodes})
		default:
			return nil, fmt.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		}
	})
	geometry := types.PlanWriteChunkRequest{WriteBinding: plannedBinding(upload), LogicalSize: int64(len(data)), StoredSize: int64(len(data)), Encoding: types.PlainEncoding, Checksum: types.CRC32C(data)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.uploadRecoverableChunk(ctx, upload, geometry, types.PlanWriteChunkResponse{Plan: initial, Chunk: chunk, Nodes: nodes}, data); err != nil {
		t.Fatalf("path-only recovery flow failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 1 || !reflect.DeepEqual(requests[0].AvoidPaths, []string{"direct"}) || len(requests[0].FailedNodes) != 0 {
		t.Fatalf("wrong recovery request: %+v", requests)
	}
	if len(putEpochs) != 2 || putEpochs[0] != 1 || putEpochs[1] != 2 {
		t.Fatalf("recovery did not fence the second upload epoch: %v", putEpochs)
	}
}

func TestWaitRecoveryChunkPathRecoveryGates(t *testing.T) {
	for _, test := range []struct {
		name     string
		enabled  bool
		path     peerhttp.Path
		attempts uint32
		full     bool
	}{
		{name: "feature-absent", path: peerhttp.PathDirect},
		{name: "already-circuit", enabled: true, path: peerhttp.PathRelay},
		{name: "attempts-exhausted", enabled: true, path: peerhttp.PathDirect, attempts: types.MaxWriteRecoveries},
		{name: "full-payload-not-done", enabled: true, path: peerhttp.PathDirect, full: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := New("http://master.test")
			c.SetPutTimeout(40 * time.Millisecond)
			c.writePathRecovery = test.enabled
			upload := types.WriteUpload{ID: types.StagingInodeBase + 7, PlanID: "path-gates", Revision: 1}
			var calls atomic.Int64
			c.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
				bytesReceived := calls.Add(1)
				if test.full {
					bytesReceived = 1024
				}
				status := types.WriteStatus{UploadID: upload.ID, Chunks: []types.WriteChunkStatus{{Index: 0, Epoch: 1, Progress: []types.WriteNodeProgress{{NodeID: 1, Attempt: 1, Bytes: bytesReceived, UpdatedAt: time.Now()}}}}}
				return pathRecoveryFlowResponse(r, http.StatusOK, status)
			})
			plan := types.WriteChunkPlan{Object: types.ContentObject{StoredSize: 1024}, Layout: types.ReplicaLayout{Epoch: 1, Nodes: []uint64{1}}, Confirmations: []uint64{1}, RequiredConfirmations: 1, Recovery: &types.WriteRecovery{Epoch: 1, Attempts: test.attempts, HardUntil: time.Now().Add(time.Second)}, Transfer: &types.WriteTransferPlan{UploadTargets: []uint64{1}, ExpiresAt: time.Now().Add(time.Second), Legs: []types.WriteTransferLeg{{ToNodeID: 1, Path: string(test.path), BPS: 1}}}}
			ctx, cancel := context.WithTimeout(context.Background(), 65*time.Millisecond)
			defer cancel()
			failed, err := c.waitRecoveryChunk(ctx, upload, plan)
			if errors.Is(err, errWritePathRecovery) {
				t.Fatalf("path recovery escaped a gate: failed=%v err=%v", failed, err)
			}
			if test.full {
				if len(failed) != 1 || failed[0] != 1 {
					t.Fatalf("full-payload replica was not left to ordinary stall handling: failed=%v err=%v", failed, err)
				}
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("gated wait did not preserve ordinary waiting: failed=%v err=%v", failed, err)
			}
		})
	}
}
