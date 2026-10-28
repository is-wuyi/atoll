package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestRecoveryWaitTracksEachRequiredReplica(t *testing.T) {
	c := New("http://master.test")
	c.SetPutTimeout(80 * time.Millisecond)
	started := time.Now()
	var calls atomic.Int64
	c.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		elapsed := time.Since(started)
		progress := int64(elapsed / (10 * time.Millisecond))
		status := types.WriteStatus{UploadID: types.StagingInodeBase + 7, Chunks: []types.WriteChunkStatus{{Index: 0, Epoch: 1, Progress: []types.WriteNodeProgress{{NodeID: 1, Attempt: 1, Bytes: progress, UpdatedAt: time.Now()}}}}}
		raw, err := json.Marshal(status)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
	})
	u := types.WriteUpload{ID: types.StagingInodeBase + 7, PlanID: "test-write", Revision: 1}
	plan := types.WriteChunkPlan{Index: 0, Object: types.ContentObject{StoredSize: 1024}, Layout: types.ReplicaLayout{Nodes: []uint64{1, 2}}, Confirmations: []uint64{1, 2}, Recovery: &types.WriteRecovery{Epoch: 1, HardUntil: time.Now().Add(time.Second)}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failed, err := c.waitRecoveryChunk(ctx, u, plan)
	if err == nil || len(failed) != 1 || failed[0] != 2 || calls.Load() < 2 || ctx.Err() != nil {
		t.Fatalf("moving source masked stalled replica: failed=%v calls=%d err=%v parent=%v", failed, calls.Load(), err, ctx.Err())
	}
}

func TestRecoveryWaitMovingReplicaCompletesAcrossIdleWindows(t *testing.T) {
	c := New("http://master.test")
	c.SetPutTimeout(80 * time.Millisecond)
	started := time.Now()
	c.HTTP.Transport = plannedTestTransport(func(r *http.Request) (*http.Response, error) {
		elapsed := time.Since(started)
		chunk := types.WriteChunkStatus{Index: 0, Epoch: 1, Progress: []types.WriteNodeProgress{{NodeID: 1, Attempt: 1, Bytes: int64(elapsed / (10 * time.Millisecond)), UpdatedAt: time.Now()}}}
		if elapsed >= 240*time.Millisecond {
			chunk.Ready = true
			chunk.Done = []uint64{1}
		}
		raw, _ := json.Marshal(types.WriteStatus{UploadID: types.StagingInodeBase + 7, Chunks: []types.WriteChunkStatus{chunk}})
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
	})
	u := types.WriteUpload{ID: types.StagingInodeBase + 7, PlanID: "test-write", Revision: 1}
	plan := types.WriteChunkPlan{Index: 0, Object: types.ContentObject{StoredSize: 1024}, Layout: types.ReplicaLayout{Nodes: []uint64{1}}, Confirmations: []uint64{1}, Recovery: &types.WriteRecovery{Epoch: 1, HardUntil: time.Now().Add(time.Second)}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if failed, err := c.waitRecoveryChunk(ctx, u, plan); err != nil || len(failed) > 0 {
		t.Fatalf("moving replica was abandoned: failed=%v err=%v", failed, err)
	}
}
