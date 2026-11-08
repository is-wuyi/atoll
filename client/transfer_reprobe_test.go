package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestPlanWriteChunkRediscoversFailedIngressOnce(t *testing.T) {
	for _, recoverPath := range []bool{true, false} {
		t.Run(map[bool]string{true: "second-probe-ready", false: "both-probes-fail"}[recoverPath], func(t *testing.T) {
			var probes, discoveries, plans atomic.Int64
			var mu sync.Mutex
			var requests []types.PlanWriteChunkRequest
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count := probes.Add(1)
				if count == 1 || !recoverPath {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer node.Close()
			master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/writes/transfer-nodes":
					discoveries.Add(1)
					_ = json.NewEncoder(w).Encode(types.WriteTransferNodes{Nodes: []types.NodeInfo{{ID: 1, Addr: node.Listener.Addr().String()}}, ObservationTTLSeconds: 30})
				case "/writes/chunks":
					plans.Add(1)
					var request types.PlanWriteChunkRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					mu.Lock()
					requests = append(requests, request)
					mu.Unlock()
					if request.Network == nil || len(request.Network.Links) != 1 || !request.Network.Links[0].Available {
						w.WriteHeader(http.StatusUnprocessableEntity)
						_ = json.NewEncoder(w).Encode(types.WriteError{Code: types.WriteNoFeasible, Error: "no measured ingress"})
						return
					}
					_ = json.NewEncoder(w).Encode(types.PlanWriteChunkResponse{})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer master.Close()
			client := New(master.URL)
			client.transferEnabled = true
			if err := client.SetTransferBudget(types.TransferBudget{UploadBPS: 1024, DownloadBPS: 1024, MaxConcurrent: 1}); err != nil {
				t.Fatal(err)
			}
			client.transferNodeIDs = map[string]uint64{node.Listener.Addr().String(): 1}
			client.transferMeasurementTTL = 30 * time.Second
			client.recordTransferMeasurement(node.Listener.Addr().String(), "http", 1, 0, 4096, time.Now().Add(-time.Second), time.Second)
			upload := types.WriteUpload{ID: 9, PlanID: "immutable-plan", Revision: 1}
			request := types.PlanWriteChunkRequest{WriteBinding: plannedBinding(upload), Index: 0, LogicalSize: 1024, StoredSize: 1088, Encoding: types.AeadRecordEncoding, Checksum: 17}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var out types.PlanWriteChunkResponse
			err := client.planWriteChunk(ctx, upload, &request, &out)
			if recoverPath && err != nil || !recoverPath && WriteCode(err) != types.WriteNoFeasible {
				t.Fatalf("plan outcome = %v, recover=%v", err, recoverPath)
			}
			if probes.Load() != 2 || discoveries.Load() != 2 || plans.Load() != 2 {
				t.Fatalf("unbounded or cached retry: probes=%d discoveries=%d plans=%d", probes.Load(), discoveries.Load(), plans.Load())
			}
			mu.Lock()
			defer mu.Unlock()
			if len(requests) != 2 || requests[0].Network.Links[0].Available || requests[0].Network.Links[0].ThroughputBPS != 0 {
				t.Fatal("old payload measurement revived the first failed probe")
			}
			first, second := requests[0], requests[1]
			first.Network, second.Network = nil, nil
			if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(second, types.PlanWriteChunkRequest{WriteBinding: plannedBinding(upload), Index: 0, LogicalSize: 1024, StoredSize: 1088, Encoding: types.AeadRecordEncoding, Checksum: 17}) {
				t.Fatal("rediscovery changed upload identity or ciphertext geometry")
			}
		})
	}
}

func TestPlanWriteChunkDoesNotReprobeFeasibleIngressOrOtherRejection(t *testing.T) {
	for _, code := range []string{types.WriteNoFeasible, types.WritePlanConflict} {
		var probes, plans atomic.Int64
		node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { probes.Add(1); w.WriteHeader(http.StatusOK) }))
		master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/writes/transfer-nodes" {
				_ = json.NewEncoder(w).Encode(types.WriteTransferNodes{Nodes: []types.NodeInfo{{ID: 1, Addr: node.Listener.Addr().String()}}})
				return
			}
			plans.Add(1)
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(types.WriteError{Code: code, Error: "independent hard constraint"})
		}))
		client := New(master.URL)
		client.transferEnabled = true
		if err := client.SetTransferBudget(types.TransferBudget{UploadBPS: 1024, DownloadBPS: 1024, MaxConcurrent: 1}); err != nil {
			t.Fatal(err)
		}
		upload := types.WriteUpload{ID: 9, PlanID: "plan", Revision: 1}
		request := types.PlanWriteChunkRequest{WriteBinding: plannedBinding(upload)}
		var out types.PlanWriteChunkResponse
		if err := client.planWriteChunk(context.Background(), upload, &request, &out); WriteCode(err) != code || probes.Load() != 1 || plans.Load() != 1 {
			t.Fatalf("unexpected reprobe for %s: %v probes=%d plans=%d", code, err, probes.Load(), plans.Load())
		}
		master.Close()
		node.Close()
	}
}

func TestPlanWriteChunkReprobeKeepsCallerDeadlineAndGeneration(t *testing.T) {
	for _, mode := range []string{"short-deadline", "session-changed"} {
		t.Run(mode, func(t *testing.T) {
			var probes, plans atomic.Int64
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				probes.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer node.Close()
			var client *Client
			master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/writes/transfer-nodes" {
					_ = json.NewEncoder(w).Encode(types.WriteTransferNodes{Nodes: []types.NodeInfo{{ID: 1, Addr: node.Listener.Addr().String()}}})
					return
				}
				plans.Add(1)
				if mode == "session-changed" {
					if err := client.UseSpace(2); err != nil {
						t.Error(err)
					}
				}
				w.WriteHeader(http.StatusUnprocessableEntity)
				_ = json.NewEncoder(w).Encode(types.WriteError{Code: types.WriteNoFeasible, Error: "failed ingress"})
			}))
			defer master.Close()
			client = New(master.URL)
			client.transferEnabled = true
			client.sec = &secureSession{generation: 1, spaceID: 1, hasSpace: true}
			if err := client.SetTransferBudget(types.TransferBudget{UploadBPS: 1024, DownloadBPS: 1024, MaxConcurrent: 1}); err != nil {
				t.Fatal(err)
			}
			upload := types.WriteUpload{ID: 9, PlanID: "plan", Revision: 1}
			request := types.PlanWriteChunkRequest{WriteBinding: plannedBinding(upload)}
			var out types.PlanWriteChunkResponse
			ctx := context.Background()
			if mode == "short-deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Second)
				defer cancel()
			}
			err := client.planWriteChunk(ctx, upload, &request, &out)
			if err == nil || probes.Load() != 1 || plans.Load() != 1 {
				t.Fatalf("deadline or generation crossing: err=%v probes=%d plans=%d", err, probes.Load(), plans.Load())
			}
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				t.Fatal("retry invented an expired caller context")
			}
		})
	}
}
