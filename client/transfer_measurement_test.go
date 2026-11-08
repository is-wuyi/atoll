package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func TestTransferMeasurementRequiresCompleteStoredSizeAcknowledgement(t *testing.T) {
	for _, mode := range []string{"stored", "wrong-size", "error-status"} {
		t.Run(mode, func(t *testing.T) {
			data := bytes.Repeat([]byte("confirmed-payload"), 128)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					return
				}
				if mode == "error-status" {
					w.WriteHeader(http.StatusConflict)
					return
				}
				size := len(data)
				if mode == "wrong-size" {
					size++
				}
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]int{"size": size})
			}))
			defer server.Close()
			client := New(server.URL)
			addr := server.Listener.Addr().String()
			client.transferNodeIDs = map[string]uint64{addr: 1}
			client.transferMeasurementTTL = 30 * time.Second
			err := client.putPlannedObject(context.Background(), addr, 1, types.CRC32C(data), data)
			if mode == "stored" {
				if err != nil || len(client.transferMeasurements) != 1 {
					t.Fatalf("verified-size response did not record a measurement: err=%v measurements=%+v", err, client.transferMeasurements)
				}
				for _, observation := range client.transferMeasurements {
					if observation.Path != "http" || observation.ThroughputBPS == 0 || !observation.Available || observation.ToNodeID != 1 {
						t.Fatalf("confirmed measurement malformed: %+v", observation)
					}
				}
			} else if err == nil || len(client.transferMeasurements) != 0 {
				t.Fatal("unconfirmed response became a successful throughput measurement")
			}
		})
	}
}

func TestTransferMeasuredPayloadPreservesTimestampAndFailedProbe(t *testing.T) {
	client := New("http://master.test")
	client.transferNodeIDs = map[string]uint64{"node.test:1": 1}
	client.transferMeasurementTTL = 30 * time.Second
	client.recordTransferMeasurement("node.test:1", "direct", 1, 0, 1024, time.Now().Add(-time.Second), time.Second)
	key := transferMeasurementKey{addr: "node.test:1", path: "direct"}
	measured := client.transferMeasurements[key]
	probes := &types.WriteTransferObservation{Links: []types.TransferObservation{{ToNodeID: 1, Path: "direct", Available: true, RTTMs: 7, ObservedAt: time.Now()}}}
	out, err := client.measuredWriteTransfer(probes, 0)
	if err != nil {
		t.Fatal(err)
	}
	if out.Links[0].ThroughputBPS != 1024 || !out.Links[0].ObservedAt.Equal(measured.ObservedAt) || out.Links[0].RTTMs != 7 {
		t.Fatal("health probe erased or prolonged the payload measurement")
	}
	probes.Links[0].Available = false
	out, err = client.measuredWriteTransfer(probes, 0)
	if err != nil || out.Links[0].Available || out.Links[0].ThroughputBPS != 0 {
		t.Fatal("past payload measurement revived a failed path")
	}
	measured.ObservedAt = time.Now().Add(-31 * time.Second)
	client.transferMeasurements[key] = measured
	probes.Links[0].Available = true
	out, err = client.measuredWriteTransfer(probes, 0)
	if err != nil || out.Links[0].ThroughputBPS != 0 || len(client.transferMeasurements) != 0 {
		t.Fatal("expired payload measurement remained selectable")
	}
}

func TestTransferObservationCacheUsesServerTTL(t *testing.T) {
	var discoveries atomic.Int64
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer node.Close()
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		discoveries.Add(1)
		_ = json.NewEncoder(w).Encode(types.WriteTransferNodes{Nodes: []types.NodeInfo{{ID: 1, Addr: node.Listener.Addr().String()}}, ObservationTTLSeconds: 1})
	}))
	defer master.Close()
	client := New(master.URL)
	if err := client.SetTransferBudget(types.TransferBudget{UploadBPS: 1024, DownloadBPS: 1024, MaxConcurrent: 1}); err != nil {
		t.Fatal(err)
	}
	upload := types.WriteUpload{ID: 1, PlanID: "probe", Revision: 1}
	if _, err := client.observeWriteTransfer(context.Background(), upload); err != nil {
		t.Fatal(err)
	}
	if time.Until(client.transferValidUntil) > time.Second {
		t.Fatal("client cache ignored the server's short observation TTL")
	}
	client.transferValidUntil = time.Now().Add(-time.Second)
	if _, err := client.observeWriteTransfer(context.Background(), upload); err != nil {
		t.Fatal(err)
	}
	if discoveries.Load() != 2 {
		t.Fatal("expired observation cache skipped a new discovery")
	}
}

func TestTransferMeasurementDoesNotGuessPeerPath(t *testing.T) {
	client := New("https://master.test")
	client.transferNodeIDs = map[string]uint64{"node.test:1": 1}
	client.transferMeasurementTTL = 30 * time.Second
	observed := &transferUploadObservation{response: peerhttp.Observation{Phase: peerhttp.PhaseResponse, Status: http.StatusCreated, Path: peerhttp.PathUnknown}}
	client.finishTransferUpload(observed, "node.test:1", 1024, time.Now().Add(-time.Second), http.StatusCreated)
	if len(client.transferMeasurements) != 0 {
		t.Fatal("unknown serving path became a direct or HTTPS measurement")
	}
}
