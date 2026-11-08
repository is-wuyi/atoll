package client

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

func TestTransferMeasurementSubmissionCannotUseNewSession(t *testing.T) {
	for _, path := range []string{"/writes/chunks", "/writes/chunks/recover"} {
		t.Run(path, func(t *testing.T) {
			origin, _ := url.Parse("https://master.test")
			session := &secureSession{generation: 1, token: "fixture-old-session", spaceID: 1, hasSpace: true}
			transport := &secureTransport{master: origin, s: session}
			ctx := context.WithValue(context.Background(), transferSubmissionKey{}, uint64(1))
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://master.test"+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			session.mu.Lock()
			session.generation = 2
			session.token = "fixture-new-session"
			session.mu.Unlock()
			if err := transport.applyMasterAuth(request); err == nil {
				t.Fatal("old observation submission authenticated with the new session")
			}
			if request.Header.Get("Authorization") != "" {
				t.Fatal("rejected observation submission received a session credential")
			}
		})
	}
}

func TestTransferMeasurementLateUploadCannotChangeNodeBinding(t *testing.T) {
	client := New("http://master.test")
	client.transferNodeIDs = map[string]uint64{"node.test:1": 1}
	client.transferMeasurementTTL = 30 * time.Second
	_, old := client.observeTransferUpload(context.Background(), "node.test:1", 7)
	client.transferNodeIDs["node.test:1"] = 2
	client.finishTransferUpload(old, "node.test:1", 1024, time.Now().Add(-time.Second), http.StatusCreated)
	if len(client.transferMeasurements) != 0 {
		t.Fatal("late upload was attributed to the address's new NodeID")
	}
	_, current := client.observeTransferUpload(context.Background(), "node.test:1", 8)
	client.finishTransferUpload(current, "node.test:1", 1024, time.Now().Add(-time.Second), http.StatusCreated)
	if len(client.transferMeasurements) != 1 {
		t.Fatal("current upload did not record its measurement")
	}
	for _, measurement := range client.transferMeasurements {
		if measurement.ToNodeID != 2 {
			t.Fatal("measurement was recorded for the old NodeID")
		}
	}
}

func TestTransferMeasurementSessionGenerationRejectsLateResult(t *testing.T) {
	client := New("http://master.test")
	client.sec = &secureSession{generation: 1, spaceID: 1, hasSpace: true}
	client.transferMeasurementGen = 1
	client.transferNodeIDs = map[string]uint64{"node.test:1": 1}
	client.transferMeasurementTTL = 30 * time.Second
	_, old := client.observeTransferUpload(context.Background(), "node.test:1", 7)
	if err := client.UseSpace(2); err != nil {
		t.Fatal(err)
	}
	client.finishTransferUpload(old, "node.test:1", 1024, time.Now().Add(-time.Second), http.StatusCreated)
	if len(client.transferMeasurements) != 0 {
		t.Fatal("upload from the prior space wrote a new-space measurement")
	}
	probes := &types.WriteTransferObservation{Links: []types.TransferObservation{{ToNodeID: 1, Available: true, Path: "direct", ObservedAt: time.Now()}}}
	if _, err := client.measuredWriteTransfer(probes, 1); err == nil {
		t.Fatal("old-generation probes were returned for the new space")
	}
	if _, current := client.observeTransferUpload(context.Background(), "node.test:1", 8); current != nil {
		t.Fatal("new space used old-generation node discovery")
	}
}

func TestTransferMeasurementNewerAttemptCannotBeOverwritten(t *testing.T) {
	client := New("http://master.test")
	client.transferNodeIDs = map[string]uint64{"node.test:1": 1}
	client.transferMeasurementTTL = 30 * time.Second
	older := time.Now().Add(-2 * time.Second)
	newer := older.Add(time.Second)
	client.recordTransferMeasurement("node.test:1", "direct", 1, 0, 2048, newer, time.Second)
	client.recordTransferMeasurement("node.test:1", "direct", 1, 0, 1024, older, time.Second)
	key := transferMeasurementKey{addr: "node.test:1", path: "direct"}
	if client.transferMeasurements[key].ThroughputBPS != 2048 {
		t.Fatal("late old attempt replaced a newer payload measurement")
	}
}

func TestTransferMeasurementRejectsCanceledSuccessfulResponse(t *testing.T) {
	client := New("http://master.test")
	client.transferNodeIDs = map[string]uint64{"node.test:1": 1}
	client.transferMeasurementTTL = 30 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	_, observed := client.observeTransferUpload(ctx, "node.test:1", 7)
	observed.response = peerhttp.Observation{Phase: peerhttp.PhaseResponse, Status: http.StatusCreated, Path: peerhttp.PathDirect}
	cancel()
	client.finishTransferUpload(observed, "node.test:1", 1024, time.Now().Add(-time.Second), http.StatusCreated)
	if len(client.transferMeasurements) != 0 {
		t.Fatal("canceled upload inserted a successful measurement")
	}
}
