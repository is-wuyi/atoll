package master

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

func newRetirementReceiptFixture(t *testing.T, reply func(http.ResponseWriter, *http.Request, types.ObjectRetirement)) (*Scanner, *meta.Store, uint64, uint64) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.ObjectRetirement
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Validate() != nil || r.Method != http.MethodPost || r.URL.Path != types.RetirementPath(req.ObjectID) {
			t.Errorf("invalid retirement request: %+v %v", req, err)
			w.WriteHeader(400)
			return
		}
		reply(w, r, req)
	}))
	t.Cleanup(target.Close)
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	node, err := store.RegisterNode(target.Listener.Addr().String(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("unpublished data")
	u, err := store.BeginPlannedWrite(meta.WriteActor{}, meta.RootID, "aborted", types.BeginWriteRequest{Path: "/aborted", Size: int64(len(data)), OpID: "receipt-fixture-begin"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	binding := types.WriteBinding{UploadID: u.ID, PlanID: u.PlanID, Revision: u.Revision}
	req := types.PlanWriteChunkRequest{WriteBinding: binding, LogicalSize: int64(len(data)), StoredSize: int64(len(data)), Encoding: types.PlainEncoding, Checksum: types.CRC32C(data)}
	plan := types.WriteChunkPlan{Object: types.ContentObject{ID: types.ChunkID(u.ID, 0), Version: 1, LogicalSize: req.LogicalSize, StoredSize: req.StoredSize, Encoding: types.PlainEncoding, Checksum: req.Checksum, ChecksumKnown: true}, Layout: types.ReplicaLayout{ObjectID: types.ChunkID(u.ID, 0), Epoch: 1, Scheme: "replicate", Nodes: []uint64{node.ID}}, Confirmations: []uint64{node.ID}, RequiredConfirmations: 1}
	if _, _, err := store.ReserveWriteChunk(meta.WriteActor{}, req, plan, 0, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.AbortPlannedWrite(meta.WriteActor{}, binding, time.Now()); err != nil {
		t.Fatal(err)
	}
	return NewScanner(store, time.Hour, time.Hour, time.Hour), store, node.ID, plan.Object.ID
}

func TestRetirementScannerRejectsUnprovenResponses(t *testing.T) {
	for _, scenario := range []string{"empty-200", "pending-202", "absent-404", "conflict-409", "missing-removed", "missing-usage", "missing-used", "wrong-attempt", "wrong-node", "duplicate-field", "oversized", "truncated"} {
		t.Run(scenario, func(t *testing.T) {
			scanner, store, nodeID, _ := newRetirementReceiptFixture(t, func(w http.ResponseWriter, _ *http.Request, req types.ObjectRetirement) {
				receipt := types.ObjectRetirementReceipt{ObjectRetirement: req, State: types.RetirementRemoved,
					Usage: types.NodeUsage{Epoch: "boot", Sequence: 1}}
				raw, _ := json.Marshal(receipt)
				var body map[string]json.RawMessage
				json.Unmarshal(raw, &body)
				switch scenario {
				case "empty-200":
					raw = nil
				case "pending-202":
					w.WriteHeader(202)
				case "absent-404":
					w.WriteHeader(404)
				case "conflict-409":
					w.WriteHeader(409)
				case "missing-removed":
					delete(body, "removed_bytes")
					raw, _ = json.Marshal(body)
				case "missing-usage":
					delete(body, "usage")
					raw, _ = json.Marshal(body)
				case "missing-used":
					body["usage"] = json.RawMessage(`{"epoch":"boot","sequence":1}`)
					raw, _ = json.Marshal(body)
				case "wrong-attempt":
					receipt.AttemptID = "wrong-attempt-12345678"
					raw, _ = json.Marshal(receipt)
				case "wrong-node":
					receipt.NodeID++
					raw, _ = json.Marshal(receipt)
				case "duplicate-field":
					raw = []byte(strings.TrimSuffix(string(raw), "}") + `,"removed_bytes":0}`)
				case "oversized":
					raw = bytes.Repeat([]byte(" "), 64<<10+1)
				case "truncated":
					raw = raw[:len(raw)-2]
				}
				w.Write(raw)
			})
			before, err := store.AutonomySnapshot()
			if err != nil {
				t.Fatal(err)
			}
			count, err := scanner.RunRetirements(t.Context())
			if err != nil || count != 0 {
				t.Fatalf("unproven response accepted: count=%d err=%v", count, err)
			}
			after, err := store.AutonomySnapshot()
			if err != nil {
				t.Fatal(err)
			}
			for i, c := range before.Capacity {
				if c.NodeID == nodeID && after.Capacity[i] != c {
					t.Fatalf("unproven response released capacity: before=%+v after=%+v", c, after.Capacity[i])
				}
			}
			records, err := store.ListRetirements()
			if err != nil || len(records) != 1 || records[0].State != meta.RetirementAttempted {
				t.Fatalf("unproven response changed retirement: %+v %v", records, err)
			}
		})
	}
}

func TestRetirementScannerAcceptsExplicitAbsenceOnce(t *testing.T) {
	var requests atomic.Int32
	scanner, store, _, _ := newRetirementReceiptFixture(t, func(w http.ResponseWriter, _ *http.Request, req types.ObjectRetirement) {
		requests.Add(1)
		json.NewEncoder(w).Encode(types.ObjectRetirementReceipt{ObjectRetirement: req, State: types.RetirementRemoved,
			Usage: types.NodeUsage{Epoch: "boot", Sequence: 1}})
	})
	for _, expected := range []int{1, 0} {
		count, err := scanner.RunRetirements(t.Context())
		if err != nil || count != expected {
			t.Fatalf("retirement count=%d want=%d err=%v", count, expected, err)
		}
	}
	if requests.Load() != 1 {
		t.Fatal("confirmed retirement dispatched again")
	}
	snapshot, err := store.AutonomySnapshot()
	if err != nil || len(snapshot.Capacity) != 1 || snapshot.Capacity[0].Reserved != 0 {
		t.Fatalf("confirmed absence remains reserved: %+v %v", snapshot.Capacity, err)
	}
}

func TestRetirementWorkerStopsWithScanner(t *testing.T) {
	started := make(chan struct{}, 1)
	scanner, _, _, _ := newRetirementReceiptFixture(t, func(w http.ResponseWriter, r *http.Request, _ types.ObjectRetirement) {
		started <- struct{}{}
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	scanner.Start(ctx)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("retirement worker did not dispatch")
	}
	cancel()
	joined := make(chan struct{})
	go func() { scanner.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(3 * time.Second):
		t.Fatal("retirement worker survived scanner cancellation")
	}
}
