package master

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

type recoveryOwnershipFixture struct {
	store  *meta.Store
	server *Server
	upload types.WriteUpload
	plan   types.WriteChunkPlan
	nodes  []uint64
	pulls  []*atomic.Int32
}

func newRecoveryOwnershipFixture(t *testing.T, recoverable, transfer bool) recoveryOwnershipFixture {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "metadata.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := NewServer(store, time.Hour)
	if err := srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 3, TransferPlanning: transfer}); err != nil {
		t.Fatal(err)
	}
	fixture := recoveryOwnershipFixture{store: store, server: srv}
	data := bytes.Repeat([]byte("owned-payload"), 8)
	for i := 0; i < 3; i++ {
		pulls := new(atomic.Int32)
		node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/objects/"):
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(data[:1])
			case r.Method == http.MethodPost && r.URL.Path == "/pull":
				pulls.Add(1)
				w.WriteHeader(http.StatusAccepted)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(node.Close)
		n, err := store.RegisterNode(node.Listener.Addr().String(), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		fixture.nodes = append(fixture.nodes, n.ID)
		fixture.pulls = append(fixture.pulls, pulls)
	}
	if transfer {
		for _, id := range fixture.nodes {
			if err := store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: id, UploadBPS: 2 << 20, DownloadBPS: 2 << 20, MaxTransferConcurrency: 4}); err != nil {
				t.Fatal(err)
			}
		}
	}
	upload, err := store.BeginPlannedWrite(meta.WriteActor{}, meta.RootID, "ownership", types.BeginWriteRequest{Path: "/ownership", OpID: "ownership-begin", Size: int64(len(data))}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	binding := types.WriteBinding{UploadID: upload.ID, PlanID: upload.PlanID, Revision: upload.Revision}
	request := types.PlanWriteChunkRequest{WriteBinding: binding, Index: 0, LogicalSize: int64(len(data)), StoredSize: int64(len(data)), Encoding: types.PlainEncoding, Checksum: types.CRC32C(data)}
	id := types.ChunkID(upload.ID, 0)
	plan := types.WriteChunkPlan{Index: 0,
		Object:        types.ContentObject{ID: id, Version: 1, LogicalSize: request.LogicalSize, StoredSize: request.StoredSize, Encoding: request.Encoding, Checksum: request.Checksum, ChecksumKnown: true},
		Layout:        types.ReplicaLayout{ObjectID: id, Epoch: 1, Scheme: "replicate", Nodes: append([]uint64(nil), fixture.nodes...)},
		Confirmations: append([]uint64(nil), fixture.nodes[:2]...), RequiredConfirmations: 2,
	}
	if recoverable {
		plan.Recovery = &types.WriteRecovery{Epoch: 1, HardUntil: time.Now().Add(types.WriteRecoveryMaxTime)}
	}
	if transfer {
		plan.Transfer = &types.WriteTransferPlan{UploadTargets: []uint64{fixture.nodes[0]}, ExpiresAt: plan.Recovery.HardUntil,
			Legs: []types.WriteTransferLeg{
				{ToNodeID: fixture.nodes[0], Path: "http", BPS: 1 << 20},
				{FromNodeID: fixture.nodes[0], ToNodeID: fixture.nodes[1], Path: "http", BPS: 1 << 20},
				{FromNodeID: fixture.nodes[0], ToNodeID: fixture.nodes[2], Path: "http", BPS: 1 << 20},
			}}
	}
	snapshot, err := store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err = store.ReserveWriteChunk(meta.WriteActor{}, request, plan, snapshot.ProfileRevision, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fixture.upload, fixture.plan = upload, plan
	fixture.confirm(t, fixture.nodes[0])
	return fixture
}

func (f recoveryOwnershipFixture) confirm(t *testing.T, nodeID uint64) {
	t.Helper()
	descriptor, err := f.store.ObjectIntegrity(f.plan.Object.ID)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := f.store.MarkVerifiedObjectDone(descriptor, nodeID)
	if err != nil || !ok {
		t.Fatalf("confirmation rejected: marked=%v err=%v", ok, err)
	}
}

func (f recoveryOwnershipFixture) replication(t *testing.T) types.ReplicationPlan {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/files/replication?object_id=%d&node_id=%d", f.plan.Object.ID, f.nodes[0]), nil)
	response := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("replication plan status=%d body=%s", response.Code, response.Body)
	}
	var plan types.ReplicationPlan
	if err := json.Unmarshal(response.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func (f recoveryOwnershipFixture) commit(t *testing.T) {
	t.Helper()
	f.confirm(t, f.nodes[1])
	request := types.CommitWriteRequest{WriteBinding: types.WriteBinding{UploadID: f.upload.ID, PlanID: f.upload.PlanID, Revision: f.upload.Revision}, OpID: "ownership-commit", Size: f.plan.Object.LogicalSize, ChunkCount: 1}
	if _, _, _, err := f.store.CommitPlannedWrite(meta.WriteActor{}, request, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryReplicationPlanDefersUnplannedPushUntilPublication(t *testing.T) {
	fixture := newRecoveryOwnershipFixture(t, true, false)
	pending := fixture.replication(t)
	if pending.WriteProgress == nil {
		t.Fatal("fixture did not create an active recovery write")
	}
	if len(pending.Targets) != 0 {
		t.Fatalf("active direct write received unplanned node pushes: %+v", pending.Targets)
	}
	fixture.commit(t)
	published := fixture.replication(t)
	if published.WriteProgress != nil || len(published.Targets) != 1 || published.Targets[0].ID != fixture.nodes[2] {
		t.Fatalf("published content lost its remaining replica repair: %+v", published)
	}
}

func TestRecoveryScannerDoesNotRaceActiveWrite(t *testing.T) {
	fixture := newRecoveryOwnershipFixture(t, true, false)
	request := types.BeginWriteProgressRequest{ObjectID: fixture.plan.Object.ID, NodeID: fixture.nodes[1], Epoch: 1, RequestID: strings.Repeat("1", 32)}
	attempt, err := fixture.store.BeginWriteProgress(request, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.RecordWriteProgress(types.WriteProgress{ObjectID: request.ObjectID, NodeID: request.NodeID, Epoch: 1, Attempt: attempt.Attempt, AttemptToken: attempt.AttemptToken, Bytes: 1}, time.Now()); err != nil {
		t.Fatal(err)
	}
	before, err := fixture.store.WriteProgressState(request.ObjectID, request.NodeID, request.Epoch, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(fixture.store, time.Hour, time.Second, time.Hour)
	scanner.RepairScanOnce()
	for i, count := range fixture.pulls {
		if count.Load() != 0 {
			t.Errorf("scanner raced active recovery write at node %d: pulls=%d", fixture.nodes[i], count.Load())
		}
	}
	after, err := fixture.store.WriteProgressState(request.ObjectID, request.NodeID, request.Epoch, time.Now())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("scanner changed the active attempt: before=%+v after=%+v err=%v", before, after, err)
	}
	fixture.commit(t)
	scanner.RepairScanOnce()
	if fixture.pulls[2].Load() != 1 {
		t.Fatalf("published remaining replica did not receive repair: pulls=%d", fixture.pulls[2].Load())
	}
}

func TestRecoveryExplicitTransferGraphRetainsNodeLegs(t *testing.T) {
	fixture := newRecoveryOwnershipFixture(t, true, true)
	pending := fixture.replication(t)
	if pending.WriteTransfer == nil || pending.WriteProgress == nil || len(pending.Targets) != 2 {
		t.Fatalf("explicit pending node legs were lost: %+v", pending)
	}
	for _, target := range pending.Targets {
		if target.ID != fixture.nodes[1] && target.ID != fixture.nodes[2] {
			t.Fatalf("unassigned target admitted: %+v", target)
		}
	}
	scanner := NewScanner(fixture.store, time.Hour, time.Second, time.Hour)
	scanner.RepairScanOnce()
	for _, count := range fixture.pulls {
		if count.Load() != 0 {
			t.Fatal("legacy repair duplicated an explicit active transfer leg")
		}
	}
}

func TestPreRecoveryStagingRetainsReplicaFallback(t *testing.T) {
	fixture := newRecoveryOwnershipFixture(t, false, false)
	if plan := fixture.replication(t); plan.WriteProgress != nil || len(plan.Targets) != 2 {
		t.Fatalf("pre-recovery write lost fallback replication: %+v", plan)
	}
	scanner := NewScanner(fixture.store, time.Hour, time.Second, time.Hour)
	scanner.RepairScanOnce()
	if fixture.pulls[1].Load() != 1 || fixture.pulls[2].Load() != 1 {
		t.Fatalf("pre-recovery staging lost repair: pulls=%d,%d", fixture.pulls[1].Load(), fixture.pulls[2].Load())
	}
}
