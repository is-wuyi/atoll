package master

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

type writePathRecoveryHTTPFixture struct {
	srv      *Server
	store    *meta.Store
	handler  http.Handler
	upload   types.WriteUpload
	plan     types.WriteChunkPlan
	nodes    []uint64
	features string
}

func writePathRecoveryFeatures() string {
	return types.WritePlanFeature + "," + types.WriteTransferFeature + "," + types.WriteRecoveryFeature + "," + types.WritePathRecoveryFeature
}

func (f *writePathRecoveryHTTPFixture) post(t *testing.T, path, features string, input, out any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(types.FeaturesHeader, features)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code >= http.StatusOK && rec.Code < http.StatusMultipleChoices && out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s response: %v", path, err)
		}
	}
	return rec
}

func writePathRecoveryClientNetwork(nodes []uint64, path peerhttp.Path, now time.Time) *types.WriteTransferObservation {
	out := &types.WriteTransferObservation{Budget: types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 2}}
	for _, id := range nodes {
		out.Links = append(out.Links, types.TransferObservation{ToNodeID: id, Path: string(path), Available: true, RTTMs: 1, ObservedAt: now})
	}
	return out
}

func newWritePathRecoveryHTTPFixture(t *testing.T) *writePathRecoveryHTTPFixture {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := NewServer(store, time.Hour)
	if err := srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 2, TransferPlanning: true}); err != nil {
		t.Fatal(err)
	}
	srv.SetHealthProbe(func(string) bool { return false })
	f := &writePathRecoveryHTTPFixture{srv: srv, store: store, handler: srv.Handler(), features: writePathRecoveryFeatures()}
	now := time.Now()
	for i := 0; i < 2; i++ {
		ns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}))
		t.Cleanup(ns.Close)
		reg, err := store.RegisterNode(ns.Listener.Addr().String(), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: reg.ID, FailureDomains: map[string]string{"zone": fmt.Sprint(i)}, UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxTransferConcurrency: 4}); err != nil {
			t.Fatal(err)
		}
		f.nodes = append(f.nodes, reg.ID)
	}
	for _, pair := range [][2]uint64{{f.nodes[0], f.nodes[1]}, {f.nodes[1], f.nodes[0]}} {
		if err := srv.RecordTransferObservation(types.TransferObservation{FromNodeID: pair[0], ToNodeID: pair[1], Path: string(peerhttp.PathDirect), Available: true, RTTMs: 1, ObservedAt: now}, now); err != nil {
			t.Fatal(err)
		}
	}
	if rec := f.post(t, "/protection", f.features, types.ProtectionRequest{Path: "/", Tier: types.ProtectionSecurity}, nil); rec.Code != http.StatusOK {
		t.Fatalf("set protection: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var begin types.BeginWriteResponse
	if rec := f.post(t, "/writes", f.features, types.BeginWriteRequest{Path: "/path-recovery", Size: 64, OpID: "begin-path-recovery"}, &begin); rec.Code != http.StatusCreated {
		t.Fatalf("begin write: status=%d body=%s", rec.Code, rec.Body.String())
	}
	f.upload = begin.Upload
	data := make([]byte, 64)
	geometry := types.PlanWriteChunkRequest{WriteBinding: types.WriteBinding{UploadID: f.upload.ID, PlanID: f.upload.PlanID, Revision: f.upload.Revision}, LogicalSize: 64, StoredSize: 64, Encoding: types.PlainEncoding, Checksum: types.CRC32C(data), Network: writePathRecoveryClientNetwork(f.nodes, peerhttp.PathDirect, now)}
	var planned types.PlanWriteChunkResponse
	if rec := f.post(t, "/writes/chunks", f.features, geometry, &planned); rec.Code != http.StatusOK {
		t.Fatalf("initial plan: status=%d body=%s", rec.Code, rec.Body.String())
	}
	f.plan = planned.Plan
	if len(f.plan.Layout.Nodes) != 2 || f.plan.RequiredConfirmations != 2 || f.plan.Transfer == nil {
		t.Fatalf("invalid initial fixture plan: %+v", f.plan)
	}
	for _, leg := range f.plan.Transfer.Legs {
		if leg.Path != string(peerhttp.PathDirect) {
			t.Fatalf("initial fixture was not direct-only: %+v", f.plan.Transfer.Legs)
		}
	}
	return f
}

func (f *writePathRecoveryHTTPFixture) recoveryRequest(path peerhttp.Path, op string) types.RecoverWriteChunkRequest {
	return types.RecoverWriteChunkRequest{WriteBinding: types.WriteBinding{UploadID: f.upload.ID, PlanID: f.upload.PlanID, Revision: f.upload.Revision}, ExpectedEpoch: f.plan.Layout.Epoch, OpID: op, AvoidPaths: []string{string(peerhttp.PathDirect)}, Network: writePathRecoveryClientNetwork(f.nodes, path, time.Now())}
}

func (f *writePathRecoveryHTTPFixture) addCircuitObservations(t *testing.T) {
	t.Helper()
	now := time.Now()
	for _, pair := range [][2]uint64{{f.nodes[0], f.nodes[1]}, {f.nodes[1], f.nodes[0]}} {
		if err := f.srv.RecordTransferObservation(types.TransferObservation{FromNodeID: pair[0], ToNodeID: pair[1], Path: string(peerhttp.PathRelay), Available: true, RTTMs: 2, ObservedAt: now}, now); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWritePathRecoveryHTTPReplacesOnlyDirectPaths(t *testing.T) {
	f := newWritePathRecoveryHTTPFixture(t)
	f.addCircuitObservations(t)
	req := f.recoveryRequest(peerhttp.PathRelay, "avoid-direct")
	legacyFeatures := types.WritePlanFeature + "," + types.WriteTransferFeature + "," + types.WriteRecoveryFeature
	if rec := f.post(t, "/writes/chunks/recover", legacyFeatures, req, nil); rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("unnegotiated path recovery status=%d body=%s", rec.Code, rec.Body.String())
	}
	var recovered types.PlanWriteChunkResponse
	if rec := f.post(t, "/writes/chunks/recover", f.features, req, &recovered); rec.Code != http.StatusOK {
		t.Fatalf("path recovery: status=%d body=%s", rec.Code, rec.Body.String())
	}
	next := recovered.Plan
	if !types.SameUint64Set(next.Layout.Nodes, f.plan.Layout.Nodes) || !types.SameUint64Set(next.Confirmations, f.plan.Confirmations) || next.RequiredConfirmations != f.plan.RequiredConfirmations || next.Layout.Epoch != f.plan.Layout.Epoch+1 || next.Recovery.Attempts != 1 || !reflect.DeepEqual(next.Recovery.AvoidPaths, []string{"direct"}) || len(next.Recovery.Excluded) != 0 {
		t.Fatalf("path recovery changed accepted layout: old=%+v new=%+v", f.plan, next)
	}
	for _, leg := range next.Transfer.Legs {
		if leg.Path != string(peerhttp.PathRelay) {
			t.Fatalf("direct leg survived path recovery: %+v", next.Transfer.Legs)
		}
	}
	if retired, err := f.store.ListRetirements(); err != nil || len(retired) != 0 {
		t.Fatalf("path recovery queued retirement: %+v %v", retired, err)
	}
	replay := req
	replay.FailedNodes = []uint64{}
	var replayed types.PlanWriteChunkResponse
	if rec := f.post(t, "/writes/chunks/recover", f.features, replay, &replayed); rec.Code != http.StatusOK || replayed.Plan.Layout.Epoch != next.Layout.Epoch || replayed.Plan.Recovery.Attempts != next.Recovery.Attempts {
		t.Fatalf("normalized replay changed recovery: status=%d old=%+v replay=%+v", rec.Code, next, replayed.Plan)
	}
}

func TestWritePathRecoveryHTTPWithoutCircuitDoesNotConsumeAttempt(t *testing.T) {
	f := newWritePathRecoveryHTTPFixture(t)
	req := f.recoveryRequest(peerhttp.PathDirect, "missing-circuit")
	if rec := f.post(t, "/writes/chunks/recover", f.features, req, nil); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("direct-only recovery status=%d body=%s", rec.Code, rec.Body.String())
	}
	current, err := f.store.GetPlannedWrite(meta.WriteActor{}, types.WriteBinding{UploadID: f.upload.ID, PlanID: f.upload.PlanID, Revision: f.upload.Revision}, time.Now())
	if err != nil || current.Chunks[0].Layout.Epoch != f.plan.Layout.Epoch || current.Chunks[0].Recovery.Attempts != 0 {
		t.Fatalf("failed path recovery consumed an attempt: %+v %v", current, err)
	}
	if retired, _ := f.store.ListRetirements(); len(retired) != 0 {
		t.Fatalf("failed path recovery queued retirement: %+v", retired)
	}
}
