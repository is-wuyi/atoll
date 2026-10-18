package master

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

func TestAutonomyAdminWriteRoutesRequireAdminToken(t *testing.T) {
	s := ieNewStack(t)
	s.srv.SetToken(auth.Token("cluster"))
	s.srv.SetAdminToken(auth.Token("admin"))
	a, err := NewAutonomy(s.store, time.Hour, AutonomyConfig{Mode: AutonomyObserve})
	if err != nil {
		t.Fatal(err)
	}
	s.srv.SetAutonomy(a)
	handler := s.srv.Handler()
	for _, path := range []string{"/admin/autonomy/step", "/admin/autonomy/profile", "/admin/autonomy/cancel"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer cluster")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("cluster key could mutate %s: %d", path, res.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/autonomy/step", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer admin")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("admin step: %d %s", res.Code, res.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/autonomy", nil)
	req.Header.Set("Authorization", "Bearer cluster")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status read: %d", res.Code)
	}
	var out struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil || !out.Enabled {
		t.Fatalf("bad status: %s %v", res.Body.String(), err)
	}
}

func TestAutonomyOffDoesNotExposeExecution(t *testing.T) {
	s := ieNewStack(t)
	for _, tc := range []struct {
		method, path string
		status       int
	}{{http.MethodGet, "/admin/autonomy", http.StatusOK}, {http.MethodPost, "/admin/autonomy/step", http.StatusConflict}} {
		res := httptest.NewRecorder()
		s.srv.Handler().ServeHTTP(res, httptest.NewRequest(tc.method, tc.path, nil))
		if res.Code != tc.status {
			t.Fatalf("%s: status %d", tc.path, res.Code)
		}
	}
}

func TestAutonomyObservationHistoryAndShadowNoTransfer(t *testing.T) {
	s := ieNewStack(t)
	s.startMaster()
	first := s.startNode()
	second := s.startNode()
	for _, n := range []*ieNode{first, second} {
		if err := s.store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: n.Info.ID, FailureDomains: map[string]string{"site": n.Addr}}); err != nil {
			t.Fatal(err)
		}
	}
	body := []byte("shadow must not create physical copies")
	in := iePublishSmall(t, s, "/shadow", body, 1, false)
	before := ieWaitDone(t, s, in.ObjID, 1)
	a, err := NewAutonomy(s.store, time.Hour, AutonomyConfig{Mode: AutonomyShadow, MaxReplicas: 2})
	if err != nil {
		t.Fatal(err)
	}
	report, err := a.Step(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Dispatched != 0 || report.ObservedNodes != 2 {
		t.Fatalf("shadow dispatch: %+v", report)
	}
	snapshot, err := s.store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Plans) != 0 || len(snapshot.Observations) != 2 {
		t.Fatalf("shadow mutated plans: %+v", snapshot)
	}
	for _, o := range snapshot.Observations {
		if len(o.Samples) != 1 || !o.Samples[0].Online {
			t.Fatalf("observation not captured: %+v", o)
		}
	}
	after, _ := s.store.ObjectIntegrity(in.ObjID)
	if len(after.Replicas) != 1 || after.Replicas[0] != before.Replicas[0] {
		t.Fatalf("shadow changed replicas: %+v", after)
	}
	for _, n := range []*ieNode{first, second} {
		status, got := ieGetObject(t, n, in.ObjID)
		if n.Info.ID == before.Replicas[0] {
			if status != 200 || !bytes.Equal(got, body) {
				t.Fatal("source changed")
			}
		} else if status != 404 {
			t.Fatalf("shadow transferred data to %d", n.Info.ID)
		}
	}
}

func TestAdditiveScannerDoesNotReplaceOfflinePositions(t *testing.T) {
	s := ieNewStack(t)
	for _, addr := range []string{"one:9421", "two:9421", "three:9421"} {
		if _, err := s.store.RegisterNode(addr, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	in, err := s.store.CreateFile(meta.RootID, "legacy", []uint64{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpdateFileSize(in.ID, 10, 123); err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(s.store, time.Hour, time.Hour, time.Hour)
	scanner.SetAdditiveOnly(true)
	scanner.executeRepair(repairTask{Action: repairReplaceDead, InodeID: in.ID, OldNodeID: 2, NewNodeID: 3, SourceAddr: "127.0.0.1:1"})
	got, _ := s.store.GetInode(in.ID)
	if len(got.Replicas) != 2 || got.Replicas[1] != 2 {
		t.Fatalf("old scanner dropped an offline holder: %+v", got)
	}
	st, err := s.store.CreateStagingFile(meta.RootID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.store.AssignChunk(st.ID, 0, 10, []uint64{1, 2}, 123)
	if err != nil {
		t.Fatal(err)
	}
	scanner.executeChunkRepair(types.ChunkObjID(c, st.ID), st.ID, 0, repairTask{Action: repairReplaceDead, OldNodeID: 2, NewNodeID: 3, SourceAddr: "127.0.0.1:1"})
	got, _ = s.store.GetInode(st.ID)
	if len(got.Chunks[0].Replicas) != 2 || got.Chunks[0].Replicas[1] != 2 {
		t.Fatalf("old chunk scanner replaced an offline holder: %+v", got)
	}
}

func TestAutonomyRepeatedTicksRespectInFlightLeaseLimit(t *testing.T) {
	s := ieNewStack(t)
	now := time.Now()
	plans := []meta.ProtectionPlan{{ID: "lease", State: meta.ProtectionPending, Targets: []meta.ProtectionTarget{{NodeID: 7, Attempts: 1, NextAttempt: now.Add(time.Minute)}}},
		{ID: "must-not-be-claimed", State: meta.ProtectionPending}}
	a, err := NewAutonomy(s.store, time.Hour, AutonomyConfig{Mode: AutonomyAdd, MaxDispatchPerTick: 1})
	if err != nil {
		t.Fatal(err)
	}
	count, err := a.executePendingLimit(context.Background(), plans, now, 1)
	if err != nil || count != 0 {
		t.Fatalf("in-flight plan did not consume slot: %d %v", count, err)
	}
}
