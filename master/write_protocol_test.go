package master

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

func TestWriteRequestJSONRejectsAmbiguity(t *testing.T) {
	for name, body := range map[string]string{
		"null":         `null`,
		"missing-size": `{"path":"/file","op_id":"id"}`,
		"null-size":    `{"path":"/file","op_id":"id","size":null}`,
		"duplicate":    `{"path":"/file","op_id":"id","size":0,"size":1}`,
		"case-alias":   `{"path":"/file","op_id":"id","size":0,"Size":1}`,
		"extra-value":  `{"path":"/file","op_id":"id","size":0} []`,
		"array":        `[]`,
		"unknown":      `{"path":"/file","op_id":"id","size":0,"min_copies":0}`,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/writes", strings.NewReader(body))
			var out types.BeginWriteRequest
			if err := decodeWriteJSON(httptest.NewRecorder(), req, &out); err == nil {
				t.Fatal("ambiguous request accepted")
			}
		})
	}
	valid := httptest.NewRequest(http.MethodPost, "/writes", strings.NewReader(`{"path":"/file","op_id":"id","size":0}`))
	var out types.BeginWriteRequest
	if err := decodeWriteJSON(httptest.NewRecorder(), valid, &out); err != nil {
		t.Fatal(err)
	}
	chunk := httptest.NewRequest(http.MethodPost, "/writes/chunks", strings.NewReader(`{"upload_id":4294967296,"plan_id":"id","revision":1,"index":0,"logical_size":4,"stored_size":4,"encoding":"plain-v1"}`))
	var plan types.PlanWriteChunkRequest
	if err := decodeWriteJSON(httptest.NewRecorder(), chunk, &plan); err == nil {
		t.Fatal("missing CRC confused with known CRC zero")
	}
}

func TestWritePlanningSnapshotProbeCancellation(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := NewServer(store, time.Hour)
	if err := srv.EnableWritePlanning(WritePlanningConfig{ProbeTimeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	started, stopped := make(chan struct{}), make(chan struct{})
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	defer node.Close()
	if _, err := store.RegisterNode(node.Listener.Addr().String(), 1024); err != nil {
		t.Fatal(err)
	}
	snap, err := store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := srv.newWriteSnapshot(ctx, snap, time.Now()); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("probe not started")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled snapshot accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled probe did not finish")
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("probe request not cancelled")
	}
}

func TestWritePlanningNoNodeEmptyAndRejectedContent(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := NewServer(store, time.Hour)
	if err := srv.EnableWritePlanning(WritePlanningConfig{}); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	call := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set(types.FeaturesHeader, types.WritePlanFeature)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := call("/writes", `{"path":"/empty","op_id":"empty","size":0}`)
	var begin types.BeginWriteResponse
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &begin) != nil {
		t.Fatalf("begin=%d %s", w.Code, w.Body)
	}
	b := types.WriteBinding{UploadID: begin.Upload.ID, PlanID: begin.Upload.PlanID, Revision: 1}
	body, _ := json.Marshal(types.CommitWriteRequest{WriteBinding: b, OpID: "empty-commit", Size: 0, ChunkCount: 0})
	if w := call("/writes/commit", string(body)); w.Code != 200 {
		t.Fatalf("empty commit=%d %s", w.Code, w.Body)
	}
	w = call("/writes", `{"path":"/data","op_id":"data","size":1}`)
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &begin) != nil {
		t.Fatal(w.Code)
	}
	b = types.WriteBinding{UploadID: begin.Upload.ID, PlanID: begin.Upload.PlanID, Revision: 1}
	body, _ = json.Marshal(types.PlanWriteChunkRequest{WriteBinding: b, Index: 0, LogicalSize: 1, StoredSize: 1, Encoding: types.PlainEncoding, Checksum: 1})
	w = call("/writes/chunks", string(body))
	if w.Code != 422 {
		t.Fatalf("unfeasible content=%d %s", w.Code, w.Body)
	}
	if _, err := store.ResolvePath("/data"); err == nil {
		t.Fatal("unconfirmed content visible")
	}
}
