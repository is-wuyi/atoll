package master

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

func TestWriteTransferCapabilityAndRestartGates(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := NewServer(store, time.Minute)
	if err := srv.EnableWritePlanning(WritePlanningConfig{TransferPlanning: true}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/writes", strings.NewReader(`{"path":"/empty","op_id":"empty","size":0}`))
	r.Header.Set(types.FeaturesHeader, types.WritePlanFeature)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("old feature accepted %d", w.Code)
	}
	r.Header.Set(types.FeaturesHeader, types.WritePlanFeature+","+types.WriteTransferFeature)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("new feature denied %d %s", w.Code, w.Body)
	}
	restarted := NewServer(store, time.Minute)
	if err := restarted.EnableWritePlanning(WritePlanningConfig{}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	restarted.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/capabilities", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("omitted transfer flag downgraded %d", w.Code)
	}
}

func TestWriteTransferRejectsForgedAndStaleObservation(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := NewServer(store, time.Minute)
	if err := srv.EnableWritePlanning(WritePlanningConfig{TransferPlanning: true}); err != nil {
		t.Fatal(err)
	}
	a, err := store.RegisterNode("127.0.0.1:58101", 10000)
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.RegisterNode("127.0.0.1:58102", 10000)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, mode := range []string{"stale", "future", "unknown", "self", "bad-path"} {
		observation := types.TransferObservation{FromNodeID: a.ID, ToNodeID: b.ID, Path: "http", Available: true, ObservedAt: now}
		switch mode {
		case "stale":
			observation.ObservedAt = now.Add(-time.Hour)
		case "future":
			observation.ObservedAt = now.Add(time.Minute)
		case "unknown":
			observation.FromNodeID = 99999
		case "self":
			observation.ToNodeID = a.ID
		case "bad-path":
			observation.Path = "guess"
		}
		if err := srv.RecordTransferObservation(observation, now); err == nil {
			t.Fatalf("accepted %s", mode)
		}
	}
	if err := srv.RecordTransferObservation(types.TransferObservation{FromNodeID: a.ID, ToNodeID: b.ID, Path: "http", Available: true, ObservedAt: now}, now); err != nil {
		t.Fatal(err)
	}
}
