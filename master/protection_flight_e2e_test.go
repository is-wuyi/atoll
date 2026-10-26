package master

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"atoll/internal/scheduler"
	"atoll/master/meta"
	atollnode "atoll/node"
	"atoll/pkg/access"
	"atoll/pkg/types"
)

func TestProtectionFlightE2ESlowPayloadCrossesInitialLease(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "slow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := NewServer(store, time.Hour)
	cfg := AutonomyConfig{Mode: AutonomyAdd, ProtectionFeedback: true, RetryInterval: 25 * time.Second, LeaseRenewWindow: 30 * time.Second, MaxLeaseRenewals: 4, MaxLeaseTotalTime: 3 * time.Minute}
	aut, err := NewAutonomy(store, time.Hour, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetAutonomy(aut)
	master := httptest.NewServer(srv.Handler())
	defer master.Close()
	payload := bytes.Repeat([]byte("slow-but-making-real-progress\n"), 160)
	var gets atomic.Int64
	var sourceID uint64
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/objects/") {
			http.NotFound(w, r)
			return
		}
		gets.Add(1)
		if r.Header.Get(access.PlanAttemptHeader) != "1" || r.Header.Get(access.PlanAttemptTokenHeader) == "" {
			t.Errorf("attempt identity missing from GET")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for offset := 0; offset < len(payload); offset += 128 {
			end := min(offset+128, len(payload))
			if _, err := w.Write(payload[offset:end]); err != nil {
				return
			}
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
		}
	}))
	defer source.Close()
	info, err := store.RegisterNode(source.Listener.Addr().String(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	sourceID = info.ID
	targetNode := atollnode.New(t.TempDir(), master.URL, "", 1<<20)
	target := httptest.NewServer(targetNode.Handler())
	defer target.Close()
	targetInfo, err := store.RegisterNode(target.Listener.Addr().String(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	targetNode.SetNodeIDForTest(targetInfo.ID)
	for _, id := range []uint64{sourceID, targetInfo.ID} {
		if err := store.Heartbeat(id, 0); err != nil {
			t.Fatal(err)
		}
		if err := store.SetNodePlacementProfile(meta.NodePlacementProfile{NodeID: id, FailureDomains: map[string]string{"site": "isolated"}}); err != nil {
			t.Fatal(err)
		}
	}
	obj, _, err := store.PrepareSmallFile(meta.SmallFileTarget{ParentID: meta.RootID, Name: "slow", Size: int64(len(payload)), Checksum: types.CRC32C(payload), Replicas: []uint64{sourceID}, PrimaryID: sourceID, Mtime: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := store.CommitSmallFile(obj.ID); err != nil {
		t.Fatal(err)
	}
	d, err := store.ObjectIntegrity(obj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if marked, err := store.MarkVerifiedObjectDone(d, sourceID); err != nil || !marked {
		t.Fatalf("source receipt: %v %v", marked, err)
	}
	d, _ = store.ObjectIntegrity(obj.ID)
	snapshot, _ := store.AutonomySnapshot()
	plan, err := store.ReserveProtection(meta.ProtectionRequest{ID: "slow-flight", Expected: d, Targets: []uint64{targetInfo.ID}, MaxBytes: d.Size, NodeMaxAge: time.Hour, ProfileRevision: snapshot.ProfileRevision}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claimedPlan, claimed, err := store.ClaimProtectionTarget(plan.ID, time.Now(), cfg.RetryInterval, meta.ProtectionExecutionBudget{MaxConcurrent: 2, MaxBytes: d.Size, MaxTotalLease: cfg.MaxLeaseTotalTime})
	if err != nil || claimed == nil {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	initialDeadline := claimed.NextAttempt
	if err := aut.executeTarget(context.Background(), claimedPlan, *claimed); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(90 * time.Second)
	var final meta.ProtectionPlan
	for time.Now().Before(deadline) {
		final, err = store.ProtectionPlan(plan.ID)
		if err != nil {
			t.Fatal(err)
		}
		if final.State == meta.ProtectionCompleted {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if final.State != meta.ProtectionCompleted || final.Targets[0].Attempts != 1 || final.Targets[0].Renewals == 0 || gets.Load() != 1 {
		t.Fatalf("slow flight did not finish in one renewed attempt: %+v GETs=%d", final, gets.Load())
	}
	if time.Now().Before(initialDeadline) {
		t.Fatal("test never crossed initial lease")
	}
	resp, err := http.Get(target.URL + "/objects/" + jsonNumber(obj.ID))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("stored payload mismatch: %d %v", len(got), err)
	}
	links := srv.transferObservationsAt(time.Now())
	found := false
	for _, link := range links {
		found = found || link.From == jsonNumber(sourceID) && link.To == jsonNumber(targetInfo.ID) && link.Path == scheduler.TransferHTTP && link.ThroughputBPS > 0
	}
	if !found {
		t.Fatalf("actual goodput never entered directional observations: %+v", links)
	}
}

func jsonNumber(id uint64) string {
	b, _ := json.Marshal(id)
	return string(b)
}
