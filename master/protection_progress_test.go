package master

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"atoll/master/meta"
)

// progressFixture：真实 store + server，预留并 claim 一个带 token 的目标。
func progressFixture(t *testing.T) (*Server, *meta.Store, meta.ProtectionPlan, *meta.ProtectionTarget) {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "progress.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.EnableProtectionFeedback(); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, time.Hour)
	var ids []uint64
	for i := 0; i < 3; i++ {
		node, err := store.RegisterNode(string(rune('a'+i))+":9421", 1000)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Heartbeat(node.ID, 0); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, node.ID)
	}
	obj, _, err := store.PrepareSmallFile(meta.SmallFileTarget{ParentID: meta.RootID, Name: "src", Size: 100, Checksum: 7, Replicas: ids[:2], PrimaryID: ids[0], Mtime: time.Now(), Overwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err = store.CommitSmallFile(obj.ID); err != nil {
		t.Fatal(err)
	}
	d, err := store.ObjectIntegrity(obj.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids[:2] {
		if ok, err := store.MarkVerifiedObjectDone(d, id); err != nil || !ok {
			t.Fatalf("source confirm %d: %v %v", id, ok, err)
		}
	}
	d, err = store.ObjectIntegrity(obj.ID)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := store.ReserveProtection(meta.ProtectionRequest{ID: "pg-plan", Expected: d, Targets: ids[2:], MaxBytes: d.Size, NodeMaxAge: time.Hour, ProfileRevision: snap.ProfileRevision, Reason: "progress http"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, target, err := store.ClaimProtectionTarget(plan.ID, time.Now(), time.Minute)
	if err != nil || target == nil {
		t.Fatalf("claim: %+v %v", target, err)
	}
	return srv, store, plan, target
}

func TestProtectionProgressEndpointRecordsAndRejects(t *testing.T) {
	srv, store, plan, target := progressFixture(t)
	h := srv.Handler()
	post := func(body map[string]any) int {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/files/protection/progress", bytes.NewReader(raw))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	good := map[string]any{"plan_id": plan.ID, "object_id": plan.Expected.ObjectID, "generation": plan.Expected.Generation, "integrity_epoch": plan.Expected.IntegrityEpoch, "node_id": target.NodeID, "attempt": target.Attempts, "attempt_token": target.AttemptToken, "bytes_done": 10, "goodput_bps": 5}
	if code := post(good); code != http.StatusOK {
		t.Fatalf("valid progress = %d", code)
	}
	// 缺字段 / 回退字节 / 旧 attempt 都 400，不静默采纳。
	if code := post(map[string]any{"plan_id": plan.ID}); code != http.StatusBadRequest {
		t.Fatalf("missing fields = %d", code)
	}
	regressed := map[string]any{"plan_id": plan.ID, "object_id": plan.Expected.ObjectID, "node_id": target.NodeID, "attempt": target.Attempts, "bytes_done": 5}
	if code := post(regressed); code != http.StatusBadRequest {
		t.Fatalf("regressed bytes = %d", code)
	}
	stale := map[string]any{"plan_id": plan.ID, "object_id": plan.Expected.ObjectID, "node_id": target.NodeID, "attempt": target.Attempts - 1, "bytes_done": 20}
	if code := post(stale); code != http.StatusBadRequest {
		t.Fatalf("stale attempt = %d", code)
	}
	got, err := store.ProtectionPlan(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Targets[0].ProgressBytes != 10 {
		t.Fatalf("progress not persisted: %+v", got.Targets[0])
	}
	// 失败类别收敛租约但不写 Done。
	fail := map[string]any{"plan_id": plan.ID, "object_id": plan.Expected.ObjectID, "generation": plan.Expected.Generation, "integrity_epoch": plan.Expected.IntegrityEpoch, "node_id": target.NodeID, "attempt": target.Attempts, "attempt_token": target.AttemptToken, "bytes_done": 10, "failure_kind": "failed", "message": "stalled"}
	if code := post(fail); code != http.StatusOK {
		t.Fatalf("failure report = %d", code)
	}
	got, err = store.ProtectionPlan(plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Targets[0].Done || got.Targets[0].FailureKind != "failed" {
		t.Fatalf("failure leaked done or kind: %+v", got.Targets[0])
	}
}
