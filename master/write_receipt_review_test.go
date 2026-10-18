package master

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestWritePlanningDeviceCannotConfirmAnotherNode(t *testing.T) {
	cl := newGuardCluster(t)
	if err := cl.srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 2}); err != nil {
		t.Fatal(err)
	}
	cl.srv.SetHealthProbe(func(string) bool { return true })
	userToken, _, space := cl.guardUser("receiptowner")
	tokenA, nodeA := cl.guardDevice("127.0.0.1:58091")
	tokenB, nodeB := cl.guardDevice("127.0.0.1:58092")
	headers := map[string]string{types.FeaturesHeader: types.WritePlanFeature}
	status, _, raw := cl.guardDo(http.MethodPost, "/writes", userToken, space.ID, headers, types.BeginWriteRequest{Path: "/file", OpID: "begin-receipt", Size: 4})
	if status != http.StatusCreated {
		t.Fatalf("begin: %d %s", status, raw)
	}
	var begin types.BeginWriteResponse
	if err := json.Unmarshal(raw, &begin); err != nil {
		t.Fatal(err)
	}
	binding := types.WriteBinding{UploadID: begin.Upload.ID, PlanID: begin.Upload.PlanID, Revision: 1}
	chunkReq := types.PlanWriteChunkRequest{WriteBinding: binding, Index: 0, LogicalSize: 4, StoredSize: 4, Encoding: types.PlainEncoding, Checksum: types.CRC32C([]byte("test"))}
	status, _, raw = cl.guardDo(http.MethodPost, "/writes/chunks", userToken, space.ID, headers, chunkReq)
	if status != http.StatusOK {
		t.Fatalf("plan: %d %s", status, raw)
	}
	var plan types.PlanWriteChunkResponse
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	d, err := cl.store.ObjectIntegrity(plan.Plan.Object.ID)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"object": d, "node_id": nodeB, "usage": types.NodeUsage{Epoch: "receipt", Sequence: 1, UsedBytes: 4}}
	status, _, raw = cl.guardDo(http.MethodPost, "/files/replicated/verified", tokenA, 0, nil, body)
	if status != http.StatusForbidden {
		t.Fatalf("node %d forged receipt for %d: %d %s", nodeA, nodeB, status, raw)
	}
	if after, err := cl.store.ObjectIntegrity(d.ObjectID); err != nil || len(after.Done) != 0 {
		t.Fatalf("forged receipt changed Done: %+v %v", after, err)
	}
	for _, token := range []string{userToken, guardControlToken} {
		status, _, raw = cl.guardDo(http.MethodPost, "/files/replicated/verified", token, space.ID, nil, body)
		if status != http.StatusForbidden {
			t.Fatalf("non-device confirmed: %d %s", status, raw)
		}
	}
	ownToken := tokenB
	if !types.ContainsUint64(d.Replicas, nodeB) {
		body["node_id"] = nodeA
		ownToken = tokenA
	}
	status, _, raw = cl.guardDo(http.MethodPost, "/files/replicated/verified", ownToken, 0, nil, body)
	if status != http.StatusOK {
		t.Fatalf("valid content-bound device receipt rejected: %d %s", status, raw)
	}
	if err := cl.store.SetNodeHeartbeatAt(body["node_id"].(uint64), time.Now()); err != nil {
		t.Fatal(err)
	}
	status, _, raw = cl.guardDo(http.MethodPost, "/writes/abort", userToken, space.ID, headers, binding)
	if status != http.StatusOK {
		t.Fatalf("abort: %d %s", status, raw)
	}
	status, _, raw = cl.guardDo(http.MethodPost, "/files/replicated/verified", ownToken, 0, nil, body)
	if status >= 200 && status < 300 {
		t.Fatalf("late receipt after abort accepted: %d %s", status, bytes.TrimSpace(raw))
	}
}
