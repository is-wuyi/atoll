package master

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"atoll/pkg/types"
)

func TestWriteProgressDeviceAuthorizationAndAttemptBinding(t *testing.T) {
	cl := newGuardCluster(t)
	if err := cl.srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 2}); err != nil {
		t.Fatal(err)
	}
	cl.srv.SetHealthProbe(func(string) bool { return true })
	userToken, _, space := cl.guardUser("progressowner")
	tokens := make(map[uint64]string)
	for _, addr := range []string{"127.0.0.1:58101", "127.0.0.1:58102", "127.0.0.1:58103"} {
		token, id := cl.guardDevice(addr)
		tokens[id] = token
	}
	headers := map[string]string{types.FeaturesHeader: types.WritePlanFeature + "," + types.WriteRecoveryFeature}
	status, _, raw := cl.guardDo(http.MethodPost, "/writes", userToken, space.ID, headers, types.BeginWriteRequest{Path: "/file", OpID: "begin-progress", Size: 64})
	guardExpect(t, "begin upload", status, http.StatusCreated, raw)
	var begin types.BeginWriteResponse
	if err := json.Unmarshal(raw, &begin); err != nil {
		t.Fatal(err)
	}
	binding := types.WriteBinding{UploadID: begin.Upload.ID, PlanID: begin.Upload.PlanID, Revision: begin.Upload.Revision}
	data := bytes.Repeat([]byte("p"), 64)
	status, _, raw = cl.guardDo(http.MethodPost, "/writes/chunks", userToken, space.ID, headers, types.PlanWriteChunkRequest{WriteBinding: binding, Index: 0, LogicalSize: 64, StoredSize: 64, Encoding: types.PlainEncoding, Checksum: types.CRC32C(data)})
	guardExpect(t, "plan chunk", status, http.StatusOK, raw)
	var planned types.PlanWriteChunkResponse
	if err := json.Unmarshal(raw, &planned); err != nil {
		t.Fatal(err)
	}
	if planned.Plan.Recovery == nil || len(planned.Plan.Layout.Nodes) == 0 {
		t.Fatalf("unexpected recovery layout: %+v", planned.Plan)
	}
	nodeID := planned.Plan.Layout.Nodes[0]
	var otherID, unassigned uint64
	for id := range tokens {
		if id != nodeID {
			otherID = id
		}
		if !types.ContainsUint64(planned.Plan.Layout.Nodes, id) {
			unassigned = id
		}
	}
	if unassigned == 0 {
		t.Fatal("fixture has no unassigned device")
	}
	start := types.BeginWriteProgressRequest{ObjectID: planned.Plan.Object.ID, NodeID: nodeID, Epoch: planned.Plan.Recovery.Epoch, RequestID: "00000000000000000000000000000001"}
	for _, feature := range []string{"write-recovery-v1", "write-recovery-v99"} {
		oldHeaders := map[string]string{types.FeaturesHeader: types.WritePlanFeature + "," + feature}
		recover := types.RecoverWriteChunkRequest{WriteBinding: binding, Index: 0, ExpectedEpoch: start.Epoch, OpID: "unsupported-recovery", FailedNodes: []uint64{nodeID}}
		status, _, raw = cl.guardDo(http.MethodPost, "/writes/chunks/recover", userToken, space.ID, oldHeaders, recover)
		guardExpect(t, "unsupported recovery feature", status, http.StatusUpgradeRequired, raw)
	}
	for _, token := range []string{userToken, guardControlToken, guardAdminToken} {
		status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress/begin", token, space.ID, nil, start)
		guardExpect(t, "non-device registration", status, http.StatusForbidden, raw)
	}
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress/begin", tokens[otherID], 0, nil, start)
	guardExpect(t, "registration claiming another node", status, http.StatusForbidden, raw)
	unassignedStart := start
	unassignedStart.NodeID = unassigned
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress/begin", tokens[unassigned], 0, nil, unassignedStart)
	guardExpect(t, "unassigned device registration", status, http.StatusConflict, raw)

	register := func(req types.BeginWriteProgressRequest) types.BeginWriteProgressResponse {
		t.Helper()
		status, _, raw := cl.guardDo(http.MethodPost, "/files/writes/progress/begin", tokens[nodeID], 0, nil, req)
		guardExpect(t, "device registration", status, http.StatusOK, raw)
		var response types.BeginWriteProgressResponse
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	first := register(start)
	if first.Attempt != 1 || !types.ValidRetirementToken(first.AttemptToken) || register(start) != first {
		t.Fatal("registration replay changed its sequence or token")
	}
	query := url.Values{"upload_id": {strconv.FormatUint(binding.UploadID, 10)}, "plan_id": {binding.PlanID}, "revision": {strconv.FormatUint(binding.Revision, 10)}}
	readStatus := func() types.WriteChunkStatus {
		t.Helper()
		status, _, raw := cl.guardDo(http.MethodGet, "/writes/status?"+query.Encode(), userToken, space.ID, headers, nil)
		guardExpect(t, "upload status", status, http.StatusOK, raw)
		var response types.WriteStatus
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatal(err)
		}
		if len(response.Chunks) != 1 {
			t.Fatalf("status omitted chunk: %+v", response)
		}
		return response.Chunks[0]
	}
	report := types.WriteProgress{ObjectID: start.ObjectID, NodeID: nodeID, Epoch: start.Epoch, Attempt: first.Attempt, AttemptToken: first.AttemptToken}
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress", tokens[nodeID], 0, nil, report)
	guardExpect(t, "zero-byte report", status, http.StatusOK, raw)
	if current := readStatus(); len(current.Progress) != 0 || current.Ready || len(current.Done) != 0 {
		t.Fatalf("registration or zero bytes became liveness or Done: %+v", current)
	}
	report.Bytes = 16
	for _, token := range []string{tokens[otherID], userToken, guardControlToken, guardAdminToken} {
		status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress", token, space.ID, nil, report)
		guardExpect(t, "unauthorized progress", status, http.StatusForbidden, raw)
	}
	forged := report
	forged.AttemptToken = "wp1_invalid_token_value"
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress", tokens[nodeID], 0, nil, forged)
	guardExpect(t, "invalid progress token", status, http.StatusConflict, raw)
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress", tokens[nodeID], 0, nil, report)
	guardExpect(t, "valid progress", status, http.StatusOK, raw)
	current := readStatus()
	if current.Ready || len(current.Done) != 0 || len(current.Progress) != 1 || current.Progress[0].RequestID != start.RequestID || current.Progress[0].Bytes != 16 {
		t.Fatalf("progress was lost or became Done: %+v", current)
	}
	updated := current.Progress[0].UpdatedAt
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress", tokens[nodeID], 0, nil, report)
	guardExpect(t, "duplicate progress", status, http.StatusOK, raw)
	if current := readStatus(); !current.Progress[0].UpdatedAt.Equal(updated) {
		t.Fatal("duplicate report renewed liveness")
	}

	nextStart := start
	nextStart.RequestID = "00000000000000000000000000000002"
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress/begin", tokens[nodeID], 0, nil, nextStart)
	guardExpect(t, "stale registration CAS", status, http.StatusConflict, raw)
	nextStart.ExpectedAttempt = first.Attempt
	second := register(nextStart)
	if second.Attempt != 2 || second.AttemptToken == first.AttemptToken {
		t.Fatal("new attempt reused the old sequence or token")
	}
	if current := readStatus(); len(current.Progress) != 0 {
		t.Fatal("old progress remained visible after a new registration")
	}
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress/begin", tokens[nodeID], 0, nil, start)
	guardExpect(t, "delayed old registration", status, http.StatusConflict, raw)
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress", tokens[nodeID], 0, nil, report)
	guardExpect(t, "delayed old progress", status, http.StatusConflict, raw)
	newReport := report
	newReport.Attempt, newReport.AttemptToken, newReport.Bytes = second.Attempt, second.AttemptToken, 8
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress", tokens[nodeID], 0, nil, newReport)
	guardExpect(t, "new attempt progress", status, http.StatusOK, raw)
	if current := readStatus(); len(current.Progress) != 1 || current.Progress[0].Attempt != 2 || current.Progress[0].RequestID != nextStart.RequestID || current.Progress[0].Bytes != 8 || current.Ready || len(current.Done) != 0 {
		t.Fatalf("attempt isolation failed: %+v", current)
	}
	status, _, raw = cl.guardDo(http.MethodPost, "/writes/abort", userToken, space.ID, headers, binding)
	guardExpect(t, "abort upload", status, http.StatusOK, raw)
	status, _, raw = cl.guardDo(http.MethodPost, "/files/writes/progress", tokens[nodeID], 0, nil, newReport)
	guardExpect(t, "progress after abort", status, http.StatusConflict, raw)
}
