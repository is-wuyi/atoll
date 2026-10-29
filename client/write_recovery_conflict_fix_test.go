package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"reflect"
	"testing"

	"atoll/pkg/types"
)

func TestRecoverWritePlanRetriesOnlySnapshotConflict(t *testing.T) {
	for _, tc := range []struct {
		code     string
		expected int
	}{{types.WriteRecoveryRetry, 2}, {types.WritePlanConflict, 1}, {types.WriteNotReady, 1}} {
		t.Run(tc.code, func(t *testing.T) {
			c := New("http://master.test")
			var requests [][]byte
			c.HTTP.Transport = plannedTestTransport(func(req *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				req.Body.Close()
				requests = append(requests, raw)
				if len(requests) == 1 || tc.code != types.WriteRecoveryRetry {
					return &http.Response{StatusCode: http.StatusConflict, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(`{"code":"` + tc.code + `","error":"injected"}`)), Request: req}, nil
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(`{}`)), Request: req}, nil
			})
			req := types.RecoverWriteChunkRequest{WriteBinding: types.WriteBinding{UploadID: types.StagingInodeBase + 7, PlanID: "same-plan", Revision: 1}, Index: 0, ExpectedEpoch: 1, OpID: "same-operation", FailedNodes: []uint64{1}}
			var result types.PlanWriteChunkResponse
			err := c.recoverWritePlan(context.Background(), req, &result)
			if len(requests) != tc.expected || (tc.code == types.WriteRecoveryRetry) != (err == nil) {
				t.Fatalf("retry classification: requests=%d err=%v", len(requests), err)
			}
			if len(requests) > 1 && !reflect.DeepEqual(requests[0], requests[1]) {
				t.Fatal("snapshot retry changed operation binding")
			}
		})
	}
}
