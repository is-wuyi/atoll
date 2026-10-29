package node

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"atoll/pkg/types"
)

func TestRecoveryRegressionPublishedCopyDoesNotRequireUploadProgressRegistration(t *testing.T) {
	data := []byte("copy after the file was committed")
	objectID := recoveryChunkID(23)
	var beginCalls atomic.Int32
	var receipts atomic.Int32
	plan := recoveryPlan(objectID, data, 1)
	plan.WriteProgress = nil
	plan.Object.Generation = 1
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/files/replication":
			json.NewEncoder(w).Encode(plan)
		case "/files/writes/progress/begin":
			beginCalls.Add(1)
			http.Error(w, "write is committed", http.StatusConflict)
		case "/files/replicated/verified":
			receipts.Add(1)
			io.WriteString(w, `{"marked":true}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	defer master.Close()
	n := New(t.TempDir(), master.URL, "", 1<<20)
	n.SetNodeIDForTest(2)
	srv := httptest.NewServer(n.Handler())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/replicate/"+strconv.FormatUint(objectID, 10), bytes.NewReader(data))
	req.Header.Set(types.WriteEpochHeader, "1")
	req.Header.Set(types.WriteAttemptHeader, "00000000000000000000000000000001")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || beginCalls.Load() != 0 || receipts.Load() != 1 {
		t.Fatalf("committed copy tied to pending-upload progress: status=%d begin=%d receipts=%d", resp.StatusCode, beginCalls.Load(), receipts.Load())
	}
}
