package node

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestPullMetadataFailureReportsDispatchedAttempt(t *testing.T) {
	reports := make(chan types.ProtectionProgress, 1)
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/files/replication" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/files/protection/progress" {
			var report types.ProtectionProgress
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Error(err)
			}
			reports <- report
			json.NewEncoder(w).Encode(types.ProtectionProgressResult{Recorded: true})
		}
	}))
	defer master.Close()
	n := New(t.TempDir(), master.URL, "", 1<<20)
	n.SetNodeIDForTest(7)
	d := types.ObjectIntegrity{ObjectID: 900, PlanID: "p", PlanAttempt: 2, PlanAttemptToken: "dispatched-token", Generation: 3, IntegrityEpoch: 4}
	n.pullObject(d.ObjectID, "127.0.0.1:1", 0, d.PlanID, d.PlanAttempt, &d)
	select {
	case report := <-reports:
		if report.AttemptToken != d.PlanAttemptToken || report.FailureKind != "failed" || report.ObjectID != d.ObjectID || report.BytesDone != 0 {
			t.Fatalf("bad metadata failure feedback: %+v", report)
		}
	default:
		t.Fatal("metadata failure invisible to master")
	}
}

func TestPullDeferDoesNotCancelUnexpiredLease(t *testing.T) {
	var count atomic.Int64
	until, hard := time.Now().Add(time.Minute), time.Now().Add(2*time.Minute)
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		io.Copy(io.Discard, r.Body)
		json.NewEncoder(w).Encode(types.ProtectionProgressResult{Recorded: true, Action: "defer", LeaseUntil: until, HardUntil: hard})
	}))
	defer master.Close()
	n := New(t.TempDir(), master.URL, "", 1<<20)
	n.SetNodeIDForTest(7)
	old := progressReportInterval
	progressReportInterval = 10 * time.Millisecond
	defer func() { progressReportInterval = old }()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	counter := &progressCounter{}
	counter.Write(bytes.Repeat([]byte("x"), 10))
	lease := newPullLease(until, hard, time.Minute, counter, cancel)
	stop, done := make(chan struct{}), make(chan struct{})
	d := types.ObjectIntegrity{ObjectID: 900, PlanID: "p", PlanAttempt: 2, PlanAttemptToken: "t"}
	go func() { defer close(done); n.progressLoopFor(ctx, stop, d, counter, lease) }()
	deadline := time.Now().Add(time.Second)
	for count.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	<-done
	if count.Load() < 2 || ctx.Err() != nil {
		t.Fatalf("defer killed a still-authorized stream: reports=%d cause=%v", count.Load(), context.Cause(ctx))
	}
}
