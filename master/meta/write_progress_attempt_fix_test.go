package meta

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/types"
)

func startProgressForTest(t *testing.T, s *Store, object, node, epoch, previous uint64, request string, now time.Time) types.WriteProgress {
	t.Helper()
	started, err := s.BeginWriteProgress(types.BeginWriteProgressRequest{ObjectID: object, NodeID: node, Epoch: epoch, ExpectedAttempt: previous, RequestID: request}, now)
	if err != nil {
		t.Fatal(err)
	}
	return types.WriteProgress{ObjectID: object, NodeID: node, Epoch: epoch, Attempt: started.Attempt, AttemptToken: started.AttemptToken}
}

func TestWriteProgressRejectsDelayedAttempt(t *testing.T) {
	s, nodes := writeTestStore(t)
	u, plan := recoveryFixture(t, s, nodes)
	now := time.Now()
	old := startProgressForTest(t, s, plan.Object.ID, nodes[1], 1, 0, "old-request", now)
	old.Bytes = 48
	if err := s.RecordWriteProgress(old, now); err != nil {
		t.Fatal(err)
	}
	newer := startProgressForTest(t, s, plan.Object.ID, nodes[1], 1, old.Attempt, "new-request", now.Add(time.Second))
	newer.Bytes = 8
	if err := s.RecordWriteProgress(newer, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := s.RecordWriteProgress(old, now.Add(time.Duration(i+2)*time.Second)); !errors.Is(err, ErrWritePlanConflict) {
			t.Fatalf("old report accepted: %v", err)
		}
		if err := s.RecordWriteProgress(newer, now.Add(time.Duration(i+2)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	status, err := s.PlannedWriteStatus(WriteActor{}, writeBinding(u), time.Hour, now.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	p := status.Chunks[0].Progress[0]
	if p.Attempt != newer.Attempt || p.Bytes != newer.Bytes || !p.UpdatedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("delayed/duplicate attempt refreshed progress: %+v", p)
	}
}

func TestWriteProgressRegistrationSurvivesWALAndClockRollback(t *testing.T) {
	s, nodes := writeTestStore(t)
	u, plan := recoveryFixture(t, s, nodes)
	now := time.Now()
	first := startProgressForTest(t, s, plan.Object.ID, nodes[0], 1, 0, "before-restart", now)
	first.Bytes = 16
	if err := s.RecordWriteProgress(first, now); err != nil {
		t.Fatal(err)
	}
	frames, err := s.FramesSince(0)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Open(filepath.Join(t.TempDir(), "restored.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatal(err)
	}
	if replay, err := restored.BeginWriteProgress(types.BeginWriteProgressRequest{ObjectID: plan.Object.ID, NodeID: nodes[0], Epoch: 1, RequestID: "before-restart"}, now.Add(-time.Second)); err != nil || replay.Attempt != first.Attempt || replay.AttemptToken != first.AttemptToken {
		t.Fatalf("attempt replay lost: %+v %v", replay, err)
	}
	second := startProgressForTest(t, restored, plan.Object.ID, nodes[0], 1, first.Attempt, "after-restart", now.Add(-time.Second))
	second.Bytes = 8
	if err := restored.RecordWriteProgress(second, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := restored.RecordWriteProgress(first, now.Add(time.Second)); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("old token survived restart: %v", err)
	}
	status, err := restored.PlannedWriteStatus(WriteActor{}, writeBinding(u), time.Hour, now)
	if err != nil || len(status.Chunks[0].Progress) != 1 || status.Chunks[0].Progress[0].Attempt != second.Attempt {
		t.Fatalf("new progress missing after clock rollback: %+v %v", status, err)
	}
}

func TestWriteProgressDuplicateCannotRenewAfterClockRollback(t *testing.T) {
	s, nodes := writeTestStore(t)
	u, plan := recoveryFixture(t, s, nodes)
	now := time.Now()
	first := startProgressForTest(t, s, plan.Object.ID, nodes[0], 1, 0, "first-clock", now)
	first.Bytes = 16
	if err := s.RecordWriteProgress(first, now); err != nil {
		t.Fatal(err)
	}
	second := startProgressForTest(t, s, plan.Object.ID, nodes[0], 1, first.Attempt, "second-clock", now.Add(-time.Second))
	second.Bytes = 8
	if err := s.RecordWriteProgress(second, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordWriteProgress(second, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	status, err := s.PlannedWriteStatus(WriteActor{}, writeBinding(u), time.Hour, now)
	if err != nil || status.Chunks[0].Progress[0].Attempt != second.Attempt || !status.Chunks[0].Progress[0].UpdatedAt.Equal(now.Add(-time.Second)) {
		t.Fatalf("duplicate refreshed progress: %+v %v", status, err)
	}
}

func TestWriteProgressStartCASAndNoZeroByteLiveness(t *testing.T) {
	s, nodes := writeTestStore(t)
	u, plan := recoveryFixture(t, s, nodes)
	now := time.Now()
	req := types.BeginWriteProgressRequest{ObjectID: plan.Object.ID, NodeID: nodes[0], Epoch: 1, ExpectedAttempt: 0, RequestID: "same-start"}
	first, err := s.BeginWriteProgress(req, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.BeginWriteProgress(req, now.Add(time.Second))
	if err != nil || first != second {
		t.Fatalf("lost begin reply consumed another attempt: %+v %+v %v", first, second, err)
	}
	bad := req
	bad.RequestID = "delayed-start"
	if _, err := s.BeginWriteProgress(bad, now.Add(2*time.Second)); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("stale CAS accepted: %v", err)
	}
	report := types.WriteProgress{ObjectID: req.ObjectID, NodeID: req.NodeID, Epoch: 1, Attempt: first.Attempt, AttemptToken: first.AttemptToken}
	if err := s.RecordWriteProgress(report, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	status, err := s.PlannedWriteStatus(WriteActor{}, writeBinding(u), time.Hour, now.Add(3*time.Second))
	if err != nil || len(status.Chunks[0].Progress) != 0 {
		t.Fatalf("begin/zero bytes created liveness: %+v %v", status, err)
	}
	report.Bytes = 16
	report.AttemptToken = "wp1_invalid_token_value"
	if err := s.RecordWriteProgress(report, now.Add(4*time.Second)); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("bad token accepted: %v", err)
	}
}
