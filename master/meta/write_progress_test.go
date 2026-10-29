package meta

import (
	"errors"
	"testing"
	"time"
)

func TestWriteProgressIsHintAndOldEpochCannotRenewIt(t *testing.T) {
	s, nodes := writeTestStore(t)
	u, plan := recoveryFixture(t, s, nodes)
	now := time.Now()
	first := startProgressForTest(t, s, plan.Object.ID, nodes[1], 1, 0, "initial", now)
	first.Bytes = 16
	if err := s.RecordWriteProgress(first, now); err != nil {
		t.Fatal(err)
	}
	status, err := s.PlannedWriteStatus(WriteActor{}, writeBinding(u), time.Hour, now)
	if err != nil || len(status.Chunks) != 1 || status.Chunks[0].Ready || len(status.Chunks[0].Done) != 0 || len(status.Chunks[0].Progress) != 1 || status.Chunks[0].Progress[0].Bytes != 16 {
		t.Fatalf("progress became confirmation: %+v %v", status, err)
	}
	first.Bytes = 8
	if err := s.RecordWriteProgress(first, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	status, err = s.PlannedWriteStatus(WriteActor{}, writeBinding(u), time.Hour, now.Add(time.Second))
	if err != nil || status.Chunks[0].Progress[0].Bytes != 16 || !status.Chunks[0].Progress[0].UpdatedAt.Equal(now) {
		t.Fatalf("regressed bytes refreshed progress: %+v %v", status, err)
	}
	req, choice := recoveredChoice(u, plan, nodes[1], nodes[2])
	if _, _, err := s.RecoverWriteChunk(WriteActor{}, req, plan, choice, 0, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	first.Bytes = 32
	if err := s.RecordWriteProgress(first, time.Now()); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("old epoch progress survived reassignment: %v", err)
	}
	fresh := startProgressForTest(t, s, plan.Object.ID, nodes[2], 2, 0, "reassigned", time.Now())
	fresh.Bytes = 32
	if err := s.RecordWriteProgress(fresh, time.Now()); err != nil {
		t.Fatal(err)
	}
	status, err = s.PlannedWriteStatus(WriteActor{}, writeBinding(u), time.Hour, time.Now())
	if err != nil || len(status.Chunks[0].Progress) != 1 || status.Chunks[0].Progress[0].NodeID != nodes[2] || status.Chunks[0].Ready {
		t.Fatalf("new epoch progress: %+v %v", status, err)
	}
	if c := capacityFor(t, s, nodes[2]); c.Reserved != 64 {
		t.Fatalf("progress released storage reservation: %+v", c)
	}
	fresh.Bytes = 65
	if err := s.RecordWriteProgress(fresh, time.Now()); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatalf("oversize progress accepted: %v", err)
	}
}
