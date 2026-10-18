package meta

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestWriteUsagePreventsPostCommitCapacityReuse(t *testing.T) {
	for _, withUsage := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-node", true: "sequenced-node"}[withUsage], func(t *testing.T) {
			s, nodes := writeTestStore(t)
			if err := s.Heartbeat(nodes[0], 800); err != nil {
				t.Fatal(err)
			}
			u := beginWriteTest(t, s, RootID, "first", 150, false)
			p := reserveWriteTest(t, s, u, make([]byte, 150), nodes[:1], nodes[:1])
			d, err := s.ObjectIntegrity(p.Object.ID)
			if err != nil {
				t.Fatal(err)
			}
			var usage *types.NodeUsage
			if withUsage {
				usage = &types.NodeUsage{Epoch: "boot-a", Sequence: 10, UsedBytes: 950}
			}
			if ok, err := s.MarkVerifiedObjectDoneWithUsage(d, nodes[0], usage); err != nil || !ok {
				t.Fatalf("receipt %v %v", ok, err)
			}
			if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(u, 150, 1), time.Hour, time.Now()); err != nil {
				t.Fatal(err)
			}
			snap, err := s.AutonomySnapshot()
			if err != nil {
				t.Fatal(err)
			}
			if snap.Capacity[0].Free != 74 {
				t.Fatalf("commit freed recent bytes: %+v", snap.Capacity[0])
			}
			if withUsage {
				if err = s.HeartbeatWithUsage(nodes[0], 800, &types.NodeUsage{Epoch: "boot-a", Sequence: 9, UsedBytes: 800}); err != nil {
					t.Fatal(err)
				}
				snap, err = s.AutonomySnapshot()
				if err != nil || snap.Capacity[0].Free != 74 {
					t.Fatalf("old heartbeat replaced receipt usage: %+v %v", snap.Capacity, err)
				}
			}
			v := beginWriteTest(t, s, RootID, "second", 100, false)
			req, choice := writeChoice(v, 0, make([]byte, 100), nodes[:1], nodes[:1])
			if _, _, err = s.ReserveWriteChunk(WriteActor{}, req, choice, 0, time.Hour, time.Now()); !errors.Is(err, ErrWriteBudget) {
				t.Fatalf("second write oversold node: %v", err)
			}
		})
	}
}

func TestWriteUsageFloorSurvivesWALRecovery(t *testing.T) {
	s, nodes := writeTestStore(t)
	n := nodes[0]
	for _, usage := range []types.NodeUsage{
		{Epoch: "boot-a", Sequence: 1, UsedBytes: 800},
		{Epoch: "boot-a", Sequence: 2, UsedBytes: 950},
		{Epoch: "boot-b", Sequence: 1, UsedBytes: 950},
		{Epoch: "boot-a", Sequence: 1, UsedBytes: 800},
	} {
		if err := s.HeartbeatWithUsage(n, usage.UsedBytes, &usage); err != nil {
			t.Fatal(err)
		}
	}
	frames, err := s.FramesSince(0)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Open(filepath.Join(t.TempDir(), "usage-recovered.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatal(err)
	}
	node, err := restored.GetNode(n)
	if err != nil || node.UsageFloorBytes != 950 {
		t.Fatalf("lost usage floor after recovery: %+v %v", node, err)
	}
	for _, usage := range []types.NodeUsage{
		{Epoch: "boot-a", Sequence: 3, UsedBytes: 800},
		{Epoch: "boot-c", Sequence: 1, UsedBytes: 0},
	} {
		if err := restored.HeartbeatWithUsage(n, usage.UsedBytes, &usage); err != nil {
			t.Fatal(err)
		}
		if cap := capacityFor(t, restored, n); cap.Free > 74 {
			t.Fatalf("usage floor released by unproven sample: %+v", cap)
		}
	}
	if err := restored.Heartbeat(n, 0); err != nil {
		t.Fatal(err)
	}
	if cap := capacityFor(t, restored, n); cap.Free > 74 {
		t.Fatalf("unsequenced heartbeat released floor: %+v", cap)
	}
}

func TestWriteUsageReplayMismatchAndEpoch(t *testing.T) {
	s, nodes := writeTestStore(t)
	u := beginWriteTest(t, s, RootID, "file", 3, false)
	p := reserveWriteTest(t, s, u, []byte("abc"), nodes[:1], nodes[:1])
	d, _ := s.ObjectIntegrity(p.Object.ID)
	usage := types.NodeUsage{Epoch: "epoch-one", Sequence: 5, UsedBytes: 3}
	if _, err := s.MarkVerifiedObjectDoneWithUsage(d, nodes[0], &usage); err != nil {
		t.Fatal(err)
	}
	if err := s.HeartbeatWithUsage(nodes[0], 2, &types.NodeUsage{Epoch: "epoch-one", Sequence: 5, UsedBytes: 2}); !errors.Is(err, ErrWritePlanConflict) {
		t.Fatal("equal sequence changed used bytes")
	}
	if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(u, 3, 1), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.HeartbeatWithUsage(nodes[0], 3, &types.NodeUsage{Epoch: "epoch-two", Sequence: 1, UsedBytes: 3}); err != nil {
		t.Fatal(err)
	}
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Capacity[0].Reserved != 3 {
		t.Fatal("new process epoch incorrectly proved old receipt inclusion")
	}
}
