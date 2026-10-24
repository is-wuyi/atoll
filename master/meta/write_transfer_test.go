package meta

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func TestWriteTransferBudgetPersistsAndRejectsOversubscription(t *testing.T) {
	s, nodes := writeTestStore(t)
	if err := s.EnableTransferPlanning(); err != nil {
		t.Fatal(err)
	}
	for _, id := range nodes {
		if err := s.SetNodePlacementProfile(NodePlacementProfile{NodeID: id, UploadBPS: 1000, DownloadBPS: 2000, MaxTransferConcurrency: 4}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range nodes {
		if err := s.Heartbeat(id, 0); err != nil {
			t.Fatal(err)
		}
		if err := s.db.Update(func(tx *bolt.Tx) error {
			var node types.NodeInfo
			if err := json.Unmarshal(tx.Bucket(bucketNodes).Get(u64be(id)), &node); err != nil {
				return err
			}
			node.TotalBytes = 3 * types.ChunkSize
			raw, err := json.Marshal(node)
			if err != nil {
				return err
			}
			return tx.Bucket(bucketNodes).Put(u64be(id), raw)
		}); err != nil {
			t.Fatal(err)
		}
	}
	u := beginWriteTest(t, s, RootID, "budget", int64(2*types.ChunkSize), false)
	now := time.Now()
	planFor := func(index int) (types.PlanWriteChunkRequest, types.WriteChunkPlan) {
		req, plan := writeChoice(u, index, make([]byte, types.ChunkSize), nodes[:2], nodes[:2])
		plan.Transfer = &types.WriteTransferPlan{UploadTargets: []uint64{nodes[0]}, ExpiresAt: now.Add(time.Minute), Legs: []types.WriteTransferLeg{{ToNodeID: nodes[0], Path: "http", BPS: 2000}, {FromNodeID: nodes[0], ToNodeID: nodes[1], Path: "http", BPS: 1000}}}
		return req, plan
	}
	snapshot, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	req, plan := planFor(0)
	if _, _, err := s.ReserveWriteChunk(WriteActor{}, req, plan, snapshot.ProfileRevision, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	req2, plan2 := planFor(1)
	if _, _, err := s.ReserveWriteChunk(WriteActor{}, req2, plan2, snapshot.ProfileRevision, time.Hour, now); !errors.Is(err, ErrWriteBudget) {
		t.Fatalf("oversubscribed shared node: %v", err)
	}
	confirmWriteTest(t, s, plan.Object.ID, nodes[:2]...)
	if _, _, err := s.ReserveWriteChunk(WriteActor{}, req2, plan2, snapshot.ProfileRevision, time.Hour, now); err != nil {
		t.Fatalf("completed flow still held: %v", err)
	}
	got, err := s.GetPlannedWrite(WriteActor{}, writeBinding(u), now)
	if err != nil || len(got.Chunks) != 2 || got.Chunks[1].Transfer == nil || got.Chunks[1].RequiredConfirmations != 2 {
		t.Fatalf("persisted plan: %+v %v", got, err)
	}
	frames, err := s.FramesSince(0)
	if err != nil {
		t.Fatal(err)
	}
	restored := newTestStore(t)
	if err := restored.ApplyFrames(frames); err != nil {
		t.Fatal(err)
	}
	got, err = restored.GetPlannedWrite(WriteActor{}, writeBinding(u), now)
	if err != nil || len(got.Chunks) != 2 || got.Chunks[0].Transfer == nil {
		t.Fatalf("WAL lost routes: %+v %v", got, err)
	}
}

func TestWriteTransferStatusRequiresEveryNamedConfirmation(t *testing.T) {
	s, nodes := writeTestStore(t)
	u := beginWriteTest(t, s, RootID, "ready", 4, false)
	plan := reserveWriteTest(t, s, u, []byte("data"), nodes, nodes[:2])
	confirmWriteTest(t, s, plan.Object.ID, nodes[0], nodes[2])
	status, err := s.PlannedWriteStatus(WriteActor{}, writeBinding(u), time.Hour, time.Now())
	if err != nil || len(status.Chunks) != 1 || status.Chunks[0].Ready {
		t.Fatalf("wrong confirmation substituted: %+v %v", status, err)
	}
	confirmWriteTest(t, s, plan.Object.ID, nodes[1])
	status, err = s.PlannedWriteStatus(WriteActor{}, writeBinding(u), time.Hour, time.Now())
	if err != nil || !status.Chunks[0].Ready {
		t.Fatalf("confirmed status: %+v %v", status, err)
	}
}
