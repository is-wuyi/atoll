package meta

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

// committed 未 Done 腿的低报反例：commit 允许 q<r，非 required 目标仍在飞；
// 若账只数 Pending，commit 后新 reserve 可与在飞腿叠加超 profile。

func completedTransferStore(t *testing.T) (*Store, []uint64, time.Time) {
	t.Helper()
	s, nodes := writeTestStore(t)
	if err := s.EnableTransferPlanning(); err != nil {
		t.Fatal(err)
	}
	for _, id := range nodes {
		if err := s.SetNodePlacementProfile(NodePlacementProfile{NodeID: id, UploadBPS: 10000, DownloadBPS: 10000, MaxTransferConcurrency: 8}); err != nil {
			t.Fatal(err)
		}
	}
	// nodes[2] 是慢的非 required 目标：下行预算仅够单腿。
	if err := s.SetNodePlacementProfile(NodePlacementProfile{NodeID: nodes[2], UploadBPS: 10000, DownloadBPS: 1500, MaxTransferConcurrency: 8}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
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
	return s, nodes, now
}

func reserveCommittedTransfer(t *testing.T, s *Store, name string, targets, confirms []uint64, legs []types.WriteTransferLeg, now time.Time) (types.WriteUpload, types.WriteChunkPlan, types.Inode) {
	t.Helper()
	data := make([]byte, 512)
	u := beginWriteTest(t, s, RootID, name, int64(len(data)), false)
	req, plan := writeChoice(u, 0, data, targets, confirms)
	plan.Transfer = &types.WriteTransferPlan{UploadTargets: []uint64{targets[0]}, ExpiresAt: now.Add(time.Minute), Legs: append([]types.WriteTransferLeg(nil), legs...)}
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := s.ReserveWriteChunk(WriteActor{}, req, plan, snap.ProfileRevision, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range confirms {
		confirmWriteTest(t, s, got.Object.ID, id)
	}
	inode, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(u, int64(len(data)), 1), time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	return u, got, inode
}

func reserveSingle(t *testing.T, s *Store, nodes []uint64, name string, target uint64, bps uint64, now time.Time) error {
	t.Helper()
	data := make([]byte, 512)
	u := beginWriteTest(t, s, RootID, name, int64(len(data)), false)
	req, plan := writeChoice(u, 0, data, []uint64{target}, []uint64{target})
	plan.Transfer = &types.WriteTransferPlan{UploadTargets: []uint64{target}, ExpiresAt: now.Add(time.Minute), Legs: []types.WriteTransferLeg{{ToNodeID: target, Path: "https", BPS: bps}}}
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.ReserveWriteChunk(WriteActor{}, req, plan, snap.ProfileRevision, time.Hour, now)
	return err
}

// T1: q<r commit 后非 required 目标未 Done 腿必须继续持有预算，新 reserve 拒绝叠加。
func TestWriteTransferCommittedUndoneLegHoldsBudget(t *testing.T) {
	s, nodes, now := completedTransferStore(t)
	_, plan, _ := reserveCommittedTransfer(t, s, "slow", nodes, nodes[:2], []types.WriteTransferLeg{
		{ToNodeID: nodes[0], Path: "https", BPS: 4000},
		{FromNodeID: nodes[0], ToNodeID: nodes[1], Path: "direct", BPS: 500},
		{FromNodeID: nodes[0], ToNodeID: nodes[2], Path: "direct", BPS: 1000},
	}, now)
	loads, err := s.WriteTransferLoads(now)
	if err != nil {
		t.Fatal(err)
	}
	if loads[nodes[2]] != (TransferLoad{DownloadBPS: 1000, Downloads: 1}) {
		t.Fatalf("committed un-Done leg must hold budget: nodes[2]=%+v", loads[nodes[2]])
	}
	if loads[nodes[0]] != (TransferLoad{UploadBPS: 1000, Uploads: 1}) {
		t.Fatalf("in-flight source must hold upload budget: nodes[0]=%+v", loads[nodes[0]])
	}
	if err := reserveSingle(t, s, nodes, "next", nodes[2], 600, now); !errors.Is(err, ErrWriteBudget) {
		t.Fatalf("new reserve must reject 1000+600>1500 over committed in-flight leg: %v", err)
	}
	confirmWriteTest(t, s, plan.Object.ID, nodes[2])
	if err := reserveSingle(t, s, nodes, "next", nodes[2], 600, now); err != nil {
		t.Fatalf("released leg must free budget for the same reserve: %v", err)
	}
}

// T6: 方向分账与 Done/Suspect 释放。
func TestWriteTransferLoadsDirections(t *testing.T) {
	s, nodes, now := completedTransferStore(t)
	data := make([]byte, 512)
	u := beginWriteTest(t, s, RootID, "dirs", int64(len(data)), false)
	req, plan := writeChoice(u, 0, data, nodes, nodes[:2])
	plan.Transfer = &types.WriteTransferPlan{UploadTargets: []uint64{nodes[0]}, ExpiresAt: now.Add(time.Minute), Legs: []types.WriteTransferLeg{
		{ToNodeID: nodes[0], Path: "https", BPS: 4000},
		{FromNodeID: nodes[0], ToNodeID: nodes[1], Path: "direct", BPS: 700},
		{FromNodeID: nodes[0], ToNodeID: nodes[2], Path: "direct", BPS: 900},
	}}
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReserveWriteChunk(WriteActor{}, req, plan, snap.ProfileRevision, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	loads, err := s.WriteTransferLoads(now)
	if err != nil {
		t.Fatal(err)
	}
	// client 腿只计入口下载；node 腿计源上行+目标下行。
	if loads[nodes[0]] != (TransferLoad{UploadBPS: 1600, Uploads: 2, DownloadBPS: 4000, Downloads: 1}) {
		t.Fatalf("ingress direction split: %+v", loads[nodes[0]])
	}
	if loads[nodes[1]] != (TransferLoad{DownloadBPS: 700, Downloads: 1}) {
		t.Fatalf("target download split: %+v", loads[nodes[1]])
	}
	if loads[nodes[2]] != (TransferLoad{DownloadBPS: 900, Downloads: 1}) {
		t.Fatalf("target download split: %+v", loads[nodes[2]])
	}
	confirmWriteTest(t, s, plan.Object.ID, nodes[0], nodes[1])
	inode, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(u, int64(len(data)), 1), time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	loads, err = s.WriteTransferLoads(now)
	if err != nil {
		t.Fatal(err)
	}
	if loads[nodes[0]] != (TransferLoad{UploadBPS: 900, Uploads: 1}) || loads[nodes[1]] != (TransferLoad{}) {
		t.Fatalf("confirmed targets must release their legs: n0=%+v n1=%+v", loads[nodes[0]], loads[nodes[1]])
	}
	if loads[nodes[2]] != (TransferLoad{DownloadBPS: 900, Downloads: 1}) {
		t.Fatalf("unconfirmed target must keep its hold: %+v", loads[nodes[2]])
	}
	confirmWriteTest(t, s, plan.Object.ID, nodes[2])
	if err := s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, inode.ID)
		if err != nil {
			return err
		}
		for i := range in.Chunks {
			if in.Chunks[i].ID == plan.Object.ID {
				in.Chunks[i].Suspect = []uint64{nodes[2]}
			}
		}
		return w.putInode(&in)
	}); err != nil {
		t.Fatal(err)
	}
	loads, err = s.WriteTransferLoads(now)
	if err != nil {
		t.Fatal(err)
	}
	if loads[nodes[2]] != (TransferLoad{DownloadBPS: 900, Downloads: 1}) || loads[nodes[0]] != (TransferLoad{UploadBPS: 900, Uploads: 1}) {
		t.Fatalf("Done+Suspect target must be held again: n0=%+v n2=%+v", loads[nodes[0]], loads[nodes[2]])
	}
}

// T2: 覆盖使 Result.ID 指向同 inode 的新对象；旧 plan 的 chunk 活块表找不到，
// 必须走 Result 快照 fallback，不报全局 error，且保守持有到 lease。
func TestWriteTransferCommittedOverwriteKeepsHoldUntilLease(t *testing.T) {
	s, nodes, now := completedTransferStore(t)
	reserveCommittedTransfer(t, s, "doc", nodes, nodes[:2], []types.WriteTransferLeg{
		{ToNodeID: nodes[0], Path: "https", BPS: 4000},
		{FromNodeID: nodes[0], ToNodeID: nodes[1], Path: "direct", BPS: 500},
		{FromNodeID: nodes[0], ToNodeID: nodes[2], Path: "direct", BPS: 1000},
	}, now)
	// 覆盖写：复用同一 inode ID、换内容。
	data2 := make([]byte, 512)
	u2 := beginWriteTest(t, s, RootID, "doc", int64(len(data2)), true)
	req2, plan2 := writeChoice(u2, 0, data2, nodes[1:2], nodes[1:2])
	plan2.Transfer = &types.WriteTransferPlan{UploadTargets: []uint64{nodes[1]}, ExpiresAt: now.Add(time.Minute), Legs: []types.WriteTransferLeg{{ToNodeID: nodes[1], Path: "https", BPS: 100}}}
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReserveWriteChunk(WriteActor{}, req2, plan2, snap.ProfileRevision, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	confirmWriteTest(t, s, plan2.Object.ID, nodes[1])
	if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(u2, int64(len(data2)), 1), time.Hour, now); err != nil {
		t.Fatal(err)
	}
	loads, err := s.WriteTransferLoads(now)
	if err != nil {
		t.Fatalf("overwritten committed record must not poison load accounting: %v", err)
	}
	if loads[nodes[2]] != (TransferLoad{DownloadBPS: 1000, Downloads: 1}) {
		t.Fatalf("fallback Result snapshot must keep the un-Done hold: %+v", loads[nodes[2]])
	}
	if loads[nodes[1]] != (TransferLoad{}) {
		t.Fatalf("overwriting write's Done leg must release: %+v", loads[nodes[1]])
	}
	if err := reserveSingle(t, s, nodes, "third", nodes[2], 600, now); !errors.Is(err, ErrWriteBudget) {
		t.Fatalf("hold must survive overwrite and reject oversubscription: %v", err)
	}
}

// T3: committed 路线 lease 内返回原计划，过期释放 (nil,nil)，账同步放行。
// WriteTransferForObject 内部取 time.Now，因此用分钟 TTL 加直接置过期，避免 sleep。
func TestWriteTransferForObjectCommittedLeaseBoundary(t *testing.T) {
	s, nodes, now := completedTransferStore(t)
	u, plan, _ := reserveCommittedTransfer(t, s, "lease", nodes, nodes[:2], []types.WriteTransferLeg{
		{ToNodeID: nodes[0], Path: "https", BPS: 4000},
		{FromNodeID: nodes[0], ToNodeID: nodes[1], Path: "direct", BPS: 500},
		{FromNodeID: nodes[0], ToNodeID: nodes[2], Path: "direct", BPS: 1000},
	}, now)
	p, err := s.WriteTransferForObject(plan.Object.ID)
	if err != nil || p == nil {
		t.Fatalf("committed within lease must return the original route: %+v %v", p, err)
	}
	if !p.ExpiresAt.Equal(plan.Transfer.ExpiresAt) || len(p.Legs) != len(plan.Transfer.Legs) {
		t.Fatalf("route must be unchanged: %+v", p)
	}
	if err := s.write(func(w *txw) error {
		rec, err := plannedWriteTx(w.tx, u.ID)
		if err != nil {
			return err
		}
		for i := range rec.Upload.Chunks {
			if rec.Upload.Chunks[i].Object.ID == plan.Object.ID {
				rec.Upload.Chunks[i].Transfer.ExpiresAt = time.Now().Add(-time.Second)
			}
		}
		return putPlannedWrite(w, rec)
	}); err != nil {
		t.Fatal(err)
	}
	p2, err := s.WriteTransferForObject(plan.Object.ID)
	if err != nil || p2 != nil {
		t.Fatalf("expired committed route must be released, not an error: %+v %v", p2, err)
	}
	loads, err := s.WriteTransferLoads(now)
	if err != nil {
		t.Fatal(err)
	}
	if loads[nodes[2]] != (TransferLoad{}) || loads[nodes[0]] != (TransferLoad{}) {
		t.Fatalf("expired committed hold must drop from accounting: n0=%+v n2=%+v", loads[nodes[0]], loads[nodes[2]])
	}
	if err := reserveSingle(t, s, nodes, "afterlease", nodes[2], 600, now); err != nil {
		t.Fatalf("expired hold must free budget: %v", err)
	}
}
