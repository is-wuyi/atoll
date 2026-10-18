package meta

import (
	"testing"
	"time"

	"atoll/pkg/types"
)

// 本文件只覆盖容量时序复核的三条诚实时序，不复制任何生产实现：
//   1. capacity_baseline_rewind  —— 重启后的迟到旧心跳能否把账面 free 抬高（当前实现：能，见 TestCapacityHonestRestartRewindOversellsFree）
//   2. capacity_receipt_rearm    —— 有 verified receipt 的计划写入在同一条重排下是否保住预留（当前实现：保住）
//   3. capacity_same_epoch_drop  —— 同 epoch 较新样本因真实删除而下降是否构成少计（当前实现：不构成）
//
// 通用前置条件：节点总容量 1024B；节点历史物理占用 800B 不在当前 inode/object 表内，
// 即 800B 只能由 node.UsedBytes 承载，inode 表对它的 allocated 贡献为 0；
// 再写入 150B 新数据，物理占用变为 950B，真实可用只有 74B。
// 这个 800/150 的不对称是刻意的：allocated 不能全覆盖，否则 max() 的并集假设退化为恒真，
// 无法区分“账面守恒”与“恰好凑数”。

func capacityFor(t *testing.T, s *Store, nodeID uint64) NodeCapacity {
	t.Helper()
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatalf("AutonomySnapshot: %v", err)
	}
	for _, c := range snap.Capacity {
		if c.NodeID == nodeID {
			return c
		}
	}
	t.Fatalf("node %d absent from capacity snapshot: %+v", nodeID, snap.Capacity)
	return NodeCapacity{}
}

func heartbeatUsage(t *testing.T, s *Store, nodeID uint64, u types.NodeUsage) {
	t.Helper()
	if err := s.HeartbeatWithUsage(nodeID, u.UsedBytes, &u); err != nil {
		t.Fatalf("HeartbeatWithUsage(%s/%d/%d): %v", u.Epoch, u.Sequence, u.UsedBytes, err)
	}
}

// legacyWriteTest 走默认（非计划写入）小文件路径：只进 inode 表，
// 不产生 planned write record，也不产生任何 usage receipt。
func legacyWriteTest(t *testing.T, s *Store, name string, nodes []uint64, size int64) {
	t.Helper()
	obj, _, err := s.PrepareSmallFile(SmallFileTarget{ParentID: RootID, Name: name, Size: size,
		Checksum: 123, Replicas: nodes, PrimaryID: nodes[0], Mtime: time.Now(), Overwrite: true})
	if err != nil {
		t.Fatalf("PrepareSmallFile(%s): %v", name, err)
	}
	if _, _, _, _, err := s.CommitSmallFile(obj.ID); err != nil {
		t.Fatalf("CommitSmallFile: %v", err)
	}
}

func plannedWriteTest(t *testing.T, s *Store, name string, nodes []uint64, size int64, confirm types.NodeUsage) {
	t.Helper()
	u := beginWriteTest(t, s, RootID, name, size, false)
	p := reserveWriteTest(t, s, u, make([]byte, size), nodes, nodes)
	d, err := s.ObjectIntegrity(p.Object.ID)
	if err != nil {
		t.Fatalf("ObjectIntegrity(%d): %v", p.Object.ID, err)
	}
	if ok, err := s.MarkVerifiedObjectDoneWithUsage(d, nodes[0], &confirm); err != nil || !ok {
		t.Fatalf("MarkVerifiedObjectDoneWithUsage: %v %v", ok, err)
	}
	if _, _, _, err := s.CommitPlannedWrite(WriteActor{}, commitWriteTest(u, size, 1), time.Hour, time.Now()); err != nil {
		t.Fatalf("CommitPlannedWrite: %v", err)
	}
}

// TestCapacityHonestRestartRewindOversellsFree 是本次复核的核心反例。
//
// 时序（每个包在发送时刻都是节点的真实采样，全部为诚实节点行为）：
//  1. HeartbeatWithUsage(boot-a, 1, 800)  —— 历史占用 800B，inode 表不覆盖
//  2. PrepareSmallFile + CommitSmallFile  —— 150B 新写落 inode 表，allocated=150
//  3. HeartbeatWithUsage(boot-a, 2, 950)  —— 真实占用 950B
//  4. HeartbeatWithUsage(boot-b, 1, 950)  —— 节点重启，随机新 epoch，真实占用仍是 950B
//  5. HeartbeatWithUsage(boot-a, 1, 800)  —— 第 1 步的心跳在网络中迟到重传
//
// expected: 每一步 Free 恒为 74（1024-950），物理占用从未下降。
// actual  : 第 5 步之后 Accounted 被回退到 800，Free=224，超计 150B，
//
//	随后一个 150B 的计划写入会被 ErrWriteBudget 之外的路径放行。
//
// 根因链：applyNodeUsage 只在 epoch 相同（write_usage.go:19）时才比较 Sequence，
// 跨 epoch 直接落到 write_usage.go:27-28 的无条件赋值；capacitiesTx 的
// Accounted=max(node.UsedBytes, allocated)（autonomy.go:244）假设被回退的样本
// 仍是“超集”，而这里 max(800, 150)=800 只覆盖了 950B 中的 800B。
// 该缺口只出现在没有 usage receipt 的写入上：writeReservationsTx 对第 2 步的
// 小文件没有任何记录可查，因此没有独立预留可以兜底。
func TestCapacityHonestRestartRewindOversellsFree(t *testing.T) {
	s := newTestStore(t)
	node, err := s.RegisterNode("127.0.0.1:59000", 1024)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []uint64{node.ID}
	n := node.ID

	heartbeatUsage(t, s, n, types.NodeUsage{Epoch: "boot-a", Sequence: 1, UsedBytes: 800})
	c := capacityFor(t, s, n)
	if c.Accounted != 800 || c.Reserved != 0 || c.Free != 224 {
		t.Fatalf("baseline: %+v, want accounted=800 free=224", c)
	}

	legacyWriteTest(t, s, "payload", nodes[:1], 150)
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	heartbeatUsage(t, s, n, types.NodeUsage{Epoch: "boot-a", Sequence: 2, UsedBytes: 950})
	c = capacityFor(t, s, n)
	if c.Accounted != 950 || c.Reserved != 0 || c.Free != 74 {
		t.Fatalf("after 150B write: %+v, want accounted=950 free=74", c)
	}

	heartbeatUsage(t, s, n, types.NodeUsage{Epoch: "boot-b", Sequence: 1, UsedBytes: 950})
	c = capacityFor(t, s, n)
	if c.Accounted != 950 || c.Free != 74 {
		t.Fatalf("after restart epoch: %+v, want free=74", c)
	}

	heartbeatUsage(t, s, n, types.NodeUsage{Epoch: "boot-a", Sequence: 1, UsedBytes: 800})
	c = capacityFor(t, s, n)

	oversold := false
	snap, err := s.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	second := beginWriteTest(t, s, RootID, "second", 150, false)
	req, choice := writeChoice(second, 0, make([]byte, 150), nodes[:1], nodes[:1])
	if _, _, err := s.ReserveWriteChunk(WriteActor{}, req, choice, snap.ProfileRevision, time.Hour, time.Now()); err == nil {
		oversold = true
	}

	if c.Free != 74 {
		t.Errorf("迟到心跳回退了占用：Accounted=%d Reserved=%d Free=%d，期望 Free=74（1024-950），超计 %d",
			c.Accounted, c.Reserved, c.Free, c.Free-74)
	}
	if oversold {
		t.Errorf("节点物理仅剩 74B 可用，150B 新写被放行；期望 ErrWriteBudget")
	}
}

// TestCapacityPlannedReceiptRearmsAfterRestartReorder 证明本批的 receipt 防线在这条
// 完全相同的重排下是有效的：重启后 epoch 变化使 coverage 判定失败，独立预留自动重新武装。
// 因此上面的缺口被精确定位在“没有 receipt 的写入”这一通道，而不是 receipt 机制本身。
func TestCapacityPlannedReceiptRearmsAfterRestartReorder(t *testing.T) {
	s, nodes := writeTestStore(t)
	n := nodes[0]

	heartbeatUsage(t, s, n, types.NodeUsage{Epoch: "boot-a", Sequence: 1, UsedBytes: 800})
	plannedWriteTest(t, s, "payload", nodes[:1], 150, types.NodeUsage{Epoch: "boot-a", Sequence: 2, UsedBytes: 950})

	c := capacityFor(t, s, n)
	if c.Accounted != 950 || c.Reserved != 0 || c.Free != 74 {
		t.Fatalf("committed planned write: %+v, want accounted=950 reserved=0 free=74", c)
	}

	heartbeatUsage(t, s, n, types.NodeUsage{Epoch: "boot-b", Sequence: 1, UsedBytes: 950})
	c = capacityFor(t, s, n)
	if c.Reserved != 150 {
		t.Fatalf("新 epoch 不应证明旧 receipt 已包含该对象：%+v, want reserved=150", c)
	}

	heartbeatUsage(t, s, n, types.NodeUsage{Epoch: "boot-a", Sequence: 1, UsedBytes: 800})
	c = capacityFor(t, s, n)
	if c.Free > 74 || c.Reserved != 150 {
		t.Fatalf("迟到心跳使 receipt 预留丢失：%+v, want reserved=150 and free<=74", c)
	}
}

// TestCapacitySameEpochNewerLowerSampleIsNotAnUndercount 覆盖“同 epoch 较新样本因对象
// 删除而下降”这一支：样本被接受且 coverage 仍成立（write_usage.go:88 只要求同 epoch 且
// seq>=receipt seq），预留释放；但 inode 表仍记着这 150B，max() 把它保留为下限，
// 账面 800B 与真实物理占用一致。这里不能反过来把“没释放”误报成少计。
func TestCapacitySameEpochNewerLowerSampleIsNotAnUndercount(t *testing.T) {
	s, nodes := writeTestStore(t)
	n := nodes[0]

	heartbeatUsage(t, s, n, types.NodeUsage{Epoch: "boot-a", Sequence: 1, UsedBytes: 800})
	plannedWriteTest(t, s, "payload", nodes[:1], 150, types.NodeUsage{Epoch: "boot-a", Sequence: 2, UsedBytes: 950})
	if c := capacityFor(t, s, n); c.Free != 74 {
		t.Fatalf("before deletion: %+v, want free=74", c)
	}

	heartbeatUsage(t, s, n, types.NodeUsage{Epoch: "boot-a", Sequence: 3, UsedBytes: 800})
	c := capacityFor(t, s, n)
	if c.Accounted != 800 || c.Reserved != 0 || c.Free != 224 {
		t.Fatalf("honest deletion: %+v, want accounted=800 reserved=0 free=224", c)
	}
}
