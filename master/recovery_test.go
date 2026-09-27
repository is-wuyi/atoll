package master

import (
	"fmt"
	"os"
	"testing"
	"time"

	"atoll/master/meta"
)

// decideRecovery 纯决策逻辑全分支。
func TestDecideRecovery(t *testing.T) {
	cases := []struct {
		name string
		in   RecoverInput
		want RecoverAction
	}{
		{"显式local有本地", RecoverInput{Mode: RecoverLocal, LocalExists: true}, ActionUseLocal},
		{"显式local无本地", RecoverInput{Mode: RecoverLocal, LocalExists: false}, ActionFailStop},
		{"显式cluster有备份", RecoverInput{Mode: RecoverCluster, ClusterFound: true}, ActionRebuild},
		{"显式cluster无备份", RecoverInput{Mode: RecoverCluster, ClusterFound: false}, ActionFailStop},
		{"未配种子", RecoverInput{Mode: RecoverAuto, SeedsGiven: false, LocalExists: true}, ActionUseLocal},
		{"本地在集群不可达", RecoverInput{Mode: RecoverAuto, SeedsGiven: true, LocalExists: true, ClusterFound: false}, ActionUseLocal},
		{"本地>=集群", RecoverInput{Mode: RecoverAuto, SeedsGiven: true, LocalExists: true, LocalSeq: 10, ClusterFound: true, ClusterSeq: 8}, ActionUseLocal},
		{"本地==集群", RecoverInput{Mode: RecoverAuto, SeedsGiven: true, LocalExists: true, LocalSeq: 8, ClusterFound: true, ClusterSeq: 8}, ActionUseLocal},
		{"本地<集群硬停", RecoverInput{Mode: RecoverAuto, SeedsGiven: true, LocalExists: true, LocalSeq: 5, ClusterFound: true, ClusterSeq: 9}, ActionFailStop},
		{"全新集群", RecoverInput{Mode: RecoverAuto, SeedsGiven: true, LocalExists: false, ClusterFound: false}, ActionFreshStart},
		{"本地没了集群有硬停", RecoverInput{Mode: RecoverAuto, SeedsGiven: true, LocalExists: false, ClusterFound: true, ClusterSeq: 3}, ActionFailStop},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := decideRecovery(c.in)
			if got != c.want {
				t.Fatalf("decideRecovery = %v，期望 %v（理由: %s）", got, c.want, reason)
			}
		})
	}
}

// 端到端灾难恢复：集群有备份 → 模拟 master 盘坏（删本地库）→ 从集群重建 → 状态一致。
func TestRecoverRebuildFromCluster(t *testing.T) {
	store, b, _ := newBackupCluster(t, 3)
	seeds := seedAddrs(b, t)

	// 造元数据并备份。
	docs, _ := store.CreateDir(meta.RootID, "docs")
	store.CreateFile(docs.ID, "a.txt", []uint64{1, 2})
	store.CreateDir(meta.RootID, "media")
	if _, err := b.BackupOnce(); err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	// 快照之后再写 + 增量 ship WAL（覆盖 snapshot+WAL 双路径）。
	store.CreateDir(docs.ID, "sub")
	f, _ := store.CreateFile(docs.ID, "b.txt", []uint64{2, 3})
	store.UpdateFileSize(f.ID, 4096, 0x1234)
	if _, shipped, err := b.ShipWAL(); err != nil || !shipped {
		t.Fatalf("ShipWAL: shipped=%v err=%v", shipped, err)
	}

	want := snapshotTree(t, store)
	dbPath := store.DBPath()
	store.Close()

	// 模拟盘坏：删本地库。
	if err := os.Remove(dbPath); err != nil {
		t.Fatalf("删库模拟盘坏: %v", err)
	}

	// 从集群重建（显式 cluster 模式）。
	rs, err := b.Recover(dbPath, seeds, RecoverCluster)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	defer rs.Close()

	got := snapshotTree(t, rs)
	if !treeEq(want, got) {
		t.Fatalf("重建后状态不符:\n want=%v\n got =%v", want, got)
	}
}

// 多分块快照重建：把分块调到很小、造 ≥11 块，验证拼接按数字下标而非字典序。
// 回归：此前 rebuildFromCluster 按 key 字符串排序，idx≥10 时 "snapshot-v-10" 排到
// "snapshot-v-2" 前，拼出的 bbolt 能打开但内容错乱（元数据静默损坏）。
func TestRecoverRebuildMultiChunkOrdering(t *testing.T) {
	orig := metaChunkSize
	metaChunkSize = 4096 // 4KB 块 → 小元数据也能造出很多块
	defer func() { metaChunkSize = orig }()

	store, b, _ := newBackupCluster(t, 3)
	seeds := seedAddrs(b, t)

	// 造足够多的目录/文件，让快照远超 11×4KB。
	docs, _ := store.CreateDir(meta.RootID, "docs")
	for i := 0; i < 200; i++ {
		store.CreateFile(docs.ID, fmt.Sprintf("f%03d.bin", i), []uint64{1, 2})
	}
	m, err := b.BackupOnce()
	if err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	if len(m.Chunks) < 11 {
		t.Fatalf("需 ≥11 块才能触发字典序错位，实际 %d 块——增大数据量", len(m.Chunks))
	}

	want := snapshotTree(t, store)
	dbPath := store.DBPath()
	store.Close()
	if err := os.Remove(dbPath); err != nil {
		t.Fatalf("删库: %v", err)
	}

	rs, err := b.Recover(dbPath, seeds, RecoverCluster)
	if err != nil {
		t.Fatalf("Recover（多块拼接若错位这里会失败或内容不符）: %v", err)
	}
	defer rs.Close()
	got := snapshotTree(t, rs)
	if !treeEq(want, got) {
		t.Fatalf("多块重建后状态不符（拼接顺序错）:\n want=%d entries\n got =%d entries", len(want), len(got))
	}
}

// chunkKeyIdx 必须按数字解析下标，不能字典序。
func TestChunkKeyIdx(t *testing.T) {
	cases := map[string]int{
		"snapshot-5-0": 0, "snapshot-5-2": 2, "snapshot-5-10": 10, "snapshot-5-123": 123,
		"bad": -1, "snapshot-5-": -1, "snapshot-5-x": -1,
	}
	for k, want := range cases {
		if got := chunkKeyIdx(k); got != want {
			t.Errorf("chunkKeyIdx(%q)=%d want %d", k, got, want)
		}
	}
	// 关键断言：10 的数字序 > 2，字典序则相反。
	if !(chunkKeyIdx("snapshot-5-10") > chunkKeyIdx("snapshot-5-2")) {
		t.Fatal("数字序应 10>2")
	}
}
// auto 模式下本地在且够新 → 直接用本地，不碰集群。
func TestRecoverAutoUsesFreshLocal(t *testing.T) {
	store, b, _ := newBackupCluster(t, 2)
	seeds := seedAddrs(b, t)
	store.CreateDir(meta.RootID, "a")
	if _, err := b.BackupOnce(); err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	// 本地又写了一笔（本地比集群新）。
	store.CreateDir(meta.RootID, "b")
	dbPath := store.DBPath()
	store.Close()

	rs, err := b.Recover(dbPath, seeds, RecoverAuto)
	if err != nil {
		t.Fatalf("Recover auto: %v", err)
	}
	defer rs.Close()
	// 本地那笔 "b" 应还在（用了本地而非回退到较旧的集群快照）。
	if _, err := rs.Lookup(meta.RootID, "b"); err != nil {
		t.Fatalf("auto 应保留更新的本地状态，但 b 丢了: %v", err)
	}
}

// 版本号播种：重启后 b.version 从集群 manifest 续增，不倒退（否则 prune 失效泄漏）。
func TestRecoverSeedsVersionFromCluster(t *testing.T) {
	st, b, addrs := newBackupCluster(t, 2)
	var seeds []string
	for id := range addrs {
		seeds = append(seeds, addrs[id])
	}
	// 备份几次把版本推到 3。
	for i := 0; i < 3; i++ {
		st.CreateDir(meta.RootID, fmt.Sprintf("d%d", i))
		if _, err := b.BackupOnce(); err != nil {
			t.Fatalf("BackupOnce: %v", err)
		}
	}
	dbPath := st.DBPath()
	st.Close()

	// 新起一个 backup 实例（模拟进程重启：version 归 0）指向同一集群。
	fresh := NewMetaBackup(nil, time.Minute, DefaultMetaBackupConfig())
	rs, err := fresh.Recover(dbPath, seeds, RecoverAuto)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	defer rs.Close()
	fresh.SetStore(rs)

	// 播种后 version 应 >= 3；再备份一次版本应是 4，不是 1。
	m, err := fresh.BackupOnce()
	if err != nil {
		t.Fatalf("BackupOnce after recover: %v", err)
	}
	if m.Version <= 3 {
		t.Fatalf("重启后版本应续增到 >3，got %d（版本倒退 bug）", m.Version)
	}
}

// auto 模式下本地没了但集群有备份 → 硬停（不自动重建）。
func TestRecoverAutoFailStopOnMissingLocal(t *testing.T) {
	store, b, _ := newBackupCluster(t, 2)
	seeds := seedAddrs(b, t)
	store.CreateDir(meta.RootID, "a")
	if _, err := b.BackupOnce(); err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	dbPath := store.DBPath()
	store.Close()
	os.Remove(dbPath)

	_, err := b.Recover(dbPath, seeds, RecoverAuto)
	if err == nil {
		t.Fatal("本地没了+集群有备份，auto 应硬停报错")
	}
	if _, ok := err.(*ErrFailStop); !ok {
		t.Fatalf("应为 ErrFailStop，got %T: %v", err, err)
	}
}

// ---- 测试辅助 ----

// seedAddrs 从 store 里的节点取地址列表当种子。
func seedAddrs(b *MetaBackup, t *testing.T) []string {
	t.Helper()
	nodes, err := b.store.ListAliveNodes(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, n := range nodes {
		out = append(out, n.Addr)
	}
	return out
}

// snapshotTree 遍历整棵树成 path→shape 映射（与 meta 包内测试同思路）。
type treeShape map[string]string

func snapshotTree(t *testing.T, s *meta.Store) treeShape {
	t.Helper()
	out := treeShape{}
	var walk func(id uint64, prefix string)
	walk = func(id uint64, prefix string) {
		kids, err := s.ListChildren(id)
		if err != nil {
			t.Fatalf("ListChildren: %v", err)
		}
		for _, k := range kids {
			p := prefix + "/" + k.Name
			out[p] = fmt.Sprintf("dir=%v size=%d sum=%x", k.Type == 0, k.Size, k.Checksum)
			if k.Type == 0 { // TypeDir == 0
				walk(k.ID, p)
			}
		}
	}
	walk(meta.RootID, "")
	return out
}

func treeEq(a, b treeShape) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
