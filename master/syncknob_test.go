package master

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
)

// 同步旋钮开启：写元数据时钩子把帧同步 ship 到集群，写成功。
func TestSyncKnobShipsFrameOnWrite(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 3)
	b.SetConfig(MetaBackupConfig{Replicas: 3, Retention: 3, Interval: time.Hour, SyncBeforeAck: true, SyncMinCopies: 2})
	b.InstallSyncHook()

	// 写一笔元数据 → 钩子应把这帧作为 wal-sync-<seq> ship 到集群。
	if _, err := store.CreateDir(meta.RootID, "synced"); err != nil {
		t.Fatalf("同步模式下写应成功: %v", err)
	}
	// 至少一个节点上应出现 wal-sync-* blob。
	found := 0
	for _, addr := range addrs {
		blobs, _ := b.listBlobs(addr)
		for _, bl := range blobs {
			if strings.HasPrefix(bl.Key, "wal-sync-") {
				found++
			}
		}
	}
	if found == 0 {
		t.Fatal("同步旋钮开启后，写元数据应在集群留下 wal-sync blob")
	}
}

// 旋钮关闭：写元数据不触发同步 ship（钩子空转）。
func TestSyncKnobOffNoShip(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 2)
	b.SetConfig(MetaBackupConfig{Replicas: 2, Retention: 3, Interval: time.Hour, SyncBeforeAck: false})
	b.InstallSyncHook()

	if _, err := store.CreateDir(meta.RootID, "async"); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	for _, addr := range addrs {
		blobs, _ := b.listBlobs(addr)
		for _, bl := range blobs {
			if strings.HasPrefix(bl.Key, "wal-sync-") {
				t.Fatal("旋钮关闭时不应产生 wal-sync blob")
			}
		}
	}
}

// 集群存活不足 W：同步写失败（决策点3：不偷偷降级，宁可写失败）。
func TestSyncKnobFailsWhenClusterBelowW(t *testing.T) {
	store, b, _ := newBackupCluster(t, 2)
	// 只有 2 个节点，却要求 W=3 确认 → 写必失败。
	b.SetConfig(MetaBackupConfig{Replicas: 3, Retention: 3, Interval: time.Hour, SyncBeforeAck: true, SyncMinCopies: 3})
	b.InstallSyncHook()

	_, err := store.CreateDir(meta.RootID, "shouldfail")
	if err == nil {
		t.Fatal("存活节点不足 W 时，同步写应失败")
	}
	if !strings.Contains(err.Error(), "同步复制") {
		t.Fatalf("错误应来自同步复制，got: %v", err)
	}
	// 注意：本地 bbolt 其实已提交（决策点1不撤回）——验证这一点。
	if _, err := store.Lookup(meta.RootID, "shouldfail"); err != nil {
		t.Fatal("决策点1：ship 失败但本地不撤回，条目应仍在本地")
	}
}

// 恢复能捞到"同步落盘但未进 manifest"的散落帧（gatherAllFramesAfter 扫 wal-sync blob）。
func TestRecoverPicksUpLooseSyncFrames(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 3)
	var seeds []string
	for _, a := range addrs {
		seeds = append(seeds, a)
	}
	b.SetConfig(MetaBackupConfig{Replicas: 3, Retention: 3, Interval: time.Hour, SyncBeforeAck: true, SyncMinCopies: 2})
	b.InstallSyncHook()

	// 先建基准快照（此时只有根）。
	store.CreateDir(meta.RootID, "base")
	if _, err := b.BackupOnce(); err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	// 快照之后再写几笔——同步旋钮把它们作为 wal-sync blob 落集群，但没跑 ShipWAL，
	// 所以它们不在 manifest 里。恢复必须靠扫 blob 找回。
	store.CreateDir(meta.RootID, "after1")
	store.CreateDir(meta.RootID, "after2")
	dbPath := store.DBPath()
	store.Close()
	os.Remove(dbPath) // 模拟盘坏

	rs, err := b.Recover(dbPath, seeds, RecoverCluster)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	defer rs.Close()
	// after1/after2 只存在于同步帧 blob，恢复后应都在。
	for _, name := range []string{"base", "after1", "after2"} {
		if _, err := rs.Lookup(meta.RootID, name); err != nil {
			t.Fatalf("恢复后应含 %s（同步帧未进 manifest 也不能丢）: %v", name, err)
		}
	}
}

// prune 清理被快照覆盖的同步帧 blob。
func TestPruneCleansSyncBlobsCoveredBySnapshot(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 2)
	b.SetConfig(MetaBackupConfig{Replicas: 2, Retention: 3, Interval: time.Hour, SyncBeforeAck: true, SyncMinCopies: 1})
	b.InstallSyncHook()

	// 写几笔 → 产生 wal-sync blob。
	store.CreateDir(meta.RootID, "a")
	store.CreateDir(meta.RootID, "b")
	// 再备份 → 快照锚点覆盖这些 seq → 下次 prune 应清掉这些 wal-sync blob。
	if _, err := b.BackupOnce(); err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	// BackupOnce 内已调 prune，但那些 wal-sync 是在快照“之前”写的，snapSeq 覆盖它们。
	leftover := 0
	for _, addr := range addrs {
		blobs, _ := b.listBlobs(addr)
		for _, bl := range blobs {
			if strings.HasPrefix(bl.Key, "wal-sync-") {
				leftover++
			}
		}
	}
	if leftover != 0 {
		t.Fatalf("被快照覆盖的同步 blob 应被清理，仍剩 %d", leftover)
	}
}

var _ = fmt.Sprintf
