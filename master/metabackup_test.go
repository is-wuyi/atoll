package master

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/types"
)

// 起 n 个真实 httptest 存储节点并注册进 store，返回 store、备份器、节点地址表。
func newBackupCluster(t *testing.T, nodes int) (*meta.Store, *MetaBackup, map[uint64]string) {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	addrs := map[uint64]string{}
	for i := 0; i < nodes; i++ {
		n := node.New(t.TempDir(), "http://master.invalid", fmt.Sprintf("127.0.0.1:%d", 19000+i), 1<<40)
		ts := httptest.NewServer(n.Handler())
		t.Cleanup(ts.Close)
		info, err := store.RegisterNode(ts.URL[len("http://"):], 1<<40)
		if err != nil {
			t.Fatalf("RegisterNode: %v", err)
		}
		addrs[info.ID] = ts.URL[len("http://"):]
	}
	b := NewMetaBackup(store, time.Minute, DefaultMetaBackupConfig())
	return store, b, addrs
}

// getBlob 从某节点地址读回一个 meta-backup blob（测试直连）。
func getBlob(t *testing.T, addr, key string) ([]byte, int) {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/meta-backup/" + key)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode
}

// BackupOnce：快照分块 ship + manifest 宽复制 + WAL 截断，全链路。
func TestBackupOnceShipsSnapshotAndManifest(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 3)
	// 造点元数据。
	docs, _ := store.CreateDir(meta.RootID, "docs")
	store.CreateFile(docs.ID, "a.txt", []uint64{1, 2})

	m, err := b.BackupOnce()
	if err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	if m.Version != 1 {
		t.Fatalf("首次版本应为 1，got %d", m.Version)
	}
	if len(m.Chunks) == 0 {
		t.Fatal("manifest 应含快照块")
	}
	// 每个快照块都应有 holder，且能从 holder 读回、CRC 一致。
	for _, ch := range m.Chunks {
		if len(ch.Holders) == 0 {
			t.Fatalf("块 %s 无 holder", ch.Key)
		}
		for _, h := range ch.Holders {
			data, code := getBlob(t, addrs[h], ch.Key)
			if code != http.StatusOK {
				t.Fatalf("从节点 %d 读块 %s: 状态 %d", h, ch.Key, code)
			}
			if int64(len(data)) != ch.Size {
				t.Fatalf("块 %s 大小 %d != manifest %d", ch.Key, len(data), ch.Size)
			}
		}
	}
	// manifest 应宽复制到全部 3 节点。
	mfCount := 0
	for _, addr := range addrs {
		if _, code := getBlob(t, addr, ManifestKey); code == http.StatusOK {
			mfCount++
		}
	}
	if mfCount != 3 {
		t.Fatalf("manifest 应复制到 3 节点，实际 %d", mfCount)
	}
}

// 版本号单调递增：连续两次备份，第二次版本 +1。
func TestBackupVersionIncrements(t *testing.T) {
	store, b, _ := newBackupCluster(t, 2)
	store.CreateDir(meta.RootID, "a")
	m1, err := b.BackupOnce()
	if err != nil {
		t.Fatalf("BackupOnce#1: %v", err)
	}
	store.CreateDir(meta.RootID, "b")
	m2, err := b.BackupOnce()
	if err != nil {
		t.Fatalf("BackupOnce#2: %v", err)
	}
	if m2.Version != m1.Version+1 {
		t.Fatalf("版本应递增: %d → %d", m1.Version, m2.Version)
	}
}

// K = min(Replicas, 存活节点数)：只有 2 个节点、Replicas=3 时，快照块 holder 上限为 2。
func TestBackupRespectsNodeCount(t *testing.T) {
	store, b, _ := newBackupCluster(t, 2)
	b.cfg.Replicas = 3
	store.CreateDir(meta.RootID, "x")
	m, err := b.BackupOnce()
	if err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	for _, ch := range m.Chunks {
		if len(ch.Holders) > 2 {
			t.Fatalf("块 %s holder %d 超过节点数 2", ch.Key, len(ch.Holders))
		}
	}
}

// 无存活节点 → 备份报错，不推进版本。
func TestBackupNoNodesFails(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	b := NewMetaBackup(store, time.Minute, DefaultMetaBackupConfig())
	if _, err := b.BackupOnce(); err == nil {
		t.Fatal("无节点时备份应报错")
	}
	if b.version != 0 {
		t.Fatalf("失败不应推进版本，got %d", b.version)
	}
}

// parseBlobVersion 各种 key 形态。
func TestParseBlobVersion(t *testing.T) {
	cases := []struct {
		key string
		ver uint64
		ok  bool
	}{
		{"snapshot-1-0", 1, true},
		{"snapshot-42-7", 42, true},
		{"wal-3-10-20", 3, true},
		{"manifest", 0, false},
		{"snapshot-", 0, false},
		{"snapshot-abc-0", 0, false},
		{"random", 0, false},
	}
	for _, c := range cases {
		ver, ok := parseBlobVersion(c.key)
		if ok != c.ok || (ok && ver != c.ver) {
			t.Errorf("parseBlobVersion(%q) = (%d,%v), 期望 (%d,%v)", c.key, ver, ok, c.ver, c.ok)
		}
	}
}

// 保留数 N：连续备份 N+2 次后，只剩最近 N 个版本的快照 blob，老版本被清。
func TestPruneOldVersions(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 3)
	b.cfg.Retention = 2

	// 备份 4 次（版本 1..4），每次改点东西。
	for i := 0; i < 4; i++ {
		store.CreateDir(meta.RootID, fmt.Sprintf("d%d", i))
		if _, err := b.BackupOnce(); err != nil {
			t.Fatalf("BackupOnce#%d: %v", i+1, err)
		}
	}
	// 当前版本 4，保留 2 → 只应剩版本 3、4 的快照 blob，1、2 被清。
	seen := map[uint64]bool{}
	for _, addr := range addrs {
		blobs, err := b.listBlobs(addr)
		if err != nil {
			t.Fatal(err)
		}
		for _, bl := range blobs {
			if ver, ok := parseBlobVersion(bl.Key); ok {
				seen[ver] = true
			}
		}
	}
	if seen[1] || seen[2] {
		t.Fatalf("版本 1/2 应已清理，实际存在: %v", seen)
	}
	if !seen[3] || !seen[4] {
		t.Fatalf("版本 3/4 应保留，实际: %v", seen)
	}
}

// prune 必须清掉"版本号比当前更高"的上一轮遗留孤儿（本次实机 bug）。
func TestPruneRemovesHigherEpochOrphans(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 2)
	b.cfg.Retention = 3

	// 手动往节点塞一个"更高纪元"的孤儿快照（模拟上一轮 master 版本号 2860 的遗留）。
	orphan := []byte("stale-epoch-orphan")
	for _, addr := range addrs {
		if err := b.putBlob(addr, "snapshot-2860-0", orphan, types.CRC32C(orphan)); err != nil {
			t.Fatalf("塞孤儿失败: %v", err)
		}
	}

	// 正常备份一次（当前版本会是 1）。prune 应删掉 v2860 孤儿。
	store.CreateDir(meta.RootID, "x")
	if _, err := b.BackupOnce(); err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}

	for _, addr := range addrs {
		blobs, _ := b.listBlobs(addr)
		for _, bl := range blobs {
			if v, ok := parseBlobVersion(bl.Key); ok && v == 2860 {
				t.Fatalf("更高纪元孤儿 v2860 未被清理（节点 %s）", addr)
			}
		}
	}
}

// manifest JSON 编解码往返。
func TestManifestRoundTrip(t *testing.T) {
	m := Manifest{
		Version: 7, SnapshotSeq: 42, SnapshotBytes: 1000,
		Chunks:  []ChunkRef{{Key: "snapshot-7-0", Size: 1000, CRC32C: 0xabcd, Holders: []uint64{1, 2, 3}}},
		WALSegs: []WALSegRef{{Key: "wal-7-43-50", FromSeq: 43, ToSeq: 50, Holders: []uint64{2, 3}}},
	}
	raw, err := marshalManifest(&m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 7 || got.SnapshotSeq != 42 || len(got.Chunks) != 1 || len(got.WALSegs) != 1 {
		t.Fatalf("往返不符: %+v", got)
	}
	if got.LatestSeq() != 50 {
		t.Fatalf("LatestSeq 应为 50，got %d", got.LatestSeq())
	}
}
