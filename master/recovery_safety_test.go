package master

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/master/meta"
)

// 恢复 seed/rebuild 边界安全回归（先红后绿，与主 agent 的发布契约对应）：
//   - 失败 fail-stop 绝不落地最终库；只有全部种子"明确回答 404"才允许 fresh start。
//   - rebuild 先进私有 workdir，全部完成后以 no-replace 方式发布到最终路径：
//     目标已存在（含悬空符号链接）拒绝且原样保留；中途被并发创建也拒绝且保住对方字节；
//     目录里既有的旧 .rebuild-tmp 不得删除/覆盖，重试靠独有 workdir 成功。
//   - 失败只清理自己的 workdir，不泄漏 restore 临时文件、不碰无关文件。
//   - 成功恢复 Store.DBPath 必须是最终目标路径，Close 再 Open 数据与 seq 一致。
//   - 有效本地库 + 种子不可达：仍按原约定用本地，不毁原数据。
//
// 约束：manifest/块字节一律用真实 BackupOnce/ShipWAL 生成（不伪造非法结构导致无关
// 失败）；测试自身绝不 meta.Open 不存在的路径（bbolt.Open 会创建文件，"不存在"只能
// 用 os.Stat 断言）；全部走 httptest 本地假节点，不连真集群。

// httptestSeedAddr 从 httptest.Server 取 host:port 形式的种子地址。
func httptestSeedAddr(ts *httptest.Server) string { return strings.TrimPrefix(ts.URL, "http://") }

// newFixedStatusSeed 起一个对所有请求都返回固定状态码的假种子节点。
func newFixedStatusSeed(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, http.StatusText(status), status)
	}))
}

// newNotFoundSeed 提供有效的空备份清单，并对 manifest 返回 404。
func newNotFoundSeed() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/meta-backup" {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, "[]")
			return
		}
		http.NotFound(w, r)
	}))
}

// listMetaBlobKeys 直连节点 LIST /meta-backup 取 blob key 列表。
func listMetaBlobKeys(t *testing.T, addr string) []string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/meta-backup")
	if err != nil {
		t.Fatalf("list blobs → %s: %v", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		t.Fatalf("list blobs → %s: 状态 %d", addr, resp.StatusCode)
	}
	var entries []struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("list blobs 解码 → %s: %v", addr, err)
	}
	var keys []string
	for _, e := range entries {
		keys = append(keys, e.Key)
	}
	return keys
}

// deleteMetaBlob 直连节点 DELETE 一个 blob。
func deleteMetaBlob(t *testing.T, addr, key string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, "http://"+addr+"/meta-backup/"+key, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete blob %s@%s: %v", key, addr, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete blob %s@%s: 状态 %d", key, addr, resp.StatusCode)
	}
}

// deleteWALSegBlobs 删除所有种子上的成段 WAL blob（wal-<ver>-<from>-<to>），
// 制造"快照在、增量拿不到"。散落同步帧 wal-sync-<seq> 不动。
func deleteWALSegBlobs(t *testing.T, seeds []string) {
	t.Helper()
	for _, addr := range seeds {
		for _, key := range listMetaBlobKeys(t, addr) {
			if strings.HasPrefix(key, "wal-") && !strings.HasPrefix(key, "wal-sync-") {
				deleteMetaBlob(t, addr, key)
			}
		}
	}
}

// dirEntryNames 目录条目名（升序），用于残留断言。
func dirEntryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// newClusterWithMissingWALSegs 造一个"快照已备份、成段 WAL 已从集群删除"的集群，
// 用于触发 rebuild 中途失败（公开入口可复现，不依赖私有 API）。
func newClusterWithMissingWALSegs(t *testing.T) (*MetaBackup, []string) {
	t.Helper()
	store, b, _ := newBackupCluster(t, 2)
	seeds := seedAddrs(b, t)
	store.CreateDir(meta.RootID, "snap")
	if _, err := b.BackupOnce(); err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	store.CreateDir(meta.RootID, "after-snapshot")
	if _, shipped, err := b.ShipWAL(); err != nil || !shipped {
		t.Fatalf("ShipWAL: shipped=%v err=%v", shipped, err)
	}
	store.Close()
	deleteWALSegBlobs(t, seeds)
	return b, seeds
}

// newCompleteBackupCluster 造一个"快照 + WAL 段齐全"的集群并停掉源库，
// 返回备份器、种子、期望树与期望 seq。
func newCompleteBackupCluster(t *testing.T) (*MetaBackup, []string, treeShape, uint64) {
	t.Helper()
	store, b, _ := newBackupCluster(t, 2)
	seeds := seedAddrs(b, t)
	docs, _ := store.CreateDir(meta.RootID, "docs")
	store.CreateFile(docs.ID, "a.txt", []uint64{1, 2})
	if _, err := b.BackupOnce(); err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	store.CreateDir(docs.ID, "sub")
	if _, shipped, err := b.ShipWAL(); err != nil || !shipped {
		t.Fatalf("ShipWAL: shipped=%v err=%v", shipped, err)
	}
	want := snapshotTree(t, store)
	wantSeq, err := store.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	return b, seeds, want, wantSeq
}

// recoverMissingLocalMustFailStop 断言：本地库不存在 + 给定种子组合下，
// Recover 必须 fail-stop 且目标路径不得出现任何文件。
func recoverMissingLocalMustFailStop(t *testing.T, seeds []string, dir string) {
	t.Helper()
	target := filepath.Join(dir, "master.db")
	b := NewMetaBackup(nil, time.Hour, DefaultMetaBackupConfig())
	store, err := b.Recover(target, seeds, RecoverAuto)
	if store != nil {
		store.Close()
	}
	if err == nil {
		t.Fatal("本地缺失 + 种子状态不可确认，不得当作全新集群建空库")
	}
	if _, ok := err.(*ErrFailStop); !ok {
		t.Fatalf("应 fail-stop 等人工裁决, got %T: %v", err, err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("fail-stop 后不得留下最终库文件: %v", statErr)
	}
}

// TestRecoverySafetyUnknownSeedFailStopLeavesNoDB 缺本地 + 全 seed 503：
// fail-stop，且最终 DB 不存在、目录零残留。
func TestRecoverySafetyUnknownSeedFailStopLeavesNoDB(t *testing.T) {
	overloaded := newFixedStatusSeed(http.StatusServiceUnavailable)
	defer overloaded.Close()

	dir := t.TempDir()
	recoverMissingLocalMustFailStop(t, []string{httptestSeedAddr(overloaded)}, dir)
	if names := dirEntryNames(t, dir); len(names) != 0 {
		t.Fatalf("fail-stop 后目录应零残留（无 .rebuild-tmp/.restore.tmp 等）: %v", names)
	}
}

// TestRecoverySafetyMixedSeedsUnknownNeverFresh 404 与 503 混合：
// 只要有一个种子"答不上来"，就不得当确认空集群 fresh start。
func TestRecoverySafetyMixedSeedsUnknownNeverFresh(t *testing.T) {
	overloaded := newFixedStatusSeed(http.StatusServiceUnavailable)
	defer overloaded.Close()
	absent := newNotFoundSeed()
	defer absent.Close()

	for _, o := range []struct {
		name  string
		seeds []string
	}{
		{"未知种子在前", []string{httptestSeedAddr(overloaded), httptestSeedAddr(absent)}},
		{"未知种子在后", []string{httptestSeedAddr(absent), httptestSeedAddr(overloaded)}},
	} {
		t.Run(o.name, func(t *testing.T) {
			recoverMissingLocalMustFailStop(t, o.seeds, t.TempDir())
		})
	}
}

// TestRecoverySafetyAllSeeds404ConfirmedEmptyFreshStart 兼容案例：
// 全部种子明确 404 = 确认无旧集群，允许 fresh start，库建在目标路径。
func TestRecoverySafetyAllSeeds404ConfirmedEmptyFreshStart(t *testing.T) {
	absent := newNotFoundSeed()
	defer absent.Close()

	dir := t.TempDir()
	target := filepath.Join(dir, "master.db")
	b := NewMetaBackup(nil, time.Hour, DefaultMetaBackupConfig())
	rs, err := b.Recover(target, []string{httptestSeedAddr(absent)}, RecoverAuto)
	if err != nil {
		t.Fatalf("全部种子明确无备份应允许全新启动: %v", err)
	}
	if rs == nil {
		t.Fatal("全新启动应返回可用 store")
	}
	defer rs.Close()
	if rs.DBPath() != target {
		t.Fatalf("全新启动应把库建在目标路径: got %s want %s", rs.DBPath(), target)
	}
	if seq, seqErr := rs.WALSeq(); seqErr != nil || seq != 0 {
		t.Fatalf("全新库 WAL seq 应为 0: seq=%d err=%v", seq, seqErr)
	}
	if _, statErr := os.Stat(target); statErr != nil {
		t.Fatalf("目标库文件应已创建: %v", statErr)
	}
}

// TestRecoverySafetyMalformedManifestNotTreatedAsEmpty 种子对 manifest 返回
// 200 + 损坏字节：不可当作"空"的证据，本地缺失时必须 fail-stop。
func TestRecoverySafetyMalformedManifestNotTreatedAsEmpty(t *testing.T) {
	garbage := []byte("{{{definitely-not-a-manifest")
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/meta-backup/"+ManifestKey {
			w.Write(garbage)
			return
		}
		http.NotFound(w, r)
	}))
	defer bad.Close()
	absent := newNotFoundSeed()
	defer absent.Close()

	for _, o := range []struct {
		name  string
		seeds []string
	}{
		{"仅损坏种子", []string{httptestSeedAddr(bad)}},
		{"损坏加404种子", []string{httptestSeedAddr(bad), httptestSeedAddr(absent)}},
	} {
		t.Run(o.name, func(t *testing.T) {
			recoverMissingLocalMustFailStop(t, o.seeds, t.TempDir())
		})
	}
}

// TestRecoverySafetyHealthyLocalPreferredWhenSeedsUnreachable 有效本地库 +
// 全 seed 503：按原约定使用本地（不硬停），且原数据分毫不动。
func TestRecoverySafetyHealthyLocalPreferredWhenSeedsUnreachable(t *testing.T) {
	store, b, _ := newBackupCluster(t, 2)
	store.CreateDir(meta.RootID, "snap")
	if _, err := b.BackupOnce(); err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	store.CreateDir(meta.RootID, "local-only") // 本地比集群新的部分
	want := snapshotTree(t, store)
	wantSeq, err := store.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	dbPath := store.DBPath()
	store.Close()

	overloaded := newFixedStatusSeed(http.StatusServiceUnavailable)
	defer overloaded.Close()

	// 新实例模拟进程重启；种子全部不可确认。
	fresh := NewMetaBackup(nil, time.Hour, DefaultMetaBackupConfig())
	rs, err := fresh.Recover(dbPath, []string{httptestSeedAddr(overloaded)}, RecoverAuto)
	if err != nil {
		t.Fatalf("有效本地库 + 种子不可达应按约定使用本地，不得硬停: %v", err)
	}
	defer rs.Close()
	if rs.DBPath() != dbPath {
		t.Fatalf("应继续使用原本地库路径: got %s want %s", rs.DBPath(), dbPath)
	}
	if got, seqErr := rs.WALSeq(); seqErr != nil || got != wantSeq {
		t.Fatalf("本地库 seq 被改动: want %d got %d err=%v", wantSeq, got, seqErr)
	}
	if got := snapshotTree(t, rs); !treeEq(want, got) {
		t.Fatalf("本地数据被毁:\n want=%v\n got =%v", want, got)
	}
	if _, err := rs.ResolvePath("/local-only"); err != nil {
		t.Fatalf("本地独有目录丢失（不得回退到集群旧快照）: %v", err)
	}
}

// TestRecoverySafetyFailedRebuildTargetDirClean 快照在、WAL 段拿不到：
// rebuild 必须失败、最终路径无半成品、只清理自己的 workdir、不碰无关文件。
func TestRecoverySafetyFailedRebuildTargetDirClean(t *testing.T) {
	b, seeds := newClusterWithMissingWALSegs(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "restore.db")
	keep := filepath.Join(dir, "unrelated.txt")
	keepBytes := []byte("unrelated-file-must-survive")
	if err := os.WriteFile(keep, keepBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := b.Recover(target, seeds, RecoverCluster); err == nil {
		t.Fatal("WAL 段缺失时恢复必须报错，不得静默用旧快照")
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("失败后最终路径不得存在半成品库: %v", statErr)
	}
	if names := dirEntryNames(t, dir); len(names) != 1 || names[0] != "unrelated.txt" {
		t.Fatalf("失败只应清理自己的 workdir，不得泄漏 restore 临时文件，目录残留: %v", names)
	}
	got, readErr := os.ReadFile(keep)
	if readErr != nil || !bytes.Equal(got, keepBytes) {
		t.Fatalf("无关文件被改动: %v %q", readErr, got)
	}
}

// TestRecoverySafetyStaleTmpPreservedAndRetrySucceeds 目录里既有的旧
// .rebuild-tmp：失败与成功的尝试都不得删除/覆盖它；重试靠独有 workdir 成功。
func TestRecoverySafetyStaleTmpPreservedAndRetrySucceeds(t *testing.T) {
	marker := []byte("stale-tmp-from-a-dead-previous-attempt")

	// A) 失败尝试：不留半成品，不动既有旧残留，自己产生的临时文件清理干净。
	b, seeds := newClusterWithMissingWALSegs(t)
	dirA := t.TempDir()
	targetA := filepath.Join(dirA, "restore.db")
	staleA := targetA + ".rebuild-tmp"
	if err := os.WriteFile(staleA, marker, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Recover(targetA, seeds, RecoverCluster); err == nil {
		t.Fatal("WAL 段缺失应失败")
	}
	if _, statErr := os.Stat(targetA); !os.IsNotExist(statErr) {
		t.Fatalf("失败后不得留半成品: %v", statErr)
	}
	if got, readErr := os.ReadFile(staleA); readErr != nil || !bytes.Equal(got, marker) {
		t.Fatalf("既有的旧 .rebuild-tmp 被删除/覆盖: %v %q", readErr, got)
	}
	if names := dirEntryNames(t, dirA); len(names) != 1 || names[0] != "restore.db.rebuild-tmp" {
		t.Fatalf("失败尝试应只清理自己的 workdir，目录残留: %v", names)
	}

	// B) 重试：数据完整的集群 + 同样存在旧残留 → 必须能用独有 workdir 成功发布。
	b2, seedsB, want, wantSeq := newCompleteBackupCluster(t)
	dirB := t.TempDir()
	targetB := filepath.Join(dirB, "restore.db")
	staleB := targetB + ".rebuild-tmp"
	if err := os.WriteFile(staleB, marker, 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := b2.Recover(targetB, seedsB, RecoverCluster)
	if err != nil {
		t.Fatalf("残留旧 .rebuild-tmp 不得妨碍重试（应用独有 workdir）: %v", err)
	}
	if rs.DBPath() != targetB {
		t.Fatalf("重试成功应发布到最终路径: got %s", rs.DBPath())
	}
	if got, seqErr := rs.WALSeq(); seqErr != nil || got != wantSeq {
		t.Fatalf("重试恢复 seq 不一致: want %d got %d err=%v", wantSeq, got, seqErr)
	}
	if got := snapshotTree(t, rs); !treeEq(want, got) {
		t.Fatal("重试恢复数据不符")
	}
	rs.Close()
	if got, readErr := os.ReadFile(staleB); readErr != nil || !bytes.Equal(got, marker) {
		t.Fatalf("成功路径也不得删除/覆盖既有旧 .rebuild-tmp: %v %q", readErr, got)
	}
	if names := dirEntryNames(t, dirB); len(names) != 2 || names[0] != "restore.db" || names[1] != "restore.db.rebuild-tmp" {
		t.Fatalf("成功后目录应只有最终库与旧残留两项，实际: %v", names)
	}
}

// TestRecoverySafetyPreExistingTargetRejectedUntouched 目标已存在（普通文件 /
// 悬空符号链接）：拒绝且不得修改。悬空链接 os.Stat 是 NotExist，必须按条目本身
// （Lstat）判定，否则发布会把链接整个替换掉。
func TestRecoverySafetyPreExistingTargetRejectedUntouched(t *testing.T) {
	t.Run("普通文件", func(t *testing.T) {
		b, seeds, _, _ := newCompleteBackupCluster(t)
		dir := t.TempDir()
		target := filepath.Join(dir, "restore.db")
		existing := []byte("pre-existing-payload-do-not-touch")
		if err := os.WriteFile(target, existing, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Recover(target, seeds, RecoverCluster); err == nil {
			t.Fatal("目标已存在必须拒绝覆盖")
		}
		got, readErr := os.ReadFile(target)
		if readErr != nil || !bytes.Equal(got, existing) {
			t.Fatalf("已存在的目标被修改: %v %q", readErr, got)
		}
	})
	t.Run("悬空符号链接", func(t *testing.T) {
		b, seeds, _, _ := newCompleteBackupCluster(t)
		dir := t.TempDir()
		target := filepath.Join(dir, "restore.db")
		missing := filepath.Join(dir, "vanished.bin")
		if err := os.Symlink(missing, target); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Recover(target, seeds, RecoverCluster); err == nil {
			t.Fatal("悬空符号链接目标必须拒绝（不得因 stat 跟随后“不存在”而放行）")
		}
		fi, lstatErr := os.Lstat(target)
		if lstatErr != nil {
			t.Fatalf("符号链接条目被删除: %v", lstatErr)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Fatal("目标不再是符号链接——发布覆盖了它")
		}
		if link, rlErr := os.Readlink(target); rlErr != nil || link != missing {
			t.Fatalf("符号链接被改动: link=%q err=%v", link, rlErr)
		}
		if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
			t.Fatal("符号链接应保持悬空")
		}
	})
}

// TestRecoverySafetyConcurrentTargetCreationRejectedKeepsForeignBytes 取
// 快照/WAL 期间目的路径被并发创建：发布必须拒绝（no-replace），并保住对方写入
// 的字节。并发创建用节点 GET 回调 + channel 同步，不用不确定的 sleep。
func TestRecoverySafetyConcurrentTargetCreationRejectedKeepsForeignBytes(t *testing.T) {
	store, b, _ := newBackupCluster(t, 2)
	seeds := seedAddrs(b, t)
	docs, _ := store.CreateDir(meta.RootID, "docs")
	store.CreateFile(docs.ID, "a.txt", []uint64{1, 2})
	m, err := b.BackupOnce()
	if err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	if len(m.Chunks) == 0 {
		t.Fatal("manifest 应含快照块")
	}
	// 真集群节点上的合法 manifest 与块字节（读结构校验用合法生成方法）。
	manifestBytes, code := getBlob(t, seeds[0], ManifestKey)
	if code != http.StatusOK {
		t.Fatalf("读回 manifest: 状态 %d", code)
	}
	chunkBytes := map[string][]byte{}
	for _, ch := range m.Chunks {
		data, c := getBlob(t, seeds[0], ch.Key)
		if c != http.StatusOK {
			t.Fatalf("读回块 %s: 状态 %d", ch.Key, c)
		}
		chunkBytes[ch.Key] = data
	}
	store.Close()

	dir := t.TempDir()
	target := filepath.Join(dir, "restore.db")
	foreign := []byte("concurrent-creator-payload-must-survive")

	var once sync.Once
	created := make(chan struct{})
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/meta-backup": // LIST：空
			w.Write([]byte("[]"))
		case r.URL.Path == "/meta-backup/"+ManifestKey:
			w.Write(manifestBytes)
		default:
			if data, ok := chunkBytes[strings.TrimPrefix(r.URL.Path, "/meta-backup/")]; ok {
				// 取块途中，第三方并发创建了最终目标文件。
				once.Do(func() {
					if werr := os.WriteFile(target, foreign, 0o600); werr != nil {
						t.Errorf("并发创建目标文件失败: %v", werr)
					}
					close(created)
				})
				w.Write(data)
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer fake.Close()

	if _, err := b.Recover(target, []string{httptestSeedAddr(fake)}, RecoverCluster); err == nil {
		t.Fatal("发布时目的路径已被并发创建，必须拒绝（no-replace），不得覆盖对方字节")
	}
	select {
	case <-created:
	default:
		t.Fatal("前置条件未触发：并发创建没有发生在取块/取 WAL 期间")
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil || !bytes.Equal(got, foreign) {
		t.Fatalf("并发写入方的字节被破坏: %v %q", readErr, got)
	}
	if names := dirEntryNames(t, dir); len(names) != 1 || names[0] != "restore.db" {
		t.Fatalf("拒绝发布后只应留下对方文件，目录残留: %v", names)
	}
}

// TestRecoverySafetySuccessfulRebuildPublishesFinalDB 成功恢复：Store.DBPath
// 是最终目标路径（不是 workdir/临时路径），Close 再 Open 数据与 seq 一致，
// 目录除最终库外无任何临时残留。
func TestRecoverySafetySuccessfulRebuildPublishesFinalDB(t *testing.T) {
	b, seeds, want, wantSeq := newCompleteBackupCluster(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "rebuilt.db")
	rs, err := b.Recover(target, seeds, RecoverCluster)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if rs.DBPath() != target {
		t.Fatalf("成功恢复的 Store 应打开在最终目标路径: got %s want %s", rs.DBPath(), target)
	}
	if got, seqErr := rs.WALSeq(); seqErr != nil || got != wantSeq {
		t.Fatalf("恢复后 seq 不一致: want %d got %d err=%v", wantSeq, got, seqErr)
	}
	if got := snapshotTree(t, rs); !treeEq(want, got) {
		t.Fatalf("恢复后数据不符:\n want=%v\n got =%v", want, got)
	}
	if err := rs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close 再 Open：库就在最终路径上，数据与 seq 与恢复结果一致。
	// （target 此刻必然存在——上面 DBPath/读取已证明，Open 不会凭空造文件。）
	rs2, err := meta.Open(target)
	if err != nil {
		t.Fatalf("重新打开最终库: %v", err)
	}
	defer rs2.Close()
	if got, seqErr := rs2.WALSeq(); seqErr != nil || got != wantSeq {
		t.Fatalf("重开后 seq 不一致: want %d got %d err=%v", wantSeq, got, seqErr)
	}
	if got := snapshotTree(t, rs2); !treeEq(want, got) {
		t.Fatal("重开后数据不符")
	}
	if names := dirEntryNames(t, dir); len(names) != 1 || names[0] != "rebuilt.db" {
		t.Fatalf("成功路径不应残留 workdir/临时文件，目录内容: %v", names)
	}
}
