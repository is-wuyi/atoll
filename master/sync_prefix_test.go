package master

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/master/meta"
)

// 同步旋钮前缀连续性测试（本文件归 sync-prefix 修复所有）。
//
// 不变量：
//  1. 同步模式下，一笔写 ack 的前提是「尚未逐帧确认的前缀 (syncSeq, seq] 中每一帧
//     都以 wal-sync-<seq> blob 取得 ≥ SyncMinCopies 个节点确认」。补不齐则报错，
//     绝不 ack 出"集群 WAL 跳号"的恢复不了的状态；阻断解除后由下一笔写补洞。
//  2. 快照吸收（BackupOnce 覆盖未确认帧）只有在该备份本身达到 W（每块快照与
//     manifest 都 ≥W 份持有）时才可以充当那段前缀的耐久载体；旋钮开时备份不达 W
//     必须整体失败，不得静默降级恢复锚点。
//  3. 本地 WAL 地板之下的缺口（历史截断）只有在 W 可靠基线（实际读集群核验/补写
//     达 W 的 manifest+快照块）覆盖时才可越过；否则 fail-closed 报错，不静默跳过。
//  4. 水印/基线是进程内状态：重启、旋钮关→开、SyncMinCopies 提高一律作废重证。
//  5. op 重放路径必须过耐久闸（EnsureDurable）：前缀未确认不得放行"回放成功"。
//
// 注意：newBackupCluster 注册节点本身占 WAL 帧，所有 seq 以 BackupOnce 之后的
// store.WALSeq() 为基线动态推导，勿硬编码。

// syncPrefixProbe 故障注入 Transport：按 blob key 阻断 PUT（可限定单个节点）、
// 整节点断写（快照/manifest）、或让前 N 次 wal-sync PUT 一律失败。其余请求直通。
type syncPrefixProbe struct {
	base              http.RoundTripper
	mu                sync.Mutex
	blocked           map[string]bool            // wal-sync key → 所有节点阻断
	blockedAt         map[string]map[string]bool // wal-sync key → 节点地址 → 阻断
	blockSnapshotAddr map[string]bool            // 节点地址 → 阻断其全部 meta-backup PUT
	failFirst         int                        // 剩余前 N 次 wal-sync PUT 失败
}

func newSyncPrefixProbe(base http.RoundTripper) *syncPrefixProbe {
	if base == nil {
		base = http.DefaultTransport
	}
	return &syncPrefixProbe{base: base, blocked: map[string]bool{}}
}

func (p *syncPrefixProbe) setBlocked(key string, on bool) {
	p.mu.Lock()
	p.blocked[key] = on
	p.mu.Unlock()
}

func (p *syncPrefixProbe) setBlockedAt(key, addr string, on bool) {
	p.mu.Lock()
	if p.blockedAt == nil {
		p.blockedAt = map[string]map[string]bool{}
	}
	if p.blockedAt[key] == nil {
		p.blockedAt[key] = map[string]bool{}
	}
	p.blockedAt[key][addr] = on
	p.mu.Unlock()
}

// blockNodeOn 让某节点的全部 meta-backup PUT 失败（构造"快照/manifest 不足 W"用）。
func (p *syncPrefixProbe) blockNodeOn(addr string, on bool) {
	p.mu.Lock()
	if p.blockSnapshotAddr == nil {
		p.blockSnapshotAddr = map[string]bool{}
	}
	p.blockSnapshotAddr[addr] = on
	p.mu.Unlock()
}

func (p *syncPrefixProbe) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPut && strings.HasPrefix(req.URL.Path, "/meta-backup/") {
		key := strings.TrimPrefix(req.URL.Path, "/meta-backup/")
		p.mu.Lock()
		nodeDown := p.blockSnapshotAddr[req.URL.Host]
		isWALSync := strings.HasPrefix(key, "wal-sync-")
		at := isWALSync && p.blockedAt[key][req.URL.Host]
		fail := nodeDown || (isWALSync && (p.blocked[key] || at || p.failFirst > 0))
		if fail && isWALSync && p.failFirst > 0 && !p.blocked[key] && !at {
			p.failFirst--
		}
		p.mu.Unlock()
		if fail {
			return &http.Response{StatusCode: http.StatusServiceUnavailable,
				Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString("blocked")), Request: req}, nil
		}
	}
	return p.base.RoundTrip(req)
}

func syncSeeds(addrs map[uint64]string) []string {
	var seeds []string
	for _, a := range addrs {
		seeds = append(seeds, a)
	}
	return seeds
}

func syncBlobKeys(t *testing.T, b *MetaBackup, addrs map[uint64]string) map[string]int {
	t.Helper()
	keys := map[string]int{}
	for _, addr := range addrs {
		blobs, err := b.listBlobs(addr)
		if err != nil {
			t.Fatalf("listBlobs: %v", err)
		}
		for _, bl := range blobs {
			if strings.HasPrefix(bl.Key, "wal-sync-") {
				keys[bl.Key]++
			}
		}
	}
	return keys
}

// syncKey 生成第 n 帧（相对基线）的同步 blob key。
func syncKey(baseSeq, n uint64) string { return fmt.Sprintf("wal-sync-%d", baseSeq+n) }

// 场景一：第 N 帧 ship 失败 → 后续写在补齐前缀前必须失败（不能跳号 ack）；
// 阻断解除后下一笔写补齐 N、N+1 再确认自己；集群重建三笔全在。
func TestSyncPrefixBackfillBlocksAckUntilFilled(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 1)
	seeds := syncSeeds(addrs)
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	baseSeq, err := store.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	b.SetConfig(MetaBackupConfig{Replicas: 1, Retention: 3, Interval: time.Hour,
		SyncBeforeAck: true, SyncMinCopies: 1})
	b.InstallSyncHook()

	probe := newSyncPrefixProbe(b.httpClient.Transport)
	b.httpClient.Transport = probe

	// 帧1：注入阻断 → 写失败（本地已提交，客户端报错）。
	probe.setBlocked(syncKey(baseSeq, 1), true)
	if _, err := store.CreateDir(meta.RootID, "first"); err == nil {
		t.Fatal("注入失败未生效：第一帧应 ship 失败")
	}
	// 帧2：前缀未补齐前必须失败，且不得把帧2单独 ship 出去（跳号）。
	if _, err := store.CreateDir(meta.RootID, "second"); err == nil {
		t.Fatal("前缀有缺口时后续写被确认——恢复时这段 ack 不可重放")
	}
	if keys := syncBlobKeys(t, b, addrs); len(keys) != 0 {
		t.Fatalf("前缀阻断期间不应产生任何 wal-sync blob（跳号 ship），got %v", keys)
	}

	// 解除阻断：帧3 的钩子必须先补齐帧1、帧2 再确认自己。
	probe.setBlocked(syncKey(baseSeq, 1), false)
	if _, err := store.CreateDir(meta.RootID, "third"); err != nil {
		t.Fatalf("阻断解除后应补齐前缀并确认: %v", err)
	}
	keys := syncBlobKeys(t, b, addrs)
	for _, n := range []uint64{1, 2, 3} {
		if keys[syncKey(baseSeq, n)] == 0 {
			t.Fatalf("补齐后集群缺 %s（got %v）", syncKey(baseSeq, n), keys)
		}
	}

	// 集群重建：三笔全在、重放无缺口。
	path := filepath.Join(t.TempDir(), "rebuilt.db")
	rs, err := b.Recover(path, seeds, RecoverCluster)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	defer rs.Close()
	for _, name := range []string{"first", "second", "third"} {
		if _, err := rs.ResolvePath("/" + name); err != nil {
			t.Errorf("恢复后缺 %s: %v（同步 ack 的写不可丢）", name, err)
		}
	}
}

// 场景二：旋钮开时备份必须达到同步耐久标准——某节点断写导致快照不足 W 份 →
// 整个 BackupOnce 失败（不更新 manifest、不截断、不清理），未确认前缀仍阻断后续
// 写；备份达 W 成功后，被快照 W 覆盖的未确认帧才可由基线承接。
func TestSyncBackupStrictAndBaselineAbsorption(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 2)
	seeds := syncSeeds(addrs)
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	baseSeq, err := store.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	b.SetConfig(MetaBackupConfig{Replicas: 2, Retention: 3, Interval: time.Hour,
		SyncBeforeAck: true, SyncMinCopies: 2})
	b.InstallSyncHook()

	probe := newSyncPrefixProbe(b.httpClient.Transport)
	b.httpClient.Transport = probe
	var addrA string
	for _, addr := range addrs {
		addrA = addr
		break
	}

	if _, err := store.CreateDir(meta.RootID, "a"); err != nil {
		t.Fatalf("a: %v", err)
	}
	if _, err := store.CreateDir(meta.RootID, "b"); err != nil {
		t.Fatalf("b: %v", err)
	}
	// 帧3 双节点都 ship 失败 → 写失败。
	probe.setBlocked(syncKey(baseSeq, 3), true)
	if _, err := store.CreateDir(meta.RootID, "c"); err == nil {
		t.Fatal("帧3 应 ship 失败")
	}
	// 节点 A 断写 → 旋钮开的备份快照最多 1/2 份 → 必须整体失败。
	probe.blockNodeOn(addrA, true)
	if _, err := b.BackupOnce(); err == nil {
		t.Fatal("旋钮开且快照只能落 1/2 份时，BackupOnce 必须失败（不得静默降级恢复锚点）")
	}
	// 备份失败期间不得产生跳号确认：帧4 仍被未确认的帧3 阻断。
	if _, err := store.CreateDir(meta.RootID, "d"); err == nil {
		t.Fatal("备份未达 W 时未确认前缀仍应阻断后续写")
	}
	probe.blockNodeOn(addrA, false)

	// 恢复到 W：备份成功且达 2/2 → 基线（快照锚点）W 覆盖帧3 → 帧4、帧5 可确认。
	if _, err := b.BackupOnce(); err != nil {
		t.Fatalf("节点恢复后 BackupOnce 应成功: %v", err)
	}
	if _, err := store.CreateDir(meta.RootID, "e"); err != nil {
		t.Fatalf("基线已 W 覆盖未确认帧，帧4/5 应可确认: %v", err)
	}
	probe.setBlocked(syncKey(baseSeq, 3), false)
	if _, err := store.CreateDir(meta.RootID, "f"); err != nil {
		t.Fatalf("f: %v", err)
	}

	path := filepath.Join(t.TempDir(), "rebuilt.db")
	rs, err := b.Recover(path, seeds, RecoverCluster)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	defer rs.Close()
	for _, name := range []string{"a", "b", "c", "d", "e", "f"} {
		if _, err := rs.ResolvePath("/" + name); err != nil {
			t.Errorf("恢复后缺 %s: %v", name, err)
		}
	}
}

// 场景三（重启）：水印/基线是进程内状态——重启后（新 MetaBackup）不得复用旧进程
// 的确认状态直接放行写：必须先重新确证基线；基线不可得（未做首次备份/不达 W）时
// fail-closed，绝不静默沿用。基线重建（重启后首拍）后写恢复、前缀连续。
func TestSyncWatermarkInvalidatedOnRestart(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 2)
	seeds := syncSeeds(addrs)
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	b.SetConfig(MetaBackupConfig{Replicas: 2, Retention: 3, Interval: time.Hour,
		SyncBeforeAck: true, SyncMinCopies: 2})
	b.InstallSyncHook()
	if _, err := store.CreateDir(meta.RootID, "a"); err != nil {
		t.Fatalf("a: %v", err)
	}
	blobsAfterA := syncBlobKeys(t, b, addrs)

	// 模拟重启：全新 MetaBackup 内存态（基线/水印归零），同一 store，尚未做首拍。
	b2 := NewMetaBackup(store, time.Minute, DefaultMetaBackupConfig())
	b2.SetConfig(MetaBackupConfig{Replicas: 2, Retention: 3, Interval: time.Hour,
		SyncBeforeAck: true, SyncMinCopies: 2})
	b2.InstallSyncHook()
	probe := newSyncPrefixProbe(b2.httpClient.Transport)
	b2.httpClient.Transport = probe
	var addrA string
	for _, addr := range addrs {
		addrA = addr
		break
	}
	// 旧进程明明已确认过帧1，但重启后内存作废：基线未重建前写必须 fail-closed，
	// 且不得产生任何新同步帧（绝不静默沿用旧状态放行）。
	probe.blockNodeOn(addrA, true)
	if _, err := store.CreateDir(meta.RootID, "b"); err == nil {
		t.Fatal("重启后基线未重建，写不得放行（不得复用旧进程确认状态）")
	}
	if keys := syncBlobKeys(t, b2, addrs); len(keys) != len(blobsAfterA) {
		t.Fatalf("基线未重建前不得新增同步帧 blob，before=%v after=%v", blobsAfterA, keys)
	}
	// 重启后首拍（对应 StartLoop）：节点 A 恢复 → 严格备份达 2/2 → 基线重建。
	probe.blockNodeOn(addrA, false)
	if _, err := b2.BackupOnce(); err != nil {
		t.Fatalf("重启后首次备份: %v", err)
	}
	if _, err := store.CreateDir(meta.RootID, "c"); err != nil {
		t.Fatalf("基线重建后写应恢复: %v", err)
	}

	path := filepath.Join(t.TempDir(), "rebuilt.db")
	rs, err := b2.Recover(path, seeds, RecoverCluster)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	defer rs.Close()
	for _, name := range []string{"a", "b", "c"} {
		if _, err := rs.ResolvePath("/" + name); err != nil {
			t.Errorf("恢复后缺 %s: %v", name, err)
		}
	}
}

// 场景四（副本要求提高）：旧水印只代表旧要求下的确认；SyncMinCopies 提高后必须
// 作废重补，不得复用。
func TestSyncWatermarkInvalidatedOnRequirementRaise(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 2)
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	baseSeq, err := store.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	b.SetConfig(MetaBackupConfig{Replicas: 2, Retention: 3, Interval: time.Hour,
		SyncBeforeAck: true, SyncMinCopies: 1})
	b.InstallSyncHook()
	if _, err := store.CreateDir(meta.RootID, "a"); err != nil {
		t.Fatalf("a: %v", err)
	}

	// 要求 1 → 2：水印按"确认要求提高即作废"处理，下笔写需重新逐帧确认。
	b.SetConfig(MetaBackupConfig{Replicas: 2, Retention: 3, Interval: time.Hour,
		SyncBeforeAck: true, SyncMinCopies: 2})
	probe := newSyncPrefixProbe(b.httpClient.Transport)
	b.httpClient.Transport = probe
	// 注入：帧1 只能落到其中一个节点（重补只得 1 份 < 2）→ 必须失败。
	var addrA string
	for _, addr := range addrs {
		addrA = addr
		break
	}
	probe.setBlockedAt(syncKey(baseSeq, 1), addrA, true)
	if _, err := store.CreateDir(meta.RootID, "b"); err == nil {
		t.Fatal("确认要求提高后不得复用旧水印：帧1 重补不足 W 应失败")
	}
	probe.setBlockedAt(syncKey(baseSeq, 1), addrA, false)
	if _, err := store.CreateDir(meta.RootID, "c"); err != nil {
		t.Fatalf("解除部分阻断后应补齐并确认: %v", err)
	}
	if keys := syncBlobKeys(t, b, addrs); keys[syncKey(baseSeq, 1)] < 2 {
		t.Fatalf("补齐后帧1 应有 2 份，got %v", keys)
	}
}

// 场景五（基线确证 fail-closed）：异步期快照只有 1 份（节点 A 断写期间备份）。
// 旋钮开之后，本地地板之下的截断缺口只有基线被"实际核验/补写到达 W"才可越过；
// 补写不上去 → 写明确报错（提示先补备份），绝不静默跳过。
func TestSyncPrefixFailClosedOnMissingBaseline(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 2)
	seeds := syncSeeds(addrs)
	probe := newSyncPrefixProbe(b.httpClient.Transport)
	b.httpClient.Transport = probe
	var addrA string
	for _, addr := range addrs {
		addrA = addr
		break
	}

	// 旋钮关：节点 A 断写期间异步备份 → 快照/manifest 只有 1 份（B 上）。
	probe.blockNodeOn(addrA, true)
	store.CreateDir(meta.RootID, "a")
	store.CreateDir(meta.RootID, "b")
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	probe.blockNodeOn(addrA, false)

	// 旋钮开（关→开作废内存基线）：帧a、b 已被截断，本地地板=快照锚点+1。
	b.SetConfig(MetaBackupConfig{Replicas: 2, Retention: 3, Interval: time.Hour,
		SyncBeforeAck: true, SyncMinCopies: 2})
	b.InstallSyncHook()

	// 再次断 A：基线核验要把它补到 2 份，补写失败 → 写必须 fail-closed。
	probe.blockNodeOn(addrA, true)
	_, err := store.CreateDir(meta.RootID, "c")
	if err == nil {
		t.Fatal("W 基线未确证且本地存在超出基线的截断缺口时，写必须失败")
	}
	if !strings.Contains(err.Error(), "基线") {
		t.Fatalf("错误应指明基线未确证，got: %v", err)
	}
	if keys := syncBlobKeys(t, b, addrs); len(keys) != 0 {
		t.Fatalf("基线未确证前不得 ship 任何同步帧，got %v", keys)
	}
	// 恢复节点 A：基线补写达 2/2 → 缺口段被 W 基线承接 → 写放行。
	probe.blockNodeOn(addrA, false)
	if _, err := store.CreateDir(meta.RootID, "d"); err != nil {
		t.Fatalf("基线补齐后写应成功: %v", err)
	}

	path := filepath.Join(t.TempDir(), "rebuilt.db")
	rs, err := b.Recover(path, seeds, RecoverCluster)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	defer rs.Close()
	for _, name := range []string{"a", "b", "c", "d"} {
		if _, err := rs.ResolvePath("/" + name); err != nil {
			t.Errorf("恢复后缺 %s: %v", name, err)
		}
	}
}

// 场景六：op 重放耐久闸——本地 ops 记录回放"成功"前，必须先确认前缀已按同步
// 策略落集群；否则回放会绕过 failed hook 造出假同步承诺。
func TestEnsureDurableGatesReplayedResults(t *testing.T) {
	store, b, _ := newBackupCluster(t, 1)
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	baseSeq, err := store.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	b.SetConfig(MetaBackupConfig{Replicas: 1, Retention: 3, Interval: time.Hour,
		SyncBeforeAck: true, SyncMinCopies: 1})
	b.InstallSyncHook()

	probe := newSyncPrefixProbe(b.httpClient.Transport)
	b.httpClient.Transport = probe
	probe.setBlocked(syncKey(baseSeq, 1), true)
	if _, err := store.CreateDir(meta.RootID, "pending"); err == nil {
		t.Fatal("帧1 应 ship 失败（本地已提交、未确认）")
	}
	// 重放路径：handler 在返回既有结果前调用 EnsureDurable——前缀未确认必须报错。
	if err := store.EnsureDurable(); err == nil {
		t.Fatal("前缀未确认时 EnsureDurable 必须失败（不得放行回放成功）")
	}
	probe.setBlocked(syncKey(baseSeq, 1), false)
	if err := store.EnsureDurable(); err != nil {
		t.Fatalf("阻断解除后 EnsureDurable 应补齐前缀并放行: %v", err)
	}
}

// 场景七：并发写 + 并发 BackupOnce（严格备份与钩子赛跑）+ 瞬时故障：最终恢复
// 必须包含每一笔"被 ack"的写。-race 下验证锁序无死锁、无数据竞争。
func TestSyncPrefixConcurrentBackupWritesRecover(t *testing.T) {
	store, b, addrs := newBackupCluster(t, 2)
	seeds := syncSeeds(addrs)
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	b.SetConfig(MetaBackupConfig{Replicas: 2, Retention: 3, Interval: time.Hour,
		SyncBeforeAck: true, SyncMinCopies: 1})
	b.InstallSyncHook()
	probe := newSyncPrefixProbe(b.httpClient.Transport)
	probe.mu.Lock()
	probe.failFirst = 6 // 前 6 次 wal-sync PUT 失败（前几帧暂不可确认）
	probe.mu.Unlock()
	b.httpClient.Transport = probe

	var mu sync.Mutex
	acked := map[string]bool{}
	errored := 0
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				name := fmt.Sprintf("conc-%d-%d", w, i)
				_, err := store.CreateDir(meta.RootID, name)
				mu.Lock()
				if err == nil {
					acked[name] = true
				} else {
					errored++
				}
				mu.Unlock()
			}
		}(w)
	}
	// 并发备份：与钩子/基线/截断赛跑（opMu 串行，严格性保证不降级锚点）。
	var backupWG sync.WaitGroup
	backupWG.Add(1)
	go func() {
		defer backupWG.Done()
		for i := 0; i < 3; i++ {
			time.Sleep(20 * time.Millisecond)
			if _, err := b.BackupOnce(); err != nil {
				t.Logf("并发 BackupOnce 失败（允许，重试即可）: %v", err)
			}
		}
	}()
	wg.Wait()
	backupWG.Wait()

	// 收尾：一笔必然成功的写把残余前缀全部补齐（故障已解除）。
	var finalErr error
	for i := 0; i < 50; i++ {
		if _, finalErr = store.CreateDir(meta.RootID, "conc-final"); finalErr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if finalErr != nil {
		t.Fatalf("故障解除后收尾写仍失败: %v", finalErr)
	}
	if errored == 0 {
		t.Fatal("注入的瞬时故障未生效（应至少有一笔写被拒）")
	}

	path := filepath.Join(t.TempDir(), "rebuilt.db")
	rs, err := b.Recover(path, seeds, RecoverCluster)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	defer rs.Close()
	for name := range acked {
		if _, err := rs.ResolvePath("/" + name); err != nil {
			t.Errorf("被 ack 的写 %s 恢复后缺失: %v", name, err)
		}
	}
}
