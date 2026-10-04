package master

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master/meta"
)

// 恢复协议三缺口回归（源自 2026-10-03 架构评估隔离复现，先红后绿）。

// TestRecoveryUnreachableSeedsNotEmptyCluster 本地库不存在 + 配置的种子全部不可达/报错，
// 必须 fail-stop——"没查到"不等于"确认没有旧集群"。全新集群需要全部种子明确 404。
func TestRecoveryUnreachableSeedsNotEmptyCluster(t *testing.T) {
	errSeed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer errSeed.Close()
	backup := NewMetaBackup(nil, time.Hour, DefaultMetaBackupConfig())
	path := filepath.Join(t.TempDir(), "lost-master.db")
	store, err := backup.Recover(path, []string{errSeed.Listener.Addr().String()}, RecoverAuto)
	if store != nil {
		defer store.Close()
	}
	if err == nil {
		t.Fatal("全部种子不可达时创建空库 = 把'没查到'误当'全新集群'")
	}
	if _, ok := err.(*ErrFailStop); !ok {
		t.Fatalf("应 fail-stop 等人工裁决, got %T: %v", err, err)
	}
	if store != nil {
		t.Fatal("fail-stop 不得返回 store（不得留下已打开的空库）")
	}
	// 对照：种子明确返回 404（确认无 manifest）才允许 fresh start。
	emptySeed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/meta-backup" {
			io.WriteString(w, "[]")
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer emptySeed.Close()
	backup2 := NewMetaBackup(nil, time.Hour, DefaultMetaBackupConfig())
	store2, err2 := backup2.Recover(filepath.Join(t.TempDir(), "fresh.db"),
		[]string{emptySeed.Listener.Addr().String()}, RecoverAuto)
	if err2 != nil {
		t.Fatalf("全部种子确认无备份时应允许全新启动: %v", err2)
	}
	if store2 == nil {
		t.Fatal("全新启动应返回可用 store")
	}
	store2.Close()
}

// TestRecoveryFailedRebuildLeavesNoFinalDB 快照落地但 WAL 段取不到时，
// 恢复必须报错且 dbPath 不能留下可正常打开的半成品库。
func TestRecoveryFailedRebuildLeavesNoFinalDB(t *testing.T) {
	src, b, _ := newBackupCluster(t, 2)
	seeds := seedAddrs(b, t)
	src.CreateDir(meta.RootID, "a")
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	src.CreateDir(meta.RootID, "after-snapshot")
	m, shipped, err := b.ShipWAL()
	if err != nil || !shipped {
		t.Fatalf("ShipWAL: shipped=%v err=%v", shipped, err)
	}
	src.Close()

	// 删除所有种子上的 WAL 段 blob，制造"快照在、增量拿不到"。
	for _, addr := range seeds {
		blobs, _ := b.listBlobs(addr)
		for _, bl := range blobs {
			if strings.HasPrefix(bl.Key, "wal-") && !strings.HasPrefix(bl.Key, "wal-sync-") {
				_ = b.deleteBlob(addr, bl.Key)
			}
		}
	}
	target := filepath.Join(t.TempDir(), "restore.db")
	_, err = b.rebuildFromCluster(target, m, seeds)
	if err == nil {
		t.Fatal("WAL 段缺失必须报错，不能静默用旧快照")
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("恢复失败后最终路径不应存在半成品库: stat=%v", statErr)
	}
}

// TestSyncKnobPrefixContinuity 同步旋钮：第 N 帧 ship 失败（本地已提交，客户端已报错），
// 后续帧在补上前缀之前不得成功 ack；补洞恢复后重放必须连续。
func TestSyncKnobPrefixContinuity(t *testing.T) {
	store, b, _ := newBackupCluster(t, 1)
	seeds := seedAddrs(b, t)
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	seq, err := store.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	blockedSeq := seq + 1
	blockedKey := fmt.Sprintf("wal-sync-%d", blockedSeq)
	var block atomic.Bool
	block.Store(true)
	// 注入：阻断特定 wal-sync 键的写入，模拟单帧同步失败。
	base := b.httpClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	b.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, blockedKey) && block.Load() {
			return &http.Response{StatusCode: http.StatusServiceUnavailable,
				Header: make(http.Header), Body: io.NopCloser(strings.NewReader("blocked")), Request: r}, nil
		}
		return base.RoundTrip(r)
	})
	b.SetConfig(MetaBackupConfig{Replicas: 1, Retention: 3, Interval: time.Hour, SyncBeforeAck: true, SyncMinCopies: 1})
	b.InstallSyncHook()

	if _, err := store.CreateDir(meta.RootID, "first"); err == nil {
		t.Fatal("注入失败未生效：第一帧应 ship 失败")
	}
	// 第二帧：前缀未补齐前必须失败（不能 ack 出一个恢复不了的状态）。
	if _, err := store.CreateDir(meta.RootID, "second"); err == nil {
		t.Fatal("前缀有缺口时后续写被确认——恢复时这段 ack 不可重放")
	}
	// 解除阻断：下一笔写必须先补上前缀再确认自己。
	block.Store(false)
	if _, err := store.CreateDir(meta.RootID, "third"); err != nil {
		t.Fatalf("阻断解除后应补齐前缀并确认: %v", err)
	}
	// 集群重建：三笔全部在（前缀连续），重放无缺口。
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

// roundTripFunc 函数型 Transport（故障注入用）。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
