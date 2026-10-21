package master

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/contentcrypto"
	"atoll/pkg/metacrypto"
)

func encryptedBackupCluster(t *testing.T, nodes int) (*meta.Store, *MetaBackup, map[uint64]string, *contentcrypto.KEK) {
	t.Helper()
	store, b, addrs := newBackupCluster(t, nodes)
	kek, err := contentcrypto.NewKEK("meta-backup-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SetMetaKEK(kek); err != nil {
		t.Fatalf("SetMetaKEK: %v", err)
	}
	return store, b, addrs, kek
}

// 加密备份全链路：节点磁盘只见密文（无明文样本、无 ATMB 头外明文），
// Recover 用同一 KEK 重建出全部内容。
func TestEncryptedBackupRoundTripAndRecover(t *testing.T) {
	store, b, addrs, kek := encryptedBackupCluster(t, 3)
	store.CreateDir(meta.RootID, "secret-dir")
	store.CreateDir(meta.RootID, "another-dir")
	m, err := b.BackupOnce()
	if err != nil {
		t.Fatalf("BackupOnce: %v", err)
	}
	if !m.Encrypted || m.Namespace == "" {
		t.Fatalf("manifest missing encryption identity: %+v", m)
	}
	// 节点磁盘：manifest 与全部快照块必须是 ATMB 密文，且搜不到明文样本。
	for _, addr := range addrs {
		for _, ch := range m.Chunks {
			raw, code := getBlob(t, addr, ch.Key)
			if code != 200 {
				t.Fatalf("node %s: %s status %d", addr, ch.Key, code)
			}
			if !metacrypto.IsEncrypted(raw) {
				t.Fatalf("node %s stores plaintext snapshot chunk %s", addr, ch.Key)
			}
			if strings.Contains(string(raw), "secret-dir") || strings.Contains(string(raw), "another-dir") {
				t.Fatalf("node %s chunk %s leaks directory names", addr, ch.Key)
			}
		}
		mf, code := getBlob(t, addr, ManifestKey)
		if code != 200 || !metacrypto.IsEncrypted(mf) {
			t.Fatalf("node %s manifest not encrypted (code=%d)", addr, code)
		}
		if strings.Contains(string(mf), "secret-dir") {
			t.Fatalf("node %s manifest leaks content names", addr)
		}
	}
	// 中心全损：本地库删除，仅凭种子 + 同一 KEK 重建。
	path := filepath.Join(t.TempDir(), "rebuilt.db")
	rs, err := b.Recover(path, syncSeeds(addrs), RecoverCluster)
	if err != nil {
		t.Fatalf("Recover with same KEK: %v", err)
	}
	defer rs.Close()
	for _, name := range []string{"secret-dir", "another-dir"} {
		if _, err := rs.ResolvePath("/" + name); err != nil {
			t.Fatalf("recovered store missing %s: %v", name, err)
		}
	}
	_ = kek
}

// 错误 KEK / 无 KEK 的恢复必须 fail-closed：密文不可降级读出，也不报成功。
func TestEncryptedRecoverRejectsWrongOrMissingKEK(t *testing.T) {
	store, b, addrs, _ := encryptedBackupCluster(t, 2)
	store.CreateDir(meta.RootID, "private")
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	seeds := syncSeeds(addrs)
	path := filepath.Join(t.TempDir(), "nokek.db")
	if rs, err := NewMetaBackup(nil, time.Minute, DefaultMetaBackupConfig()).Recover(path, seeds, RecoverCluster); err == nil || rs != nil {
		t.Fatal("recover without KEK must fail closed")
	}
	// 换一把不同 KEK 的备份器：同 keyID 也不行（HMAC 域隔离）。
	fresh := NewMetaBackup(nil, time.Minute, DefaultMetaBackupConfig())
	fresh.SetToken("")
	if err := fresh.SetMetaKEK(mustOtherKEK(t)); err != nil {
		t.Fatal(err)
	}
	fresh.SetStore(store)
	path2 := filepath.Join(t.TempDir(), "wrongkek.db")
	if rs, err := fresh.Recover(path2, seeds, RecoverCluster); err == nil || rs != nil {
		t.Fatal("recover with wrong KEK must fail closed")
	}
}

func mustOtherKEK(t *testing.T) *contentcrypto.KEK {
	t.Helper()
	// 同 keyID、不同密钥材料——防"只比 keyID"的假校验。
	kek, err := contentcrypto.NewKEKFromSecret("meta-backup-test", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

// 同步旋钮 + 加密：wal-sync 帧同样密文上船；基线核验/补写按解密内容比对，
// 写 ack 前缀语义不回归。
func TestEncryptedSyncKnobAndLooseFrames(t *testing.T) {
	store, b, addrs, _ := encryptedBackupCluster(t, 3)
	if _, err := b.BackupOnce(); err != nil {
		t.Fatal(err)
	}
	b.SetConfig(MetaBackupConfig{Replicas: 3, Retention: 3, Interval: time.Hour,
		SyncBeforeAck: true, SyncMinCopies: 2})
	b.InstallSyncHook()
	store.CreateDir(meta.RootID, "synced-1")
	store.CreateDir(meta.RootID, "synced-2")
	// 同步帧也必须密文。
	plainFound := false
	for _, addr := range addrs {
		for key := range syncBlobKeys(t, b, addrs) {
			raw, code := getBlob(t, addr, key)
			if code == 200 && strings.HasPrefix(key, "wal-sync-") && !metacrypto.IsEncrypted(raw) {
				plainFound = true
			}
		}
	}
	if plainFound {
		t.Fatal("sync frames leaked plaintext with encryption enabled")
	}
	// 中心全损后恢复：快照 + 散落同步帧都要回来。
	dbPath := store.DBPath()
	store.Close()
	os.Remove(dbPath)
	rs, err := b.Recover(dbPath, syncSeeds(addrs), RecoverCluster)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	defer rs.Close()
	for _, name := range []string{"synced-1", "synced-2"} {
		if _, err := rs.ResolvePath("/" + name); err != nil {
			t.Fatalf("recovered store missing %s: %v", name, err)
		}
	}
}
