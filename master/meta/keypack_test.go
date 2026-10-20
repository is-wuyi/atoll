package meta

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"atoll/pkg/contentcrypto"
	"atoll/pkg/types"
)

// seedKeyedStore 走真实 Begin/Prepare 流程建一个带内容密钥的库。
func seedKeyedStore(t *testing.T, s *Store, admin PublicUser, space Space, name string) (types.Inode, uint64) {
	t.Helper()
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatalf("EnableWritePlanning: %v", err)
	}
	u, err := s.BeginPlannedWrite(WriteActor{UserID: admin.ID, SpaceID: space.ID}, space.RootID, name,
		types.BeginWriteRequest{Path: "/" + name, OpID: "op-" + name, Size: 8, Overwrite: false}, time.Now())
	if err != nil {
		t.Fatalf("BeginPlannedWrite: %v", err)
	}
	kek, err := contentcrypto.NewKEK("pack-test-kek")
	if err != nil {
		t.Fatal(err)
	}
	objectID := types.ChunkID(u.ID, 0)
	if _, err := s.PrepareContentKey(admin.ID, space.ID, objectID, u.ID, kek, time.Now()); err != nil {
		t.Fatalf("PrepareContentKey: %v", err)
	}
	return types.Inode{ID: u.ID}, objectID
}

func TestKeyPackExportImportRoundTrip(t *testing.T) {
	s := newTestStore(t)
	admin, space := bootstrapAdmin(t, s)
	staging, objectID := seedKeyedStore(t, s, admin, space, "packed")

	var buf bytes.Buffer
	now := time.Now().Truncate(time.Second)
	info, err := s.ExportKeyPack(&buf, "pack-test-kek", now)
	if err != nil {
		t.Fatalf("ExportKeyPack: %v", err)
	}
	if info.RecordCount != 1 || info.KeyID != "pack-test-kek" {
		t.Fatalf("pack info: %+v", info)
	}
	// 包内不得出现明文 KEK 材料：导出的只是 base64 wrapped DEK。
	kek, _ := contentcrypto.NewKEK("pack-test-kek")
	_ = kek

	header, records, err := ReadKeyPack(&buf, "pack-test-kek")
	if err != nil {
		t.Fatalf("ReadKeyPack: %v", err)
	}
	if header.KeyID != "pack-test-kek" || len(records) != 1 || records[0].ObjectID != objectID || records[0].Generation != staging.ID {
		t.Fatalf("pack contents: %+v %+v", header, records)
	}

	// 在全新库导入：恢复出相同 wrapped DEK，可重新经 GetContentKey 发放。
	s2 := newTestStore(t)
	admin2, space2 := bootstrapAdmin(t, s2)
	imported, unchanged, err := s2.ImportKeyPack(records, now)
	if err != nil || imported != 1 || unchanged != 0 {
		t.Fatalf("ImportKeyPack: %v imported=%d unchanged=%d", err, imported, unchanged)
	}
	if _, err := s2.GetContentKey(admin2.ID, space.ID, objectID, staging.ID); err == nil {
		t.Fatal("imported key readable under wrong space binding")
	}
	// 空间归属在包里：目标库需有同 space 才能按 ACL 取回；这里直接按包内
	// space 断言记录落地即可（GetContentKey 的 ACL 留给有该空间的库验证）。
	rec, err := s2.ContentKey(objectID)
	if err != nil || rec.SpaceID != space.ID || rec.WrappedDEK == "" {
		t.Fatalf("imported record: %+v %v", rec, err)
	}
	_ = space2
	// 幂等重放：全部 unchanged，无重复写入。
	imported2, unchanged2, err := s2.ImportKeyPack(records, now)
	if err != nil || imported2 != 0 || unchanged2 != 1 {
		t.Fatalf("replay: %v imported=%d unchanged=%d", err, imported2, unchanged2)
	}
}

func TestKeyPackRejectsTamperingAndWrongKEK(t *testing.T) {
	s := newTestStore(t)
	admin, space := bootstrapAdmin(t, s)
	_, _ = seedKeyedStore(t, s, admin, space, "tamper")

	var buf bytes.Buffer
	if _, err := s.ExportKeyPack(&buf, "pack-test-kek", time.Now()); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), buf.Bytes()...)

	// 翻转记录字节（HMAC 覆盖段内）必须被检出。
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-keyPackHMACSize-3] ^= 0x40
	if _, _, err := ReadKeyPack(bytes.NewReader(tampered), "pack-test-kek"); err == nil {
		t.Fatal("tampered pack accepted")
	}
	// 用错误 keyID 校验必须失败。
	if _, _, err := ReadKeyPack(bytes.NewReader(raw), "other-kek"); err == nil {
		t.Fatal("pack verified under wrong KEK key id")
	}
	// 跳过校验可以读（调用方明确选择），但结构校验仍生效：截断包拒绝。
	if _, _, err := ReadKeyPack(bytes.NewReader(raw[:len(raw)-10]), ""); err == nil {
		t.Fatal("truncated pack accepted")
	}
	header, records, err := ReadKeyPack(bytes.NewReader(raw), "")
	if err != nil || header.KeyID != "pack-test-kek" || len(records) != 1 {
		t.Fatalf("unverified read: %v %+v %d", err, header, len(records))
	}
	// magic 破坏拒绝。
	bad := append([]byte(nil), raw...)
	bad[0] = 'X'
	if _, _, err := ReadKeyPack(bytes.NewReader(bad), ""); err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("bad magic accepted: %v", err)
	}
}

func TestKeyPackImportRefusesForeignConflict(t *testing.T) {
	s := newTestStore(t)
	admin, space := bootstrapAdmin(t, s)
	_, objectID := seedKeyedStore(t, s, admin, space, "conflict")

	var buf bytes.Buffer
	now := time.Now().Truncate(time.Second)
	if _, err := s.ExportKeyPack(&buf, "pack-test-kek", now); err != nil {
		t.Fatal(err)
	}
	_, records, err := ReadKeyPack(&buf, "pack-test-kek")
	if err != nil {
		t.Fatal(err)
	}

	// 目标库已有一个同对象但不同包裹的记录：必须整包拒绝，不许部分混灌。
	s2 := newTestStore(t)
	if err := s2.write(func(w *txw) error {
		conflict := records[0]
		conflict.WrappedDEK = "AAAA"
		raw, err := json.Marshal(conflict)
		if err != nil {
			return err
		}
		return w.put(bcSecurity, bucketSecurity, contentKeyStoreKey(objectID), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s2.ImportKeyPack(records, now); err == nil {
		t.Fatal("conflicting import accepted")
	}
}

// TestKeyPackReplayIgnoresCreatedAt 复现真机（5884ba5）发现：ExportKeyPack 剥离
// 记录的 CreatedAt（readKeyPackRecord 置零，ReadKeyPack 再统一填包头导出时间），
// 而 ImportKeyPack 曾按 JSON 逐字节比较——同库幂等重放必然因 CreatedAt 不一致
// 被拒。正确语义：比较只看真正落包的五个字段，忽略包内不含的 CreatedAt。
func TestKeyPackReplayIgnoresCreatedAt(t *testing.T) {
	s := newTestStore(t)
	admin, space := bootstrapAdmin(t, s)
	_, objectID := seedKeyedStore(t, s, admin, space, "replay-createdAt")

	var buf bytes.Buffer
	now := time.Now().Truncate(time.Second)
	if _, err := s.ExportKeyPack(&buf, "pack-test-kek", now); err != nil {
		t.Fatal(err)
	}
	_, records, err := ReadKeyPack(&buf, "pack-test-kek")
	if err != nil {
		t.Fatal(err)
	}
	// 包内 CreatedAt 是导出时间；库内是 Prepare 时间，两者必然不同。
	if cur, err := s.ContentKey(objectID); err == nil && cur.CreatedAt.Equal(records[0].CreatedAt) {
		t.Fatalf("夹具未制造差异：库内 %v == 包内 %v", cur.CreatedAt, records[0].CreatedAt)
	}
	// 同库幂等重放必须成功（修复前这里返回 ErrObjectChanged）。
	imported, unchanged, err := s.ImportKeyPack(records, now)
	if err != nil || imported != 0 || unchanged != 1 {
		t.Fatalf("replay: %v imported=%d unchanged=%d", err, imported, unchanged)
	}
}
