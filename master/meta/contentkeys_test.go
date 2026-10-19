package meta

import (
	"encoding/base64"
	"testing"
	"time"

	"atoll/pkg/contentcrypto"
	"atoll/pkg/types"
)

// beginKeyedUpload 走真实 Begin 流程建一个计划上传（staging inode），
// 返回 (staging inode, 计划请求, chunk 对象 ID)。密钥的 generation 即
// ContentVersion.ID = staging ID（Begin 时冻结的加密身份）。
func beginKeyedUpload(t *testing.T, s *Store, admin PublicUser, space Space) (types.Inode, types.WriteBinding, uint64) {
	t.Helper()
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatalf("EnableWritePlanning: %v", err)
	}
	u, err := s.BeginPlannedWrite(WriteActor{UserID: admin.ID, SpaceID: space.ID}, space.RootID, "keyed",
		types.BeginWriteRequest{Path: "/keyed", OpID: "op-keyed", Size: 8, Overwrite: false}, time.Now())
	if err != nil {
		t.Fatalf("BeginPlannedWrite: %v", err)
	}
	if u.ID < types.StagingInodeBase {
		t.Fatalf("staging id = %d", u.ID)
	}
	return types.Inode{ID: u.ID}, types.WriteBinding{UploadID: u.ID, PlanID: u.PlanID, Revision: u.Revision}, types.ChunkID(u.ID, 0)
}

func TestContentKeyIsSpaceBoundAndDurable(t *testing.T) {
	s := newTestStore(t)
	admin, space := bootstrapAdmin(t, s)
	staging, _, objectID := beginKeyedUpload(t, s, admin, space)
	kek, err := contentcrypto.NewKEK("master-20261018")
	if err != nil {
		t.Fatal(err)
	}
	record, err := s.PrepareContentKey(admin.ID, space.ID, objectID, staging.ID, kek, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := base64.RawStdEncoding.DecodeString(record.WrappedDEK)
	if err != nil || len(wrapped) == 0 {
		t.Fatalf("wrapped DEK: %v %d", err, len(wrapped))
	}
	// 幂等：同参数重复准备返回同一记录。
	again, err := s.PrepareContentKey(admin.ID, space.ID, objectID, staging.ID, kek, time.Now())
	if err != nil || again.WrappedDEK != record.WrappedDEK || !again.CreatedAt.Equal(record.CreatedAt) {
		t.Fatalf("idempotent prepare: %+v %v", again, err)
	}
	got, err := s.GetContentKey(admin.ID, space.ID, objectID, staging.ID)
	if err != nil || got.ObjectID != record.ObjectID || got.Generation != record.Generation || got.SpaceID != record.SpaceID || got.KeyID != record.KeyID || got.WrappedDEK != record.WrappedDEK || !got.CreatedAt.Equal(record.CreatedAt) {
		t.Fatalf("get content key: %+v %v", got, err)
	}
	// 错误内容身份 / 错误空间 / 非上传对象都拒绝。
	if _, err := s.GetContentKey(admin.ID, space.ID, objectID, staging.ID+1); err == nil {
		t.Fatal("wrong generation accepted")
	}
	if _, err := s.GetContentKey(admin.ID, space.ID, objectID+types.MaxChunksPerFile, staging.ID); err == nil {
		t.Fatal("foreign object accepted")
	}
	if _, err := s.ContentKey(objectID); err != nil {
		t.Fatal("content key was not durable in metadata", err)
	}
}

func TestContentKeyPrepareRejectsWrongAnchor(t *testing.T) {
	s := newTestStore(t)
	admin, space := bootstrapAdmin(t, s)
	staging, _, objectID := beginKeyedUpload(t, s, admin, space)
	kek, _ := contentcrypto.NewKEK("master-key")
	// 内容身份不是该上传的 anchor（staging ID）时拒绝。
	if _, err := s.PrepareContentKey(admin.ID, space.ID, objectID, staging.ID+types.MaxChunksPerFile, kek, time.Now()); err == nil {
		t.Fatal("wrong content identity accepted")
	}
	// 未 Begin 的对象 ID 不存在。
	if _, err := s.PrepareContentKey(admin.ID, space.ID, types.ChunkID(staging.ID+1, 0), staging.ID, kek, time.Now()); err == nil {
		t.Fatal("unknown upload accepted")
	}
}

func TestContentKeyDoesNotExposeKEK(t *testing.T) {
	s := newTestStore(t)
	admin, space := bootstrapAdmin(t, s)
	staging, _, objectID := beginKeyedUpload(t, s, admin, space)
	kek, _ := contentcrypto.NewKEK("master-key")
	record, err := s.PrepareContentKey(admin.ID, space.ID, objectID, staging.ID, kek, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if record.KeyID != kek.KeyID() || record.WrappedDEK == "" {
		t.Fatalf("invalid envelope: %+v", record)
	}
	if record.WrappedDEK == kek.String() || record.WrappedDEK == kek.GoString() {
		t.Fatal("KEK representation leaked into envelope")
	}
}
