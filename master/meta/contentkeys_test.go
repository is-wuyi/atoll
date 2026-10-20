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

// 已发布（WriteCommitted）的加密对象：团队 read 成员可取钥，跨空间拒绝；
// 在途（Pending）上传仍只有 Actor 本人可取。
func TestPublishedContentKeySharedAfterCommit(t *testing.T) {
	s := newTestStore(t)
	admin, _ := bootstrapAdmin(t, s)
	guest, _ := inviteAndRegister(t, s, admin.ID, "guest", time.Now())

	// admin 建团队空间并加 guest 为 read 成员。
	team, err := s.CreateTeam(admin.ID, "team")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTeamMember(admin.ID, team.ID, guest.ID, RoleRead); err != nil {
		t.Fatalf("add read member: %v", err)
	}

	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	u, err := s.BeginPlannedWrite(WriteActor{UserID: admin.ID, SpaceID: team.ID}, team.RootID, "teamfile",
		types.BeginWriteRequest{Path: "/teamfile", OpID: "op-team", Size: 8, Overwrite: false}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kek, _ := contentcrypto.NewKEK("team-kek")
	objectID := types.ChunkID(u.ID, 0)
	if _, err := s.PrepareContentKey(admin.ID, team.ID, objectID, u.ID, kek, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Pending：非上传人被拒（在途上传私有）。
	if _, err := s.GetContentKey(guest.ID, team.ID, objectID, u.ID); err == nil {
		t.Fatal("pending upload key leaked to non-actor")
	}

	// 补全合规 Committed 记录。
	result := types.Inode{ID: u.ID, Type: types.TypeFile, Chunked: true, Size: 8, Generation: 1,
		Content: &types.ContentVersion{ID: u.ID, LogicalSize: 8,
			Extents: []types.ContentExtent{{Offset: 0, Length: 8, Object: types.ContentObject{
				ID: objectID, Version: 1, LogicalSize: 8, StoredSize: 8, Encoding: types.PlainEncoding, ChecksumKnown: true}}}},
		Chunks: []types.ChunkInfo{{ID: objectID, Index: 0, Size: 8, ChecksumKnown: true, Replicas: []uint64{1}, Done: []uint64{1}}}}
	commit := types.CommitWriteRequest{WriteBinding: writeBinding(u), OpID: "op-team", Size: 8, ChunkCount: 1}
	if err := s.write(func(w *txw) error {
		rec, err := plannedWriteTx(w.tx, u.ID)
		if err != nil {
			return err
		}
		rec.Upload.State = types.WriteCommitted
		rec.Upload.Result = &result
		rec.Commit = &commit
		return putPlannedWrite(w, rec)
	}); err != nil {
		t.Fatal(err)
	}
	// Committed：上传人与团队 read 成员都可取——修复点。
	if _, err := s.GetContentKey(admin.ID, team.ID, objectID, u.ID); err != nil {
		t.Fatalf("owner denied after publish: %v", err)
	}
	if _, err := s.GetContentKey(guest.ID, team.ID, objectID, u.ID); err != nil {
		t.Fatalf("team read member denied after publish: %v", err)
	}
	// 跨空间仍拒：guest 用个人空间取团队对象的钥。
	if _, err := s.GetContentKey(guest.ID, guest.PersonalSpaceID, objectID, u.ID); err == nil {
		t.Fatal("cross-space key fetch accepted")
	}
}
