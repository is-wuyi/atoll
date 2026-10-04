package meta

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestObjectIDAllocationDoesNotOverlapLegacyStaging(t *testing.T) {
	s := newTestStore(t)
	obj, err := s.AllocateObjectID()
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.CreateStagingFileLegacy(RootID, "pending", []uint64{2})
	if err != nil {
		t.Fatal(err)
	}
	if obj == st.ID || obj < uint64(1)<<63 {
		t.Fatalf("content object %d overlaps legacy/staging namespace (staging=%d)", obj, st.ID)
	}
}

func TestSmallOpSurvivesSnapshotAndWAL(t *testing.T) {
	s := newTestStore(t)
	var snapshot bytes.Buffer
	if _, err := s.Snapshot(&snapshot); err != nil {
		t.Fatal(err)
	}
	seq, err := s.WALSeq()
	if err != nil {
		t.Fatal(err)
	}
	in := types.Inode{ID: 2, Type: types.TypeFile, Generation: 1, Size: 4}
	if err := s.PutOpResult("result-after-snapshot", "small", in); err != nil {
		t.Fatal(err)
	}
	frames, err := s.FramesSince(seq)
	if err != nil {
		t.Fatal(err)
	}
	r, err := RestoreFromReader(filepath.Join(t.TempDir(), "restore.db"), bytes.NewReader(snapshot.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.ApplyFrames(frames); err != nil {
		t.Fatal(err)
	}
	got, ok, err := r.GetOpResult("result-after-snapshot")
	if err != nil || !ok || got.Inode.ID != in.ID {
		t.Fatalf("op result lost by WAL replay: present=%v value=%+v err=%v", ok, got, err)
	}
}

func TestSmallPublishRejectsRenamedTarget(t *testing.T) {
	s := newTestStore(t)
	old, err := s.CreateFile(RootID, "before", []uint64{2})
	if err != nil {
		t.Fatal(err)
	}
	// Prepare 在 rename 之前锁定目标快照（FileID+Generation）；
	// 之后目标被改名 → commit 必须 CAS 拒绝，绝不复活旧路径或污染新位置。
	target := SmallFileTarget{
		ParentID: RootID, Name: "before", RemotePath: "/before",
		Size: 4, Checksum: 42, Replicas: []uint64{2}, PrimaryID: 2,
		Overwrite: true, Mtime: time.Now(),
	}
	obj, _, err := s.PrepareSmallFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if obj.Target == nil || obj.Target.FileID != old.ID {
		t.Fatalf("prepare snapshot should pin existing target: %+v", obj.Target)
	}
	if err := s.Rename(old.ID, "after"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := s.CommitSmallFile(obj.ID); err == nil {
		t.Error("publication resurrected a path after its target was renamed")
	}
	if _, err := s.ResolvePath("/before"); !errors.Is(err, ErrNotExist) {
		t.Errorf("old path became visible: %v", err)
	}
	current, err := s.ResolvePath("/after")
	if err != nil || current.ID != old.ID || current.ObjID != 0 {
		t.Fatalf("renamed file changed: %+v err=%v", current, err)
	}
}
