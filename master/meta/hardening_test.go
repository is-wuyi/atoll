package meta

import (
	"errors"
	"path/filepath"
	"testing"

	"atoll/pkg/types"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// stageChunks 建 staging 文件并按 (index,size) 分配块 + 标记主副本 Done（节点 1）。
func stageChunks(t *testing.T, s *Store, chunks [][2]int64) uint64 {
	t.Helper()
	st, err := s.CreateStagingFile(RootID)
	if err != nil {
		t.Fatalf("CreateStagingFile: %v", err)
	}
	for _, c := range chunks {
		if _, err := s.AssignChunk(st.ID, int(c[0]), c[1], []uint64{1}, 0); err != nil {
			t.Fatalf("AssignChunk %d: %v", c[0], err)
		}
		if err := s.MarkChunkDone(types.ChunkID(st.ID, int(c[0])), 1); err != nil {
			t.Fatalf("MarkChunkDone %d: %v", c[0], err)
		}
	}
	return st.ID
}

// P0-1: commit 必须拒绝跳号块表（缺 index 1）。
func TestCommitRejectsIndexGap(t *testing.T) {
	s := openTestStore(t)
	id := stageChunks(t, s, [][2]int64{{0, 100}, {2, 200}}) // 缺 index 1
	_, _, _, err := s.CommitStagingFile(id, "gap.bin", 300)
	if !errors.Is(err, ErrCommitFailed) {
		t.Fatalf("跳号块表应被拒绝(ErrCommitFailed)，实际: %v", err)
	}
}

// P0-1: 连续块表正常 commit。
func TestCommitAcceptsContiguous(t *testing.T) {
	s := openTestStore(t)
	id := stageChunks(t, s, [][2]int64{{0, 100}, {1, 200}, {2, 50}})
	if _, _, _, err := s.CommitStagingFile(id, "ok.bin", 350); err != nil {
		t.Fatalf("连续块表应成功 commit，实际: %v", err)
	}
}

// P0-4: commit / create / rename 一律拒绝非法文件名。
func TestNameValidation(t *testing.T) {
	bad := []string{"../../etc/passwd", "a/b", "/", ".", "..", ""}
	for _, name := range bad {
		s := openTestStore(t)
		id := stageChunks(t, s, [][2]int64{{0, 10}})
		if _, _, _, err := s.CommitStagingFile(id, name, 10); !errors.Is(err, ErrBadName) {
			t.Errorf("commit 非法名 %q 应被拒绝(ErrBadName)，实际: %v", name, err)
		}
		if _, err := s.CreateFile(RootID, name, nil); !errors.Is(err, ErrBadName) {
			t.Errorf("CreateFile 非法名 %q 应被拒绝，实际: %v", name, err)
		}
		if _, err := s.CreateDir(RootID, name); !errors.Is(err, ErrBadName) {
			t.Errorf("CreateDir 非法名 %q 应被拒绝，实际: %v", name, err)
		}
	}
}

// P0-3: ReplaceReplica 拒绝把已有副本节点重复放入（防并发修复造重复）。
func TestReplaceReplicaRejectsDuplicate(t *testing.T) {
	s := openTestStore(t)
	in, err := s.CreateFile(RootID, "f", []uint64{1, 2})
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	// 把 node 1 替换成 2 —— 2 已在副本集，应拒绝。
	if err := s.ReplaceReplica(in.ID, 1, 2); !errors.Is(err, ErrReplicaDup) {
		t.Fatalf("重复副本应被拒绝(ErrReplicaDup)，实际: %v", err)
	}
	got, _ := s.GetInode(in.ID)
	if len(got.Replicas) != 2 || got.Replicas[0] != 1 || got.Replicas[1] != 2 {
		t.Fatalf("拒绝后副本集不应改动，实际: %v", got.Replicas)
	}
	// 正常替换成一个新节点仍然成功。
	if err := s.ReplaceReplica(in.ID, 1, 5); err != nil {
		t.Fatalf("替换成新节点应成功，实际: %v", err)
	}
}

// P0-3: ReplaceChunkReplica 同样拒绝重复。
func TestReplaceChunkReplicaRejectsDuplicate(t *testing.T) {
	s := openTestStore(t)
	st, _ := s.CreateStagingFile(RootID)
	if _, err := s.AssignChunk(st.ID, 0, 10, []uint64{1, 2}, 0); err != nil {
		t.Fatalf("AssignChunk: %v", err)
	}
	if err := s.ReplaceChunkReplica(st.ID, 0, 1, 2); !errors.Is(err, ErrReplicaDup) {
		t.Fatalf("块重复副本应被拒绝，实际: %v", err)
	}
}
