package meta

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"atoll/pkg/types"
)

// newTestStore 每个测试用独立的临时数据库。
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "meta.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRootExists(t *testing.T) {
	s := newTestStore(t)
	root, err := s.GetInode(RootID)
	if err != nil {
		t.Fatalf("GetInode(RootID): %v", err)
	}
	if root.Type != types.TypeDir {
		t.Fatalf("根目录类型 = %d, want TypeDir", root.Type)
	}
	// 根目录应可被路径解析。
	got, err := s.ResolvePath("/")
	if err != nil || got.ID != RootID {
		t.Fatalf("ResolvePath(\"/\") = %v, %v; want ID=%d", got, err, RootID)
	}
}

func TestCreateDirAndResolve(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreateDir(RootID, "docs"); err != nil {
		t.Fatalf("CreateDir: %v", err)
	}
	if _, err := s.CreateDir(2, "notes"); err != nil { // docs 的 ID 应为 2
		t.Fatalf("CreateDir nested: %v", err)
	}
	in, err := s.ResolvePath("/docs/notes")
	if err != nil {
		t.Fatalf("ResolvePath: %v", err)
	}
	if in.Name != "notes" || in.ParentID != 2 {
		t.Fatalf("解析结果不符: %+v", in)
	}
}

func TestCreateDirDuplicate(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreateDir(RootID, "a"); err != nil {
		t.Fatalf("CreateDir: %v", err)
	}
	if _, err := s.CreateDir(RootID, "a"); !errors.Is(err, ErrExist) {
		t.Fatalf("重复创建应返回 ErrExist, got %v", err)
	}
}

func TestCreateFileAndLookup(t *testing.T) {
	s := newTestStore(t)
	dir, _ := s.CreateDir(RootID, "docs")
	f, err := s.CreateFile(dir.ID, "a.txt", []uint64{7, 8})
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if f.Type != types.TypeFile || f.Size != 0 {
		t.Fatalf("新建文件字段不符: %+v", f)
	}
	got, err := s.Lookup(dir.ID, "a.txt")
	if err != nil || got.ID != f.ID {
		t.Fatalf("Lookup = %+v, %v", got, err)
	}
	if len(got.Replicas) != 2 || got.Replicas[0] != 7 {
		t.Fatalf("副本位置不符: %v", got.Replicas)
	}
}

func TestListChildrenSorted(t *testing.T) {
	s := newTestStore(t)
	s.CreateDir(RootID, "docs")
	s.CreateFile(RootID, "b.txt", nil)
	s.CreateFile(RootID, "a.txt", nil)
	kids, err := s.ListChildren(RootID)
	if err != nil {
		t.Fatalf("ListChildren: %v", err)
	}
	var names []string
	for _, k := range kids {
		names = append(names, k.Name)
	}
	want := []string{"a.txt", "b.txt", "docs"}
	if len(names) != len(want) {
		t.Fatalf("子项数 = %d, want %d (%v)", len(names), len(want), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("排序不符: %v, want %v", names, want)
		}
	}
}

func TestDeleteDirNotEmpty(t *testing.T) {
	s := newTestStore(t)
	dir, _ := s.CreateDir(RootID, "docs")
	s.CreateFile(dir.ID, "x.txt", nil)
	if err := s.DeleteDir(dir.ID); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("删除非空目录应返回 ErrNotEmpty, got %v", err)
	}
}

func TestDeleteFile(t *testing.T) {
	s := newTestStore(t)
	f, _ := s.CreateFile(RootID, "gone.txt", nil)
	if err := s.DeleteFile(f.ID); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if _, err := s.Lookup(RootID, "gone.txt"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("删除后 Lookup 应返回 ErrNotExist, got %v", err)
	}
}

func TestRenameSameDir(t *testing.T) {
	s := newTestStore(t)
	f, _ := s.CreateFile(RootID, "old.txt", nil)
	if err := s.Rename(f.ID, "new.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := s.Lookup(RootID, "new.txt"); err != nil {
		t.Fatalf("改名后 Lookup 失败: %v", err)
	}
	if _, err := s.Lookup(RootID, "old.txt"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("旧名字应已不存在, got %v", err)
	}
}

func TestUpdateFile(t *testing.T) {
	s := newTestStore(t)
	f, _ := s.CreateFile(RootID, "a.txt", []uint64{1})
	if err := s.UpdateFile(f.ID, 1024, []uint64{1, 2}); err != nil {
		t.Fatalf("UpdateFile: %v", err)
	}
	got, _ := s.GetInode(f.ID)
	if got.Size != 1024 || len(got.Replicas) != 2 {
		t.Fatalf("更新后字段不符: %+v", got)
	}
}

func TestNodeRegisterAndHeartbeat(t *testing.T) {
	s := newTestStore(t)
	n, err := s.RegisterNode("127.0.0.1:9000", 1<<30)
	if err != nil {
		t.Fatalf("RegisterNode: %v", err)
	}
	if n.ID == 0 {
		t.Fatal("节点 ID 不应为 0")
	}
	if err := s.Heartbeat(n.ID, 2048); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	got, _ := s.GetNode(n.ID)
	if got.UsedBytes != 2048 {
		t.Fatalf("UsedBytes = %d, want 2048", got.UsedBytes)
	}
	alive, err := s.ListAliveNodes(time.Minute)
	if err != nil || len(alive) != 1 {
		t.Fatalf("ListAliveNodes = %v, %v; want 1 个节点", alive, err)
	}
	// 不存在的节点心跳应报错。
	if err := s.Heartbeat(9999, 0); !errors.Is(err, ErrNotExist) {
		t.Fatalf("未知节点心跳应返回 ErrNotExist, got %v", err)
	}
}

// 重新打开数据库应保留全部数据（持久化验证）。
func TestPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "meta.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	dir, _ := s.CreateDir(RootID, "keep")
	f, _ := s.CreateFile(dir.ID, "data.bin", []uint64{3})
	s.Close()

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer s2.Close()
	got, err := s2.ResolvePath("/keep/data.bin")
	if err != nil || got.ID != f.ID {
		t.Fatalf("重开后数据丢失: %+v, %v", got, err)
	}
}
