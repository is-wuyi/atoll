package meta

import (
	"errors"
	"fmt"
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

// 节点重启后重复注册：同一地址应复用原 ID（幂等），而不是产生新记录。
func TestRegisterNodeIdempotent(t *testing.T) {
	s := newTestStore(t)
	n1, _ := s.RegisterNode("27119.et.net:9421", 100)
	n2, _ := s.RegisterNode("27119.et.net:9421", 200) // 重启后容量变化
	if n1.ID != n2.ID {
		t.Fatalf("同一地址重复注册应复用 ID: %d vs %d", n1.ID, n2.ID)
	}
	// 只应有一条节点记录。
	alive, _ := s.ListAliveNodes(time.Hour)
	if len(alive) != 1 {
		t.Fatalf("应只有 1 个节点记录, got %d", len(alive))
	}
	// 容量被刷新。
	got, _ := s.GetNode(n1.ID)
	if got.TotalBytes != 200 {
		t.Fatalf("TotalBytes = %d, want 200（重启后新容量）", got.TotalBytes)
	}
	// 不同地址注册新 ID。
	n3, _ := s.RegisterNode("27472.et.net:9421", 100)
	if n3.ID == n1.ID {
		t.Fatal("不同地址应是新节点")
	}
}

func TestListNodes(t *testing.T) {
	s := newTestStore(t)
	// 注册 3 个节点。
	s.RegisterNode("n1:9421", 100)
	s.RegisterNode("n2:9421", 200)
	s.RegisterNode("n3:9421", 300)
	nodes, err := s.ListNodes()
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("ListNodes = %d 个, want 3", len(nodes))
	}
	ids := make(map[uint64]bool)
	for _, n := range nodes {
		ids[n.ID] = true
	}
	if len(ids) != 3 {
		t.Fatalf("节点 ID 应唯一, got %v", ids)
	}
}

func TestForEachFile(t *testing.T) {
	s := newTestStore(t)
	s.CreateFile(RootID, "a.txt", nil)
	s.CreateFile(RootID, "b.txt", nil)
	dir, _ := s.CreateDir(RootID, "sub")
	s.CreateFile(dir.ID, "c.txt", nil) // 目录下的文件也应遍历到

	var collected []uint64
	err := s.ForEachFile(func(in types.Inode) error {
		collected = append(collected, in.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("ForEachFile: %v", err)
	}
	if len(collected) != 3 {
		t.Fatalf("ForEachFile 收集 %d 个文件, want 3", len(collected))
	}
	// 目录不应出现。
	for _, id := range collected {
		in, _ := s.GetInode(id)
		if in.Type != types.TypeFile {
			t.Fatalf("ForEachFile 返回了非文件 inode: %+v", in)
		}
	}
}

func TestForEachFileAbort(t *testing.T) {
	s := newTestStore(t)
	s.CreateFile(RootID, "a.txt", nil)
	s.CreateFile(RootID, "b.txt", nil)
	sentinel := fmt.Errorf("stop")
	count := 0
	err := s.ForEachFile(func(in types.Inode) error {
		count++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("应返回 sentinel, got %v", err)
	}
	if count != 1 {
		t.Fatalf("fn 应只调用 1 次, got %d", count)
	}
}

func TestReplaceReplica(t *testing.T) {
	s := newTestStore(t)
	f, _ := s.CreateFile(RootID, "data.bin", []uint64{10, 20, 30})
	// 手动标记 10、20 为 Done。
	s.AddReplicaDone(f.ID, 10)
	s.AddReplicaDone(f.ID, 20)

	// 把节点 10 替换为 99。
	if err := s.ReplaceReplica(f.ID, 10, 99); err != nil {
		t.Fatalf("ReplaceReplica: %v", err)
	}
	got, _ := s.GetInode(f.ID)
	// Replicas 中 10 应变为 99。
	found99 := false
	for _, r := range got.Replicas {
		if r == 10 {
			t.Fatal("Replicas 中不应再有 10")
		}
		if r == 99 {
			found99 = true
		}
	}
	if !found99 {
		t.Fatalf("Replicas 中应有 99, got %v", got.Replicas)
	}
	// DoneReplicas 中 10 应被移除，20 仍存在。
	for _, r := range got.DoneReplicas {
		if r == 10 {
			t.Fatal("DoneReplicas 中不应再有 10")
		}
	}
	if len(got.DoneReplicas) != 1 || got.DoneReplicas[0] != 20 {
		t.Fatalf("DoneReplicas = %v, want [20]", got.DoneReplicas)
	}
}

func TestReplaceReplicaInodeNotExist(t *testing.T) {
	s := newTestStore(t)
	err := s.ReplaceReplica(99999, 1, 2)
	if !errors.Is(err, ErrNotExist) {
		t.Fatalf("不存在 inode 应返回 ErrNotExist, got %v", err)
	}
}

func TestReplaceReplicaOldNotInReplicas(t *testing.T) {
	s := newTestStore(t)
	f, _ := s.CreateFile(RootID, "x.txt", []uint64{1, 2})
	err := s.ReplaceReplica(f.ID, 99, 3)
	if err == nil {
		t.Fatal("oldNodeID 不在 Replicas 中应返回错误")
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
