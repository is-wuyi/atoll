package mount

import (
	"testing"

	"atoll/pkg/types"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// TestMountSymlinkRawFS 符号链接支持：SYMLINK 创建 → LOOKUP 报 S_IFLNK → READLINK 返回目标
// → master 持久化 Type=TypeSymlink + Target。Finder 拷贝含符号链接的目录（rustfs 事故：
// .claude/skills -> ../.agents/skills）时发 SYMLINK，此前未实现回 ENOTSUP → 整个拷贝中止。
func TestMountSymlinkRawFS(t *testing.T) {
	c, m := newTestCluster(t, 1)
	root, raw := namespaceFS(m)
	_ = root

	var out fuse.EntryOut
	if status := raw.Symlink(nil, &fuse.InHeader{NodeId: 1}, "../target/file.txt", "lnk", &out); status != fuse.OK {
		t.Fatalf("Symlink 应成功（曾 ENOTSUP 中止 Finder 拷贝）: %v", status)
	}
	if out.Attr.Mode&fuse.S_IFLNK == 0 {
		t.Errorf("Symlink 应报 S_IFLNK, got mode=%o", out.Attr.Mode)
	}
	if out.Attr.Size != uint64(len("../target/file.txt")) {
		t.Errorf("符号链接 size 应=目标长度 %d, got %d", len("../target/file.txt"), out.Attr.Size)
	}

	// 再次 Lookup：同一节点复用、仍是 S_IFLNK（st_ino 稳定）。
	var l2 fuse.EntryOut
	if status := raw.Lookup(nil, &fuse.InHeader{NodeId: 1}, "lnk", &l2); status != fuse.OK {
		t.Fatalf("Lookup lnk: %v", status)
	}
	if l2.NodeId != out.NodeId || l2.Ino != out.Ino {
		t.Errorf("Lookup 应复用同一节点: got node=%d ino=%d, want node=%d ino=%d", l2.NodeId, l2.Ino, out.NodeId, out.Ino)
	}

	// READLINK 返回目标。
	tgt, status := raw.Readlink(nil, &fuse.InHeader{NodeId: l2.NodeId})
	if status != fuse.OK {
		t.Fatalf("Readlink: %v", status)
	}
	if string(tgt) != "../target/file.txt" {
		t.Errorf("Readlink = %q, want %q", tgt, "../target/file.txt")
	}

	// master 侧持久化：Type=TypeSymlink、Target 原样保存。
	in, _, err := c.Lookup("/lnk")
	if err != nil {
		t.Fatalf("master Lookup: %v", err)
	}
	if in.Type != types.TypeSymlink || in.Target != "../target/file.txt" {
		t.Fatalf("master 元数据不符: type=%d target=%q", in.Type, in.Target)
	}
}

// TestMountReaddirSeekdir 内核对已读过的目录回卷（offset 回 0）时，go-fuse 要求
// DirStream 实现 Seekdir，否则回 ENOTSUP（真机 Finder 刷新根目录时踩到 3 次 45）。
func TestMountReaddirSeekdir(t *testing.T) {
	_, m := newTestCluster(t, 1)
	_, raw := namespaceFS(m)

	f2 := createNamespaceFile(t, raw, "s2.txt")
	_ = f2

	var od fuse.OpenOut
	if status := raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{NodeId: 1}}, &od); status != fuse.OK {
		t.Fatalf("OpenDir: %v", status)
	}
	read := func(off uint64) fuse.Status {
		l := fuse.NewDirEntryList(make([]byte, 4096), 0)
		return raw.ReadDir(nil, &fuse.ReadIn{InHeader: fuse.InHeader{NodeId: 1}, Fh: od.Fh, Offset: off}, l)
	}
	if status := read(0); status != fuse.OK {
		t.Fatalf("首读目录: %v", status)
	}
	// 回卷到 0 重读：需要 Seekdir 支持（此前 ENOTSUP）。
	if status := read(0); status != fuse.OK {
		t.Fatalf("目录回卷(offset=0)重读应成功（sliceDirStream 缺 Seekdir）: %v", status)
	}
	// 顺序续读也不回归。
	if status := read(0); status != fuse.OK {
		t.Fatalf("再次回卷: %v", status)
	}
}
