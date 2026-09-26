//go:build fuse

// Finder/macOS 行为集成测试：真实 macFUSE 挂载 + 真实集群，复刻 Finder 拷贝的
// 真实调用模式（预分配、占位-删-重建、写中并发只读、xattr、inode 稳定性）。
// 这些都是普通 cp / 单测覆盖不到、却在真机反复咬人的路径。
// 运行：go test -tags fuse -run TestFinder ./mount/
package mount

import (
	"bytes"
	"crypto/md5"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// mountForTest 起真集群 + 真挂载，返回挂载点目录。
func mountForTest(t *testing.T, numNodes int) string {
	t.Helper()
	_, m := newTestCluster(t, numNodes)
	mnt := t.TempDir()
	server, err := fs.Mount(mnt, m.Root(), &fs.Options{
		MountOptions: fuse.MountOptions{Name: "atoll-test"},
	})
	if err != nil {
		t.Skipf("挂载失败（环境不支持 FUSE）: %v", err)
	}
	t.Cleanup(func() { server.Unmount() })
	return mnt
}

func md5sum(b []byte) [16]byte { return md5.Sum(b) }

// PLACEHOLDER

// Finder 预分配多块：先 ftruncate 到完整大小再顺序写（Finder copyfile 的模式）。
// 曾因 truncate 一律放弃流式→close 整传→大文件超时「设备已消失」。
func TestFinderPreallocateMultiChunk(t *testing.T) {
	withChunkSize(t, 256*1024) // 256KB 块
	mnt := mountForTest(t, 2)
	p := filepath.Join(mnt, "prealloc.bin")

	content := bytes.Repeat([]byte("atoll-finder-"), 160000) // ~2MB → 多块
	fd, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := fd.Truncate(int64(len(content))); err != nil { // 预分配
		t.Fatalf("ftruncate: %v", err)
	}
	if _, err := fd.Write(content); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := fd.Close(); err != nil {
		t.Fatalf("close（预分配路径若卡住/失败即回归）: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || md5sum(got) != md5sum(content) {
		t.Fatalf("读回不符: err=%v len=%d/%d", err, len(got), len(content))
	}
}

// Finder 占位-删-重建序列 + 写后 chmod/utimes：不得中途失败。
func TestFinderPlaceholderDance(t *testing.T) {
	withChunkSize(t, 256*1024)
	mnt := mountForTest(t, 2)
	p := filepath.Join(mnt, "trae.dmg")

	// 1) O_EXCL 占位 → close
	fd, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("占位 create: %v", err)
	}
	fd.Close()
	// 2) 删除占位
	if err := os.Remove(p); err != nil {
		t.Fatalf("unlink 占位: %v", err)
	}
	// 3) 重建 + 预分配 + 写 + close
	content := bytes.Repeat([]byte("DMG"), 400000) // ~1.2MB
	fd, err = os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("重建 create: %v", err)
	}
	fd.Truncate(int64(len(content)))
	if _, err := fd.Write(content); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := fd.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// 4) chmod + utimes（Finder 收尾会做）
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	got, _ := os.ReadFile(p)
	if md5sum(got) != md5sum(content) {
		t.Fatalf("读回不符: %d/%d", len(got), len(content))
	}
}

// 写入中(staging)多块文件被并发只读打开：必须读到已写内容、不 ENOENT。
// 这是 Finder「设备已消失」的直接触发：Finder/Spotlight 写中回读拿到 ENOENT → 删文件。
func TestFinderConcurrentReadDuringWrite(t *testing.T) {
	withChunkSize(t, 256*1024)
	mnt := mountForTest(t, 2)
	p := filepath.Join(mnt, "concurrent.bin")

	fd, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer fd.Close()
	first := bytes.Repeat([]byte("Z"), 300*1024) // 已写 300KB（跨块）
	if _, err := fd.Write(first); err != nil {
		t.Fatalf("write: %v", err)
	}
	// 不 close：文件仍 staging。并发只读打开读回已写部分。
	rf, err := os.Open(p)
	if err != nil {
		t.Fatalf("写入中只读打开不应失败（曾 ENOENT→设备已消失）: %v", err)
	}
	defer rf.Close()
	buf := make([]byte, len(first))
	nr, _ := rf.ReadAt(buf, 0)
	if nr != len(first) || !bytes.Equal(buf[:nr], first) {
		t.Fatalf("写入中读回不符: n=%d/%d", nr, len(first))
	}
}

// inode 稳定性：写入中 stat 的 ino == 提交后 stat 的 ino（都为真实值、不变）。
func TestFinderInodeStableAcrossCommit(t *testing.T) {
	withChunkSize(t, 256*1024)
	mnt := mountForTest(t, 2)
	p := filepath.Join(mnt, "stable.bin")

	fd, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := fd.Write(bytes.Repeat([]byte("S"), 500*1024)); err != nil {
		t.Fatalf("write: %v", err)
	}
	fiDuring, err := os.Stat(p) // 写入中（staging）
	if err != nil {
		t.Fatalf("stat 写入中: %v", err)
	}
	inoDuring := fiDuring.Sys().(*syscall.Stat_t).Ino
	fd.Close() // 提交
	fiAfter, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat 提交后: %v", err)
	}
	inoAfter := fiAfter.Sys().(*syscall.Stat_t).Ino
	if inoDuring != inoAfter {
		t.Fatalf("inode 跨提交变了: 写入中 %d != 提交后 %d（Finder 会认不出→拷贝不收尾）", inoDuring, inoAfter)
	}
}

// xattr 写入必须被"接受"（不报错），否则 Finder 拷贝整体中止弹 -43。
func TestFinderXattrAccepted(t *testing.T) {
	mnt := mountForTest(t, 2)
	p := filepath.Join(mnt, "x.txt")
	if err := os.WriteFile(p, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if out, err := exec.Command("xattr", "-w", "com.apple.quarantine", "0081;test;Safari;", p).CombinedOutput(); err != nil {
		t.Fatalf("setxattr quarantine 应被接受，got: %v (%s)", err, out)
	}
}

