//go:build fuse

// 运行内核挂载 e2e 测试: go test -tags fuse -run TestKernelMount ./mount/
package mount

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// 内核挂载 e2e：需要 /dev/fuse + FUSE 内核模块。
// 覆盖：mkdir/写文件/读回/分段读/ls/rename/跨目录拒绝/rm/stat。
func TestKernelMount(t *testing.T) {
	c, m := newTestCluster(t, 2)

	mnt := t.TempDir()
	server, err := fs.Mount(mnt, m.Root(), &fs.Options{
		MountOptions: fuse.MountOptions{Name: "atoll-test"},
	})
	if err != nil {
		t.Skipf("挂载失败（环境不支持）: %v", err)
	}
	t.Cleanup(func() { server.Unmount() })

	// ---- 目录 ----
	if err := os.Mkdir(filepath.Join(mnt, "dir"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// ---- 写文件（Create→Write→Flush 整传）----
	content := []byte("kernel mounted atoll! 0123456789")
	if err := os.WriteFile(filepath.Join(mnt, "dir", "k.txt"), content, 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}

	// ---- 读回（Range 读）----
	got, err := os.ReadFile(filepath.Join(mnt, "dir", "k.txt"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("读回: %v %q", err, got)
	}

	// ---- 分段读（dd 式 offset 读取，验证 Range 逻辑）----
	f, err := os.Open(filepath.Join(mnt, "dir", "k.txt"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	buf := make([]byte, 7)
	if _, err := f.ReadAt(buf, 7); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != "mounted" {
		t.Fatalf("分段读: %q", buf)
	}
	f.Close()

	// ---- 覆盖写（Open O_TRUNC）----
	if err := os.WriteFile(filepath.Join(mnt, "dir", "k.txt"), []byte("short"), 0o644); err != nil {
		t.Fatalf("覆盖写: %v", err)
	}
	got2, _ := os.ReadFile(filepath.Join(mnt, "dir", "k.txt"))
	if string(got2) != "short" {
		t.Fatalf("覆盖后内容: %q", got2)
	}

	// ---- ls ----
	ents, err := os.ReadDir(filepath.Join(mnt, "dir"))
	if err != nil || len(ents) != 1 || ents[0].Name() != "k.txt" {
		t.Fatalf("ls: %v %+v", err, ents)
	}

	// ---- stat ----
	st, err := os.Stat(filepath.Join(mnt, "dir", "k.txt"))
	if err != nil || st.Size() != 5 || st.Mode().IsRegular() == false {
		t.Fatalf("stat: %v %+v", err, st)
	}

	// ---- rename 同目录 ----
	if err := os.Rename(filepath.Join(mnt, "dir", "k.txt"), filepath.Join(mnt, "dir", "k2.txt")); err != nil {
		t.Fatalf("rename: %v", err)
	}

	// ---- 跨目录 rename → EXDEV ----
	if err := os.Rename(filepath.Join(mnt, "dir", "k2.txt"), filepath.Join(mnt, "top.txt")); err == nil {
		t.Fatal("跨目录 rename 应失败（EXDEV）")
	}

	// ---- rm ----
	if err := os.Remove(filepath.Join(mnt, "dir", "k2.txt")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	// ---- rmdir（空目录）----
	if err := os.Remove(filepath.Join(mnt, "dir")); err != nil {
		t.Fatalf("rmdir: %v", err)
	}

	// ---- 集群侧独立验证 ----
	if _, _, err := c.Lookup("/dir"); err == nil {
		t.Fatal("集群侧 /dir 应已删除")
	}

	// ---- 大文件 Range 读验证（512KB，跨多个读块）----
	big := bytes.Repeat([]byte("A"), 512*1024)
	if err := os.WriteFile(filepath.Join(mnt, "big.bin"), big, 0o644); err != nil {
		t.Fatalf("写大文件: %v", err)
	}
	bf, _ := os.Open(filepath.Join(mnt, "big.bin"))
	tail := make([]byte, 4096)
	if _, err := bf.ReadAt(tail, 500*1024); err != nil {
		t.Fatalf("大文件尾部分段读: %v", err)
	}
	if !bytes.Equal(tail, bytes.Repeat([]byte("A"), 4096)) {
		t.Fatal("大文件分段读内容不符")
	}
	bf.Close()
}

// 写入中(staging)文件的只读打开必须能读到本地缓冲，而不是 ENOENT。
// Finder 拷贝后回读校验 / Spotlight / QuickLook 会在文件还没提交时只读打开它，
// 若返回 ENOENT，Finder 判拷贝失败→删文件→报「设备已消失」。
func TestReadInProgressFile(t *testing.T) {
	_, m := newTestCluster(t, 2)
	mnt := t.TempDir()
	server, err := fs.Mount(mnt, m.Root(), &fs.Options{
		MountOptions: fuse.MountOptions{Name: "atoll-test"},
	})
	if err != nil {
		t.Skipf("挂载失败（环境不支持）: %v", err)
	}
	t.Cleanup(func() { server.Unmount() })

	p := filepath.Join(mnt, "inprogress.bin")
	wf, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("创建写句柄: %v", err)
	}
	content := bytes.Repeat([]byte("Z"), 3000)
	if _, err := wf.Write(content); err != nil {
		t.Fatalf("写: %v", err)
	}
	// 不 close wf：文件仍是 staging（未提交）。此刻另开只读句柄读它。
	rf, err := os.Open(p)
	if err != nil {
		t.Fatalf("写入中文件只读打开不应失败（曾 ENOENT→设备已消失）: %v", err)
	}
	got := make([]byte, len(content))
	nr, err := rf.ReadAt(got, 0)
	rf.Close()
	if err != nil && err.Error() != "EOF" {
		t.Fatalf("读: %v", err)
	}
	if nr != len(content) || !bytes.Equal(got[:nr], content) {
		t.Fatalf("读回不符: n=%d want %d", nr, len(content))
	}
	wf.Close()
}
