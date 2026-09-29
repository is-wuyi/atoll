package mount

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// TestWriteHandleConcurrentOpenShares 并发写同一路径必须共享一个句柄（引用计数），
// 而非覆盖 registry：否则旧句柄从 registry 消失，Getattr 读到新空缓冲 size 归零、
// 两句柄各自 commit 后写静默丢失、旧临时文件泄漏。此前 newWriteHandle 无条件覆盖 → 复现这些。
func TestWriteHandleConcurrentOpenShares(t *testing.T) {
	c, m := newTestCluster(t, 1)
	if _, err := c.Mkdir("/cc"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	ctx := context.Background()

	w1, err := m.newWriteHandle("/cc/f.txt", true)
	if err != nil {
		t.Fatalf("newWriteHandle 1: %v", err)
	}
	if _, errno := w1.Write(ctx, bytes.Repeat([]byte("A"), 4096), 0); errno != 0 {
		t.Fatalf("Write w1: %v", errno)
	}

	// 第二个写打开同一路径：必须返回同一个句柄、共享缓冲，registry 只 1 条。
	w2, err := m.newWriteHandle("/cc/f.txt", false)
	if err != nil {
		t.Fatalf("newWriteHandle 2: %v", err)
	}
	if w2 != w1 {
		t.Fatal("并发写同一路径应共享句柄，实际得到两个不同句柄（registry 被覆盖）")
	}
	m.mu.Lock()
	n := len(m.writes)
	m.mu.Unlock()
	if n != 1 {
		t.Fatalf("registry 应只有 1 条共享句柄, got %d", n)
	}

	// Getattr 期间不得因为"第二次打开新建空缓冲"把 size 归零。
	// Getattr 期间不得因为"第二次打开新建空缓冲"把 size 归零。
	var a fuse.Attr
	w1.attr(&a)
	if a.Size != 4096 {
		t.Fatalf("共享后 size 应仍为 4096（不被第二次打开清零）, got %d", a.Size)
	}

	// 第一次 Release 只减引用、不清理；第二次才真正清理。
	if errno := w1.Release(ctx); errno != 0 {
		t.Fatalf("Release w1: %v", errno)
	}
	if _, err := os.Stat(w1.local); err != nil {
		t.Fatal("仍有引用时不应删除本地缓冲")
	}
	m.mu.Lock()
	_, still := m.writes["/cc/f.txt"]
	m.mu.Unlock()
	if !still {
		t.Fatal("仍有引用时不应从 registry 移除")
	}

	if errno := w2.Release(ctx); errno != 0 {
		t.Fatalf("Release w2: %v", errno)
	}
	if _, err := os.Stat(w1.local); !os.IsNotExist(err) {
		t.Fatal("最后一个 Release 应删除本地缓冲")
	}
	m.mu.Lock()
	_, gone := m.writes["/cc/f.txt"]
	m.mu.Unlock()
	if gone {
		t.Fatal("最后一个 Release 应从 registry 移除")
	}
}

// TestWriteHandleDroppedGuards 句柄被 discard（Unlink）后，Write/Read/truncate 必须拒绝，
// 不得对已关闭的 fd 做 I/O；attr 也不得因本地文件已删而误报 size=0。
func TestWriteHandleDroppedGuards(t *testing.T) {
	_, m := newTestCluster(t, 1)
	ctx := context.Background()
	w, err := m.newWriteHandle("/g.txt", true)
	if err != nil {
		t.Fatalf("newWriteHandle: %v", err)
	}
	if _, errno := w.Write(ctx, bytes.Repeat([]byte("Z"), 2048), 0); errno != 0 {
		t.Fatalf("Write: %v", errno)
	}
	w.discard()

	if _, errno := w.Write(ctx, []byte("x"), 0); errno == 0 {
		t.Fatal("discard 后 Write 应返回错误（不得写已关闭 fd）")
	}
	if _, errno := w.Read(ctx, make([]byte, 4), 0); errno == 0 {
		t.Fatal("discard 后 Read 应返回错误")
	}
	if errno := w.truncate(0); errno == 0 {
		t.Fatal("discard 后 truncate 应返回错误")
	}
	// attr 用记录的逻辑大小兜底，不因本地文件已删而报 0。
	var a fuse.Attr
	w.attr(&a)
	if a.Size != 2048 {
		t.Fatalf("discard 后 attr 应报最后逻辑大小 2048, got %d", a.Size)
	}
}

// TestWriteHandleConcurrentReleaseRace -race 下并发 Release/attr/Write 不得数据竞争或崩溃。
func TestWriteHandleConcurrentReleaseRace(t *testing.T) {
	c, m := newTestCluster(t, 1)
	if _, err := c.Mkdir("/r"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	ctx := context.Background()
	w, err := m.newWriteHandle("/r/f.txt", true)
	if err != nil {
		t.Fatalf("newWriteHandle: %v", err)
	}
	w2, err := m.newWriteHandle("/r/f.txt", false) // refs=2
	if err != nil {
		t.Fatalf("newWriteHandle 2: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); w.Write(ctx, []byte("data"), 0) }()
	go func() { defer wg.Done(); var a fuse.Attr; w.attr(&a) }()
	go func() { defer wg.Done(); w.Release(ctx) }()
	wg.Wait()
	w2.Release(ctx)
	_ = filepath.Base(w.local)
}
