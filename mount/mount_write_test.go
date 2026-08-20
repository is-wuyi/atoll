package mount

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"atoll/client"
)

// waitReplica 轮询直到文件有 >= n 个已完成副本。
func waitReplica(t *testing.T, c *client.Client, path string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, reps, err := c.Lookup(path)
		if err == nil {
			done := 0
			for _, r := range reps {
				if r.Done {
					done++
				}
			}
			if done >= n {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等待 %d 副本超时: %s", n, path)
}

// TestWriteHandleFlushRelease 验证 write→flush→release 完整生命周期。
func TestWriteHandleFlushRelease(t *testing.T) {
	c, m := newTestCluster(t, 1)

	if _, err := c.Mkdir("/wr"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	// 创建 writeHandle 并验证注册。
	w, err := m.newWriteHandle("/wr/file.txt", true)
	if err != nil {
		t.Fatalf("newWriteHandle: %v", err)
	}
	m.mu.Lock()
	if _, ok := m.writes["/wr/file.txt"]; !ok {
		m.mu.Unlock()
		t.Fatal("writeHandle 未注册到 writes")
	}
	m.mu.Unlock()

	// Write 数据。
	data := []byte("hello, write handle lifecycle!")
	n, errno := w.Write(context.Background(), data, 0)
	if errno != 0 || n != uint32(len(data)) {
		t.Fatalf("Write: n=%d errno=%v", n, errno)
	}

	// Flush 上传。
	if errno := w.Flush(context.Background()); errno != 0 {
		t.Fatalf("Flush: %v", errno)
	}
	waitReplica(t, c, "/wr/file.txt", 1)

	// 集群侧可 Get 到写入内容。
	outPath := filepath.Join(t.TempDir(), "out.txt")
	if err := c.Get("/wr/file.txt", outPath); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(outPath)
	if !bytes.Equal(got, data) {
		t.Fatalf("内容不符: got %q, want %q", got, data)
	}

	// Release 后验证本地缓冲文件被删除、writes 注册表清空。
	if errno := w.Release(context.Background()); errno != 0 {
		t.Fatalf("Release: %v", errno)
	}
	if _, err := os.Stat(w.local); !os.IsNotExist(err) {
		t.Fatal("本地缓冲文件应已删除")
	}
	m.mu.Lock()
	_, ok := m.writes["/wr/file.txt"]
	m.mu.Unlock()
	if ok {
		t.Fatal("writes 注册表应已清空")
	}
}

// TestWriteHandleOverwrite 验证同路径二次写入，第二次覆盖第一次。
func TestWriteHandleOverwrite(t *testing.T) {
	c, m := newTestCluster(t, 1)

	if _, err := c.Mkdir("/ow"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	// 第一次写入。
	w1, err := m.newWriteHandle("/ow/data.txt", true)
	if err != nil {
		t.Fatalf("newWriteHandle 1: %v", err)
	}
	w1.Write(context.Background(), []byte("version-1"), 0)
	if errno := w1.Flush(context.Background()); errno != 0 {
		t.Fatalf("Flush 1: %v", errno)
	}
	waitReplica(t, c, "/ow/data.txt", 1)

	// 第二次写入（同路径，overwrite）。
	w2, err := m.newWriteHandle("/ow/data.txt", true)
	if err != nil {
		t.Fatalf("newWriteHandle 2: %v", err)
	}
	w2.Write(context.Background(), []byte("version-2"), 0)
	if errno := w2.Flush(context.Background()); errno != 0 {
		t.Fatalf("Flush 2: %v", errno)
	}
	waitReplica(t, c, "/ow/data.txt", 1)

	// 集群侧内容为第二版本。
	outPath := filepath.Join(t.TempDir(), "ow_out.txt")
	if err := c.Get("/ow/data.txt", outPath); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(outPath)
	if string(got) != "version-2" {
		t.Fatalf("应为第二版本, got %q", got)
	}

	w1.Release(context.Background())
	w2.Release(context.Background())
}

// TestWriteHandleDiscardFlushNoop 验证 discard 后 Flush 不触发上传。
func TestWriteHandleDiscardFlushNoop(t *testing.T) {
	c, m := newTestCluster(t, 1)

	c.Mkdir("/disc")

	w, err := m.newWriteHandle("/disc/test.txt", true)
	if err != nil {
		t.Fatalf("newWriteHandle: %v", err)
	}
	w.Write(context.Background(), []byte("will be discarded"), 0)

	// discard。
	w.discard()

	// Flush 应为 no-op（dropped=true，直接返回）。
	if errno := w.Flush(context.Background()); errno != 0 {
		t.Fatalf("Flush after discard: %v", errno)
	}

	// 集群侧无该文件。
	if _, _, err := c.Lookup("/disc/test.txt"); err == nil {
		t.Fatal("文件不应存在于集群（discard 后 Flush 不应上传）")
	}
}

// TestWriteHandleRenameFollows 验证写入中路径被 rename 后，Flush 上传到新路径。
func TestWriteHandleRenameFollows(t *testing.T) {
	c, m := newTestCluster(t, 1)

	if _, err := c.Mkdir("/rdir"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	w, err := m.newWriteHandle("/rdir/old.txt", true)
	if err != nil {
		t.Fatalf("newWriteHandle: %v", err)
	}
	w.Write(context.Background(), []byte("rename me"), 0)

	// 模拟同目录 rename（与 node.Rename 中写注册表更新逻辑一致）。
	oldPath := "/rdir/old.txt"
	newPath := "/rdir/new.txt"
	m.mu.Lock()
	if wh, ok := m.writes[oldPath]; ok {
		delete(m.writes, oldPath)
		wh.remote = newPath
		m.writes[newPath] = wh
	}
	m.mu.Unlock()

	// 验证注册表键已更新。
	m.mu.Lock()
	_, hasOld := m.writes[oldPath]
	_, hasNew := m.writes[newPath]
	m.mu.Unlock()
	if hasOld {
		t.Fatal("旧路径应已从 writes 中移除")
	}
	if !hasNew {
		t.Fatal("新路径应存在于 writes 中")
	}

	// Flush 上传到新路径。
	if errno := w.Flush(context.Background()); errno != 0 {
		t.Fatalf("Flush: %v", errno)
	}
	waitReplica(t, c, "/rdir/new.txt", 1)

	// 新路径可读到内容。
	outPath := filepath.Join(t.TempDir(), "rename_out.txt")
	if err := c.Get("/rdir/new.txt", outPath); err != nil {
		t.Fatalf("Get new path: %v", err)
	}
	got, _ := os.ReadFile(outPath)
	if string(got) != "rename me" {
		t.Fatalf("内容不符: %q", got)
	}

	// 旧路径不存在。
	if _, _, err := c.Lookup("/rdir/old.txt"); err == nil {
		t.Fatal("旧路径不应存在于集群")
	}

	w.Release(context.Background())
}

// TestWriteHandleTruncate 验证 Truncate(0) 后本地缓冲文件大小为 0。
func TestWriteHandleTruncate(t *testing.T) {
	_, m := newTestCluster(t, 1)

	w, err := m.newWriteHandle("/trunc/file.txt", true)
	if err != nil {
		t.Fatalf("newWriteHandle: %v", err)
	}

	// 写入数据。
	w.Write(context.Background(), []byte("some data here"), 0)

	// Truncate(0)。
	if errno := w.truncate(0); errno != 0 {
		t.Fatalf("truncate: %v", errno)
	}

	// 本地缓冲文件大小为 0。
	st, err := os.Stat(w.local)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() != 0 {
		t.Fatalf("truncate 后文件大小应为 0, got %d", st.Size())
	}

	w.Release(context.Background())
}

// TestWriteHandleFlushThenWriteAgain 回归测试：同一句柄 Flush 上传后必须还能继续 Write。
// 根因：http transport 上传完会关闭 req.Body，直接传 *os.File 会把句柄关掉，
// 实机表现为 O_TRUNC 覆盖写路径（SETATTR→FLUSH→WRITE）第二次写报 EIO。
func TestWriteHandleFlushThenWriteAgain(t *testing.T) {
	c, m := newTestCluster(t, 1)

	ctx := context.Background()
	w, err := m.newWriteHandle("/reuse.txt", true)
	if err != nil {
		t.Fatalf("newWriteHandle: %v", err)
	}

	// 第一轮：写入 v1 并 Flush（触发上传）。
	if _, errno := w.Write(ctx, []byte("v1-data"), 0); errno != 0 {
		t.Fatalf("第一次 Write: %v", errno)
	}
	if errno := w.Flush(ctx); errno != 0 {
		t.Fatalf("第一次 Flush: %v", errno)
	}

	// 第二轮：同一句柄继续写（旧 bug 在此 EIO：句柄已被 transport 关闭）。
	if _, errno := w.Write(ctx, []byte("v2-data"), 0); errno != 0 {
		t.Fatalf("Flush 后再次 Write 失败（句柄被 http transport 关闭的回归 bug）: %v", errno)
	}
	if errno := w.truncate(0); errno != 0 {
		t.Fatalf("truncate: %v", errno)
	}
	if _, errno := w.Write(ctx, []byte("v2-data"), 0); errno != 0 {
		t.Fatalf("truncate 后 Write: %v", errno)
	}
	if errno := w.Flush(ctx); errno != 0 {
		t.Fatalf("第二次 Flush: %v", errno)
	}
	w.Release(ctx)

	// 集群侧最终内容必须是第二轮版本。
	down := filepath.Join(t.TempDir(), "down.txt")
	if err := c.Get("/reuse.txt", down); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(down)
	if !bytes.Equal(got, []byte("v2-data")) {
		t.Fatalf("最终内容: %q, want %q", got, "v2-data")
	}
}
