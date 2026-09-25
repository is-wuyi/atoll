package mount

import (
	"bytes"
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"atoll/pkg/types"
)

// withChunkSize 临时把全局块大小改小以构造真实多块流式链路，测试结束恢复。
// mount 包测试顺序执行（无 t.Parallel），改全局 var 安全。
func withChunkSize(t *testing.T, sz int64) {
	t.Helper()
	orig := types.ChunkSize
	types.ChunkSize = sz
	t.Cleanup(func() { types.ChunkSize = orig })
}

// streamWriteAndVerify 用给定的写投递顺序把 content 写进 remote，Flush 后下载比对。
// pieces 是 [off,len) 段列表，按其顺序调用 Write，模拟 FUSE 的顺序/乱序投递。
func streamWriteAndVerify(t *testing.T, cc *chunkCluster, remote string, content []byte, order [][2]int) {
	t.Helper()
	w, err := cc.m.newWriteHandle(remote, true)
	if err != nil {
		t.Fatalf("newWriteHandle: %v", err)
	}
	w.created = true // Create 置位；流式路径不依赖它，仅保持与真实句柄一致
	w.streamOn = true
	ctx := context.Background()
	for _, seg := range order {
		off, n := seg[0], seg[1]
		if _, errno := w.Write(ctx, content[off:off+n], int64(off)); errno != 0 {
			t.Fatalf("Write(off=%d,n=%d): errno=%v", off, n, errno)
		}
	}
	if errno := w.Flush(ctx); errno != 0 {
		t.Fatalf("Flush: errno=%v（提交卡住/失败即说明块不全）", errno)
	}
	if errno := w.Release(ctx); errno != 0 {
		t.Fatalf("Release: errno=%v", errno)
	}

	in, _, err := cc.client.Lookup(remote)
	if err != nil {
		t.Fatalf("Lookup 提交后: %v", err)
	}
	if !in.Chunked {
		t.Fatalf("应为分块文件, got %+v", in)
	}
	if in.Size != int64(len(content)) {
		t.Fatalf("大小不符: got %d want %d", in.Size, len(content))
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := cc.client.Get(remote, out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatalf("读回内容不符: got %d bytes want %d", len(got), len(content))
	}
}

// 顺序多块写：小于一块的多次追加写必须攒够 64MB（此处 1KB）成整块推送。
// 旧实现的 off==sentIdx 判定会在第二次写就漏掉（sentIdx 未含 pend 长度），
// 导致只推首段、commit 因缺块死等——本例锁死该回归。
func TestStreamWriteSequentialMultiChunk(t *testing.T) {
	withChunkSize(t, 1024) // 1KB 块
	cc := newChunkedCluster(t, 2)
	if _, err := cc.client.Mkdir("/s"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := make([]byte, 3584) // 3×1024 + 512 → 4 块
	rand.New(rand.NewSource(7)).Read(content)

	var order [][2]int // 顺序 200B 一段
	for off := 0; off < len(content); off += 200 {
		n := 200
		if off+n > len(content) {
			n = len(content) - off
		}
		order = append(order, [2]int{off, n})
	}
	streamWriteAndVerify(t, cc, "/s/seq.bin", content, order)
}

// 乱序多块写：FUSE 并发投递可乱序（go-fuse 每请求一 goroutine，抢锁顺序不定）。
// 流式必须据"连续写入水位"从本地文件读整块，而非按到达的 data 攒块——否则漏块
// 或拼错。本例把段打乱后投递，验证提交成功且内容逐字节一致。
func TestStreamWriteOutOfOrder(t *testing.T) {
	withChunkSize(t, 1024)
	cc := newChunkedCluster(t, 2)
	if _, err := cc.client.Mkdir("/s"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := make([]byte, 4096) // 恰 4 整块，无尾巴
	rand.New(rand.NewSource(99)).Read(content)

	var order [][2]int
	for off := 0; off < len(content); off += 128 {
		order = append(order, [2]int{off, 128})
	}
	// 打乱投递顺序（含把 0 号段排到很后面，考验延迟建会话 + ooo 吸收）。
	rng := rand.New(rand.NewSource(12345))
	rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	streamWriteAndVerify(t, cc, "/s/ooo.bin", content, order)
}

// 预分配写（Finder 拷贝的模式）：先 ftruncate 到完整大小再顺序写。
// 之前 truncate 一律放弃流式→退回 close 整传→大文件把 Finder close 拖超时
// （「设备已消失」）。修复后预分配应保留流式；本例锁死该回归。
func TestStreamWritePreallocatedThenWrite(t *testing.T) {
	withChunkSize(t, 1024)
	cc := newChunkedCluster(t, 2)
	if _, err := cc.client.Mkdir("/s"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := make([]byte, 3584) // 3×1024 + 512 → 4 块
	rand.New(rand.NewSource(23)).Read(content)

	w, err := cc.m.newWriteHandle("/s/prealloc.bin", true)
	if err != nil {
		t.Fatalf("newWriteHandle: %v", err)
	}
	w.created = true
	w.streamOn = true
	ctx := context.Background()
	// Finder 式：先预分配到完整大小。
	if errno := w.truncate(uint64(len(content))); errno != 0 {
		t.Fatalf("truncate(预分配): %v", errno)
	}
	if !w.streamOn {
		t.Fatalf("预分配后不应关闭流式（否则大文件 close 会拖垮 Finder）")
	}
	for off := 0; off < len(content); off += 200 {
		n := 200
		if off+n > len(content) {
			n = len(content) - off
		}
		if _, errno := w.Write(ctx, content[off:off+n], int64(off)); errno != 0 {
			t.Fatalf("Write(off=%d): %v", off, errno)
		}
	}
	if errno := w.Flush(ctx); errno != 0 {
		t.Fatalf("Flush: %v（预分配路径卡住即回归）", errno)
	}
	_ = w.Release(ctx)

	in, _, err := cc.client.Lookup("/s/prealloc.bin")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !in.Chunked || in.Size != int64(len(content)) {
		t.Fatalf("元数据不符: chunked=%v size=%d want %d", in.Chunked, in.Size, len(content))
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := cc.client.Get("/s/prealloc.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatalf("读回不符: got %d want %d", len(got), len(content))
	}
}
