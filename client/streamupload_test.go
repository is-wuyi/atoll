package client

import (
	"bytes"
	"testing"

	"atoll/pkg/types"
)

// 流式上传全链路：Begin → Push 若干整块 → Finish 尾巴 → commit → 状态正确。
// 复用 withChunkSize 把块调小，构造真实多块流而不必传 64MB×3。
func TestStreamUploadBasic(t *testing.T) {
	withChunkSize(t, 1024) // 1KB 块
	c, _ := newClusterV2(t, 3)

	u, err := c.BeginStreamUpload("/stream.bin", 2)
	if err != nil {
		t.Fatalf("BeginStreamUpload: %v", err)
	}
	// 3 整块 + 100B 尾巴。
	blk := bytes.Repeat([]byte{0xAB}, int(types.ChunkSize))
	for i := 0; i < 3; i++ {
		if err := u.Push(blk); err != nil {
			t.Fatalf("Push #%d: %v", i, err)
		}
	}
	tail := bytes.Repeat([]byte{0xCD}, 100)
	total := int64(3*types.ChunkSize + 100)
	if err := u.Finish(tail, total); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	// commit 后可见、大小与块数正确。
	in, _, err := c.Lookup("/stream.bin")
	if err != nil {
		t.Fatalf("Lookup after stream: %v", err)
	}
	if in.Size != total {
		t.Fatalf("size %d != %d", in.Size, total)
	}
	if len(in.Chunks) != 4 {
		t.Fatalf("chunks %d != 4", len(in.Chunks))
	}
	// commit 只保证主副本落盘（minCopies=1）；第 2 份由后台复制/修复异步补齐，
	// commit 时不作保证。
	for _, c2 := range in.Chunks {
		if len(c2.Done) < 1 {
			t.Fatalf("块 %d done=%v < 1（minCopies=1）", c2.Index, c2.Done)
		}
	}
	if got := u.Progress(); got != total {
		t.Fatalf("Progress %d != total %d", got, total)
	}
}

// Close 未 Finish = abort：staging 不应变成已提交文件。
func TestStreamUploadCloseWithoutFinish(t *testing.T) {
	withChunkSize(t, 1024)
	c, _ := newClusterV2(t, 2)

	u, err := c.BeginStreamUpload("/cw.bin", 2)
	if err != nil {
		t.Fatal(err)
	}
	blk := bytes.Repeat([]byte{0x11}, int(types.ChunkSize))
	if err := u.Push(blk); err != nil {
		t.Fatal(err)
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	// Close 后 Finish 必失败（staging 已 abort）。
	if err := u.Finish(nil, types.ChunkSize); err == nil {
		t.Fatal("Close 后 Finish 应失败")
	}
	// 目录里不应出现该文件。
	if _, _, err := c.Lookup("/cw.bin"); err == nil {
		t.Fatal("abort 的 staging 不应出现在目录里")
	}
}

// 小文件流式（只有尾巴、无整块）也应 commit 成功。
func TestStreamUploadTailOnly(t *testing.T) {
	withChunkSize(t, 1024)
	c, _ := newClusterV2(t, 2)

	u, err := c.BeginStreamUpload("/small.bin", 2)
	if err != nil {
		t.Fatal(err)
	}
	tail := []byte("streaming small file")
	if err := u.Finish(tail, int64(len(tail))); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	in, _, err := c.Lookup("/small.bin")
	if err != nil || in.Size != int64(len(tail)) {
		t.Fatalf("小文件流式失败: %v %+v", err, in)
	}
}

// Push 后 Finish 前 Progress 应反映已上传字节（异步，允许短暂滞后，这里
// 用小块+同步等待避免抖动：Finish 成功后 Progress 必须等于总量）。
func TestStreamUploadProgressAccounting(t *testing.T) {
	withChunkSize(t, 512)
	c, _ := newClusterV2(t, 2)

	u, err := c.BeginStreamUpload("/prog.bin", 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := u.Push(bytes.Repeat([]byte{byte(i)}, 512)); err != nil {
			t.Fatal(err)
		}
	}
	tail := []byte("tail")
	if err := u.Finish(tail, 2*512+int64(len(tail))); err != nil {
		t.Fatal(err)
	}
	if got := u.Progress(); got != 2*512+int64(len(tail)) {
		t.Fatalf("Progress %d != %d", got, 2*512+int64(len(tail)))
	}
}
