package client

import (
	"bytes"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"atoll/pkg/types"
)

// withChunkSize 临时把全局块大小改小以构造真实多块链路，测试结束恢复。
// client 包测试默认顺序执行（无 t.Parallel），改全局 var 安全。
func withChunkSize(t *testing.T, sz int64) {
	t.Helper()
	orig := types.ChunkSize
	types.ChunkSize = sz
	t.Cleanup(func() { types.ChunkSize = orig })
}

// TestMultiChunkPutGet 真实多块（4 块，末块不满）流水线上传 → 元数据块表校验 →
// 下载逐字节比对 → 多块覆盖写。补上 spec 测试计划第 3 条长期缺失的多块链路。
func TestMultiChunkPutGet(t *testing.T) {
	withChunkSize(t, 1024) // 1KB 块
	c, _ := newClusterV2(t, 3)
	dir := t.TempDir()

	if _, err := c.Mkdir("/m"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	// 3584B = 3×1024 + 512 → 4 块。内容随机，确保任何拼装错位都能被 bytes.Equal 抓到。
	content := make([]byte, 3584)
	rand.New(rand.NewSource(42)).Read(content)
	local := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(local, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.PutChunked(local, "/m/big.bin", 2); err != nil {
		t.Fatalf("PutChunked: %v", err)
	}

	// 元数据：4 块，下标 0..3 连续，末块 512B，Σ = 3584。
	in, _, err := c.Lookup("/m/big.bin")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !in.Chunked || len(in.Chunks) != 4 {
		t.Fatalf("应为 4 块，实际: %d 块 (%+v)", len(in.Chunks), in.Chunks)
	}
	var sum int64
	for i, ch := range in.Chunks {
		if ch.Index != i {
			t.Fatalf("块下标不连续: 位置 %d 是 index %d", i, ch.Index)
		}
		sum += ch.Size
	}
	if sum != int64(len(content)) || in.Chunks[3].Size != 512 {
		t.Fatalf("块大小不符: Σ=%d 末块=%d", sum, in.Chunks[3].Size)
	}

	// 下载逐字节比对。
	out := filepath.Join(dir, "big_out.bin")
	if err := c.Get("/m/big.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatalf("多块下载内容不符: 得 %d 字节", len(got))
	}

	// 多块覆盖写：换成 2.5 块的新内容，读回应为新版本。
	content2 := make([]byte, 2560) // 2×1024 + 512 → 3 块
	rand.New(rand.NewSource(99)).Read(content2)
	os.WriteFile(local, content2, 0o644)
	if err := c.PutChunkedOverwrite(local, "/m/big.bin", 2, true); err != nil {
		t.Fatalf("覆盖写: %v", err)
	}
	out2 := filepath.Join(dir, "big_out2.bin")
	if err := c.Get("/m/big.bin", out2); err != nil {
		t.Fatalf("Get v2: %v", err)
	}
	got2, _ := os.ReadFile(out2)
	if !bytes.Equal(got2, content2) {
		t.Fatalf("覆盖写后读回应为新版本（%d 字节），得 %d 字节", len(content2), len(got2))
	}
}

// TestGetShortReadFailover 一个副本返回截断内容（200 但字节数不足）时，
// client 应识别短读并转移到完整副本，而非把截断数据当成功返回（静默截断回归保护）。
func TestGetShortReadFailover(t *testing.T) {
	c, _ := newClusterV2(t, 1)
	dir := t.TempDir()
	content := bytes.Repeat([]byte("ATOLL"), 4000) // 20000B
	local := filepath.Join(dir, "s.bin")
	os.WriteFile(local, content, 0o644)
	if err := c.Put(local, "/s.bin", 1); err != nil {
		t.Fatalf("Put: %v", err)
	}
	waitDone(t, c, "/s.bin", 1)
	in, reps, _ := c.Lookup("/s.bin")

	// 坏代理：200 但只回前 100 字节（截断）。
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(content[:100])
	}))
	defer bad.Close()
	badReplica := Replica{ID: 999, Addr: bad.Listener.Addr().String(), Done: true}
	good := reps[0]
	good.Done = true

	// 坏地址在前、好地址在后：长度校验应跳过截断副本，最终从好副本取回完整内容。
	out := filepath.Join(dir, "s_out.bin")
	if err := c.getFromReplicas(in, []Replica{badReplica, good}, out); err != nil {
		t.Fatalf("应能从好副本抢救完整内容，实际: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatalf("短读转移后应得完整内容（%d 字节），得 %d 字节", len(content), len(got))
	}

	// 只有坏副本时必须失败（不能把 100 字节当成功）。
	if err := c.getFromReplicas(in, []Replica{badReplica}, out); err == nil {
		t.Fatal("只有截断副本时 Get 应失败，而非返回截断数据")
	}
}
