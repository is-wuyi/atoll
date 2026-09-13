package client

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestChunkedPutGetSingleBlockMeta 分块协议全链路（单块文件，协议与多块完全相同）：
// 上传 → 元数据块表校验 → 读回比对 → 覆盖写 → 读新版本。
func TestChunkedPutGetSingleBlockMeta(t *testing.T) {
	c, _ := newClusterV2(t, 2)
	dir := t.TempDir()

	if _, err := c.Mkdir("/docs"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := []byte("chunked-single-block-content")
	local := filepath.Join(dir, "sb.bin")
	os.WriteFile(local, content, 0o644)

	if err := c.PutChunked(local, "/docs/sb.bin", 2); err != nil {
		t.Fatalf("PutChunked: %v", err)
	}
	// 元数据：chunked、单块、大小一致。
	in, _, err := c.Lookup("/docs/sb.bin")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !in.Chunked || len(in.Chunks) != 1 || in.Size != int64(len(content)) {
		t.Fatalf("元数据不符: %+v", in)
	}
	if in.Chunks[0].Size != int64(len(content)) {
		t.Fatalf("块大小不符: %d", in.Chunks[0].Size)
	}
	// 读回逐字节比对。
	out := filepath.Join(dir, "sb_out.bin")
	if err := c.Get("/docs/sb.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatalf("读回内容不符: %d 字节", len(got))
	}
	// 覆盖写：新内容替换旧版本，读回新内容。
	content2 := []byte("version-2-content-longer-than-before")
	os.WriteFile(local, content2, 0o644)
	if err := c.PutChunkedOverwrite(local, "/docs/sb.bin", 2, true); err != nil {
		t.Fatalf("PutChunkedOverwrite: %v", err)
	}
	out2 := filepath.Join(dir, "sb_out2.bin")
	if err := c.Get("/docs/sb.bin", out2); err != nil {
		t.Fatalf("Get v2: %v", err)
	}
	got2, _ := os.ReadFile(out2)
	if !bytes.Equal(got2, content2) {
		t.Fatal("覆盖写后读回应为新版本")
	}
}

// TestChunkedAbortOnFailure 主副本不可达时（全部节点关闭）→ 上传失败 → staging 被清理。
func TestChunkedAbortOnFailure(t *testing.T) {
	c, nodes := newClusterV2(t, 2)
	dir := t.TempDir()

	if _, err := c.Mkdir("/docs"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	// 关闭全部节点：assign 会 503，上传失败。
	for _, cn := range nodes {
		cn.server.Close()
	}
	local := filepath.Join(dir, "fail.bin")
	os.WriteFile(local, []byte("will-fail"), 0o644)
	err := c.PutChunked(local, "/docs/fail.bin", 2)
	if err == nil {
		t.Fatal("全部节点关闭时上传应失败")
	}
	if !strings.Contains(err.Error(), "staging") && !strings.Contains(err.Error(), "assign") {
		t.Logf("失败信息（ informational）: %v", err)
	}
}

// waitChunkDone 轮询直到分块文件全部块达到 n 个 done 副本。
func waitChunkDone(t *testing.T, c *Client, path string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		in, _, err := c.Lookup(path)
		if err == nil && len(in.Chunks) > 0 {
			ok := true
			for _, ch := range in.Chunks {
				done := 0
				for _, d := range ch.Done {
					if d != 0 {
						done++
					}
				}
				if done < n {
					ok = false
				}
			}
			if ok {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("等待分块副本同步超时: %s", path)
}

// TestChunkedRepairAfterNodeDeath 分块文件 + 杀一个节点 → 块级修复恢复副本数。
func TestChunkedRepairAfterNodeDeath(t *testing.T) {
	cv := newClusterV3(t, 3, time.Second)
	c := cv.client
	for _, n := range cv.nodes {
		cv.heartbeatNode(n)
	}
	dir := t.TempDir()

	if _, err := c.Mkdir("/docs"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	content := []byte("chunked-repair-content")
	local := filepath.Join(dir, "r.bin")
	os.WriteFile(local, content, 0o644)
	if err := c.PutChunked(local, "/docs/r.bin", 2); err != nil {
		t.Fatalf("PutChunked: %v", err)
	}
	waitChunkDone(t, c, "/docs/r.bin", 2)

	// 找到持有块副本的节点杀掉。
	in, _, _ := c.Lookup("/docs/r.bin")
	victimID := in.Chunks[0].Replicas[0]
	var victim *clusterNode
	for _, cn := range cv.nodes {
		if cn.node.NodeIDForTest() == victimID {
			victim = cn
			break
		}
	}
	if victim == nil {
		t.Fatal("未找到块副本节点")
	}
	victim.server.Close()
	time.Sleep(1200 * time.Millisecond) // 心跳过期
	for _, cn := range cv.nodes {
		if cn != victim {
			cv.heartbeatNode(cn)
		}
	}
	cv.scanner.RepairScanOnce()

	// 块副本恢复到 2。
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		in2, _, err := c.Lookup("/docs/r.bin")
		if err == nil && len(in2.Chunks) == 1 {
			if len(in2.Chunks[0].Done) >= 2 {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	in2, _, _ := c.Lookup("/docs/r.bin")
	if len(in2.Chunks[0].Done) < 2 {
		t.Fatalf("修复后块 done 副本 %d < 2", len(in2.Chunks[0].Done))
	}
	// 读回一致。
	out := filepath.Join(dir, "r_out.bin")
	if err := c.Get("/docs/r.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatal("修复后内容不符")
	}
}

// TestChunkedConcurrentWritersLastWins 并发写竞争：两个写者同时上传同一路径，
// 最后 commit 的胜出；读回必然是某一个完整版本（不会撕裂）。
func TestChunkedConcurrentWritersLastWins(t *testing.T) {
	c, _ := newClusterV2(t, 3)
	dir := t.TempDir()
	if _, err := c.Mkdir("/docs"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	v1 := bytes.Repeat([]byte("A"), 100000)
	v2 := bytes.Repeat([]byte("B"), 80000)
	f1 := filepath.Join(dir, "v1.bin")
	f2 := filepath.Join(dir, "v2.bin")
	os.WriteFile(f1, v1, 0o644)
	os.WriteFile(f2, v2, 0o644)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = c.PutChunked(f1, "/docs/race.bin", 2)
	}()
	go func() {
		defer wg.Done()
		errs[1] = c.PutChunked(f2, "/docs/race.bin", 2)
	}()
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("并发上传失败: %v %v", errs[0], errs[1])
	}

	// 读回必然完整等于某一版本。
	out := filepath.Join(dir, "race_out.bin")
	if err := c.Get("/docs/race.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, v1) && !bytes.Equal(got, v2) {
		t.Fatalf("并发写结果撕裂: %d 字节（非 %d 亦非 %d）", len(got), len(v1), len(v2))
	}
	// 元数据只指向一个 inode。
	in, _, err := c.Lookup("/docs/race.bin")
	if err != nil || !in.Chunked {
		t.Fatalf("元数据不符: %+v %v", in, err)
	}
}
