package client

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"atoll/pkg/types"
)

// TestPutSmallEndToEnd 小文件单请求通道（v2-2a）：
// 数据内联进一个 POST，master 服务端写节点并单事务提交，客户端 1 次往返。
// 落库为 legacy 模型（非 chunked、content=inode ID），覆盖写保留 inode（Generation++）。
func TestPutSmallEndToEnd(t *testing.T) {
	c, _ := newClusterV2(t, 2)
	if _, err := c.Mkdir("/sm"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	// 创建：1 次往返落库，legacy 模型，内容可读。
	data := bytes.Repeat([]byte("small-payload-"), 100) // 1400B
	in1, err := c.PutSmall("/sm/a.txt", data, 2, false)
	if err != nil {
		t.Fatalf("PutSmall create: %v", err)
	}
	if in1.Chunked || in1.Size != int64(len(data)) {
		t.Fatalf("应为 legacy 模型且大小一致: %+v", in1)
	}
	if in1.Generation != 1 {
		t.Fatalf("首次提交 Generation 应为 1, got %d", in1.Generation)
	}
	out := filepath.Join(t.TempDir(), "out1")
	if err := c.Get("/sm/a.txt", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, data) {
		t.Fatalf("内容不符: got %d bytes want %d", len(got), len(data))
	}

	// 覆盖写：inode 保留（legacy in-place），Generation++，内容更新。
	data2 := bytes.Repeat([]byte("V2-"), 100)
	in2, err := c.PutSmall("/sm/a.txt", data2, 2, true)
	if err != nil {
		t.Fatalf("PutSmall overwrite: %v", err)
	}
	if in2.ID != in1.ID {
		t.Fatalf("覆盖写应保留 inode: %d != %d", in2.ID, in1.ID)
	}
	if in2.Generation != 2 {
		t.Fatalf("覆盖后 Generation 应为 2, got %d", in2.Generation)
	}
	out2 := filepath.Join(t.TempDir(), "out2")
	if err := c.Get("/sm/a.txt", out2); err != nil {
		t.Fatalf("Get v2: %v", err)
	}
	if got, _ := os.ReadFile(out2); !bytes.Equal(got, data2) {
		t.Fatalf("覆盖后内容不符")
	}

	// 无 overwrite 重复创建 → 冲突。
	if _, err := c.PutSmall("/sm/a.txt", data, 2, false); err == nil {
		t.Fatal("已存在且未 overwrite 应报错")
	}
	// 超过 SmallFileMax → 拒绝（客户端与 master 双重防线，这里测客户端侧拒绝）。
	if _, err := c.PutSmall("/sm/big.bin", make([]byte, types.SmallFileMax+1), 1, false); err == nil {
		t.Fatal("超限应报错")
	}
	// 父目录不存在 → 报错。
	if _, err := c.PutSmall("/no/such/x.txt", data, 1, false); err == nil {
		t.Fatal("父目录缺失应报错")
	}
}

// TestPutSmallChunkedOverwriteConvertsLegacy 小内容覆盖 chunked 大文件：记录转为
// legacy 单对象模型（Chunked=false），旧块对象由 master 回收，读路径立即可用。
func TestPutSmallChunkedOverwriteConvertsLegacy(t *testing.T) {
	c, _ := newClusterV2(t, 2)
	if _, err := c.Mkdir("/sm"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	// 先放一个 chunked 文件（复用现有协议）。
	local := filepath.Join(t.TempDir(), "big.bin")
	big := bytes.Repeat([]byte("B"), 3000)
	os.WriteFile(local, big, 0o644)
	if err := c.PutChunked(local, "/sm/f.bin", 2); err != nil {
		t.Fatalf("PutChunked: %v", err)
	}
	inBig, _, err := c.Lookup("/sm/f.bin")
	if err != nil || !inBig.Chunked {
		t.Fatalf("前置应为 chunked: %+v %v", inBig, err)
	}

	// 小内容覆盖 → 转 legacy。
	small := []byte("now-i-am-small")
	inSmall, err := c.PutSmall("/sm/f.bin", small, 2, true)
	if err != nil {
		t.Fatalf("PutSmall overwrite chunked: %v", err)
	}
	if inSmall.Chunked {
		t.Fatalf("小内容覆盖后应转 legacy: %+v", inSmall)
	}
	if inSmall.ID != inBig.ID || inSmall.Generation != inBig.Generation+1 {
		t.Fatalf("应保留身份且 Generation 递进: %+v vs %+v", inSmall, inBig)
	}
	out := filepath.Join(t.TempDir(), "out")
	if err := c.Get("/sm/f.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, small) {
		t.Fatalf("覆盖后内容不符")
	}
}
