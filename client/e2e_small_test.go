package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

// dropSmallResponseOnce 丢掉 /files/small 的第一个响应（服务端已处理、客户端没收到），
// 模拟响应丢失。PutSmall 应凭 op_id 内部重试拿到幂等结果。
type dropSmallResponseOnce struct {
	base     http.RoundTripper
	dropped  bool
	dropNext atomic.Bool
}

func (d *dropSmallResponseOnce) RoundTrip(r *http.Request) (*http.Response, error) {
	if d.dropNext.CompareAndSwap(true, false) && strings.Contains(r.URL.Path, "/files/small") {
		resp, err := d.base.RoundTrip(r)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return nil, fmt.Errorf("simulated: response lost (server had processed)")
	}
	return d.base.RoundTrip(r)
}

// TestPutSmallResponseLostRetriesIdempotently 响应丢失 → PutSmall 内部以同一 op_id 重试 →
// 服务端回放原结果 → 客户端拿到成功且文件只创建一份（v2-3a）。
func TestPutSmallResponseLostRetriesIdempotently(t *testing.T) {
	c, _ := newClusterV2(t, 1)
	if _, err := c.Mkdir("/sm"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	hc := *c.HTTP
	hc.Transport = &dropSmallResponseOnce{base: http.DefaultTransport, dropNext: *new(atomic.Bool)}
	hc.Transport.(*dropSmallResponseOnce).dropNext.Store(true)
	c.HTTP = &hc

	data := bytes.Repeat([]byte("lost-response-"), 64)
	in, err := c.PutSmall("/sm/lost.txt", data, 1, false)
	if err != nil {
		t.Fatalf("响应丢失后 PutSmall 应凭 op_id 重试成功: %v", err)
	}
	if in.Generation != 1 {
		t.Fatalf("Generation 应为 1: %+v", in)
	}
	// 文件存在且内容正确（服务端第一次就已成功，重试只是拿回结果）。
	out := filepath.Join(t.TempDir(), "out")
	if err := c.Get("/sm/lost.txt", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, data) {
		t.Fatal("内容不符")
	}
}

// TestPutSmallFullCycleIdempotency 真节点全链路：首次执行 201 → 同 op_id 重试 200
// 回放同一 inode（服务端不重复创建）。raw HTTP 以固定 op_id 驱动。
func TestPutSmallFullCycleIdempotency(t *testing.T) {
	c, _ := newClusterV2(t, 1)
	if _, err := c.Mkdir("/sm"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	post := func(opID string) (int, uint64) {
		u := fmt.Sprintf("%s/files/small?path=/sm/idem.txt&replicas=1&overwrite=false&op_id=%s", c.MasterURL, opID)
		resp, err := http.Post(u, "application/octet-stream", bytes.NewReader([]byte("payload")))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Inode struct {
				ID uint64 `json:"id"`
			} `json:"inode"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out.Inode.ID
	}
	code1, id1 := post("op-e2e-fixed")
	if code1 != 201 {
		t.Fatalf("首次应 201, got %d", code1)
	}
	code2, id2 := post("op-e2e-fixed")
	if code2 != 200 || id2 != id1 {
		t.Fatalf("重试应 200 且返回原 inode: code=%d id=%d (want 200/%d)", code2, id2, id1)
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
