package client

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/master"
	"atoll/master/meta"
	"atoll/node"
)

// postRaw 发送原始 JSON POST（测试辅助）。
func postRaw(url, body string) (*http.Response, error) {
	return http.Post(url, "application/json", strings.NewReader(body))
}

// newCluster 用 httptest 启动一套最小集群：1 master + N node，并完成注册。
func newCluster(t *testing.T, numNodes int) *Client {
	t.Helper()

	// master
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	masterSrv := httptest.NewServer(master.NewServer(store, time.Hour).Handler())
	t.Cleanup(func() { masterSrv.Close() })

	// nodes：注册地址用 httptest 的 host:port，保证客户端能直连。
	for i := 0; i < numNodes; i++ {
		n := node.New(filepath.Join(t.TempDir(), "data"), masterSrv.URL, "", 1<<30)
		nodeSrv := httptest.NewServer(n.Handler())
		t.Cleanup(func() { nodeSrv.Close() })

		// 手动注册（不走 n.Register 的心跳协程，测试里不需要）。
		body := `{"addr": "` + nodeSrv.Listener.Addr().String() + `", "total_bytes": 1073741824}`
		resp, err := postRaw(masterSrv.URL+"/nodes/register", body)
		if err != nil || resp.StatusCode != 201 {
			t.Fatalf("node 注册失败: %v, status=%d", err, resp.StatusCode)
		}
		resp.Body.Close()
	}
	return New(masterSrv.URL)
}

// 全链路：mkdir → put → ls → get → rm
func TestEndToEnd(t *testing.T) {
	c := newCluster(t, 1)

	// 1. mkdir
	if _, err := c.Mkdir("/docs"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	// 2. put：本地临时文件上传
	dir := t.TempDir()
	local := filepath.Join(dir, "hello.txt")
	content := []byte("hello, atoll archipelago!")
	if err := os.WriteFile(local, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(local, "/docs/hello.txt"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// 3. ls：应看到文件
	kids, err := c.Ls("/docs")
	if err != nil {
		t.Fatalf("Ls: %v", err)
	}
	if len(kids) != 1 || kids[0].Name != "hello.txt" {
		t.Fatalf("Ls 结果不符: %+v", kids)
	}
	if kids[0].Size != int64(len(content)) {
		t.Fatalf("大小不符: %d, want %d", kids[0].Size, len(content))
	}

	// 4. get：下载并比对内容
	down := filepath.Join(dir, "down.txt")
	if err := c.Get("/docs/hello.txt", down); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(down)
	if !bytes.Equal(got, content) {
		t.Fatalf("读回内容不符: %q", got)
	}

	// 5. rm：删除后 ls 应为空，get 应报错
	if err := c.Rm("/docs/hello.txt"); err != nil {
		t.Fatalf("Rm: %v", err)
	}
	kids2, _ := c.Ls("/docs")
	if len(kids2) != 0 {
		t.Fatalf("删除后目录应空: %+v", kids2)
	}
	errOut := filepath.Join(dir, "gone.txt")
	if err := c.Get("/docs/hello.txt", errOut); err == nil {
		t.Fatal("删除后 Get 应报错")
	}
}

// put 已存在的路径应失败（重名检查走 master）
func TestPutDuplicateFails(t *testing.T) {
	c := newCluster(t, 1)
	dir := t.TempDir()
	local := filepath.Join(dir, "a.txt")
	os.WriteFile(local, []byte("first"), 0o644)

	if err := c.Put(local, "/a.txt"); err != nil {
		t.Fatalf("首次 Put: %v", err)
	}
	if err := c.Put(local, "/a.txt"); err == nil {
		t.Fatal("重复 Put 同一路径应失败")
	}
}
