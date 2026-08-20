package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

// clusterNode 记录测试集群里一个 node 的句柄。
type clusterNode struct {
	node   *node.Node
	server *httptest.Server
}

// addr 返回供客户端直连的 host:port。
func (cn *clusterNode) addr() string {
	return cn.server.Listener.Addr().String()
}

// newClusterV2 用 httptest 启动一套最小集群：1 master + N node。
// node 走真实注册流程（拿到 nodeID，复制逻辑才会生效）。
func newClusterV2(t *testing.T, numNodes int) (*Client, []*clusterNode) {
	t.Helper()

	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	masterSrv := httptest.NewServer(master.NewServer(store, time.Hour).Handler())
	t.Cleanup(func() { masterSrv.Close() })

	var nodes []*clusterNode
	for i := 0; i < numNodes; i++ {
		n := node.New(filepath.Join(t.TempDir(), "data"), masterSrv.URL, "", 1<<30)
		nodeSrv := httptest.NewServer(n.Handler())
		t.Cleanup(func() { nodeSrv.Close() })
		cn := &clusterNode{node: n, server: nodeSrv}

		// 真实注册：node 自己发请求拿 ID（走 node.Register 的 HTTP 部分）。
		resp, err := postRaw(masterSrv.URL+"/nodes/register",
			fmt.Sprintf(`{"addr": %q, "total_bytes": 1073741824}`, cn.addr()))
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("node %d 注册失败: %v status=%d", i, err, resp.StatusCode)
		}
		var reg struct {
			ID uint64 `json:"id"`
		}
		if err := decodeBody(resp.Body, &reg); err != nil {
			t.Fatalf("解码注册响应: %v", err)
		}
		resp.Body.Close()
		n.SetNodeIDForTest(reg.ID)
		nodes = append(nodes, cn)
	}
	return New(masterSrv.URL), nodes
}

// waitDone 轮询 master 直到该文件有 >= n 个已完成副本，超时失败。
func waitDone(t *testing.T, c *Client, path string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, nodes, err := c.lookup(path)
		if err == nil {
			done := 0
			for _, nd := range nodes {
				if nd.Done {
					done++
				}
			}
			if done >= n {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("等待 %d 个副本同步完成超时: %s", n, path)
}

// 全链路（单副本基础流）：mkdir → put → ls → get → rm
func TestEndToEnd(t *testing.T) {
	c, _ := newClusterV2(t, 1)

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
	if err := c.Put(local, "/docs/hello.txt", 1); err != nil {
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
	c, _ := newClusterV2(t, 1)
	dir := t.TempDir()
	local := filepath.Join(dir, "a.txt")
	os.WriteFile(local, []byte("first"), 0o644)

	if err := c.Put(local, "/a.txt", 1); err != nil {
		t.Fatalf("首次 Put: %v", err)
	}
	if err := c.Put(local, "/a.txt", 1); err == nil {
		t.Fatal("重复 Put 同一路径应失败")
	}
}

// 阶段2核心：多副本异步复制——put 后等待全部副本落盘，验证每个节点都有对象。
func TestAsyncReplication(t *testing.T) {
	c, nodes := newClusterV2(t, 3)

	dir := t.TempDir()
	local := filepath.Join(dir, "big.bin")
	content := bytes.Repeat([]byte("atoll-replica-"), 10000) // ~140KB
	if err := os.WriteFile(local, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(local, "/repl.bin", 3); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// 等待 3 副本全部 Done。
	waitDone(t, c, "/repl.bin", 3)

	// 直接读每个节点的磁盘，验证对象确实存在且内容正确。
	// node.objectPath 是私有的，改用遍历 objects 目录找 inode 文件。
	for i, cn := range nodes {
		found := false
		var data []byte
		err := filepath.WalkDir(filepath.Join(cn.node.DataDirForTest(), "objects"), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			found = true
			data, _ = os.ReadFile(p)
			return nil
		})
		if err != nil || !found {
			t.Fatalf("节点 %d 上没有对象文件: %v", i, err)
		}
		if !bytes.Equal(data, content) {
			t.Fatalf("节点 %d 上的对象内容不符", i)
		}
	}
}

// 阶段2核心：主副本"宕机"后，从已完成副本读取——容错价值验证。
func TestFailoverRead(t *testing.T) {
	c, nodes := newClusterV2(t, 3)

	dir := t.TempDir()
	local := filepath.Join(dir, "f.txt")
	content := []byte("survive the primary crash!")
	os.WriteFile(local, content, 0o644)
	if err := c.Put(local, "/failover.txt", 3); err != nil {
		t.Fatalf("Put: %v", err)
	}
	waitDone(t, c, "/failover.txt", 3)

	// 关掉主副本（nodes[0] 是 master 分配的第一个候选；查找真正的主副本）。
	// master 的分配是随机的，这里直接关掉"持有该对象的所有节点中的第一个 done 节点"。
	_, replNodes, err := c.lookup("/failover.txt")
	if err != nil {
		t.Fatal(err)
	}
	var primaryAddr string
	for _, nd := range replNodes {
		if nd.Done {
			primaryAddr = nd.Addr
			break
		}
	}
	// 找到对应测试句柄并关闭。
	var victim *clusterNode
	for _, cn := range nodes {
		if cn.addr() == primaryAddr {
			victim = cn
			break
		}
	}
	if victim == nil {
		t.Fatal("找不到主副本节点")
	}
	victim.server.Close()

	// 从剩下的副本读——Get 会在 done 节点里随机挑，victim 已关，
	// 若挑到它会连接失败；随机可能踩坑，重试几次保证不是运气问题。
	var lastErr error
	ok := false
	for i := 0; i < 10 && !ok; i++ {
		out := filepath.Join(dir, "out.txt")
		if lastErr = c.Get("/failover.txt", out); lastErr == nil {
			got, _ := os.ReadFile(out)
			ok = bytes.Equal(got, content)
		}
	}
	if !ok {
		t.Fatalf("主副本宕机后读取失败: %v", lastErr)
	}
}

// 删除时通知节点回收对象（阶段2顺手实现）。
func TestDeleteReclaimsObjects(t *testing.T) {
	c, nodes := newClusterV2(t, 2)

	dir := t.TempDir()
	local := filepath.Join(dir, "del.txt")
	os.WriteFile(local, []byte("to be reclaimed"), 0o644)
	if err := c.Put(local, "/del.txt", 2); err != nil {
		t.Fatalf("Put: %v", err)
	}
	waitDone(t, c, "/del.txt", 2)

	if err := c.Rm("/del.txt"); err != nil {
		t.Fatalf("Rm: %v", err)
	}

	// master 的回收通知是异步的，轮询等待所有节点对象消失。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		remaining := 0
		for _, cn := range nodes {
			filepath.WalkDir(filepath.Join(cn.node.DataDirForTest(), "objects"), func(p string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					remaining++
				}
				return nil
			})
		}
		if remaining == 0 {
			return // 全部回收
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("删除后对象未被回收（超时）")
}

func decodeBody(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}
