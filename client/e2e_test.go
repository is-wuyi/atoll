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
	"strconv"
	"strings"
	"testing"
	"time"

	"atoll/master"
	"atoll/master/meta"
	"atoll/node"
)

// clusterV3 支持可配 nodeMaxAge + Scanner 的测试集群。
type clusterV3 struct {
	client  *Client
	store   *meta.Store
	server  *httptest.Server
	scanner *master.Scanner
	nodes   []*clusterNode
}

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

// newClusterV3 创建带 Scanner 的测试集群（nodeMaxAge 可配）。
func newClusterV3(t *testing.T, numNodes int, nodeMaxAge time.Duration) *clusterV3 {
	t.Helper()

	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	srv := master.NewServer(store, nodeMaxAge)
	scanner := master.NewScanner(store, nodeMaxAge, time.Hour, time.Hour)
	srv.SetScanner(scanner)
	masterSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { masterSrv.Close() })

	var nodes []*clusterNode
	for i := 0; i < numNodes; i++ {
		n := node.New(filepath.Join(t.TempDir(), "data"), masterSrv.URL, "", 1<<30)
		nodeSrv := httptest.NewServer(n.Handler())
		t.Cleanup(func() { nodeSrv.Close() })
		cn := &clusterNode{node: n, server: nodeSrv}

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
	return &clusterV3{
		client:  New(masterSrv.URL),
		store:   store,
		server:  masterSrv,
		scanner: scanner,
		nodes:   nodes,
	}
}

// heartbeatNode 手动发送心跳维持节点 alive。
func (cv *clusterV3) heartbeatNode(cn *clusterNode) {
	body, _ := json.Marshal(map[string]any{
		"node_id":    cn.node.NodeIDForTest(),
		"used_bytes": int64(0),
	})
	http.Post(cv.server.URL+"/nodes/heartbeat", "application/json", bytes.NewReader(body))
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

	// 单次 Get 就应成功：客户端故障转移会跳过宕机节点从其他副本读。
	out := filepath.Join(dir, "out.txt")
	if err := c.Get("/failover.txt", out); err != nil {
		t.Fatalf("主副本宕机后单次读取应故障转移: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatalf("故障转移读回内容不符")
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

// 覆写场景：overwrite=true 成功覆盖；不带 overwrite 重复创建返回 409。
func TestPutOverwrite(t *testing.T) {
	c, _ := newClusterV2(t, 1)
	dir := t.TempDir()

	// — 场景 1：覆写成功 —
	// 首次创建 /a.txt
	localA := filepath.Join(dir, "a.txt")
	os.WriteFile(localA, []byte("version-1"), 0o644)
	if err := c.Put(localA, "/a.txt", 1); err != nil {
		t.Fatalf("首次 Put /a.txt: %v", err)
	}

	// 带 overwrite=true 覆写为新内容
	os.WriteFile(localA, []byte("version-2"), 0o644)
	if err := c.PutOverwrite(localA, "/a.txt", 1, true); err != nil {
		t.Fatalf("覆写 /a.txt: %v", err)
	}

	// 验证 Get 得到新版本
	outA := filepath.Join(dir, "a_out.txt")
	if err := c.Get("/a.txt", outA); err != nil {
		t.Fatalf("Get /a.txt: %v", err)
	}
	gotA, _ := os.ReadFile(outA)
	if string(gotA) != "version-2" {
		t.Fatalf("覆写后内容不符: got %q, want %q", gotA, "version-2")
	}

	// — 场景 2：不带 overwrite 仍 409 —
	localB := filepath.Join(dir, "b.txt")
	os.WriteFile(localB, []byte("first"), 0o644)
	if err := c.Put(localB, "/b.txt", 1); err != nil {
		t.Fatalf("首次 Put /b.txt: %v", err)
	}

	err := c.Put(localB, "/b.txt", 1)
	if err == nil {
		t.Fatal("重复 Put /b.txt 不带 overwrite 应返回错误")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Fatalf("期望 409 冲突错误, got: %v", err)
	}
}

// ---- 阶段4 e2e 测试 ----

// repairOnceAndWait 杀掉 victim 后：等待心跳过期 → 给幸存节点重新心跳 →
// 触发一次修复扫描 → 轮询直到文件 done 副本恢复至 want 个。
// 返回恢复后的副本列表。前置：集群 nodeMaxAge=1s。
func repairOnceAndWait(t *testing.T, cv *clusterV3, c *Client, path string, victim *clusterNode, want int) []Replica {
	t.Helper()
	victim.server.Close()

	// 等待 victim 心跳过期（nodeMaxAge=1s）。
	time.Sleep(1200 * time.Millisecond)

	// 关键：给幸存节点重新发心跳，否则全部节点心跳过期会被判 dead，无源可修。
	for _, n := range cv.nodes {
		if n != victim {
			cv.heartbeatNode(n)
		}
	}

	cv.scanner.RepairScanOnce()

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
			if done >= want {
				return reps
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("副本修复超时: 等待 %d 个 done 副本: %s", want, path)
	return nil
}

// TestRepairAfterNodeDeath 4 节点 3 副本杀 1 → 修复后 done 恢复 3、Replicas 不含 dead 节点、内容一致。
func TestRepairAfterNodeDeath(t *testing.T) {
	cv := newClusterV3(t, 4, time.Second)
	c := cv.client

	// 初始心跳全部 alive。
	for _, n := range cv.nodes {
		cv.heartbeatNode(n)
	}

	// 创建 3 副本文件。
	dir := t.TempDir()
	local := filepath.Join(dir, "data.bin")
	content := bytes.Repeat([]byte("repair-test-"), 1000)
	os.WriteFile(local, content, 0o644)
	if err := c.Put(local, "/data.bin", 3); err != nil {
		t.Fatalf("Put: %v", err)
	}
	waitDone(t, c, "/data.bin", 3)

	// 找到持有 Done 副本的一个节点作为 victim。
	_, reps, _ := c.Lookup("/data.bin")
	var victim *clusterNode
	for _, r := range reps {
		if r.Done {
			for _, cn := range cv.nodes {
				if cn.addr() == r.Addr {
					victim = cn
					break
				}
			}
			if victim != nil {
				break
			}
		}
	}
	if victim == nil {
		t.Fatal("未找到持有 Done 副本的节点")
	}
	victimAddr := victim.addr()

	reps = repairOnceAndWait(t, cv, c, "/data.bin", victim, 3)

	// Replicas 不应再包含 dead 节点地址。
	for _, r := range reps {
		if r.Addr == victimAddr {
			t.Fatalf("修复后 Replicas 仍含 dead 节点 %s", victimAddr)
		}
	}

	// 验证内容不变。
	out := filepath.Join(dir, "out.bin")
	if err := c.Get("/data.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatal("修复后内容不符")
	}
}

// TestRepairAfterNodeDeath3Nodes 3 节点 2 副本杀 1 → 修复后 done 恢复 2（换到第 3 台）。
func TestRepairAfterNodeDeath3Nodes(t *testing.T) {
	cv := newClusterV3(t, 3, time.Second)
	c := cv.client

	for _, n := range cv.nodes {
		cv.heartbeatNode(n)
	}

	dir := t.TempDir()
	local := filepath.Join(dir, "data.bin")
	content := []byte("three-node-repair-test")
	os.WriteFile(local, content, 0o644)
	if err := c.Put(local, "/data.bin", 2); err != nil {
		t.Fatalf("Put: %v", err)
	}
	waitDone(t, c, "/data.bin", 2)

	_, reps, _ := c.Lookup("/data.bin")
	var victim *clusterNode
	for _, r := range reps {
		if r.Done {
			for _, cn := range cv.nodes {
				if cn.addr() == r.Addr {
					victim = cn
					break
				}
			}
			if victim != nil {
				break
			}
		}
	}
	if victim == nil {
		t.Fatal("未找到持有 Done 副本的节点")
	}

	reps = repairOnceAndWait(t, cv, c, "/data.bin", victim, 2)
	if len(reps) < 2 {
		t.Fatalf("修复后副本数 %d < 2", len(reps))
	}

	out := filepath.Join(dir, "out.bin")
	if err := c.Get("/data.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, content) {
		t.Fatal("修复后内容不符")
	}
}

// TestGCOrphanReclaim 验证孤儿对象回收。
func TestGCOrphanReclaim(t *testing.T) {
	cv := newClusterV3(t, 2, time.Hour)
	c := cv.client

	// 写入文件并等待副本。
	dir := t.TempDir()
	local := filepath.Join(dir, "keep.txt")
	os.WriteFile(local, []byte("keep-me"), 0o644)
	if err := c.Put(local, "/keep.txt", 2); err != nil {
		t.Fatalf("Put: %v", err)
	}
	waitDone(t, c, "/keep.txt", 2)

	// 在节点磁盘放假孤儿对象（必须放在正确分桶 id%256 下，DELETE 才能命中）。
	const orphanID = 99999 // 99999%256=159=0x9f
	orphanPath := filepath.Join(cv.nodes[0].node.DataDirForTest(), "objects",
		fmt.Sprintf("%02x", orphanID%256), strconv.FormatUint(orphanID, 10))
	os.MkdirAll(filepath.Dir(orphanPath), 0o755)
	os.WriteFile(orphanPath, []byte("orphan"), 0o644)

	// dry-run 应报告孤儿。
	reports, err := cv.scanner.RunGC(false)
	if err != nil {
		t.Fatalf("GC dry-run: %v", err)
	}
	foundOrphan := false
	for _, r := range reports {
		for _, o := range r.Orphans {
			if o.ID == orphanID {
				foundOrphan = true
			}
		}
	}
	if !foundOrphan {
		t.Fatal("dry-run 应报告孤儿对象 99999")
	}

	// execute 应删除孤儿。
	_, err = cv.scanner.RunGC(true)
	if err != nil {
		t.Fatalf("GC execute: %v", err)
	}
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatal("孤儿对象应已删除")
	}

	// 正常文件不受影响。
	out := filepath.Join(dir, "out.txt")
	if err := c.Get("/keep.txt", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "keep-me" {
		t.Fatalf("正常文件内容不符: %q", got)
	}
}

func decodeBody(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}
