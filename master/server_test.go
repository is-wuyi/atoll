package master

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"atoll/master/meta"
)

// newTestServer 启动一个内存态 master（临时 bbolt + httptest）。
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	srv := NewServer(store, time.Hour) // 测试里节点心跳 1 小时内都算存活
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close() })
	return ts
}

// postJSON 发送 JSON POST 并解析响应到 out。
func postJSON(t *testing.T, url string, body, out any) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(mustJSON(t, body)))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("解码响应失败: %v", err)
		}
	}
	return resp
}

func getJSON(t *testing.T, url string, out any) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("解码响应失败: %v", err)
		}
	}
	return resp
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// registerNode 注册一个存储节点。
func registerNode(t *testing.T, base string, i int) uint64 {
	t.Helper()
	var node struct {
		ID uint64 `json:"id"`
	}
	resp := postJSON(t, base+"/nodes/register", map[string]any{
		"addr":        fmt.Sprintf("127.0.0.1:900%d", i),
		"total_bytes": 1 << 30,
	}, &node)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("注册节点状态码 = %d", resp.StatusCode)
	}
	return node.ID
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d", resp.StatusCode)
	}
}

func TestNodeRegisterAndHeartbeat(t *testing.T) {
	ts := newTestServer(t)
	id := registerNode(t, ts.URL, 1)
	if id == 0 {
		t.Fatal("节点 ID 为 0")
	}
	resp := postJSON(t, ts.URL+"/nodes/heartbeat", map[string]any{
		"node_id": id, "used_bytes": 100,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("心跳状态码 = %d", resp.StatusCode)
	}
}

func TestCreateFileAllocatesReplicas(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	registerNode(t, ts.URL, 2)

	var out struct {
		Inode struct {
			ID   uint64 `json:"id"`
			Name string `json:"name"`
		} `json:"inode"`
		Nodes []struct {
			ID uint64 `json:"id"`
		} `json:"nodes"`
	}
	resp := postJSON(t, ts.URL+"/files", map[string]any{
		"path": "/a.txt", "replicas": 2,
	}, &out)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("创建文件状态码 = %d", resp.StatusCode)
	}
	if out.Inode.Name != "a.txt" {
		t.Fatalf("文件名 = %s", out.Inode.Name)
	}
	if len(out.Nodes) != 2 {
		t.Fatalf("分配节点数 = %d, want 2", len(out.Nodes))
	}
}

func TestCreateFileNotEnoughNodes(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1) // 只有 1 个节点
	resp := postJSON(t, ts.URL+"/files", map[string]any{
		"path": "/a.txt", "replicas": 3,
	}, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("节点不足应返回 503, got %d", resp.StatusCode)
	}
}

func TestMkdirAndListChildren(t *testing.T) {
	ts := newTestServer(t)
	resp := postJSON(t, ts.URL+"/dirs", map[string]any{"path": "/docs"}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mkdir 状态码 = %d", resp.StatusCode)
	}
	registerNode(t, ts.URL, 1)
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/docs/a.txt"}, nil)

	var kids []struct {
		Name string `json:"name"`
		Type uint8  `json:"type"`
	}
	resp = getJSON(t, ts.URL+"/dirs/children?path=/docs", &kids)
	if resp.StatusCode != http.StatusOK || len(kids) != 1 || kids[0].Name != "a.txt" {
		t.Fatalf("列目录结果不符: code=%d kids=%+v", resp.StatusCode, kids)
	}
}

func TestLookupReturnsNodeAddrs(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt", "replicas": 1}, nil)

	var out struct {
		Inode struct {
			ID   uint64 `json:"id"`
			Type uint8  `json:"type"`
		} `json:"inode"`
		Nodes []struct {
			ID   uint64 `json:"id"`
			Addr string `json:"addr"`
		} `json:"nodes"`
	}
	resp := getJSON(t, ts.URL+"/meta?path=/a.txt", &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lookup 状态码 = %d", resp.StatusCode)
	}
	if len(out.Nodes) != 1 || out.Nodes[0].Addr == "" {
		t.Fatalf("lookup 应返回节点地址: %+v", out)
	}
}

func TestCommitUpdatesSize(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	var created struct {
		Inode struct {
			ID uint64 `json:"id"`
		} `json:"inode"`
	}
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt"}, &created)

	resp := postJSON(t, ts.URL+"/files/commit", map[string]any{
		"inode_id": created.Inode.ID, "size": 4096,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("commit 状态码 = %d", resp.StatusCode)
	}

	var out struct {
		Inode struct {
			Size     int64   `json:"size"`
			Replicas []uint64 `json:"replicas"`
		} `json:"inode"`
	}
	getJSON(t, ts.URL+"/meta?path=/a.txt", &out)
	if out.Inode.Size != 4096 {
		t.Fatalf("size = %d, want 4096", out.Inode.Size)
	}
	if len(out.Inode.Replicas) != 1 {
		t.Fatalf("commit 不应清空副本列表: %+v", out.Inode)
	}
}

func TestDeleteFile(t *testing.T) {
	ts := newTestServer(t)
	registerNode(t, ts.URL, 1)
	postJSON(t, ts.URL+"/files", map[string]any{"path": "/a.txt"}, nil)

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/entry?path=/a.txt", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("删除状态码 = %d", resp.StatusCode)
	}
	resp2 := getJSON(t, ts.URL+"/meta?path=/a.txt", nil)
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("删除后 lookup 应 404, got %d", resp2.StatusCode)
	}
}

func TestInvalidPathRejected(t *testing.T) {
	ts := newTestServer(t)
	resp := postJSON(t, ts.URL+"/dirs", map[string]any{"path": "/"}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("根目录创建应 400, got %d", resp.StatusCode)
	}
}

func TestSplitPath(t *testing.T) {
	cases := []struct{ in, parent, name string }{
		{"/a/b/c.txt", "/a/b", "c.txt"},
		{"/a", "/", "a"},
		{"a", "/", "a"},
		{"/a/", "/", "a"},
	}
	for _, c := range cases {
		p, n := splitPath(c.in)
		if p != c.parent || n != c.name {
			t.Errorf("splitPath(%q) = (%q, %q), want (%q, %q)", c.in, p, n, c.parent, c.name)
		}
	}
}
