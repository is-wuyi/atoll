package node

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
	"sync"
	"testing"
	"time"
)

// newTestNode 启动一个 httptest 存储节点。
func newTestNode(t *testing.T) (*Node, *httptest.Server) {
	t.Helper()
	n := New(filepath.Join(t.TempDir(), "data"), "http://master.invalid", "127.0.0.1:9000", 1<<30)
	ts := httptest.NewServer(n.Handler())
	t.Cleanup(func() { ts.Close() })
	return n, ts
}

func TestPutGetDeleteObject(t *testing.T) {
	_, ts := newTestNode(t)
	data := []byte("hello atoll")

	// PUT
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/42", bytes.NewReader(data))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT 状态码 = %d", resp.StatusCode)
	}

	// GET
	resp2, err := http.Get(ts.URL + "/objects/42")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET 状态码 = %d", resp2.StatusCode)
	}
	got, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("读取响应: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("读回内容不符: %q", got)
	}

	// GET 不存在的对象
	resp3, _ := http.Get(ts.URL + "/objects/999")
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("不存在对象应 404, got %d", resp3.StatusCode)
	}

	// DELETE
	req2, _ := http.NewRequest(http.MethodDelete, ts.URL+"/objects/42", nil)
	resp4, _ := http.DefaultClient.Do(req2)
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("DELETE 状态码 = %d", resp4.StatusCode)
	}
	// 再删一次应幂等成功。
	resp5, _ := http.DefaultClient.Do(req2)
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusOK {
		t.Fatalf("重复 DELETE 应幂等, got %d", resp5.StatusCode)
	}
}

func TestPutInvalidID(t *testing.T) {
	_, ts := newTestNode(t)
	for _, id := range []string{"abc", "0", "-1"} {
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/"+id, bytes.NewReader([]byte("x")))
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PUT id=%q 应 400, got %d", id, resp.StatusCode)
		}
	}
}

// 用量统计：写入、覆盖写、删除后 used 应正确。
func TestUsedBytesAccounting(t *testing.T) {
	n, ts := newTestNode(t)
	put := func(id string, data []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/"+id, bytes.NewReader(data))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	put("1", []byte("12345")) // 5
	if u := n.used.Load(); u != 5 {
		t.Fatalf("used = %d, want 5", u)
	}
	put("1", []byte("123")) // 覆盖写: 5 → 3
	if u := n.used.Load(); u != 3 {
		t.Fatalf("覆盖后 used = %d, want 3", u)
	}
	put("2", []byte("ab")) // +2
	if u := n.used.Load(); u != 5 {
		t.Fatalf("used = %d, want 5", u)
	}

	// 重启模拟：新实例统计已有数据。
	n2 := New(n.dataDir, "http://master.invalid", "127.0.0.1:9001", 1<<30)
	if err := n2.InitUsedBytes(); err != nil {
		t.Fatalf("InitUsedBytes: %v", err)
	}
	if u := n2.used.Load(); u != 5 {
		t.Fatalf("重启后 used = %d, want 5", u)
	}
}

// Range 请求：206 部分内容、后缀区间、越界 416。
func TestRangeRequests(t *testing.T) {
	_, ts := newTestNode(t)
	data := []byte("0123456789abcdef") // 16 字节
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/1", bytes.NewReader(data))
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	get := func(rangeHeader string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/objects/1", nil)
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, body
	}

	// 普通区间
	resp, body := get("bytes=2-5")
	if resp.StatusCode != http.StatusPartialContent || string(body) != "2345" {
		t.Fatalf("bytes=2-5: code=%d body=%q", resp.StatusCode, body)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "bytes 2-5/16" {
		t.Fatalf("Content-Range = %q", cr)
	}

	// 开区间到结尾
	resp, body = get("bytes=10-")
	if resp.StatusCode != http.StatusPartialContent || string(body) != "abcdef" {
		t.Fatalf("bytes=10-: code=%d body=%q", resp.StatusCode, body)
	}

	// end 超过文件大小，截断
	resp, body = get("bytes=10-99")
	if resp.StatusCode != http.StatusPartialContent || string(body) != "abcdef" {
		t.Fatalf("bytes=10-99: code=%d body=%q", resp.StatusCode, body)
	}

	// 后缀区间
	resp, body = get("bytes=-4")
	if resp.StatusCode != http.StatusPartialContent || string(body) != "cdef" {
		t.Fatalf("bytes=-4: code=%d body=%q", resp.StatusCode, body)
	}

	// 越界 → 416
	resp, _ = get("bytes=20-30")
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("越界应 416, got %d", resp.StatusCode)
	}

	// 非法头 → 416
	resp, _ = get("bytes=5-2")
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("倒序区间应 416, got %d", resp.StatusCode)
	}

	// 无 Range → 200 全量
	resp, body = get("")
	if resp.StatusCode != http.StatusOK || string(body) != string(data) {
		t.Fatalf("全量: code=%d body=%q", resp.StatusCode, body)
	}
}

// parseRange 的纯函数测试。
func TestParseRange(t *testing.T) {
	cases := []struct {
		in          string
		size        int64
		start, end  int64
		ok          bool
	}{
		{"bytes=0-0", 10, 0, 0, true},
		{"bytes=9-", 10, 9, 9, true},
		{"bytes=-3", 10, 7, 9, true},
		{"bytes=-99", 10, 0, 9, true},
		{"bytes=0-99", 10, 0, 9, true},
		{"bytes=5-2", 10, 0, 0, false},
		{"bytes=10-", 10, 0, 0, false},  // start == size
		{"bytes=0-1,3-4", 10, 0, 0, false}, // 多区间
		{"bytes=abc", 10, 0, 0, false},
		{"chars=1-2", 10, 0, 0, false},
	}
	for _, c := range cases {
		s, e, ok := parseRange(c.in, c.size)
		if ok != c.ok || (ok && (s != c.start || e != c.end)) {
			t.Errorf("parseRange(%q, %d) = (%d,%d,%v), want (%d,%d,%v)",
				c.in, c.size, s, e, ok, c.start, c.end, c.ok)
		}
	}
}

// 注册与心跳：用假 master 验证交互。
func TestRegisterAndHeartbeat(t *testing.T) {
	var mu sync.Mutex
	registered := 0
	heartbeats := 0
	fakeMaster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nodes/register":
			mu.Lock()
			registered++
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id": 7}`)
		case "/nodes/heartbeat":
			mu.Lock()
			heartbeats++
			mu.Unlock()
			fmt.Fprint(w, `{"status":"ok"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer fakeMaster.Close()

	n := New(filepath.Join(t.TempDir(), "data"), fakeMaster.URL, "127.0.0.1:9000", 1<<30)
	n.heartbeatInterval = 10 * time.Millisecond
	if err := n.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if n.nodeID.Load() != 7 {
		t.Fatalf("nodeID = %d, want 7", n.nodeID.Load())
	}
	// 等几次心跳。
	time.Sleep(60 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if registered != 1 {
		t.Fatalf("注册次数 = %d, want 1", registered)
	}
	if heartbeats < 2 {
		t.Fatalf("心跳次数 = %d, want >= 2", heartbeats)
	}
}

// TestPullObject 验证 POST /pull：从源节点拉取对象并落盘，内容一致。
func TestPullObject(t *testing.T) {
	// 源节点：持有对象 100。
	_, sourceTS := newTestNode(t)
	data := []byte("pull me from source")
	req, _ := http.NewRequest(http.MethodPut, sourceTS.URL+"/objects/100", bytes.NewReader(data))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("源节点 PUT 状态码 = %d", resp.StatusCode)
	}

	// 目标节点：收到 pull 请求后应异步拉取。
	_, targetTS := newTestNode(t)
	// sourceTS.URL 形如 "http://127.0.0.1:PORT"，需要去掉 "http://" 前缀。
	sourceAddr := sourceTS.URL[len("http://"):]
	pullBody, _ := json.Marshal(map[string]any{
		"inode_id":    100,
		"source_addr": sourceAddr,
	})
	pullResp, err := http.Post(targetTS.URL+"/pull", "application/json", bytes.NewReader(pullBody))
	if err != nil {
		t.Fatal(err)
	}
	pullResp.Body.Close()
	if pullResp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /pull 状态码 = %d, want 202", pullResp.StatusCode)
	}

	// 轮询等待对象落盘。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		getResp, err := http.Get(targetTS.URL + "/objects/100")
		if err == nil {
			body, _ := io.ReadAll(getResp.Body)
			getResp.Body.Close()
			if getResp.StatusCode == http.StatusOK && bytes.Equal(body, data) {
				return // 成功
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pull 后对象未在目标节点落盘或内容不一致")
}

// TestAdminObjects 验证 GET /admin/objects 返回全部对象，跳过 .tmp-* 临时文件。
func TestAdminObjects(t *testing.T) {
	n, ts := newTestNode(t)

	// 写入 3 个对象。
	put := func(id string, data []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/"+id, bytes.NewReader(data))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("PUT /objects/%s 状态码 = %d", id, resp.StatusCode)
		}
	}
	put("1", []byte("aaa"))  // 3 bytes
	put("10", []byte("bb"))  // 2 bytes
	put("256", []byte("c"))  // 1 byte

	// 手动创建一个 .tmp-* 文件，应被跳过。
	tmpPath := filepath.Join(n.DataDirForTest(), "objects", "01", ".tmp-fake")
	if err := os.MkdirAll(filepath.Dir(tmpPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpPath, []byte("temp"), 0o644); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(ts.URL + "/admin/objects")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/objects 状态码 = %d", resp.StatusCode)
	}

	var objects []struct {
		ID   uint64 `json:"id"`
		Size int64  `json:"size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&objects); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(objects) != 3 {
		t.Fatalf("对象数量 = %d, want 3 (应跳过 .tmp-*)", len(objects))
	}

	// 验证按 ID 排序。
	if objects[0].ID != 1 || objects[0].Size != 3 {
		t.Fatalf("objects[0] = {ID:%d, Size:%d}, want {1, 3}", objects[0].ID, objects[0].Size)
	}
	if objects[1].ID != 10 || objects[1].Size != 2 {
		t.Fatalf("objects[1] = {ID:%d, Size:%d}, want {10, 2}", objects[1].ID, objects[1].Size)
	}
	if objects[2].ID != 256 || objects[2].Size != 1 {
		t.Fatalf("objects[2] = {ID:%d, Size:%d}, want {256, 1}", objects[2].ID, objects[2].Size)
	}
}

// errReader 读一次就报错，模拟写入中途断流。
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// TestStoreObjectOverwriteKeepsOldOnFailure 验证写失败时旧对象不受影响、临时文件被清理。
func TestStoreObjectOverwriteKeepsOldOnFailure(t *testing.T) {
	n, _ := newTestNode(t)
	// 先落一个正式对象。
	if _, _, err := n.storeObject(7, bytes.NewReader([]byte("old")), 0); err != nil {
		t.Fatal(err)
	}
	// 模拟中途断流：Reader 第一次读就报错。
	if _, _, err := n.storeObject(7, errReader{}, 0); err == nil {
		t.Fatal("写入应失败")
	}
	// 旧对象原样保留。
	data, err := os.ReadFile(n.objectPathForTest(7))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("旧对象内容 = %q, want %q", data, "old")
	}
	// 目录里不应残留 .tmp-*。
	entries, err := os.ReadDir(filepath.Join(n.DataDirForTest(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bucket := range entries {
		files, err := os.ReadDir(filepath.Join(n.DataDirForTest(), "objects", bucket.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if strings.HasPrefix(f.Name(), ".tmp-") {
				t.Fatalf("残留临时文件未清理: %s", f.Name())
			}
		}
	}
}

// TestInitUsedBytesCleansTmp 验证重启时清理 .tmp-* 残留且不计入用量。
func TestInitUsedBytesCleansTmp(t *testing.T) {
	n, _ := newTestNode(t)
	if _, _, err := n.storeObject(1, bytes.NewReader([]byte("hello")), 0); err != nil {
		t.Fatal(err)
	}
	// 手动放置一个崩溃残留的临时文件。
	tmpPath := filepath.Join(n.DataDirForTest(), "objects", "01", ".tmp-crash")
	if err := os.MkdirAll(filepath.Dir(tmpPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpPath, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 模拟重启：新实例初始化。
	n2 := New(n.dataDir, "http://master.invalid", "127.0.0.1:9002", 1<<30)
	if err := n2.InitUsedBytes(); err != nil {
		t.Fatal(err)
	}
	// tmp 被清掉。
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("临时文件应被清理: %v", err)
	}
	// 用量只算正式对象。
	if u := n2.used.Load(); u != 5 {
		t.Fatalf("重启后 used = %d, want 5（tmp 不应计入）", u)
	}
}
