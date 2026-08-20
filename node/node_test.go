package node

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
