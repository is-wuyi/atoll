package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// newCmdCluster 拉起 1 master + N node（真实注册）供 CLI e2e。
func newCmdCluster(t *testing.T, numNodes int) (masterURL string) {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	masterSrv := httptest.NewServer(master.NewServer(store, time.Hour).Handler())
	t.Cleanup(func() { masterSrv.Close() })
	for i := 0; i < numNodes; i++ {
		n := node.New(filepath.Join(t.TempDir(), "data"), masterSrv.URL, "", 1<<30)
		nodeSrv := httptest.NewServer(n.Handler())
		t.Cleanup(func() { nodeSrv.Close() })
		body := fmt.Sprintf(`{"addr": %q, "total_bytes": 1073741824}`,
			nodeSrv.Listener.Addr().String())
		resp, err := http.Post(masterSrv.URL+"/nodes/register", "application/json", strings.NewReader(body))
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("node 注册失败: %v status=%d", err, resp.StatusCode)
		}
		var reg struct {
			ID uint64 `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
			t.Fatalf("解析注册响应: %v", err)
		}
		resp.Body.Close()
		n.SetNodeIDForTest(reg.ID)
	}
	return masterSrv.URL
}

// TestCLIPutGetE2E put 走分块流水线 → inode 为 Chunked → get 读回一致。
func TestCLIPutGetE2E(t *testing.T) {
	masterURL := newCmdCluster(t, 2)
	dir := t.TempDir()
	local := filepath.Join(dir, "up.bin")
	data := bytes.Repeat([]byte("cli-chunked-e2e!"), 3000) // ~45KB
	if err := os.WriteFile(local, data, 0o644); err != nil {
		t.Fatal(err)
	}
	remote := "/cli/e2e.bin"

	var out, errBuf bytes.Buffer
	if code := run([]string{"mkdir", "-master", masterURL, "/cli"}, &out, &errBuf); code != 0 {
		t.Fatalf("mkdir: code=%d %s", code, errBuf.String())
	}
	if code := run([]string{"put", "-master", masterURL, "-replicas", "2", local, remote}, &out, &errBuf); code != 0 {
		t.Fatalf("put: code=%d %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "已上传") {
		t.Fatalf("put 输出: %q", out.String())
	}

	// 验证走的是分块路径：查 meta。
	resp, err := http.Get(masterURL + "/meta?path=" + remote)
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Inode struct {
			Chunked bool `json:"chunked"`
		} `json:"inode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !meta.Inode.Chunked {
		t.Fatalf("put 应走分块路径（Chunked=true），实际 legacy")
	}

	// get 读回。
	down := filepath.Join(dir, "down.bin")
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"get", "-master", masterURL, remote, down}, &out, &errBuf); code != 0 {
		t.Fatalf("get: code=%d %s", code, errBuf.String())
	}
	got, _ := os.ReadFile(down)
	if !bytes.Equal(got, data) {
		t.Fatalf("读回不符: got %d bytes want %d", len(got), len(data))
	}

	// 覆盖写（-f）：新版本原子替换。
	data2 := bytes.Repeat([]byte("v2!"), 5000)
	if err := os.WriteFile(local, data2, 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"put", "-master", masterURL, "-f", local, remote}, &out, &errBuf); code != 0 {
		t.Fatalf("put -f: code=%d %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "已覆盖") {
		t.Fatalf("put -f 输出: %q", out.String())
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"get", "-master", masterURL, remote, down}, &out, &errBuf); code != 0 {
		t.Fatalf("get 2: code=%d %s", code, errBuf.String())
	}
	got, _ = os.ReadFile(down)
	if !bytes.Equal(got, data2) {
		t.Fatalf("覆盖后读回不符: got %d bytes want %d", len(got), len(data2))
	}
}
