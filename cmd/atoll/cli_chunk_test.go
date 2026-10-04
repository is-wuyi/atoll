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
	"atoll/pkg/types"
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

func TestCLIPutRoutesBySizeAndCopies(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		minCopies string
		chunked   bool
	}{
		{name: "empty"},
		{name: "small", size: 4096},
		{name: "small_limit", size: int(types.SmallFileMax)},
		{name: "over_limit", size: int(types.SmallFileMax) + 1, chunked: true},
		{name: "small_two_copies", size: 4096, minCopies: "2", chunked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			masterURL := newCmdCluster(t, 2)
			local := filepath.Join(t.TempDir(), "input")
			data := bytes.Repeat([]byte{0x5a}, tc.size)
			if err := os.WriteFile(local, data, 0o644); err != nil {
				t.Fatal(err)
			}
			args := []string{"put", "-master", masterURL, "-replicas", "2"}
			if tc.minCopies != "" {
				args = append(args, "-min-copies", tc.minCopies)
			}
			args = append(args, local, "/file")
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("put: code=%d %s", code, errBuf.String())
			}
			// v2-4b 兼容计划：直连 HTTP 的 meta 读要按新客户端身份带特性协商头，
			// master 对返回新 ObjID 的 meta 读缺失该头时回 426（保护旧客户端）。
			req, err := http.NewRequest(http.MethodGet, masterURL+"/meta?path=/file", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Atoll-Features", "object-id-v1")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("meta status=%d", resp.StatusCode)
			}
			var result struct {
				Inode types.Inode `json:"inode"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if result.Inode.Chunked != tc.chunked || result.Inode.Size != int64(tc.size) {
				t.Fatalf("metadata=%+v, want chunked=%v size=%d", result.Inode, tc.chunked, tc.size)
			}
			// v2-4b：small 写的内容对象应有显式高位 ObjID（0 字节文件无对象，走 legacy 整传）。
			if !tc.chunked && tc.size > 0 && result.Inode.ObjID < types.StagingInodeBase {
				t.Errorf("small upload should carry an explicit high ObjID: %+v", result.Inode)
			}
			if tc.minCopies == "2" {
				for _, chunk := range result.Inode.Chunks {
					if len(chunk.Done) < 2 {
						t.Errorf("explicit min-copies not satisfied: %+v", chunk)
					}
				}
			}
			down := filepath.Join(t.TempDir(), "output")
			out.Reset()
			errBuf.Reset()
			if code := run([]string{"get", "-master", masterURL, "/file", down}, &out, &errBuf); code != 0 {
				t.Fatalf("get: code=%d %s", code, errBuf.String())
			}
			got, err := os.ReadFile(down)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("readback bytes=%d, want %d, err=%v", len(got), len(data), err)
			}
		})
	}
}

// TestCLIPutGetE2E put 走分块流水线 → inode 为 Chunked → get 读回一致。
func TestCLIPutGetE2E(t *testing.T) {
	masterURL := newCmdCluster(t, 2)
	dir := t.TempDir()
	local := filepath.Join(dir, "up.bin")
	data := bytes.Repeat([]byte("cli-chunked-e2e!"), 20000) // 300KB，超过小文件通道上限
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
