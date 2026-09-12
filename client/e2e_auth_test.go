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
	"atoll/pkg/auth"
)

// TestAuthFullChain 带 token 的全链路：master+node 启用认证后，put/get/复制/修复全通；
// 无 token 的裸客户端被 401 拒绝。
func TestAuthFullChain(t *testing.T) {
	const tok = "test-cluster-token"
	token := auth.Token(tok)

	// master：启用认证。
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := master.NewServer(store, time.Hour)
	srv.SetToken(token)
	scanner := master.NewScanner(store, time.Hour, time.Hour, time.Hour)
	scanner.SetToken(token)
	srv.SetScanner(scanner)
	masterSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { masterSrv.Close() })

	// node：启用认证（注册/心跳走 node 自己的 client，须带 token）。
	dataDir := t.TempDir()
	n := node.New(dataDir, masterSrv.URL, "", 1<<30)
	n.SetToken(token)
	nodeSrv := httptest.NewServer(n.Handler())
	t.Cleanup(func() { nodeSrv.Close() })
	n.SetNodeIDForTest(1)

	// 注册 node：直接 POST（带 token）。
	regReq, _ := http.NewRequest(http.MethodPost, masterSrv.URL+"/nodes/register",
		strings.NewReader(`{"addr":"`+nodeSrv.Listener.Addr().String()+`","total_bytes":1073741824}`))
	regReq.Header.Set("Content-Type", "application/json")
	token.Set(regReq)
	regResp, err := http.DefaultClient.Do(regReq)
	if err != nil {
		t.Fatal(err)
	}
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("注册状态码 = %d", regResp.StatusCode)
	}
	n.SetNodeIDForTest(1)

	// 裸客户端（无 token）应被拒。
	bareC := New(masterSrv.URL)
	if _, err := bareC.Ls("/"); err == nil {
		t.Fatal("无 token 的客户端应被 401 拒绝")
	}

	// 无 token 直连 node 读写也应被拒。
	if resp, err := http.Get(nodeSrv.URL + "/objects/9"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("无 token GET node 状态码 = %d, want 401", resp.StatusCode)
		}
	}

	// healthz 应豁免（探活不需要 token）。
	if resp, err := http.Get(masterSrv.URL + "/healthz"); err != nil || resp.StatusCode != http.StatusOK {
		if err == nil {
			resp.Body.Close()
		}
		t.Fatalf("healthz 应豁免认证: %v", err)
	}

	// 带 token 的客户端全链路：put → 复制 → get。
	c := NewWithToken(masterSrv.URL, token)
	if _, err := c.Mkdir("/"); err != nil && !strings.Contains(err.Error(), "invalid path") {
		t.Fatalf("mkdir: %v", err)
	}
	local := filepath.Join(t.TempDir(), "up.bin")
	if err := os.WriteFile(local, []byte("auth-e2e-payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(local, "/auth-e2e.bin", 1); err != nil {
		t.Fatalf("put: %v", err)
	}
	down := filepath.Join(t.TempDir(), "down.bin")
	if err := c.Get("/auth-e2e.bin", down); err != nil {
		t.Fatalf("get: %v", err)
	}
	data, err := os.ReadFile(down)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("auth-e2e-payload")) {
		t.Fatalf("读回内容不符: %q", data)
	}

	// 复制链路：主副本应向 master 查询目标并推送（全部带 token）。
	waitDone(t, c, "/auth-e2e.bin", 1)
}

// TestAuthCompatMode 空 token 集群：无 token 客户端照常工作（滚动升级兼容窗口）。
func TestAuthCompatMode(t *testing.T) {
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := master.NewServer(store, time.Hour)
	masterSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { masterSrv.Close() })

	c := New(masterSrv.URL) // 无 token
	if _, err := c.Ls("/"); err != nil {
		t.Fatalf("兼容模式下无 token 客户端应可用: %v", err)
	}
}
