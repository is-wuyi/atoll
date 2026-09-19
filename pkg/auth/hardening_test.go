package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// req 构造一个带 Authorization 头的请求打到 wrapped handler，返回状态码。
func doReq(h http.Handler, path, bearer string) int {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// 读/管 token 分离：/admin/gc 需 adminToken，普通路径需 token，互不通用。
func TestWrapTokensSeparation(t *testing.T) {
	ok := func(code int) bool { return code == http.StatusOK }
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := WrapTokens(next, "cluster", "admintok", map[string]bool{"/admin/gc": true})

	// 普通路径：集群 token 通过，admin token 或错 token 被拒。
	if !ok(doReq(h, "/files", "cluster")) {
		t.Error("普通路径 + 集群 token 应通过")
	}
	if ok(doReq(h, "/files", "admintok")) {
		t.Error("普通路径 + admin token 应被拒")
	}
	if ok(doReq(h, "/files", "")) {
		t.Error("普通路径无 token 应被拒")
	}
	// 管理路径：仅 admin token 通过，集群 token 被拒（分离生效）。
	if !ok(doReq(h, "/admin/gc", "admintok")) {
		t.Error("/admin/gc + admin token 应通过")
	}
	if ok(doReq(h, "/admin/gc", "cluster")) {
		t.Error("/admin/gc + 集群 token 应被拒（读/管分离）")
	}
}

// adminToken 为空时回退：管理路径用集群 token 校验（向后兼容）。
func TestWrapTokensAdminFallback(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := WrapTokens(next, "cluster", "", map[string]bool{"/admin/gc": true})
	if doReq(h, "/admin/gc", "cluster") != http.StatusOK {
		t.Error("未配 admin token 时 /admin/gc 应回退用集群 token")
	}
	if doReq(h, "/admin/gc", "wrong") == http.StatusOK {
		t.Error("错 token 仍应被拒")
	}
}

// healthz 永远豁免；兼容模式（token 全空）放行。
func TestWrapTokensExemptAndCompat(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := WrapTokens(next, "cluster", "", nil)
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Error("/healthz 应豁免认证")
	}
	compat := WrapTokens(next, "", "", nil)
	if doReq(compat, "/files", "") != http.StatusOK {
		t.Error("兼容模式（无 token）应放行")
	}
}

// TLS 客户端配置：HTTPTransport(skip-verify) 能连到自签名 TLS 服务端。
func TestClientTLSSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg, err := ClientTLS("", true)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: HTTPTransport("tok", cfg, nil)}
	resp, err := c.Get(srv.URL) // httptest TLS 用自签名证书，skip-verify 才能连
	if err != nil {
		t.Fatalf("skip-verify 应能连自签名 TLS: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token 应随 TLS 请求注入: status %d", resp.StatusCode)
	}

	// 不跳过校验时，自签名证书应连接失败（证明校验确实生效）。
	strict := &http.Client{Transport: HTTPTransport("tok", nil, nil)}
	if _, err := strict.Get(srv.URL); err == nil {
		t.Error("默认 transport（无 TLS 配置）不应信任自签名证书")
	}
}
