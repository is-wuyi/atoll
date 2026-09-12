package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWrapRejectsMissingOrWrongToken 配置 token 后：无/错误 token 返回 401，正确 token 放行。
func TestWrapRejectsMissingOrWrongToken(t *testing.T) {
	tok := Token("secret-token-abc")
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), tok)

	// 无 Authorization 头 → 401。
	r := httptest.NewRequest(http.MethodGet, "/files", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("无 token 状态码 = %d, want 401", w.Code)
	}

	// 错误 token → 401。
	r = httptest.NewRequest(http.MethodGet, "/files", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("错误 token 状态码 = %d, want 401", w.Code)
	}

	// 正确 token → 放行。
	r = httptest.NewRequest(http.MethodGet, "/files", nil)
	tok.Set(r)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("正确 token 状态码 = %d, want 200", w.Code)
	}
}

// TestWrapExemptsHealthz /healthz 永远豁免。
func TestWrapExemptsHealthz(t *testing.T) {
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), Token("secret"))
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz 状态码 = %d, want 200", w.Code)
	}
}

// TestWrapEmptyTokenCompatMode 空 token = 兼容模式，任何请求都放行。
func TestWrapEmptyTokenCompatMode(t *testing.T) {
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "")
	r := httptest.NewRequest(http.MethodDelete, "/objects/9", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("兼容模式状态码 = %d, want 200", w.Code)
	}
}

// TestTransportInjectsHeader Transport 在出站请求上注入 Bearer 头。
func TestTransportInjectsHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	client := &http.Client{Transport: &Transport{Token: Token("tk")}}
	resp, err := client.Get(srv.URL + "/meta")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "Bearer tk" {
		t.Fatalf("注入头 = %q, want %q", got, "Bearer tk")
	}
}

// TestTransportEmptyTokenNoHeader 空 token 的 Transport 不注入头（兼容模式客户端）。
func TestTransportEmptyTokenNoHeader(t *testing.T) {
	var has bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, has = r.Header["Authorization"]
	}))
	defer srv.Close()

	client := &http.Client{Transport: &Transport{Token: ""}}
	resp, err := client.Get(srv.URL + "/meta")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if has {
		t.Fatal("空 token 不应注入 Authorization 头")
	}
}

// TestGenerate 生成的 token 足够随机且格式合法。
func TestGenerate(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("两次生成不应相同")
	}
	if len(a) != 43 || strings.ContainsAny(a, "+/=") {
		t.Fatalf("token 格式异常: %q", a)
	}
}
