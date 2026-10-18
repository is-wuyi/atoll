// Security regression tests — added per review findings.
// These tests use a fakeRT to inspect the exact context deadline that the
// transport attaches to the ticket request, plus minimal host-mismatch and
// malformed-login wire-result cases.  All tests are hermetic: they never
// touch the network and never wait real seconds.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/pkg/access"
)

// ---- fakeRT: records the context deadline of every outgoing request ----

type fakeRT struct {
	mu       sync.Mutex
	deadline time.Time
	hasDL    bool
	canceled bool
	// handler is called after recording; it may return a canned response.
	handler func(req *http.Request) (*http.Response, error)
	// ticketResponse is the JSON body served for /security/tickets.
	ticketBody string
}

func (f *fakeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	if dl, ok := req.Context().Deadline(); ok {
		f.deadline, f.hasDL = dl, true
	}
	f.mu.Unlock()

	if err := req.Context().Err(); err != nil {
		f.mu.Lock()
		f.canceled = true
		f.mu.Unlock()
		return nil, err
	}

	if f.handler != nil {
		return f.handler(req)
	}

	// Default: serve a minimal ticket response.
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(f.ticketBody))),
		Header:     make(http.Header),
	}, nil
}

func (f *fakeRT) lastDeadline() (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadline, f.hasDL
}

func (f *fakeRT) wasCanceled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.canceled
}

// newFakeTicketClient returns a secureTransport whose base is fakeRT, so we
// can observe the deadline on the ticket request without any real network.
func newFakeTicketClient(t *testing.T, rt *fakeRT) *secureTransport {
	t.Helper()
	master, err := url.Parse("https://master.example")
	if err != nil {
		t.Fatal(err)
	}
	return &secureTransport{
		master: master,
		base:   rt,
		s:      &secureSession{token: "tok", spaceID: 7, hasSpace: true},
	}
}

// ---- 1. fetchTicket deadline: min(parentDeadline, maxTicketWait) ----

func TestFetchTicketUsesParentDeadlineWhenShorter(t *testing.T) {
	// Parent ctx with 5s deadline — the ticket request must inherit 5s, not 30s.
	rt := &fakeRT{ticketBody: `{"token":"t","expires_at":"2099-01-01T00:00:00Z"}`}
	tr := newFakeTicketClient(t, rt)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://node.example/objects/1", nil)
	_, _ = tr.fetchTicket(req, "tok", 7)

	dl, ok := rt.lastDeadline()
	if !ok {
		t.Fatal("ticket request should have a deadline")
	}
	remaining := time.Until(dl)
	if remaining > 6*time.Second || remaining < 4*time.Second {
		t.Fatalf("expected ~5s remaining (parent deadline), got %s", remaining)
	}
}

func TestFetchTicketUsesMaxTicketWaitWhenNoParentDeadline(t *testing.T) {
	rt := &fakeRT{ticketBody: `{"token":"t","expires_at":"2099-01-01T00:00:00Z"}`}
	tr := newFakeTicketClient(t, rt)

	req, _ := http.NewRequest(http.MethodGet, "http://node.example/objects/1", nil)
	_, _ = tr.fetchTicket(req, "tok", 7)

	dl, ok := rt.lastDeadline()
	if !ok {
		t.Fatal("ticket request should have a deadline even without parent deadline")
	}
	remaining := time.Until(dl)
	if remaining > 31*time.Second || remaining < 28*time.Second {
		t.Fatalf("expected ~30s remaining (maxTicketWait), got %s", remaining)
	}
}

func TestFetchTicketCapsLongParentDeadline(t *testing.T) {
	// Parent ctx with 1h deadline — ticket request must be capped at 30s.
	rt := &fakeRT{ticketBody: `{"token":"t","expires_at":"2099-01-01T00:00:00Z"}`}
	tr := newFakeTicketClient(t, rt)

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://node.example/objects/1", nil)
	_, _ = tr.fetchTicket(req, "tok", 7)

	dl, ok := rt.lastDeadline()
	if !ok {
		t.Fatal("ticket request should have a deadline")
	}
	remaining := time.Until(dl)
	if remaining > 31*time.Second {
		t.Fatalf("1h parent deadline must be capped at 30s, got %s remaining", remaining)
	}
}

func TestFetchTicketPropagatesCanceledContext(t *testing.T) {
	rt := &fakeRT{ticketBody: `{"token":"t","expires_at":"2099-01-01T00:00:00Z"}`}
	tr := newFakeTicketClient(t, rt)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://node.example/objects/1", nil)
	_, err := tr.fetchTicket(req, "tok", 7)
	if err == nil {
		t.Fatal("canceled context should cause fetchTicket to fail")
	}
	if !rt.wasCanceled() {
		t.Fatal("fakeRT should have observed the canceled context")
	}
}

// ---- 2. Fragment / RawFragment rejection ----

func TestSecureRejectsFragmentInRequestURL(t *testing.T) {
	c, spy, node := newSecureTestCluster(t, nil, nil)

	for _, frag := range []string{"#frag", "#section"} {
		req, err := http.NewRequest(http.MethodGet, node.URL+"/objects/1"+frag, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.HTTP.Do(req); err == nil {
			t.Fatalf("request URL with fragment %q should be rejected", frag)
		} else if !strings.Contains(err.Error(), "拒绝") || !strings.Contains(err.Error(), "URL") {
			t.Fatalf("rejection message should mention 拒绝 URL: %v", err)
		}
	}
	if spy.nodeHits != 0 {
		t.Fatalf("fragmented URL must not reach node, hits=%d", spy.nodeHits)
	}
}

func TestNewSecureRejectsFragment(t *testing.T) {
	for _, raw := range []string{
		"https://master.example#frag",
		"https://master.example/#f",
		"https://master.example/path#frag",
	} {
		if _, err := NewSecure(raw, nil, true); err == nil {
			t.Fatalf("NewSecure should reject URL with fragment: %s", raw)
		}
	}
}

// ForceQuery（尾随 "?"）在 url.Parse 后 RawQuery 为空串：只查 RawQuery 的检查会
// 静默放行 "https://host/?"——调用方会以为 query 部分在安全路径上生效。必须显式拒。
func TestNewSecureRejectsForceQuery(t *testing.T) {
	for _, raw := range []string{
		"https://master.example?",
		"https://master.example/?",
		"https://master.example/path?",
	} {
		if _, err := NewSecure(raw, nil, true); err == nil {
			t.Fatalf("NewSecure should reject ForceQuery master URL: %s", raw)
		}
	}
	// 无尾随 "?" 的纯 origin 仍然放行。
	if _, err := NewSecure("https://master.example", nil, true); err != nil {
		t.Fatalf("plain origin must be accepted: %v", err)
	}
}

// 请求 URL 上的 ForceQuery 同样 fail-closed（尾随 "?" 的节点 URL）。
func TestSecureRejectsForceQueryInRequestURL(t *testing.T) {
	c, spy, node := newSecureTestCluster(t, nil, nil)
	req, err := http.NewRequest(http.MethodGet, node.URL+"/objects/1?", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.HTTP.Do(req); err == nil {
		t.Fatal("request URL with trailing ? should be rejected")
	} else if !strings.Contains(err.Error(), "拒绝") || !strings.Contains(err.Error(), "URL") {
		t.Fatalf("rejection message should mention 拒绝 URL: %v", err)
	}
	if spy.nodeHits != 0 {
		t.Fatalf("ForceQuery URL must not reach node, hits=%d", spy.nodeHits)
	}
}

// 本地拒绝不能触达底层传输；对象内容只能由最终数据面传输消费。

// recordingRT 记录每次被调用的请求形态（路径 + body 是否被读过）。
type recordingRT struct {
	mu      sync.Mutex
	calls   int
	paths   []string
	bodyErr error
	// consumed 观测：到达 base 的请求体在 transport 返回时是否已被读完/关闭。
	lastBodyRead bool
	lastBodyNil  bool
	handler      func(req *http.Request) (*http.Response, error)
}

func (r *recordingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.calls++
	r.paths = append(r.paths, req.URL.Path)
	r.mu.Unlock()
	if r.handler != nil {
		return r.handler(req)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
}

func (r *recordingRT) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// newRecordingSecureClient 构造 base=recordingRT 的 secureTransport 客户端
// （无真实网络；master origin 与 base 都是假的）。
func newRecordingSecureClient(t *testing.T, rt *recordingRT, token string, spaceID uint64) *Client {
	t.Helper()
	master, err := url.Parse("https://master.example")
	if err != nil {
		t.Fatal(err)
	}
	s := &secureSession{}
	if token != "" {
		s.token = token
		s.spaceID, s.hasSpace = spaceID, spaceID != 0
	}
	tr := &secureTransport{master: master, base: rt, s: s}
	return &Client{MasterURL: "https://master.example", HTTP: &http.Client{Transport: tr}, sec: s, secTransport: tr}
}

func TestLocalDenialNeverReachesBaseRoundTripper(t *testing.T) {
	rt := &recordingRT{}
	c := newRecordingSecureClient(t, rt, "tok", 7)

	denials := []struct {
		name string
		url  string
	}{
		{"userinfo", "https://bob@node.example/objects/1"},
		{"opaque", "https://node.example/objects/1"}, // 下面单独置 Opaque
		{"host_mismatch", "https://node.example/objects/2"},
		{"scheme_mismatch", "http://node.example/objects/3"},
	}
	for _, d := range denials {
		req := mustReq(t, http.MethodGet, d.url)
		switch d.name {
		case "userinfo":
			req.URL.User = url.User("bob")
		case "opaque":
			req.URL.Opaque = "https://node.example/objects/1"
		case "host_mismatch":
			req.Host = "other.example"
		}
		if _, err := c.HTTP.Do(req); err == nil {
			t.Fatalf("%s should be locally denied", d.name)
		}
	}
	// 无会话（token 空）本地拒绝：同样零 base 命中。
	c2 := newRecordingSecureClient(t, rt, "", 0)
	if _, err := c2.HTTP.Do(mustReq(t, http.MethodGet, "https://node.example/objects/9")); err == nil {
		t.Fatal("no-session node request must be denied locally")
	}
	if got := rt.count(); got != 0 {
		t.Fatalf("local denials must never reach the base transport: calls=%d paths=%v", got, rt.paths)
	}
}

// 对象数据面请求到达 base 时 payload 未被读取：body 仍是原样、可完整读回
// （票据绑定对 /objects/* 恒空——绝不为此缓冲/消耗对象流）。
func TestObjectPayloadNotConsumedByTransport(t *testing.T) {
	var ticketBodyHash string
	rt := &recordingRT{handler: func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/security/tickets" {
			var tr access.TicketRequest
			_ = json.NewDecoder(req.Body).Decode(&tr)
			ticketBodyHash = tr.BodyHash
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"token":"tk","expires_at":"2099-01-01T00:00:00Z"}`)),
				Header:     make(http.Header),
			}, nil
		}
		// 节点 PUT：确认 body 未被提前读走——读到的恰是调用方写入的 payload。
		data, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if string(data) != "PAYLOAD-BYTES" {
			return nil, fmt.Errorf("object payload corrupted/consumed by transport: %q", data)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
	}}
	c := newRecordingSecureClient(t, rt, "tok", 7)

	req := mustReq(t, http.MethodPut, "https://node.example/objects/42")
	req.Body = io.NopCloser(strings.NewReader("PAYLOAD-BYTES"))
	req.ContentLength = int64(len("PAYLOAD-BYTES"))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ticketBodyHash != "" {
		t.Fatalf("/objects/* data-plane ticket BodyHash must stay empty, got %q", ticketBodyHash)
	}
	if rt.count() != 2 { // 一次换票 + 一次节点 PUT
		t.Fatalf("expected ticket + node PUT to reach base, calls=%d paths=%v", rt.count(), rt.paths)
	}
}

// ---- 3. req.Host vs URL.Host mismatch (virtual-host confusion) ----

func TestSecureRejectsHostHeaderMismatch(t *testing.T) {
	c, spy, node := newSecureTestCluster(t, nil, nil)

	// Case-insensitive match (same host) — should be allowed.
	req, err := http.NewRequest(http.MethodGet, node.URL+"/objects/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = strings.ToUpper(req.URL.Host) // e.g. "127.0.0.1:PORT"
	if _, err := c.HTTP.Do(req); err != nil {
		t.Fatalf("same-origin Host (case-insensitive) should be allowed: %v", err)
	}

	// Different host — must be rejected.
	req2, err := http.NewRequest(http.MethodGet, node.URL+"/objects/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Host = "evil.example"
	if _, err := c.HTTP.Do(req2); err == nil {
		t.Fatal("Host header different from URL.Host should be rejected")
	} else if !strings.Contains(err.Error(), "Host") {
		t.Fatalf("rejection should mention Host: %v", err)
	}

	if spy.nodeHits != 1 {
		t.Fatalf("only the case-insensitive request should reach node, got %d", spy.nodeHits)
	}
}

// ---- 4. SetSession: 空 token = 清会话（合法）；含空白/换行/超服务端 512 上限拒绝 ----
//
// 名字说明：本测试断言的是「空 token 合法清会话」这一**已修复**语义；历史上它叫
// TestSetSessionRejectsEmptyToken（当时实现真的拒绝空值，后来修成合法清空）。旧名
// 与断言相反、误导后来者，故改名——不是「测试改错后换名」。

func TestSetSessionEmptyTokenClearsSession(t *testing.T) {
	c, _, _ := newSecureTestCluster(t, nil, nil)

	// 空 token = 合法清会话语义（CLI 登录前清空）。
	if err := c.SetSession(""); err != nil {
		t.Fatalf("SetSession(\"\") 应合法（清会话），got %v", err)
	}
	token, _, _ := c.sec.snapshot()
	if token != "" {
		t.Fatalf("空 token 应清除会话，got %q", token)
	}

	// 含空白字符的非空 token 拒绝。
	for _, bad := range []string{" has-space", "tab\there", "nl\nhere", "cr\rhere"} {
		if err := c.SetSession(bad); err == nil {
			t.Fatalf("SetSession(%q) 应拒绝含空白字符的 token", bad)
		}
	}

	// 超服务端 512 上限的 token 拒绝（master bearer() 同样 >512 一律视为无 token）。
	if err := c.SetSession(strings.Repeat("x", 513)); err == nil {
		t.Fatal("SetSession 应拒绝超过服务端 512 上限的 token")
	}
	// 512 恰达上限：服务端该长度仍受理，客户端必须放行（阈值不收紧到把合法 token 误杀）。
	if err := c.SetSession(strings.Repeat("x", 512)); err != nil {
		t.Fatalf("SetSession 512 字节（服务端受理的上限）应放行: %v", err)
	}

	// 合法非空 token 接受。
	if err := c.SetSession("valid-token"); err != nil {
		t.Fatal(err)
	}
	token, _, _ = c.sec.snapshot()
	if token != "valid-token" {
		t.Fatalf("合法 token 应被设置，got %q", token)
	}
}

// SetSession 空 token 的 CLI 兼容语义：未登录入口（ATOLL_SESSION 为空）必须能清空
// 既有会话而不是报错——cmd/atoll sessionClient 直接把环境变量交给 SetSession。
func TestSetSessionEmptyClearsPriorSessionForCLI(t *testing.T) {
	c, _, _ := newSecureTestCluster(t, nil, nil)
	if err := c.SetSession("prior-session"); err != nil {
		t.Fatal(err)
	}
	if err := c.UseSpace(7); err != nil {
		t.Fatal(err)
	}
	// 模拟 CLI 未登录：环境变量为空 → 合法清会话（同时清 space 选择）。
	if err := c.SetSession(""); err != nil {
		t.Fatalf("CLI 未登录入口 SetSession(\"\") 必须合法: %v", err)
	}
	token, spaceID, hasSpace := c.sec.snapshot()
	if token != "" || hasSpace || spaceID != 0 {
		t.Fatalf("清会话后应为无 token/无 space: token=%q space=%d has=%v", token, spaceID, hasSpace)
	}
}

// SetSession 拒收超长 token 后：旧有效会话与 space 选择必须原样保留——拒绝发生在
// 写状态之前，失败调用不得产生副作用（否则一次误传就把已登录客户端打回未登录）。
func TestSetSessionRejectionPreservesExistingSession(t *testing.T) {
	c, _, _ := newSecureTestCluster(t, nil, nil)
	if err := c.SetSession("good-session"); err != nil {
		t.Fatal(err)
	}
	if err := c.UseSpace(7); err != nil {
		t.Fatal(err)
	}
	if err := c.SetSession(strings.Repeat("x", 600)); err == nil {
		t.Fatal("超长 token 应被拒绝")
	}
	if err := c.SetSession("bad\ttoken"); err == nil {
		t.Fatal("含空白 token 应被拒绝")
	}
	token, spaceID, hasSpace := c.sec.snapshot()
	if token != "good-session" || !hasSpace || spaceID != 7 {
		t.Fatalf("拒绝后旧会话必须保留: token=%q space=%d has=%v", token, spaceID, hasSpace)
	}
}

// ---- 5. Login rejects malformed wire result ----

// Login malformed（空 token/过期/无 personal space）必须 fail-closed 且不覆盖旧有效
// 会话：旧 token 与 space 选择原样保留——否则一次坏响应就把已登录客户端打回未登录。
func TestLoginRejectsMalformedResult(t *testing.T) {
	malformedCases := []struct {
		name   string
		result LoginResult
	}{
		{"empty_token", LoginResult{
			Token:     "",
			ExpiresAt: time.Now().Add(time.Hour),
			User:      UserInfo{ID: 1, Username: "alice", PersonalSpaceID: 7},
		}},
		{"expired", LoginResult{
			Token:     "tok",
			ExpiresAt: time.Now().Add(-time.Second),
			User:      UserInfo{ID: 1, Username: "alice", PersonalSpaceID: 7},
		}},
		{"zero_expiry", LoginResult{
			Token: "tok",
			User:  UserInfo{ID: 1, Username: "alice", PersonalSpaceID: 7},
		}},
		{"zero_personal_space", LoginResult{
			Token:     "tok",
			ExpiresAt: time.Now().Add(time.Hour),
			User:      UserInfo{ID: 1, Username: "alice", PersonalSpaceID: 0},
		}},
	}

	for _, tc := range malformedCases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tc.result)
			})
			master := httptest.NewServer(mux)
			t.Cleanup(master.Close)

			c, err := NewSecure(master.URL, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			// 先建立旧有效会话：坏响应不得把它顶掉。
			if err := c.SetSession("prior-good-session"); err != nil {
				t.Fatal(err)
			}
			if err := c.UseSpace(7); err != nil {
				t.Fatal(err)
			}
			_, err = c.Login(context.Background(), "alice", "pw")
			if err == nil {
				t.Fatalf("Login should reject malformed result: %s", tc.name)
			}
			// The session must remain the previously valid one, untouched.
			token, spaceID, hasSpace := c.sec.snapshot()
			if token != "prior-good-session" || !hasSpace || spaceID != 7 {
				t.Fatalf("failed Login must not overwrite a valid session: token=%q space=%d has=%v", token, spaceID, hasSpace)
			}
		})
	}

	// 无旧会话时同样不写入坏 token。
	t.Run("no_prior_session", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(LoginResult{Token: "", ExpiresAt: time.Now().Add(time.Hour)})
		})
		master := httptest.NewServer(mux)
		t.Cleanup(master.Close)
		c, err := NewSecure(master.URL, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Login(context.Background(), "alice", "pw"); err == nil {
			t.Fatal("empty token Login should fail")
		}
		token, _, _ := c.sec.snapshot()
		if token != "" {
			t.Fatalf("session must remain empty after failed Login, got %q", token)
		}
	})
}

// ---- 6. NewSecure clones tls.Config ----

func TestNewSecureClonesTLSConfig(t *testing.T) {
	orig := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // test fixture
	c, err := NewSecure("https://master.example", orig, false)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the original — the client's transport must be unaffected.
	orig.MinVersion = tls.VersionTLS10 //nolint:gosec // test fixture

	tr := c.secTransport.base.(*http.Transport)
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("client TLS config was mutated by caller: MinVersion=%x", tr.TLSClientConfig.MinVersion)
	}
}
