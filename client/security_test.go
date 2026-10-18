// 安全会话客户端的传输层测试（httptest 假 master/节点，真组件 e2e 由主 agent 负责）：
//   - 会话只注入 master 源；节点请求只带短期票据（session/space 头绝不外发节点）；
//   - 无会话时节点请求本地拒绝、master 请求不带任何认证头（由 master 裁决拒绝）；
//   - Logout 在线注销后本地会话清除；
//   - 无 space 选择时不发 X-Atoll-Space（master 对用户文件方法一律要求 space，缺头即拒）；
//   - 跨源重定向拒绝；对象数据面票据 BodyHash 恒空（两端协议一致）。
//
// 全部使用本地 httptest 与假凭据，不触碰真实集群。
package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/auth"
)

const (
	testSession = "sess-tok-abcdef"
	testTicket  = "node-ticket-123456"
	testSpaceID = "7"
)

// secSpy 汇集两台假服务（master/节点）观测到的请求头与体。
type secSpy struct {
	mu sync.Mutex

	// master 侧（按 path 记最后一次观测）
	auth  map[string]string // path → Authorization
	space map[string]string // path → X-Atoll-Space
	// login 请求体
	loginUser, loginPass string
	// 票据请求
	ticketReq access.TicketRequest
	ticketCnt int
	// 节点侧
	nodeAuth  string
	nodeSpace string
	nodeHits  int
}

func (s *secSpy) recordMaster(path, authorization, space string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth[path] = authorization
	s.space[path] = space
}

func (s *secSpy) recordTicket(r access.TicketRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ticketReq = r
	s.ticketCnt++
}

func (s *secSpy) recordNode(authorization, space string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeAuth = authorization
	s.nodeSpace = space
	s.nodeHits++
}

// newSecureTestCluster 起假 master + 假节点并返回已登录、已选 space 的 secure client。
// master 额外路由经 extra 注册；nodeGET 对节点对象 GET 的响应可定制。
func newSecureTestCluster(t *testing.T, extra map[string]http.HandlerFunc, nodeObject http.HandlerFunc) (*Client, *secSpy, *httptest.Server) {
	t.Helper()
	spy := &secSpy{auth: map[string]string{}, space: map[string]string{}}

	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spy.recordNode(r.Header.Get("Authorization"), r.Header.Get(access.SpaceHeader))
		if nodeObject != nil {
			nodeObject(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "payload")
	}))
	t.Cleanup(node.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		spy.mu.Lock()
		spy.loginUser, spy.loginPass = in.Username, in.Password
		spy.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(LoginResult{
			Token:     testSession,
			ExpiresAt: time.Now().Add(time.Hour),
			User:      UserInfo{ID: 1, Username: in.Username, PersonalSpaceID: 7},
			Space:     &SpaceInfo{ID: 7, Name: "home", Kind: "personal"},
		})
	})
	mux.HandleFunc("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		spy.recordMaster(r.URL.Path, r.Header.Get("Authorization"), r.Header.Get(access.SpaceHeader))
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/security/tickets", func(w http.ResponseWriter, r *http.Request) {
		spy.recordMaster(r.URL.Path, r.Header.Get("Authorization"), r.Header.Get(access.SpaceHeader))
		var tr access.TicketRequest
		json.NewDecoder(r.Body).Decode(&tr)
		spy.recordTicket(tr)
		json.NewEncoder(w).Encode(access.Ticket{Token: testTicket, ExpiresAt: time.Now().Add(time.Minute)})
	})
	for p, h := range extra {
		mux.HandleFunc(p, h)
	}
	master := httptest.NewServer(mux)
	t.Cleanup(master.Close)

	c, err := NewSecure(master.URL, nil, true) // 测试显式允许明文 http
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(context.Background(), "alice", "pw-secret"); err != nil {
		t.Fatal(err)
	}
	if err := c.UseSpace(7); err != nil {
		t.Fatal(err)
	}
	// mount 接线依赖的不变量：ObjectTransport 与 c.HTTP 的 transport 同一实例。
	if c.ObjectTransport() != c.HTTP.Transport {
		t.Fatal("ObjectTransport 必须返回与 c.HTTP 相同的 transport（挂载层共享连接池/票据逻辑）")
	}
	return c, spy, node
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// NewSecure 基础校验：无 scheme 默认 https；明文 http 必须 allowInsecure 显式放行。
func TestNewSecureSchemePolicy(t *testing.T) {
	if _, err := NewSecure("http://127.0.0.1:9", nil, false); err == nil {
		t.Fatal("明文 http 未显式放行时应报错")
	}
	c, err := NewSecure("127.0.0.1:9", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.MasterURL != "https://127.0.0.1:9" {
		t.Fatalf("无 scheme 应默认 https，got %q", c.MasterURL)
	}
}

// InsecureSkipVerify 与明文同级危险：未显式 allowInsecure 必须拒绝。
func TestNewSecureRejectsSkipVerifyWithoutAllow(t *testing.T) {
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // 测试对象本身就是这个开关
	if _, err := NewSecure("https://127.0.0.1:9", cfg, false); err == nil {
		t.Fatal("InsecureSkipVerify 未显式放行时应报错")
	}
	if _, err := NewSecure("https://127.0.0.1:9", cfg, true); err != nil {
		t.Fatalf("显式放行后应接受: %v", err)
	}
}

// 登录：凭据只出现在 /auth/login 请求体；登录后 master 请求注入会话+默认 space。
func TestSecureLoginInjectsSessionOnMasterOnly(t *testing.T) {
	var dirsAuth, dirsSpace string
	c, spy, _ := newSecureTestCluster(t, map[string]http.HandlerFunc{
		"/dirs/children": func(w http.ResponseWriter, r *http.Request) {
			dirsAuth = r.Header.Get("Authorization")
			dirsSpace = r.Header.Get(access.SpaceHeader)
			io.WriteString(w, `[]`)
		},
	}, nil)

	if spy.loginUser != "alice" || spy.loginPass != "pw-secret" {
		t.Fatalf("login 凭据未按契约送达: %q/%q", spy.loginUser, spy.loginPass)
	}
	if _, err := c.Ls("/"); err != nil {
		t.Fatal(err)
	}
	if dirsAuth != "Bearer "+testSession {
		t.Fatalf("master 请求应注入会话，got %q", dirsAuth)
	}
	if dirsSpace != testSpaceID {
		t.Fatalf("master 请求应携带 space 头 %q，got %q", testSpaceID, dirsSpace)
	}
	// Login 请求本身（尚未登录）不带任何认证头。
	spy.mu.Lock()
	loginAuth := spy.auth["/auth/login"]
	spy.mu.Unlock()
	if loginAuth != "" {
		t.Fatalf("login 不应带认证头，got %q", loginAuth)
	}
}

// UseSpace 显式切换 / 0 清除；未选 space 时绝不发 X-Atoll-Space（master 侧对
// 用户文件方法缺头即拒——客户端保证不伪造默认值）。
func TestUseSpaceChoiceControlsSpaceHeader(t *testing.T) {
	var gotSpace, gotAuth string
	record := func(w http.ResponseWriter, r *http.Request) {
		gotSpace = r.Header.Get(access.SpaceHeader)
		gotAuth = r.Header.Get("Authorization")
		io.WriteString(w, `[]`)
	}
	c, _, _ := newSecureTestCluster(t, map[string]http.HandlerFunc{"/dirs/children": record}, nil)

	if err := c.UseSpace(9); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ls("/"); err != nil {
		t.Fatal(err)
	}
	if gotSpace != "9" || gotAuth != "Bearer "+testSession {
		t.Fatalf("UseSpace(9) 后头不符: space=%q auth=%q", gotSpace, gotAuth)
	}

	if err := c.UseSpace(0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ls("/"); err != nil {
		t.Fatal(err)
	}
	if gotSpace != "" {
		t.Fatalf("清除 space 选择后不应携带 space 头，got %q", gotSpace)
	}
}

// 无 space 选择的会话（如仅 SetSession 恢复登录态）：master 请求带会话但无 space 头，
// 由 master 拒绝需要 space 的调用——客户端不本地伪造。
func TestSetSessionWithoutSpaceOmitsSpaceHeader(t *testing.T) {
	var gotAuth, gotSpace string
	c, _, _ := newSecureTestCluster(t, map[string]http.HandlerFunc{
		"/dirs/children": func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			gotSpace = r.Header.Get(access.SpaceHeader)
			io.WriteString(w, `[]`)
		},
	}, nil)
	// 覆盖登录默认值：仅手动会话、不选 space。
	if err := c.SetSession(testSession); err != nil {
		t.Fatal(err)
	}
	if err := c.UseSpace(0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ls("/"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer "+testSession {
		t.Fatalf("手动会话应注入 Authorization，got %q", gotAuth)
	}
	if gotSpace != "" {
		t.Fatalf("未选 space 不应携带 space 头，got %q", gotSpace)
	}
}

// 核心安全断言：节点请求只带短期票据；会话与 space 头绝不外发；换票请求才携带会话；
// /objects/* 数据面票据 BodyHash 恒空；调用方原始请求不被改写。
func TestNodeRequestsUseTicketSessionNeverLeaked(t *testing.T) {
	c, spy, node := newSecureTestCluster(t, nil, nil)

	req, err := http.NewRequest(http.MethodGet, node.URL+"/objects/123", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "payload" {
		t.Fatalf("节点响应体 = %q", body)
	}
	// 节点侧：只允许票据，绝不出现会话与 space。
	if spy.nodeAuth != "Bearer "+testTicket {
		t.Fatalf("节点应收到票据 Bearer，got %q", spy.nodeAuth)
	}
	if strings.Contains(spy.nodeAuth, testSession) {
		t.Fatal("会话泄漏到节点！")
	}
	if spy.nodeSpace != "" {
		t.Fatalf("space 头不得发往节点，got %q", spy.nodeSpace)
	}
	// 换票请求（master 侧）携带会话+space。
	if spy.auth["/security/tickets"] != "Bearer "+testSession {
		t.Fatalf("换票请求应带会话，got %q", spy.auth["/security/tickets"])
	}
	if spy.space["/security/tickets"] != testSpaceID {
		t.Fatalf("换票请求应带 space，got %q", spy.space["/security/tickets"])
	}
	spy.mu.Lock()
	tr := spy.ticketReq
	spy.mu.Unlock()
	if tr.NodeAddr != mustHost(t, node.URL) || tr.Method != http.MethodGet || tr.Path != "/objects/123" {
		t.Fatalf("票据绑定属性不符: %+v", tr)
	}
	if tr.BodyHash != "" {
		t.Fatalf("/objects/* 数据面票据 BodyHash 必须恒空，got %q", tr.BodyHash)
	}
	// 调用方请求不被 transport 改写。
	if req.Header.Get("Authorization") != "" {
		t.Fatal("transport 不得改写调用方请求头")
	}
}

// 未登录/未选 space：节点换票本地直接拒绝（不外发任何东西、不触达换票端点），
// master 请求不带认证头交给 master 拒。
func TestNodeDeniedWithoutSessionOrSpace(t *testing.T) {
	c, spy, node := newSecureTestCluster(t, nil, nil)
	if err := c.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := c.HTTP.Do(mustReq(t, http.MethodGet, node.URL+"/objects/1")); err == nil {
		t.Fatal("无会话的节点请求应被本地拒绝")
	}
	spy.mu.Lock()
	hits, auth, tickets := spy.nodeHits, spy.nodeAuth, spy.ticketCnt
	spy.mu.Unlock()
	if hits != 0 || auth != "" || tickets != 0 {
		t.Fatalf("无会话不得触达节点/换票端点: hits=%d auth=%q tickets=%d", hits, auth, tickets)
	}

	// 有会话但未选 space：换票同属用户文件操作，同样本地拒绝。
	c2, spy2, node2 := newSecureTestCluster(t, nil, nil)
	if err := c2.UseSpace(0); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.HTTP.Do(mustReq(t, http.MethodGet, node2.URL+"/objects/1")); err == nil {
		t.Fatal("未选 space 的节点请求应被本地拒绝")
	}
	spy2.mu.Lock()
	tickets2, hits2 := spy2.ticketCnt, spy2.nodeHits
	spy2.mu.Unlock()
	if tickets2 != 0 || hits2 != 0 {
		t.Fatalf("未选 space 不得换票/触达节点: tickets=%d hits=%d", tickets2, hits2)
	}
}

// Logout：在线注销带会话；之后本地会话清除——master 请求无认证头、节点请求拒绝。
func TestLogoutClearsSession(t *testing.T) {
	var dirsAuth string
	c, spy, _ := newSecureTestCluster(t, map[string]http.HandlerFunc{
		"/dirs/children": func(w http.ResponseWriter, r *http.Request) {
			dirsAuth = r.Header.Get("Authorization")
			io.WriteString(w, `[]`)
		},
	}, nil)

	if err := c.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if spy.auth["/auth/logout"] != "Bearer "+testSession {
		t.Fatalf("在线注销应带会话，got %q", spy.auth["/auth/logout"])
	}
	if _, err := c.Ls("/"); err != nil {
		t.Fatal(err)
	}
	if dirsAuth != "" {
		t.Fatalf("注销后 master 请求不应携带认证头，got %q", dirsAuth)
	}
}

// 跨源重定向拒绝：节点 30x 到其它主机必须失败，凭据/数据不得被引走。
func TestCrossOriginRedirectRefused(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("重定向目标主机不应被请求: %s", r.URL)
	}))
	defer evil.Close()

	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/steal", http.StatusFound)
	}))
	defer node.Close()

	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(access.Ticket{Token: testTicket, ExpiresAt: time.Now().Add(time.Minute)})
	}))
	defer master.Close()

	c, err := NewSecure(master.URL, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetSession(testSession); err != nil {
		t.Fatal(err)
	}
	// 未选 space 会在换票前被本地拒绝，到不了重定向逻辑——先选上。
	if err := c.UseSpace(7); err != nil {
		t.Fatal(err)
	}
	if _, err := c.HTTP.Do(mustReq(t, http.MethodGet, node.URL+"/objects/1")); err == nil {
		t.Fatal("跨源重定向应被拒绝")
	} else if !strings.Contains(err.Error(), "跨源重定向") {
		t.Fatalf("错误应说明跨源重定向被拒: %v", err)
	}
}

// NewSecure 拒绝歧义 master URL：userinfo/query/fragment/非根路径不得静默丢弃。
func TestNewSecureRejectsAmbiguousMasterURL(t *testing.T) {
	for _, raw := range []string{
		"https://alice:pw@master.example",
		"https://master.example/sub",
		"https://master.example/sub?x=1",
		"https://master.example/?q=1",
		"https://master.example/#frag",
	} {
		if _, err := NewSecure(raw, nil, true); err == nil {
			t.Fatalf("带歧义信息的 master URL 应被拒绝: %s", raw)
		}
	}
	// 纯 origin（含尾随 "/"）放行。
	c, err := NewSecure("https://master.example/", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.MasterURL != "https://master.example" {
		t.Fatalf("归一 origin = %q", c.MasterURL)
	}
}

// 请求 URL 歧义形态（userinfo/opaque/转义 RawPath）fail-closed。
func TestSecureRejectsAmbiguousRequestURL(t *testing.T) {
	c, spy, node := newSecureTestCluster(t, nil, nil)
	mk := func(mutate func(*url.URL)) *http.Request {
		req, err := http.NewRequest(http.MethodGet, node.URL+"/objects/1", nil)
		if err != nil {
			t.Fatal(err)
		}
		mutate(req.URL)
		return req
	}
	cases := map[string]func(*url.URL){
		"userinfo": func(u *url.URL) { u.User = url.User("bob") },
		"opaque":   func(u *url.URL) { u.Opaque = "/objects/1" },
		"rawpath": func(u *url.URL) {
			u.RawPath = u.Path // Path 的合法转义编码，RawPath 非空即歧义
		},
	}
	for name, mutate := range cases {
		if _, err := c.HTTP.Do(mk(mutate)); err == nil {
			t.Fatalf("%s 形态请求 URL 应被拒绝", name)
		} else if !strings.Contains(err.Error(), "拒绝") || !strings.Contains(err.Error(), "URL") {
			t.Fatalf("%s 拒绝原因不明确: %v", name, err)
		}
	}
	if spy.nodeHits != 0 {
		t.Fatalf("歧义 URL 不得触达节点: hits=%d", spy.nodeHits)
	}
}

// scheme 必须与 master 配置一致：https master 绝不向明文 http 节点换票/交付数据，
// 反向（http master → https node）同样本地拒绝；拒绝发生在任何网络请求之前。
func TestSecureRejectsSchemeMismatchedNode(t *testing.T) {
	// https master（构造即可，无需真连）→ http node。
	c, err := NewSecure("https://127.0.0.1:1", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetSession(testSession); err != nil {
		t.Fatal(err)
	}
	if err := c.UseSpace(7); err != nil {
		t.Fatal(err)
	}
	if _, err := c.HTTP.Do(mustReq(t, http.MethodGet, "http://127.0.0.1:2/objects/1")); err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("https master → http node 应本地拒绝并说明 scheme 不符: %v", err)
	}

	// http master（allowInsecure）→ https node 同拒。
	c2, _, _ := newSecureTestCluster(t, nil, nil)
	if _, err := c2.HTTP.Do(mustReq(t, http.MethodGet, "https://127.0.0.1:2/objects/1")); err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("http master → https node 应本地拒绝并说明 scheme 不符: %v", err)
	}
}

// 过期/零值票据拒收：不发往节点，错误说明原因。
func TestSecureRejectsExpiredOrZeroTicket(t *testing.T) {
	for name, exp := range map[string]time.Time{
		"expired": time.Now().Add(-time.Second),
		"zero":    {},
	} {
		nodeHits := 0
		node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nodeHits++
			w.WriteHeader(http.StatusOK)
		}))
		master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(access.Ticket{Token: "short-lived", ExpiresAt: exp})
		}))
		c, err := NewSecure(master.URL, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.SetSession(testSession); err != nil {
			t.Fatal(err)
		}
		if err := c.UseSpace(7); err != nil {
			t.Fatal(err)
		}
		if _, err := c.HTTP.Do(mustReq(t, http.MethodGet, node.URL+"/objects/1")); err == nil || !strings.Contains(err.Error(), "过期") {
			t.Fatalf("%s 票据应被拒并说明过期: %v", name, err)
		}
		node.Close()
		master.Close()
		if nodeHits != 0 {
			t.Fatalf("%s 票据不得发往节点: hits=%d", name, nodeHits)
		}
	}
}

// secure 模式容量改走受限聚合端点 /auth/capacity（不再读整个 /admin/nodes）。
func TestSecureClusterCapacityUsesAuthCapacity(t *testing.T) {
	var adminHit bool
	var capAuth, capSpace string
	c, _, _ := newSecureTestCluster(t, map[string]http.HandlerFunc{
		"/auth/capacity": func(w http.ResponseWriter, r *http.Request) {
			capAuth = r.Header.Get("Authorization")
			capSpace = r.Header.Get(access.SpaceHeader)
			io.WriteString(w, `{"total_bytes":100,"used_bytes":30}`)
		},
		"/admin/nodes": func(w http.ResponseWriter, r *http.Request) {
			adminHit = true
			io.WriteString(w, `[]`)
		},
	}, nil)
	total, used, err := c.ClusterCapacity()
	if err != nil {
		t.Fatal(err)
	}
	if total != 100 || used != 30 {
		t.Fatalf("容量 = %d/%d, want 100/30", total, used)
	}
	if adminHit {
		t.Fatal("secure 模式不得读 /admin/nodes")
	}
	if capAuth != "Bearer "+testSession || capSpace != testSpaceID {
		t.Fatalf("/auth/capacity 应带会话+space: auth=%q space=%q", capAuth, capSpace)
	}
}

// secure 模式空文件建档走 /auth/files/empty（master 服务端落盘，不直写 legacy 对象）。
func TestSecureEmptyFileUsesAuthEndpoint(t *testing.T) {
	var body map[string]any
	var emptyAuth, emptySpace string
	c, spy, _ := newSecureTestCluster(t, map[string]http.HandlerFunc{
		"/auth/files/empty": func(w http.ResponseWriter, r *http.Request) {
			emptyAuth = r.Header.Get("Authorization")
			emptySpace = r.Header.Get(access.SpaceHeader)
			json.NewDecoder(r.Body).Decode(&body)
			io.WriteString(w, `{"inode":{"id":42,"size":0}}`)
		},
		"/files": func(w http.ResponseWriter, r *http.Request) {
			t.Error("空文件不应创建 staging")
			w.WriteHeader(http.StatusInternalServerError)
		},
	}, nil)

	if err := c.PutReaderOverwrite("/docs/empty.txt", 0, strings.NewReader(""), 2, true); err != nil {
		t.Fatal(err)
	}
	if body["path"] != "/docs/empty.txt" || body["overwrite"] != true {
		t.Fatalf("/auth/files/empty 请求体不符: %v", body)
	}
	if emptyAuth != "Bearer "+testSession || emptySpace != testSpaceID {
		t.Fatal("空文件建档请求应带会话+space")
	}
	if spy.nodeHits != 0 {
		t.Fatalf("空文件建档不应触达节点，hits=%d", spy.nodeHits)
	}
}

// 0 字节文件 Get：无数据对象/无副本也不触网，直接落 0 字节本地文件。
func TestGetZeroByteFileSkipsNodes(t *testing.T) {
	var metaServed bool
	c, spy, _ := newSecureTestCluster(t, map[string]http.HandlerFunc{
		"/meta": func(w http.ResponseWriter, r *http.Request) {
			metaServed = true
			io.WriteString(w, `{"inode":{"id":42,"size":0,"name":"e"},"nodes":[]}`)
		},
	}, nil)

	local := filepath.Join(t.TempDir(), "out")
	if err := c.Get("/e", local); err != nil {
		t.Fatal(err)
	}
	if !metaServed {
		t.Fatal("应先查元数据")
	}
	st, err := os.Stat(local)
	if err != nil || st.Size() != 0 {
		t.Fatalf("本地文件应为 0 字节: %v %v", st, err)
	}
	if spy.nodeHits != 0 {
		t.Fatalf("0 字节 Get 不应触达节点，hits=%d", spy.nodeHits)
	}
}

// 旧构造函数不变：非 secure 客户端没有会话语义，行为保持兼容模式。
func TestLegacyClientHasNoSessionSemantics(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		io.WriteString(w, `[]`)
	}))
	defer srv.Close()

	c := New(srv.URL)
	if err := c.SetSession("x"); err != errNotSecure {
		t.Fatalf("旧客户端 SetSession 应返回 errNotSecure, got %v", err)
	}
	if _, err := c.Login(context.Background(), "u", "p"); err != errNotSecure {
		t.Fatalf("旧客户端 Login 应返回 errNotSecure, got %v", err)
	}
	if _, err := c.Ls("/"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Fatalf("旧客户端不应注入头，got %q", gotAuth)
	}

	// NewWithToken 静态 token 行为不变（含发往节点——这正是 secure 模式要替代的）。
	tn := NewWithToken(srv.URL, auth.Token("static"))
	if _, err := tn.Ls("/"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer static" {
		t.Fatalf("静态 token 注入行为应保持，got %q", gotAuth)
	}
}

func mustReq(t *testing.T, method, raw string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
