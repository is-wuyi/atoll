package node

// node/security_test.go：security 模式单测。用 fake master 实现安全端点协议
// （/security/devices/*、/security/tickets、/security/check），覆盖：
// 合法注册/续期、挑战绑定篡改全拒绝、票据/裁决绑定、零/过期拒绝、master 不可达
// fail-closed、集群 token 不被接受也不透传、跨 origin 拒发与重定向不跟随、
// /pull 控制体哈希绑定与还原、peer 出站票据白名单与端到端 pull。

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
	"atoll/pkg/types"
)

// ---- fake master ----

type ticketRecord struct {
	req access.TicketRequest
	exp time.Time
}

type fakeSecMaster struct {
	t   *testing.T
	mu  sync.Mutex
	srv *httptest.Server

	sessionTTL        time.Duration                              // 默认 30m
	mutate            func(c *edgeidentity.Challenge, id string) // 挑战篡改钩子
	ticketErr         bool                                       // /security/tickets 返回 503
	checkErr          bool                                       // /security/check 返回 503
	sessionZeroExpiry bool                                       // 会话返回零过期时刻
	invalidOldTokens  bool                                       // 续期后旧设备 token 立即失效
	planFor           map[uint64]types.ReplicationPlan           // /files/replication
	redirectTo        string                                     // /test/redirect 的 302 目标

	nodeIDSeq  int
	chSeq      int
	challenges map[string]access.DeviceChallengeRequest // id -> 挑战请求（含公钥）
	signed     map[string]edgeidentity.Challenge        // id -> 签发（可能被篡改）的挑战
	inviteSeen []string
	chCount    int
	sessCount  int
	devTokens  map[string]bool
	lastDevTok string
	ticketSeq  int
	mintSeq    int
	tickets    map[string]ticketRecord
	ticketLog  []access.TicketRequest
	checks     []access.CheckRequest
	heartbeats []string
}

func newFakeSecMaster(t *testing.T) *fakeSecMaster {
	fm := &fakeSecMaster{
		t:          t,
		sessionTTL: 30 * time.Minute,
		challenges: map[string]access.DeviceChallengeRequest{},
		signed:     map[string]edgeidentity.Challenge{},
		devTokens:  map[string]bool{},
		tickets:    map[string]ticketRecord{},
		planFor:    map[uint64]types.ReplicationPlan{},
	}
	fm.srv = httptest.NewServer(http.HandlerFunc(fm.serve))
	t.Cleanup(fm.srv.Close)
	return fm
}

func (fm *fakeSecMaster) serve(w http.ResponseWriter, r *http.Request) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/security/devices/challenge":
		var req access.DeviceChallengeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlResponse)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		fm.chSeq++
		fm.chCount++
		id := fmt.Sprintf("ch-%d", fm.chSeq)
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			http.Error(w, "rand", http.StatusInternalServerError)
			return
		}
		now := time.Now()
		ch := edgeidentity.Challenge{
			Nonce:     nonce,
			Audience:  deviceChallengeAudience,
			Purpose:   deviceChallengePurpose,
			NotBefore: now,
			ExpiresAt: now.Add(2 * time.Minute),
			Extras: map[string]string{
				"challenge_id": id,
				"node_id":      string(edgeidentity.DeriveNodeID(req.PublicKey)),
				"addr":         req.Addr,
				"total_bytes":  strconv.FormatInt(req.TotalBytes, 10),
			},
		}
		if fm.mutate != nil {
			fm.mutate(&ch, id)
		}
		fm.challenges[id] = req
		fm.signed[id] = ch
		fm.inviteSeen = append(fm.inviteSeen, req.Invite)
		writeTestJSON(w, http.StatusOK, access.DeviceChallenge{ID: id, Challenge: ch})

	case r.Method == http.MethodPost && r.URL.Path == "/security/devices/session":
		var req access.DeviceLoginRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlResponse)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		chReq, ok := fm.challenges[req.ChallengeID]
		stored, sok := fm.signed[req.ChallengeID]
		if !ok || !sok {
			http.Error(w, "unknown challenge", http.StatusForbidden)
			return
		}
		if err := edgeidentity.VerifyAt(chReq.PublicKey, stored, req.Signature, time.Now(), 0); err != nil {
			http.Error(w, "bad signature", http.StatusForbidden)
			return
		}
		fm.sessCount++
		fm.nodeIDSeq++
		if fm.invalidOldTokens {
			fm.devTokens = map[string]bool{}
		}
		tok := fmt.Sprintf("devtoken-%d", fm.sessCount)
		fm.devTokens[tok] = true
		fm.lastDevTok = tok
		exp := time.Now().Add(fm.sessionTTL)
		if fm.sessionZeroExpiry {
			exp = time.Time{}
		}
		writeTestJSON(w, http.StatusOK, access.DeviceSession{NodeID: uint64(fm.nodeIDSeq), Token: tok, ExpiresAt: exp})

	case r.Method == http.MethodPost && r.URL.Path == "/security/tickets":
		if fm.ticketErr {
			http.Error(w, "tickets unavailable", http.StatusServiceUnavailable)
			return
		}
		if !fm.devTokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req access.TicketRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlResponse)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		fm.ticketSeq++
		tok := fmt.Sprintf("ticket-%d", fm.ticketSeq)
		exp := time.Now().Add(time.Minute)
		fm.tickets[tok] = ticketRecord{req: req, exp: exp}
		fm.ticketLog = append(fm.ticketLog, req)
		writeTestJSON(w, http.StatusOK, access.Ticket{Token: tok, ExpiresAt: exp})

	case r.Method == http.MethodPost && r.URL.Path == "/security/check":
		if fm.checkErr {
			http.Error(w, "check unavailable", http.StatusServiceUnavailable)
			return
		}
		if !fm.devTokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var cr access.CheckRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlResponse)).Decode(&cr); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		fm.checks = append(fm.checks, cr)
		rec, ok := fm.tickets[cr.Token]
		if !ok ||
			rec.req.Method != cr.Method || rec.req.Path != cr.Path || rec.req.Query != cr.Query ||
			rec.req.PlanID != cr.PlanID || rec.req.BodyHash != cr.BodyHash {
			// 与真 master 协议一致：node 会话有效但票据不存在/绑定不符 → 403
			//（节点映射为本地 401；仅 master 不可达才是 503）。
			http.Error(w, "invalid ticket", http.StatusForbidden)
			return
		}
		// 已知票据：200+Allowed（过期由节点按 ExpiresAt 拒绝）。
		writeTestJSON(w, http.StatusOK, access.CheckResult{Allowed: true, ExpiresAt: rec.exp})

	case r.Method == http.MethodGet && r.URL.Path == "/files/replication":
		id, _ := strconv.ParseUint(r.URL.Query().Get("object_id"), 10, 64)
		plan, ok := fm.planFor[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeTestJSON(w, http.StatusOK, plan)

	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/files/"): // 回执类
		writeTestJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	case r.Method == http.MethodPost && r.URL.Path == "/nodes/heartbeat":
		fm.heartbeats = append(fm.heartbeats, r.Header.Get("Authorization"))
		writeTestJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	case r.Method == http.MethodPost && r.URL.Path == "/test/ticket": // 测试直发票据
		var req struct {
			access.TicketRequest
			ExpiresAt  time.Time `json:"expires_at"`
			ZeroExpiry bool      `json:"zero_expiry"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxControlResponse)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		fm.mintSeq++
		tok := fmt.Sprintf("mint-%d", fm.mintSeq)
		exp := req.ExpiresAt
		switch {
		case req.ZeroExpiry:
			exp = time.Time{}
		case exp.IsZero():
			exp = time.Now().Add(time.Minute)
		}
		fm.tickets[tok] = ticketRecord{req: req.TicketRequest, exp: exp}
		fm.ticketLog = append(fm.ticketLog, req.TicketRequest)
		writeTestJSON(w, http.StatusOK, access.Ticket{Token: tok, ExpiresAt: exp})

	case r.Method == http.MethodGet && r.URL.Path == "/test/redirect":
		http.Redirect(w, r, fm.redirectTo, http.StatusFound)

	default:
		http.NotFound(w, r)
	}
}

// mintTicket 测试直接签发一张绑定票据（模拟 caller 拿到票据后访问节点）。
// exp 零值 = 默认 1 分钟。注意：不得持锁发 HTTP——serve() 自己会加锁。
func (fm *fakeSecMaster) mintTicket(tr access.TicketRequest, exp time.Time) string {
	body, _ := json.Marshal(struct {
		access.TicketRequest
		ExpiresAt time.Time `json:"expires_at"`
	}{tr, exp})
	resp, err := http.Post(fm.srv.URL+"/test/ticket", "application/json", bytes.NewReader(body))
	if err != nil {
		fm.t.Fatalf("mint ticket: %v", err)
	}
	defer resp.Body.Close()
	var tk access.Ticket
	if err := json.NewDecoder(resp.Body).Decode(&tk); err != nil || tk.Token == "" {
		fm.t.Fatalf("mint ticket decode: %v", err)
	}
	return tk.Token
}

// mintZeroTicket 签发过期时刻为零的票据（节点必须拒绝）。
func (fm *fakeSecMaster) mintZeroTicket(tr access.TicketRequest) string {
	body, _ := json.Marshal(struct {
		access.TicketRequest
		ZeroExpiry bool `json:"zero_expiry"`
	}{tr, true})
	resp, err := http.Post(fm.srv.URL+"/test/ticket", "application/json", bytes.NewReader(body))
	if err != nil {
		fm.t.Fatalf("mint zero ticket: %v", err)
	}
	defer resp.Body.Close()
	var tk access.Ticket
	if err := json.NewDecoder(resp.Body).Decode(&tk); err != nil || tk.Token == "" {
		fm.t.Fatalf("mint zero ticket decode: %v", err)
	}
	return tk.Token
}

// ---- 测试辅助 ----

func writeTestJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// newSecureNode 建一个启用 security 模式的节点（allowInsecure: 本地测试明文 HTTP）。
func newSecureNode(t *testing.T, fm *fakeSecMaster, advertise, invite string) *Node {
	t.Helper()
	n := New(filepath.Join(t.TempDir(), "data"), fm.srv.URL, advertise, 1<<30)
	if err := n.EnableSecurity(filepath.Join(t.TempDir(), "identity.key"), invite, true); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	return n
}

func mustRegister(t *testing.T, n *Node) {
	t.Helper()
	if err := n.registerOnce(); err != nil {
		t.Fatalf("register (device session): %v", err)
	}
}

// ---- EnableSecurity 前置校验 ----

func TestEnableSecurityGuards(t *testing.T) {
	fm := newFakeSecMaster(t)

	// 明文 HTTP 未显式 allowInsecure：拒绝。
	n1 := New(filepath.Join(t.TempDir(), "d1"), fm.srv.URL, "127.0.0.1:9000", 1<<30)
	if err := n1.EnableSecurity(filepath.Join(t.TempDir(), "id1.key"), "", false); err == nil {
		t.Fatalf("plain HTTP without allowInsecure must fail")
	}
	// 显式 allowInsecure（localtests）：通过。
	if err := n1.EnableSecurity(filepath.Join(t.TempDir(), "id1.key"), "", true); err != nil {
		t.Fatalf("EnableSecurity(allowInsecure): %v", err)
	}
	if err := n1.EnableSecurity(filepath.Join(t.TempDir(), "id1b.key"), "", true); err == nil {
		t.Fatalf("double EnableSecurity must fail")
	}

	// 已注册（legacy 或其它来源）后再启用：拒绝。
	n2 := New(filepath.Join(t.TempDir(), "d2"), fm.srv.URL, "127.0.0.1:9001", 1<<30)
	n2.SetNodeIDForTest(5)
	if err := n2.EnableSecurity(filepath.Join(t.TempDir(), "id2.key"), "", true); err == nil {
		t.Fatalf("EnableSecurity after register must fail")
	}

	// HTTPS master 无需 allowInsecure；SetTLS 由 caller 先行配置并被带进共享
	// 传输。用服务器真实证书做根（不跳过校验）走完整注册流。
	fmTLS := newFakeSecMaster(t)
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(fmTLS.serve))
	t.Cleanup(tlsSrv.Close)
	fmTLS.srv = tlsSrv
	n3 := New(filepath.Join(t.TempDir(), "d3"), tlsSrv.URL, "127.0.0.1:9002", 1<<30)
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	n3.SetTLS(&tls.Config{RootCAs: pool})
	if err := n3.EnableSecurity(filepath.Join(t.TempDir(), "id3.key"), "", false); err != nil {
		t.Fatalf("EnableSecurity(https): %v", err)
	}
	if tr, ok := n3.httpClient.Transport.(*deviceTransport); !ok {
		t.Fatalf("master transport not security-wrapped")
	} else if base, ok := tr.base.(*http.Transport); !ok || base.TLSClientConfig == nil {
		t.Fatalf("TLS config not carried into shared transport")
	}
	mustRegister(t, n3) // HTTPS 上完成设备挑战注册

	// TLS skip-verify 必须显式 allowInsecure。
	n4 := New(filepath.Join(t.TempDir(), "d4"), tlsSrv.URL, "127.0.0.1:9003", 1<<30)
	n4.SetTLS(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // 仅用于断言被拒绝
	if err := n4.EnableSecurity(filepath.Join(t.TempDir(), "id4.key"), "", false); err == nil {
		t.Fatalf("TLS skip-verify without allowInsecure must fail")
	}
}

// ---- 设备注册与挑战绑定 ----

func TestDeviceRegisterChallengeBinding(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *edgeidentity.Challenge, id string)
		wantOK bool
	}{
		{"valid", nil, true},
		{"audience", func(c *edgeidentity.Challenge, _ string) { c.Audience = "atoll-master-device-v2" }, false},
		{"purpose", func(c *edgeidentity.Challenge, _ string) { c.Purpose = "other-session" }, false},
		{"short-nonce", func(c *edgeidentity.Challenge, _ string) { c.Nonce = c.Nonce[:8] }, false},
		{"expired", func(c *edgeidentity.Challenge, _ string) { c.ExpiresAt = time.Now().Add(-time.Minute) }, false},
		{"zero-expiry", func(c *edgeidentity.Challenge, _ string) { c.ExpiresAt = time.Time{} }, false},
		{"window-too-long", func(c *edgeidentity.Challenge, _ string) { c.ExpiresAt = time.Now().Add(5 * time.Minute) }, false},
		{"notbefore-far-future", func(c *edgeidentity.Challenge, _ string) { c.NotBefore = time.Now().Add(10 * time.Minute) }, false},
		{"wrong-addr", func(c *edgeidentity.Challenge, _ string) { c.Extras["addr"] = "10.9.9.9:1" }, false},
		{"wrong-total-bytes", func(c *edgeidentity.Challenge, _ string) { c.Extras["total_bytes"] = "1" }, false},
		{"wrong-node-id", func(c *edgeidentity.Challenge, _ string) { c.Extras["node_id"] = "nid1-OTHER" }, false},
		{"wrong-challenge-id", func(c *edgeidentity.Challenge, _ string) { c.Extras["challenge_id"] = "ch-other" }, false},
		{"missing-extra", func(c *edgeidentity.Challenge, _ string) { delete(c.Extras, "addr") }, false},
		{"extra-unknown-key", func(c *edgeidentity.Challenge, _ string) { c.Extras["invite"] = "leak" }, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fm := newFakeSecMaster(t)
			fm.mutate = tc.mutate
			n := newSecureNode(t, fm, "127.0.0.1:9100", "invite-xyz")
			err := n.registerOnce()
			if tc.wantOK && err != nil {
				t.Fatalf("register: %v", err)
			}
			if !tc.wantOK {
				if err == nil {
					t.Fatalf("tampered challenge must be rejected")
				}
				fm.mu.Lock()
				sessions := fm.sessCount
				fm.mu.Unlock()
				if sessions != 0 {
					t.Fatalf("no session must be created for rejected challenge")
				}
				return
			}
			fm.mu.Lock()
			id := uint64(fm.nodeIDSeq)
			invites := append([]string(nil), fm.inviteSeen...)
			sessions := fm.sessCount
			lastTok := fm.lastDevTok
			fm.mu.Unlock()
			if id != 1 {
				t.Fatalf("nodeID = %d, want 1", id)
			}
			if n.nodeID.Load() != 1 {
				t.Fatalf("node.nodeID = %d, want 1", n.nodeID.Load())
			}
			if len(invites) != 1 || invites[0] != "invite-xyz" {
				t.Fatalf("invite seen = %v, want [invite-xyz]", invites)
			}
			if sessions != 1 {
				t.Fatalf("sessions = %d, want 1", sessions)
			}
			if tok, _ := n.sec.snapshot(); tok != lastTok || tok == "" {
				t.Fatalf("node token not the issued device session token")
			}
		})
	}
}

// 会话零过期/已过期拒绝：节点不得接受永久或过期会话。
func TestDeviceSessionExpiryRejected(t *testing.T) {
	fm := newFakeSecMaster(t)
	fm.sessionZeroExpiry = true
	n := newSecureNode(t, fm, "127.0.0.1:9101", "")
	if err := n.registerOnce(); err == nil {
		t.Fatalf("zero-expiry device session must be rejected")
	}
}

// 续期：同 key、无 invite、token 轮转、旧会话作废；新鲜会话不重复续期。
func TestDeviceSessionRenewal(t *testing.T) {
	fm := newFakeSecMaster(t)
	fm.invalidOldTokens = true
	n := newSecureNode(t, fm, "127.0.0.1:9102", "invite-1")
	mustRegister(t, n)
	tok1, _ := n.sec.snapshot()

	// 临期（margin 大于剩余寿命）→ 主动续期：challenge 两次、invite 仅首次。
	n.sec.renewMargin = 35 * time.Minute
	if err := n.sec.establishSession(context.Background(), false); err != nil {
		t.Fatalf("renew: %v", err)
	}
	tok2, _ := n.sec.snapshot()
	if tok1 == "" || tok2 == "" || tok1 == tok2 {
		t.Fatalf("token must rotate on renewal: %q vs %q", tok1, tok2)
	}
	fm.mu.Lock()
	invites := append([]string(nil), fm.inviteSeen...)
	challenges := fm.chCount
	sessions := fm.sessCount
	oldValid := fm.devTokens[tok1]
	fm.mu.Unlock()
	if challenges != 2 || sessions != 2 {
		t.Fatalf("challenges/sessions = %d/%d, want 2/2", challenges, sessions)
	}
	if len(invites) != 2 || invites[0] != "invite-1" || invites[1] != "" {
		t.Fatalf("invites = %v, want [invite-1 \"\"]", invites)
	}
	if oldValid {
		t.Fatalf("old device token must be invalidated after renewal")
	}

	// 新鲜会话 + 正常 margin：no-op（避免多 goroutine 反复续期互相作废）。
	n.sec.renewMargin = sessionRenewMargin
	if err := n.sec.establishSession(context.Background(), false); err != nil {
		t.Fatalf("establish: %v", err)
	}
	fm.mu.Lock()
	sessions = fm.sessCount
	fm.mu.Unlock()
	if sessions != 2 {
		t.Fatalf("fresh session must not renew: sessions = %d", sessions)
	}

	// errUnknownNode 重注册路径：强制重建，仍不带 invite。
	if err := n.registerOnce(); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	fm.mu.Lock()
	invites = append([]string(nil), fm.inviteSeen...)
	sessions = fm.sessCount
	fm.mu.Unlock()
	if sessions != 3 || invites[2] != "" {
		t.Fatalf("forced re-register: sessions=%d invites=%v", sessions, invites)
	}
}

// ---- 心跳携带设备 Bearer（而非集群 token）----

func TestHeartbeatUsesDeviceBearer(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9103", "")
	n.SetToken("cluster-secret") // legacy token 在 security 模式必须被忽略
	mustRegister(t, n)
	if err := n.heartbeatOnce(); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	fm.mu.Lock()
	heartbeats := append([]string(nil), fm.heartbeats...)
	devTok := fm.lastDevTok
	fm.mu.Unlock()
	if len(heartbeats) != 1 {
		t.Fatalf("heartbeats = %d, want 1", len(heartbeats))
	}
	if want := "Bearer " + devTok; heartbeats[0] != want {
		t.Fatalf("heartbeat auth = %q, want device bearer %q", heartbeats[0], want)
	}
	if strings.Contains(heartbeats[0], "cluster-secret") {
		t.Fatalf("cluster token leaked to master")
	}
}

// ---- 入站 handler：默认拒 + 在线 check ----

func TestSecurityHandler(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9104", "")
	n.SetToken("cluster-secret")
	mustRegister(t, n)
	ts := httptest.NewServer(n.Handler())
	t.Cleanup(ts.Close)

	mint := func(method, path string, exp time.Time) string {
		return fm.mintTicket(access.TicketRequest{NodeAddr: "irrelevant", Method: method, Path: path}, exp)
	}

	// /healthz 永远公开。
	if resp, err := http.Get(ts.URL + "/healthz"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %v", err, resp)
	} else {
		resp.Body.Close()
	}

	data := []byte("secured object payload")
	put := func(token string) int {
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/55", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// 无凭据 / 垃圾凭据 / 集群 token / 非 Bearer：一律 401。
	for _, tc := range []struct{ name, auth string }{
		{"missing", ""},
		{"garbage", "Bearer nope"},
		{"cluster-token", "Bearer cluster-secret"},
		{"not-bearer", "Basic dXNlcjpwYXNz"},
	} {
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/55", bytes.NewReader(data))
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", tc.name, resp.StatusCode)
		}
	}

	// 合法票据：201 落盘。
	if code := put(mint(http.MethodPut, "/objects/55", time.Time{})); code != http.StatusCreated {
		t.Fatalf("PUT with valid ticket = %d, want 201", code)
	}

	// 绑定不符（路径错）：401。
	if code := put(mint(http.MethodPut, "/objects/56", time.Time{})); code != http.StatusUnauthorized {
		t.Fatalf("PUT with wrong-path ticket = %d, want 401", code)
	}

	// 过期票据（Allowed=true 但过期）：401；零过期：401。
	if code := put(mint(http.MethodPut, "/objects/55", time.Now().Add(-time.Second))); code != http.StatusUnauthorized {
		t.Fatalf("PUT with expired ticket = %d, want 401", code)
	}
	if code := put(fm.mintZeroTicket(access.TicketRequest{Method: http.MethodPut, Path: "/objects/55"})); code != http.StatusUnauthorized {
		t.Fatalf("PUT with zero-expiry ticket = %d, want 401", code)
	}

	// GET 对象合法票据：200 + 内容。
	get := func(id uint64, token string) (int, []byte) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/objects/%d", ts.URL, id), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}
	if code, body := get(55, mint(http.MethodGet, "/objects/55", time.Time{})); code != http.StatusOK || !bytes.Equal(body, data) {
		t.Fatalf("GET with valid ticket = %d %q", code, body)
	}

	// check 不可达（master 5xx）：fail-closed 503，即使票据本身有效。
	fm.mu.Lock()
	fm.checkErr = true
	fm.mu.Unlock()
	if code := put(mint(http.MethodPut, "/objects/55", time.Time{})); code != http.StatusServiceUnavailable {
		t.Fatalf("PUT with check down = %d, want 503", code)
	}
	fm.mu.Lock()
	fm.checkErr = false
	fm.mu.Unlock()

	// master 彻底不可达：fail-closed 503（网络错误路径）。
	fm.srv.Close()
	if code := put("mint-after-close"); code != http.StatusServiceUnavailable {
		t.Fatalf("PUT with master unreachable = %d, want 503", code)
	}
}

// ---- /pull 控制体哈希绑定与还原 ----

func TestPullBodyHashBinding(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9105", "")
	mustRegister(t, n)
	ts := httptest.NewServer(n.Handler())
	t.Cleanup(ts.Close)

	body := []byte(`{"inode_id":7,"source_addr":"127.0.0.1:1"}`)
	// 合法绑定：202（handler 收到还原后的控制体并接受）。
	tok := fm.mintTicket(access.TicketRequest{Method: http.MethodPost, Path: "/pull", BodyHash: sha256Hex(body)}, time.Time{})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /pull with bound ticket = %d, want 202", resp.StatusCode)
	}
	fm.mu.Lock()
	last := fm.checks[len(fm.checks)-1]
	fm.mu.Unlock()
	if last.BodyHash != sha256Hex(body) || last.Path != "/pull" || last.Query != "" || last.PlanID != "" {
		t.Fatalf("check request = %+v", last)
	}

	// 哈希不符：401。
	other := []byte(`{"inode_id":8,"source_addr":"127.0.0.1:1"}`)
	tok2 := fm.mintTicket(access.TicketRequest{Method: http.MethodPost, Path: "/pull", BodyHash: sha256Hex(other)}, time.Time{})
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/pull", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+tok2)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /pull with wrong body hash = %d, want 401", resp2.StatusCode)
	}

	// 超过 64KiB：413（fail-closed，绝不缓冲无界控制体）。
	tok3 := fm.mintTicket(access.TicketRequest{Method: http.MethodPost, Path: "/pull"}, time.Time{})
	big := bytes.Repeat([]byte("a"), maxControlBody+1)
	req3, _ := http.NewRequest(http.MethodPost, ts.URL+"/pull", bytes.NewReader(big))
	req3.Header.Set("Authorization", "Bearer "+tok3)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST /pull oversize = %d, want 413", resp3.StatusCode)
	}
}

// /verify：query 只取 plan_id，空 body → BodyHash 空。
func TestVerifyQueryPlanBinding(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9106", "")
	mustRegister(t, n)
	ts := httptest.NewServer(n.Handler())
	t.Cleanup(ts.Close)

	tok := fm.mintTicket(access.TicketRequest{Method: http.MethodPost, Path: "/verify/7", Query: "plan_id=p-3", PlanID: "p-3"}, time.Time{})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/verify/7?plan_id=p-3", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// wrapper 放行后 handler 因 master 无该 plan 返回 409（而非 401/503）。
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /verify = %d, want 409 (allowed by ticket)", resp.StatusCode)
	}
	fm.mu.Lock()
	last := fm.checks[len(fm.checks)-1]
	fm.mu.Unlock()
	if last.PlanID != "p-3" || last.Query != "plan_id=p-3" || last.BodyHash != "" || last.Method != http.MethodPost || last.Path != "/verify/7" {
		t.Fatalf("check request = %+v", last)
	}
}

// ---- 出站：peer 票据流 ----

func TestOutboundPeerTicket(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9107", "")
	mustRegister(t, n)

	var peerHitsMu sync.Mutex
	var peerAuth []string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerHitsMu.Lock()
		peerAuth = append(peerAuth, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		peerHitsMu.Unlock()
		if r.URL.Path == "/objects/42" {
			io.WriteString(w, "peer-object")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()
	peerHost := strings.TrimPrefix(peer.URL, "http://")

	// GET /objects/42：先向 master 换票，再以票据访问 peer。
	req, _ := http.NewRequest(http.MethodGet, peer.URL+"/objects/42", nil)
	resp, err := n.bulkClient.Do(req)
	if err != nil {
		t.Fatalf("peer GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "peer-object" {
		t.Fatalf("peer GET = %d %q", resp.StatusCode, body)
	}

	fm.mu.Lock()
	devTok := fm.lastDevTok
	var got access.TicketRequest
	if len(fm.ticketLog) > 0 {
		got = fm.ticketLog[len(fm.ticketLog)-1]
	}
	fm.mu.Unlock()
	if got.NodeAddr != peerHost || got.Method != http.MethodGet || got.Path != "/objects/42" || got.Query != "" || got.PlanID != "" || got.BodyHash != "" {
		t.Fatalf("ticket request = %+v", got)
	}
	peerHitsMu.Lock()
	auth := peerAuth[len(peerAuth)-1]
	peerHitsMu.Unlock()
	// peerAuth 记录 "METHOD path Authorization"；票据以 ticket- 前缀直达 peer。
	if !strings.Contains(auth, "Bearer ticket-") {
		t.Fatalf("peer saw auth = %q, want issued ticket", auth)
	}
	if strings.Contains(auth, devTok) || strings.Contains(auth, "cluster-secret") {
		t.Fatalf("device/cluster credential leaked to peer: %q", auth)
	}

	// Plan 头 → 票据 PlanID（pull/push 计划流绑定）。
	req2, _ := http.NewRequest(http.MethodGet, peer.URL+"/objects/42", nil)
	req2.Header.Set(access.PlanHeader, "plan-9")
	resp2, err := n.bulkClient.Do(req2)
	if err != nil {
		t.Fatalf("peer GET plan: %v", err)
	}
	resp2.Body.Close()
	fm.mu.Lock()
	got = fm.ticketLog[len(fm.ticketLog)-1]
	fm.mu.Unlock()
	if got.PlanID != "plan-9" {
		t.Fatalf("ticket PlanID = %q, want plan-9", got.PlanID)
	}

	// PUT /replicate/{id}（流式 body：GetBody 为 nil → BodyHash 空，payload 不进 master）。
	req3, _ := http.NewRequest(http.MethodPut, peer.URL+"/replicate/7", io.NopCloser(bytes.NewReader([]byte("object-bytes"))))
	req3.ContentLength = 12
	resp3, err := n.bulkClient.Do(req3)
	if err != nil {
		t.Fatalf("peer PUT: %v", err)
	}
	resp3.Body.Close()
	fm.mu.Lock()
	got = fm.ticketLog[len(fm.ticketLog)-1]
	callerAuth := req3.Header.Get("Authorization") // 原请求不得被写入票据（clone 隔离）
	fm.mu.Unlock()
	if got.Method != http.MethodPut || got.Path != "/replicate/7" || got.BodyHash != "" {
		t.Fatalf("PUT ticket request = %+v", got)
	}
	if callerAuth != "" {
		t.Fatalf("caller request Authorization mutated: %q", callerAuth)
	}

	// 白名单外路径：拒绝换票，master 不收到 ticket 请求，peer 不被访问。
	fm.mu.Lock()
	before := len(fm.ticketLog)
	fm.mu.Unlock()
	req4, _ := http.NewRequest(http.MethodGet, peer.URL+"/admin/objects", nil)
	if _, err := n.bulkClient.Do(req4); err == nil {
		t.Fatalf("non-ticketable peer path must fail")
	}
	fm.mu.Lock()
	after := len(fm.ticketLog)
	fm.mu.Unlock()
	if after != before {
		t.Fatalf("master must not be asked for tickets on non-allowlisted paths")
	}
	peerHitsMu.Lock()
	hits := len(peerAuth)
	peerHitsMu.Unlock()
	if hits != 3 {
		t.Fatalf("peer hits = %d, want 3 (admin path never reached peer)", hits)
	}

	// 非法 id / 方法不匹配：拒绝。
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/objects/"},
		{http.MethodGet, "/objects/abc"},
		{http.MethodGet, "/replicate/1"},
		{http.MethodPut, "/objects/1"},
		{http.MethodDelete, "/objects/1"},
	} {
		r, _ := http.NewRequest(tc.method, peer.URL+tc.path, nil)
		if _, err := n.bulkClient.Do(r); err == nil {
			t.Fatalf("%s %s must not be ticketable", tc.method, tc.path)
		}
	}
}

// ---- master origin 防护：跨 origin 拒发凭据、重定向不跟随 ----

func TestMasterOriginGuard(t *testing.T) {
	evilHit := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evilHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer evil.Close()

	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9108", "")
	mustRegister(t, n)

	// 非 master origin：设备凭据拒绝发送。
	if _, err := n.httpClient.Get(evil.URL + "/steal"); err == nil {
		t.Fatalf("request to non-master origin must be refused")
	}
	// master 302 → evil：不跟随（最后响应 302），evil 不被命中。
	fm.mu.Lock()
	fm.redirectTo = evil.URL + "/steal"
	fm.mu.Unlock()
	resp, err := n.httpClient.Get(fm.srv.URL + "/test/redirect")
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect status = %d, want 302 (not followed)", resp.StatusCode)
	}
	if evilHit {
		t.Fatalf("credentials/requests must never reach a non-master origin")
	}
}

// ---- 端到端：security 模式双节点 + fake master 的计划外 pull ----

func TestSecurityPullEndToEnd(t *testing.T) {
	fm := newFakeSecMaster(t)

	data := []byte("e2e secured pull payload 0123456789")
	crc := types.CRC32C(data)

	// 源节点（先注册 → nodeID 1）。
	src := newSecureNode(t, fm, "127.0.0.1:9110", "")
	mustRegister(t, src)
	srcTS := httptest.NewServer(src.Handler())
	t.Cleanup(srcTS.Close)
	if _, _, err := src.storeObject(100, bytes.NewReader(data), crc); err != nil {
		t.Fatalf("store object on source: %v", err)
	}
	srcAddr := strings.TrimPrefix(srcTS.URL, "http://")

	// 目标节点（nodeID 2）。
	dst := newSecureNode(t, fm, "127.0.0.1:9111", "")
	mustRegister(t, dst)
	dstTS := httptest.NewServer(dst.Handler())
	t.Cleanup(dstTS.Close)

	fm.mu.Lock()
	fm.planFor[100] = types.ReplicationPlan{
		Protocol: types.IntegrityProtocol,
		Object: types.ObjectIntegrity{
			ObjectID: 100, InodeID: 100, Size: int64(len(data)),
			Checksum: crc, ChecksumKnown: true, Replicas: []uint64{1, 2},
		},
		Sources: []types.NodeInfo{{ID: 1, Addr: srcAddr}},
	}
	fm.mu.Unlock()

	// 以 caller 身份为 POST /pull 签发绑定票据（控制体 SHA256 全绑定）。
	pullBody, _ := json.Marshal(map[string]any{"inode_id": 100, "source_addr": srcAddr, "checksum": crc})
	tok := fm.mintTicket(access.TicketRequest{Method: http.MethodPost, Path: "/pull", BodyHash: sha256Hex(pullBody)}, time.Time{})
	req, _ := http.NewRequest(http.MethodPost, dstTS.URL+"/pull", bytes.NewReader(pullBody))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /pull = %d, want 202", resp.StatusCode)
	}

	// 轮询：目标节点经（目标→master 换票 → 源节点 check → 数据流）落盘。
	deadline := time.Now().Add(5 * time.Second)
	ok := false
	for time.Now().Before(deadline) && !ok {
		getTok := fm.mintTicket(access.TicketRequest{Method: http.MethodGet, Path: "/objects/100"}, time.Time{})
		greq, _ := http.NewRequest(http.MethodGet, dstTS.URL+"/objects/100", nil)
		greq.Header.Set("Authorization", "Bearer "+getTok)
		gresp, gerr := http.DefaultClient.Do(greq)
		if gerr == nil {
			b, _ := io.ReadAll(gresp.Body)
			gresp.Body.Close()
			ok = gresp.StatusCode == http.StatusOK && bytes.Equal(b, data)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("object did not land on target via secured pull")
	}

	// 目标节点对源节点的出站 GET 必须经过换票：NodeAddr/Path 正确。
	fm.mu.Lock()
	defer fm.mu.Unlock()
	found := false
	for _, tr := range fm.ticketLog {
		if tr.Method == http.MethodGet && tr.Path == "/objects/100" && tr.NodeAddr == srcAddr {
			found = true
		}
	}
	if !found {
		t.Fatalf("outbound pull GET was not ticketed: %+v", fm.ticketLog)
	}
}

// ---- Register 全链路（含心跳循环启动）----

func TestRegisterFullStackSecurity(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9112", "invite-full")
	n.heartbeatInterval = 10 * time.Millisecond
	if err := n.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fm.mu.Lock()
		hb := len(fm.heartbeats)
		fm.mu.Unlock()
		if hb >= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("heartbeats did not flow with device bearer")
}

// ---- 持久安全标记：重启忘带 --secure 时 fail-closed ----

func TestSecurityMarkerFailClosed(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9114", "")
	mustRegister(t, n)

	// EnableSecurity 成功 → dataDir 落 0600 标记，且不含任何机密。
	marker := filepath.Join(n.dataDir, securityMarkerName)
	st, err := os.Stat(marker)
	if err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("marker perm = %04o, want 0600", st.Mode().Perm())
	}
	body, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{fm.lastDevTok, "devtoken-", "invite"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatalf("marker must not contain secrets (%q)", secret)
		}
	}

	// 模拟重启后 security 未启用：同 dataDir 新 Node → Handler fail-closed（healthz 除外）。
	n2 := New(n.dataDir, fm.srv.URL, "127.0.0.1:9115", 1<<30)
	ts2 := httptest.NewServer(n2.Handler())
	defer ts2.Close()
	if resp, err := http.Get(ts2.URL + "/healthz"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz must stay public: %v %v", err, resp)
	} else {
		resp.Body.Close()
	}
	resp, err := http.Get(ts2.URL + "/objects/1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("marker present without security = %d, want 503", resp.StatusCode)
	}

	// 无标记的全新节点：legacy 行为不变（兼容模式放行 mux，404 而非 503）。
	n3 := New(filepath.Join(t.TempDir(), "data"), fm.srv.URL, "127.0.0.1:9116", 1<<30)
	ts3 := httptest.NewServer(n3.Handler())
	defer ts3.Close()
	resp3, err := http.Get(ts3.URL + "/objects/1")
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode == http.StatusServiceUnavailable {
		t.Fatalf("legacy node without marker must keep legacy behavior")
	}
}

// ---- 非 allowInsecure：入站明文（r.TLS == nil）fail-closed ----

func TestPlaintextInboundRejected(t *testing.T) {
	fmTLS := newFakeSecMaster(t)
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(fmTLS.serve))
	defer tlsSrv.Close()
	fmTLS.srv = tlsSrv

	n := New(filepath.Join(t.TempDir(), "data"), tlsSrv.URL, "127.0.0.1:9117", 1<<30)
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	n.SetTLS(&tls.Config{RootCAs: pool})
	if err := n.EnableSecurity(filepath.Join(t.TempDir(), "id.key"), "", false); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	mustRegister(t, n)
	h := n.Handler()

	// 同一 handler 挂明文 server：非 healthz 请求必须 400（r.TLS == nil）。
	plain := httptest.NewServer(h)
	defer plain.Close()
	resp, err := http.Get(plain.URL + "/objects/1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plaintext = %d, want 400", resp.StatusCode)
	}
	if resp, err := http.Get(plain.URL + "/healthz"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v", err)
	} else {
		resp.Body.Close()
	}

	// TLS server 挂同一 handler + 校验过的客户端：不被明文闸拦截（无票据 → 401）。
	nodeTLS := httptest.NewTLSServer(h)
	defer nodeTLS.Close()
	nodePool := x509.NewCertPool()
	nodePool.AddCert(nodeTLS.Certificate())
	tlsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: nodePool}}}
	treq, _ := http.NewRequest(http.MethodGet, nodeTLS.URL+"/objects/1", nil)
	tresp, err := tlsClient.Do(treq)
	if err != nil {
		t.Fatal(err)
	}
	tresp.Body.Close()
	if tresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tls request = %d, want 401", tresp.StatusCode)
	}
}

// ---- token 不落日志 ----

// syncWriter 是并发安全的日志捕获缓冲：既有测试泄漏的心跳 goroutine 仍会
// 并发写全局 log，直接用 bytes.Buffer 会构成数据竞争。
type syncWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func TestNoTokenInLogs(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9113", "")

	var buf syncWriter
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	mustRegister(t, n)
	tok, _ := n.sec.snapshot()
	fm.mu.Lock()
	devTok := fm.lastDevTok
	fm.mu.Unlock()

	// 触发会写日志的路径：启用日志、check 不可达 503、续期失败。
	fm.mu.Lock()
	fm.checkErr = true
	fm.mu.Unlock()
	ts := httptest.NewServer(n.Handler())
	tk := fm.mintTicket(access.TicketRequest{Method: http.MethodPut, Path: "/objects/1"}, time.Time{})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/1", bytes.NewReader([]byte("x")))
	req.Header.Set("Authorization", "Bearer "+tk)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 fail-closed, got %d", resp.StatusCode)
	}
	fm.srv.Close()
	if err := n.sec.establishSession(context.Background(), true); err == nil {
		t.Fatal("expected renewal failure after master close")
	}

	out := buf.String()
	for _, secret := range []string{tok, devTok, "devtoken-", "ticket-", "mint-"} {
		if strings.Contains(out, secret) {
			t.Fatalf("log leaks secret %q:\n%s", secret, out)
		}
	}
}
