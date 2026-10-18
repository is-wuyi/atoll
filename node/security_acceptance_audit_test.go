package node

// security_acceptance_audit_test.go —— 独立验收审计回归（允许修改 node 实现与测试）。
//
// 覆盖五组此前钉死/本次修复的验收点：
//  1. 401 失效会话自愈：master 作废「本地仍新鲜」的设备 token 后，401 路径必须
//     按被拒 token 条件强制重建（不等 renewMargin），自愈后旧 token 作废、心跳用新
//     token 恢复。
//  2. 重建收敛：24 并发 401（同步 renewAfterRejection + 异步 kickRenewFor 混合）
//     在 opMu 内按「被拒 token == 当前快照」CAS 判断，恰好多重建 1 次；被拒 token
//     已轮换的迟到 401 一律 no-op，绝不作废新会话。
//  3. peer 换票 401 → 恰好一次条件重建后重试成功；设备凭据绝不上 peer 线；
//     peer 302 不跟随；authorizePeer 的 scheme/URL 歧义加固（https master 拒绝
//     为 http peer 换票，userinfo/opaque/转义路径/空 host 一律拒绝）。
//  4. 入站 wrapper 精确中继绑定：check 上报的 Method/Path/Query 与票据逐字节一致
//     （未清洗路径、跨对象、跨方法、多余 query 一律 401），合法裁决逐请求在线重查。
//  5. 安全标记绑定与持久性：首建 durable（temp→fsync→rename→父目录 sync）；
//     已有标记读取校验——同 identity/master 重启放行且不重写（inode 不变），
//     不同 identity/master / 损坏 / 不可读一律 fail-closed 且绝不改写标记文件。
//
// 测试使用本文件自带的 auditFakeMaster（可注入 challenge 延迟与「票据 401 恰好
// 一次」）与同包 fakeSecMaster（mintTicket/check 精确匹配，已对照真 master 实现
// 核实等价）。

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/pkg/access"
	"atoll/pkg/edgeidentity"
)

// ---- 审计专用 fake master（最小协议面：challenge/session/tickets） ----

type auditFakeMaster struct {
	t   *testing.T
	mu  sync.Mutex
	srv *httptest.Server

	challengeDelay time.Duration // 拉长 challenge 往返，给并发 CAS 留出确定性窗口
	ticket401Once  bool          // 下一次 /security/tickets 无条件 401（模拟 in-flight 旧 token）
	sessionTTL     time.Duration

	chSeq   int
	sessSeq int
	pubkeys map[string][]byte                 // challenge id → 请求公钥（验签用）
	signed  map[string]edgeidentity.Challenge // challenge id → 签发挑战（验签用）
	devTok  map[string]bool
	tokSeq  int
	tktSeq  int
	tickets map[string]access.TicketRequest

	ticket401s int
	ticketOK   int
}

func newAuditFakeMaster(t *testing.T) *auditFakeMaster {
	fm := &auditFakeMaster{
		t:          t,
		sessionTTL: 30 * time.Minute,
		pubkeys:    map[string][]byte{},
		signed:     map[string]edgeidentity.Challenge{},
		devTok:     map[string]bool{},
		tickets:    map[string]access.TicketRequest{},
	}
	fm.srv = httptest.NewServer(http.HandlerFunc(fm.serve))
	t.Cleanup(fm.srv.Close)
	return fm
}

func (fm *auditFakeMaster) serve(w http.ResponseWriter, r *http.Request) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/security/devices/challenge":
		if fm.challengeDelay > 0 {
			time.Sleep(fm.challengeDelay)
		}
		var req access.DeviceChallengeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		fm.chSeq++
		id := fmt.Sprintf("audit-ch-%d", fm.chSeq)
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
		fm.pubkeys[id] = req.PublicKey
		fm.signed[id] = ch
		writeTestJSON(w, http.StatusOK, access.DeviceChallenge{ID: id, Challenge: ch})

	case r.Method == http.MethodPost && r.URL.Path == "/security/devices/session":
		var req access.DeviceLoginRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pub, okPub := fm.pubkeys[req.ChallengeID]
		stored, okCh := fm.signed[req.ChallengeID]
		if !okPub || !okCh {
			http.Error(w, "unknown challenge", http.StatusForbidden)
			return
		}
		// 与真 master 同规：先验签（对签发时的完整挑战）再发会话。
		if err := edgeidentity.VerifyAt(pub, stored, req.Signature, time.Now(), 0); err != nil {
			http.Error(w, "bad signature", http.StatusForbidden)
			return
		}
		fm.sessSeq++
		// 真实轮换语义：每次发会话即作废旧 token（master 侧 SessionVersion 递增）。
		fm.devTok = map[string]bool{}
		fm.tokSeq++
		tok := fmt.Sprintf("audit-devtoken-%d", fm.tokSeq)
		fm.devTok[tok] = true
		writeTestJSON(w, http.StatusOK, access.DeviceSession{
			NodeID:    uint64(fm.sessSeq),
			Token:     tok,
			ExpiresAt: time.Now().Add(fm.sessionTTL),
		})

	case r.Method == http.MethodPost && r.URL.Path == "/security/tickets":
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !fm.devTok[bearer] {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if fm.ticket401Once {
			fm.ticket401Once = false
			fm.ticket401s++
			http.Error(w, "stale in-flight device token", http.StatusUnauthorized)
			return
		}
		var req access.TicketRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		fm.tktSeq++
		tok := fmt.Sprintf("audit-ticket-%d", fm.tktSeq)
		fm.tickets[tok] = req
		fm.ticketOK++
		writeTestJSON(w, http.StatusOK, access.Ticket{Token: tok, ExpiresAt: time.Now().Add(time.Minute)})

	case r.Method == http.MethodPost && r.URL.Path == "/nodes/heartbeat":
		// 与真 master 同规：设备会话失效 → 401（自愈路径的触发源）。
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !fm.devTok[bearer] {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		http.NotFound(w, r)
	}
}

func (fm *auditFakeMaster) counts() (ch, sess, t401, tok int) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.chSeq, fm.sessSeq, fm.ticket401s, fm.tokSeq
}

func (fm *auditFakeMaster) tokenValid(tok string) bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.devTok[tok]
}

// newAuditSecureNode 与 security_test.go 的 newSecureNode 等价，但接受本文件
// 的 auditFakeMaster（不改动既有 fixture 的签名）。
func newAuditSecureNode(t *testing.T, fm *auditFakeMaster, advertise, invite string) *Node {
	t.Helper()
	n := New(filepath.Join(t.TempDir(), "data"), fm.srv.URL, advertise, 1<<30)
	if err := n.EnableSecurity(filepath.Join(t.TempDir(), "identity.key"), invite, true); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	return n
}

// waitRenewQuiescent 等待 kickRenewFor 的异步续期彻底结束（含短暂 straggler 窗口）。
func waitRenewQuiescent(t *testing.T, s *nodeSecurity) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !s.renewing.Load() {
			time.Sleep(80 * time.Millisecond)
			if !s.renewing.Load() {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("async renewal did not quiesce")
}

//  1. master 作废「本地仍新鲜」的会话：真实心跳 401 → 按被拒 token 条件重建自愈，
//     恰好一次重建；旧 token 作废、新 token 通过心跳验收。此前实现此处 no-op
//     （新鲜度短路），是最长约 25min 的 401 停摆缺陷。
func TestAuditRenewAfterServerInvalidation(t *testing.T) {
	fm := newAuditFakeMaster(t)
	n := newAuditSecureNode(t, fm, "127.0.0.1:9210", "")
	mustRegister(t, n)
	s1, _ := n.sec.snapshot()

	// master 侧作废 S1（会话记录丢失/被轮换），本地会话仍新鲜。
	fm.mu.Lock()
	fm.devTok = map[string]bool{}
	base := fm.sessSeq
	fm.mu.Unlock()

	if err := n.heartbeatOnce(); err == nil {
		t.Fatalf("heartbeat with invalidated token must fail with 401")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, sess, _, _ := fm.counts()
		if sess >= base+1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session rebuild did not happen after 401: sessSeq < %d (401 失效会话未自愈)", base+1)
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitRenewQuiescent(t, n.sec)

	s2, _ := n.sec.snapshot()
	if s2 == "" || s2 == s1 {
		t.Fatalf("token must rotate after server-side invalidation: %q", s2)
	}
	if fm.tokenValid(s1) {
		t.Fatalf("invalidated old token must not be resurrected")
	}
	if !fm.tokenValid(s2) {
		t.Fatalf("new token must be accepted by master")
	}
	if _, sess, _, _ := fm.counts(); sess != base+1 {
		t.Fatalf("exactly one rebuild expected: sess=%d, want %d", sess, base+1)
	}
	if err := n.heartbeatOnce(); err != nil {
		t.Fatalf("heartbeat must recover with renewed session: %v", err)
	}
}

//  2. 重建收敛：master 作废当前 token 后，24 并发同步 renewAfterRejection 与
//     异步 kickRenewFor 混合触发，opMu 内「被拒 token == 当前快照」判断使
//     重建恰好 1 次（第一个重建，其余看到快照已轮换自然 no-op，无强制重登风暴）。
func TestAuditConcurrent401SingleRebuild(t *testing.T) {
	fm := newAuditFakeMaster(t)
	n := newAuditSecureNode(t, fm, "127.0.0.1:9211", "")
	mustRegister(t, n)
	s1, _ := n.sec.snapshot()
	fm.mu.Lock()
	fm.devTok = map[string]bool{} // master 作废 S1
	fm.mu.Unlock()
	ch0, sess0, _, _ := fm.counts()

	const burst = 24
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = n.sec.renewAfterRejection(ctx, s1)
		}()
	}
	for i := 0; i < 4; i++ { // 混入异步路径（deviceTransport 401 触发形态）
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			n.sec.kickRenewFor(s1)
		}()
	}
	close(start)
	wg.Wait()
	waitRenewQuiescent(t, n.sec)

	ch1, sess1, _, _ := fm.counts()
	if ch1-ch0 != 1 || sess1-sess0 != 1 {
		t.Fatalf("concurrent 401 rebuild must happen exactly once: ch delta=%d sess delta=%d, want 1/1",
			ch1-ch0, sess1-sess0)
	}
	s2, _ := n.sec.snapshot()
	if s2 == "" || s2 == s1 {
		t.Fatalf("token must rotate exactly once: %q", s2)
	}
	if fm.tokenValid(s1) {
		t.Fatalf("rejected token must be invalidated")
	}
	if !fm.tokenValid(s2) {
		t.Fatalf("new token must be the only valid one")
	}
}

//  3. 迟到 401 不作废新会话：被拒 token 已轮换（快照变化）后，同 token 的
//     同步/异步 401 处理必须 no-op（回归守卫：条件重建不得退化成无条件 force）。
func TestAuditLate401KeepsRotatedSession(t *testing.T) {
	fm := newAuditFakeMaster(t)
	fm.challengeDelay = 50 * time.Millisecond
	n := newAuditSecureNode(t, fm, "127.0.0.1:9212", "")
	mustRegister(t, n)
	s1, _ := n.sec.snapshot()

	// 本地主动轮换到 S2（模拟并发 renewal 已完成）。
	if err := n.sec.establishSession(context.Background(), true); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	s2, _ := n.sec.snapshot()
	if s2 == s1 {
		t.Fatalf("rotation must change token")
	}
	ch0, sess0, _, _ := fm.counts()

	// 迟到的 S1 401：同步与异步路径都必须 no-op。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.sec.renewAfterRejection(ctx, s1); err != nil {
		t.Fatalf("late 401 for rotated token must be a no-op, got %v", err)
	}
	n.sec.kickRenewFor(s1)
	waitRenewQuiescent(t, n.sec)

	ch1, sess1, _, _ := fm.counts()
	if ch1 != ch0 || sess1 != sess0 {
		t.Fatalf("late 401 must not rebuild: ch %d->%d sess %d->%d", ch0, ch1, sess0, sess1)
	}
	if cur, _ := n.sec.snapshot(); cur != s2 {
		t.Fatalf("current session must stay intact: %q", cur)
	}
	if !fm.tokenValid(s2) {
		t.Fatalf("rotated session must remain valid at master")
	}
}

//  4. peer 换票 401：恰好一次条件重建后重试成功；设备凭据绝不上 peer 线、
//     调用方请求不被改写；peer 302 不跟随（票据/请求体不被引走）。
func TestAuditPeerTicketRecoversFromSingle401(t *testing.T) {
	fm := newAuditFakeMaster(t)
	n := newAuditSecureNode(t, fm, "127.0.0.1:9213", "")
	mustRegister(t, n)

	evilHit := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evilHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer evil.Close()

	var peerMu sync.Mutex
	var peerAuth []string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerMu.Lock()
		peerAuth = append(peerAuth, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		peerMu.Unlock()
		if r.URL.Path == "/objects/7" {
			http.Redirect(w, r, evil.URL+"/steal", http.StatusFound)
			return
		}
		io.WriteString(w, "peer-object")
	}))
	defer peer.Close()

	devTok, _ := n.sec.snapshot()

	// 第一笔换票请求 401（master 报本设备会话失效）：条件重建恰 1 次，重试成功。
	fm.mu.Lock()
	fm.ticket401Once = true
	fm.mu.Unlock()

	req, _ := http.NewRequest(http.MethodGet, peer.URL+"/objects/42", nil)
	resp, err := n.bulkClient.Do(req)
	if err != nil {
		t.Fatalf("peer GET after single 401: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "peer-object" {
		t.Fatalf("peer GET = %d %q, want 200 peer-object", resp.StatusCode, body)
	}
	if callerAuth := req.Header.Get("Authorization"); callerAuth != "" {
		t.Fatalf("caller request must not be mutated, got %q", callerAuth)
	}

	ch, sess, t401, _ := fm.counts()
	if t401 != 1 {
		t.Fatalf("exactly one ticket 401 expected, got %d", t401)
	}
	if ch != 2 || sess != 2 { // 注册 1 次 + 401 条件重建 1 次
		t.Fatalf("single ticket 401 must trigger exactly one rebuild: ch=%d sess=%d, want 2/2", ch, sess)
	}
	waitRenewQuiescent(t, n.sec) // deviceTransport 对同一 401 的异步 kick 不得再重建
	if ch, sess, _, _ = fm.counts(); ch != 2 || sess != 2 {
		t.Fatalf("async kick after sync rebuild must no-op: ch=%d sess=%d", ch, sess)
	}
	if s2, _ := n.sec.snapshot(); s2 == devTok {
		t.Fatalf("session must have rotated after 401")
	}

	peerMu.Lock()
	auth := peerAuth[len(peerAuth)-1]
	peerMu.Unlock()
	if !strings.Contains(auth, "Bearer audit-ticket-") {
		t.Fatalf("peer must receive a ticket bearer, got %q", auth)
	}
	if strings.Contains(auth, devTok) || strings.Contains(auth, "audit-devtoken") {
		t.Fatalf("device session leaked to peer: %q", auth)
	}

	// peer 302 → evil：不跟随（票据/请求体不被引走）。
	req2, _ := http.NewRequest(http.MethodGet, peer.URL+"/objects/7", nil)
	resp2, err := n.bulkClient.Do(req2)
	if err != nil {
		t.Fatalf("peer redirect: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("peer redirect status = %d, want 302 (not followed)", resp2.StatusCode)
	}
	if evilHit {
		t.Fatalf("redirect target must never be contacted")
	}
}

//  5. authorizePeer scheme/URL 歧义加固：https master 下拒绝为 http peer 换票
//     （TLS 降级面），userinfo/opaque/转义路径/空 host 一律在触网前拒绝。
func TestAuditPeerSchemeGuard(t *testing.T) {
	fmTLS := newFakeSecMaster(t)
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(fmTLS.serve))
	defer tlsSrv.Close()
	fmTLS.srv = tlsSrv

	n := New(filepath.Join(t.TempDir(), "data"), tlsSrv.URL, "127.0.0.1:9214", 1<<30)
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	n.SetTLS(&tls.Config{RootCAs: pool})
	if err := n.EnableSecurity(filepath.Join(t.TempDir(), "id.key"), "", false); err != nil {
		t.Fatalf("EnableSecurity: %v", err)
	}
	mustRegister(t, n)

	mkURL := func(mutate func(*url.URL)) *http.Request {
		u := &url.URL{Scheme: "https", Host: "peer.example:9", Path: "/objects/5"}
		if mutate != nil {
			mutate(u)
		}
		return &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}}
	}
	ticketsIssued := func() int {
		fmTLS.mu.Lock()
		defer fmTLS.mu.Unlock()
		return len(fmTLS.ticketLog)
	}

	// https master + https peer：正常换票（守卫不得误伤）。
	before := ticketsIssued()
	if err := n.sec.authorizePeer(mkURL(nil)); err != nil {
		t.Fatalf("https peer must be ticketable: %v", err)
	}
	if ticketsIssued() != before+1 {
		t.Fatalf("https peer must exchange a ticket")
	}

	// scheme 降级：https master 拒绝为 http peer 换票（RED on old: 直接放行换票）。
	before = ticketsIssued()
	if err := n.sec.authorizePeer(mkURL(func(u *url.URL) { u.Scheme = "http" })); err == nil {
		t.Fatalf("http peer must be refused when master is https")
	}
	if ticketsIssued() != before {
		t.Fatalf("master must not be asked for a ticket for a downgraded peer")
	}

	// 歧义 URL 形态：判定所依据的 origin/路径与实际发送目标可能不一致，一律拒绝。
	ambiguous := []struct {
		name   string
		mutate func(*url.URL)
	}{
		{"userinfo", func(u *url.URL) { u.User = url.User("evil") }},
		{"opaque", func(u *url.URL) { u.Opaque = "//peer.example:9/objects/5"; u.Host = "" }},
		{"escaped-path", func(u *url.URL) { u.RawPath = "/objects/%35" }},
		{"empty-host", func(u *url.URL) { u.Host = "" }},
	}
	for _, tc := range ambiguous {
		before = ticketsIssued()
		if err := n.sec.authorizePeer(mkURL(tc.mutate)); err == nil {
			t.Fatalf("%s: ambiguous peer URL must be refused", tc.name)
		}
		if ticketsIssued() != before {
			t.Fatalf("%s: master must not be contacted for ambiguous peer URLs", tc.name)
		}
	}
}

// 6) 安全标记绑定与持久性：
//   - 首建 durable（无 temp 残片）、0600、内容为版本+identity+master；
//   - 同 identity/master 重启放行且不重写（inode 不变）；
//   - 不同 identity / 不同 master / 损坏 / 不可读 → EnableSecurity fail-closed，
//     且标记文件一字节不动；损坏标记下无 security 的 Handler 保持 503 全拒。
func TestAuditMarkerIdentityMasterBinding(t *testing.T) {
	fm := newFakeSecMaster(t)
	idDir := filepath.Join(t.TempDir(), "ids")
	id1 := filepath.Join(idDir, "id1.key")
	id2 := filepath.Join(idDir, "id2.key")

	enable := func(dataDir, idPath, masterURL string) error {
		n := New(dataDir, masterURL, "127.0.0.1:9215", 1<<30)
		return n.EnableSecurity(idPath, "", true) // 明文本地测试放行
	}
	markerOf := func(dataDir string) string { return filepath.Join(dataDir, securityMarkerName) }
	readMarker := func(t *testing.T, dataDir string) (string, string) {
		t.Helper()
		raw, err := os.ReadFile(markerOf(dataDir))
		if err != nil {
			t.Fatalf("read marker: %v", err)
		}
		var body struct {
			Version  int    `json:"version"`
			Identity string `json:"identity"`
			Master   string `json:"master"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("marker json: %v", err)
		}
		return body.Identity, body.Master
	}

	// —— 首建 + 同配置重启 ——
	dirA := filepath.Join(t.TempDir(), "dataA")
	if err := enable(dirA, id1, fm.srv.URL); err != nil {
		t.Fatalf("first enable: %v", err)
	}
	markerA := markerOf(dirA)
	fi1, err := os.Stat(markerA)
	if err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	if fi1.Mode().Perm() != 0o600 {
		t.Fatalf("marker perm = %04o, want 0600", fi1.Mode().Perm())
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dirA, ".security-marker-tmp-*")); len(leftovers) != 0 {
		t.Fatalf("durable write left temp fragments: %v", leftovers)
	}
	gotID, gotMaster := readMarker(t, dirA)
	if gotID == "" || gotMaster != fm.srv.URL {
		t.Fatalf("marker content = identity %q master %q", gotID, gotMaster)
	}

	// 同 identity + 同 master 重启：放行，且不重写（inode 不变 = 无 rename 覆盖）。
	if err := enable(dirA, id1, fm.srv.URL); err != nil {
		t.Fatalf("restart with same identity/master must be accepted: %v", err)
	}
	fi2, err := os.Stat(markerA)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fi1, fi2) {
		t.Fatalf("matching marker must not be rewritten (inode changed)")
	}

	// —— 不同 identity：拒绝，标记一字节不动 ——
	want, _ := os.ReadFile(markerA)
	if err := enable(dirA, id2, fm.srv.URL); err == nil {
		t.Fatalf("different identity must be refused on marked data dir")
	}
	got, _ := os.ReadFile(markerA)
	if !bytesEqual(got, want) {
		t.Fatalf("marker must be untouched after identity mismatch refusal")
	}

	// —— 不同 master：拒绝，标记不动 ——
	other := fmt.Sprintf("http://127.0.0.1:1") // EnableSecurity 不拨号；标记校验先行
	if err := enable(dirA, id1, other); err == nil {
		t.Fatalf("different master must be refused on marked data dir")
	}
	got, _ = os.ReadFile(markerA)
	if !bytesEqual(got, want) {
		t.Fatalf("marker must be untouched after master mismatch refusal")
	}

	// —— 损坏标记：EnableSecurity fail-closed；无 security 的 Handler 全拒 503 ——
	dirB := filepath.Join(t.TempDir(), "dataB")
	if err := enable(dirB, id1, fm.srv.URL); err != nil {
		t.Fatalf("seed enable: %v", err)
	}
	if err := os.WriteFile(markerOf(dirB), []byte(`{"version":1,"identi`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := enable(dirB, id1, fm.srv.URL); err == nil {
		t.Fatalf("corrupt marker must fail-closed EnableSecurity")
	}
	n2 := New(dirB, fm.srv.URL, "127.0.0.1:9216", 1<<30) // 重启未带 --secure
	ts := httptest.NewServer(n2.Handler())
	resp, err := http.Get(ts.URL + "/objects/1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("corrupt marker without security = %d, want 503", resp.StatusCode)
	}
	ts.Close()

	// —— 不可读标记（权限）：fail-closed，且不越权改写 ——
	dirC := filepath.Join(t.TempDir(), "dataC")
	if err := enable(dirC, id1, fm.srv.URL); err != nil {
		t.Fatalf("seed enable: %v", err)
	}
	seeded, _ := os.ReadFile(markerOf(dirC))
	if err := os.Chmod(markerOf(dirC), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := enable(dirC, id1, fm.srv.URL); err == nil {
		t.Fatalf("unreadable marker must fail-closed")
	}
	if err := os.Chmod(markerOf(dirC), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(markerOf(dirC))
	if !bytesEqual(got, seeded) {
		t.Fatalf("unreadable marker must not be overwritten")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

//  7. 入站 wrapper 的精确中继绑定：check 上报的 Method/Path/Query 与票据逐字节一致。
//     未清洗路径（mux 清洗前 wrapper 已先裁决）、尾斜杠、跨方法、跨对象、多余 query
//     一律 401；合法裁决逐请求在线重查（两次相同合法 GET = 两次 /security/check）。
//     等价性说明：真 master（meta/security_tickets.go）对 node 上报的 Path 走
//     normalizeTicketRequest（拒绝 "//"、要求 query 仅 plan_id）后与票据记录严格相等，
//     本 fake 的逐字节相等在这些 case 上判定一致（../ 形态不被 normalize 清洗）。
func TestAuditWrapperRelayExactness(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9217", "")
	mustRegister(t, n)
	ts := httptest.NewServer(n.Handler())
	t.Cleanup(ts.Close)

	data := []byte("audit payload for object 55")
	putTok := fm.mintTicket(access.TicketRequest{Method: http.MethodPut, Path: "/objects/55"}, time.Time{})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/objects/55", strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+putTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("control PUT = %d, want 201", resp.StatusCode)
	}

	checksBaseline := func() int {
		fm.mu.Lock()
		defer fm.mu.Unlock()
		return len(fm.checks)
	}

	getTok := fm.mintTicket(access.TicketRequest{Method: http.MethodGet, Path: "/objects/55"}, time.Time{})
	get := func(rawPath string, tok string, want int) int {
		greq, _ := http.NewRequest(http.MethodGet, ts.URL+rawPath, nil)
		if tok != "" {
			greq.Header.Set("Authorization", "Bearer "+tok)
		}
		gresp, err := http.DefaultClient.Do(greq)
		if err != nil {
			t.Fatalf("GET %s: %v", rawPath, err)
		}
		b, _ := io.ReadAll(gresp.Body)
		gresp.Body.Close()
		if gresp.StatusCode != want {
			t.Fatalf("GET %s = %d, want %d", rawPath, gresp.StatusCode, want)
		}
		// 被拒的形态绝不允许带出对象内容。
		if want == http.StatusUnauthorized && strings.Contains(string(b), string(data)) {
			t.Fatalf("GET %s must never leak object content", rawPath)
		}
		return gresp.StatusCode
	}

	// 全部越权/歧义形态：401（在线裁决拒绝），绝无内容、绝不 3xx 绕过。
	for _, tc := range []struct{ name, raw string }{
		{"dotdot-escape", "/objects/55/../56"},
		{"dotdot-self", "/objects/55/../55"},
		{"double-slash", "/objects//55"},
		{"trailing-slash", "/objects/55/"},
		{"noncanonical-id", "/objects/055"},
		{"cross-object", "/objects/56"},
		{"extra-query", "/objects/55?plan_id=x"},
	} {
		get(tc.raw, getTok, http.StatusUnauthorized)
	}
	// 方法绑定：GET 票据不得用于 DELETE /objects/55。
	dreq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/objects/55", nil)
	dreq.Header.Set("Authorization", "Bearer "+getTok)
	dresp, err := http.DefaultClient.Do(dreq)
	if err != nil {
		t.Fatal(err)
	}
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("DELETE with GET ticket = %d, want 401", dresp.StatusCode)
	}

	// 对照：合法票据 + 精确路径 + 精确方法 → 200，且两次请求两次在线 check（不缓存）。
	before := checksBaseline()
	get("/objects/55", getTok, http.StatusOK)
	get("/objects/55", getTok, http.StatusOK)
	if delta := checksBaseline() - before; delta != 2 {
		t.Fatalf("valid GETs must re-check online each time: checks delta = %d, want 2", delta)
	}
}
