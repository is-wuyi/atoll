package client

// client/peer_register_retry_test.go —— 客户端 peer 登记幂等/重试/关停的定点测试。
//
// 覆盖：
//  1. 同一次操作（同 op id/同签名）的网络失败重试必须复用完全相同的已签名请求
//     字节（master 幂等重放），绝不在网络重试时换 op 或换签名。
//  2. 409 CAS 冲突只触发「重读 self revision + 新 op」；op id 与 expected revision
//     都变化，且不改变「同 op 重试复用原 raw」的不变量。
//  3. 登记在途时 session 切换（真并发 barrier：独立 goroutine 在 POST 在途时改写
//     会话）：成功响应属于旧快照，不得覆盖新登记。
//  4. CloseP2P 与在途登记真并发：关停取消在途登记、慢结果不落库；排队在 regMu
//     后的登记改用当前 live 会话快照，绝不用陈旧凭据。
//  5. EnableP2P 启动失败（登记 500）后原样恢复 base/peerID/ensureRegistered，
//     可安全重试；重试成功后 CloseP2P 令后续 ensureRegistered 拒绝（fail-closed）。
//  6. CloseP2P 的有界签名释放：POST /peers/client/release 复核 proof/revision，
//     master 挂起时关停仍有界返回（TTL 兜底）。
//  7. 控制请求与 proof 绑定构造时固定的 master origin：改写 c.MasterURL 不改变
//     请求目标（会话 token 绝不发往其它源）。
//
// 全部用 stub RuntimeAPI + 可编程 RoundTripper，不依赖真实 peer 网络。

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ---- 测试身份 / stub runtime / stub transport ----

func testPeerIdentity(t *testing.T) (string, []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return id.String(), []byte(pub)
}

// stubPeerRuntime 实现 peertransport.RuntimeAPI：身份 + 可编程目录/授权，供单元测试。
type stubPeerRuntime struct {
	peerID     string
	pubKey     []byte
	addresses  []string
	dir        peerauth.Directory
	allowed    map[string]bool
	authorizer func(context.Context, string) bool
}

func (r *stubPeerRuntime) PeerID() string                  { return r.peerID }
func (r *stubPeerRuntime) PublicKey() []byte               { return r.pubKey }
func (r *stubPeerRuntime) Sign(msg []byte) ([]byte, error) { return append([]byte(nil), msg...), nil }
func (r *stubPeerRuntime) Addresses() []string             { return r.addresses }
func (r *stubPeerRuntime) SetDirectory(d peerauth.Directory) error {
	r.dir = d
	return nil
}
func (r *stubPeerRuntime) SetAuthorizer(f func(context.Context, string) bool) { r.authorizer = f }
func (r *stubPeerRuntime) AllowedPeer(id string) bool                         { return r.allowed[id] }
func (r *stubPeerRuntime) Listener() (net.Listener, error)                    { return nil, errors.New("unused") }
func (r *stubPeerRuntime) ConnContext(ctx context.Context, _ net.Conn) context.Context {
	return ctx
}
func (r *stubPeerRuntime) ReserveRelay(context.Context, peerauth.Infrastructure) (time.Time, error) {
	return time.Time{}, nil
}
func (r *stubPeerRuntime) EnableRelay() error { return nil }
func (r *stubPeerRuntime) Dial(context.Context, peerauth.Endpoint, peerauth.Infrastructure, peerhttp.Path) peertransport.DialResult {
	return peertransport.DialResult{}
}
func (r *stubPeerRuntime) Close() error { return nil }

// stubRoundTripper 可编程 master 响应；捕获每个请求以断言重试字节。
type stubRoundTripper struct {
	mu      sync.Mutex
	handler func(*http.Request) (*http.Response, error)
}

func (rt *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	rt.mu.Lock()
	h := rt.handler
	rt.mu.Unlock()
	if h == nil {
		return jsonResp(http.StatusNotFound, []byte(`{}`)), nil
	}
	return h(req)
}

func jsonResp(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}
}

func bodyOf(req *http.Request) []byte {
	if req.Body == nil {
		return nil
	}
	b, _ := io.ReadAll(req.Body)
	req.Body.Close()
	return b
}

func regFromBody(t *testing.T, body []byte) peerauth.ClientRegistration {
	t.Helper()
	var reg peerauth.ClientRegistration
	if err := json.Unmarshal(body, &reg); err != nil {
		t.Fatalf("解析登记请求体: %v (body=%s)", err, body)
	}
	return reg
}

func clientEndpointJSON(t *testing.T, peerID string, pub []byte, revision uint64) []byte {
	t.Helper()
	endpoint := peerauth.Endpoint{
		Role:       peerauth.RoleClient,
		PeerID:     peerID,
		PublicKey:  append([]byte(nil), pub...),
		Revision:   revision,
		ValidUntil: time.Now().UTC().Add(time.Minute),
	}
	raw, err := json.Marshal(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func clientStateJSON(t *testing.T, revision uint64) []byte {
	t.Helper()
	raw, err := json.Marshal(peerauth.ClientState{Revision: revision})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// newRegClient 构建最小 Client + clientP2P，仅登记路径所需字段。
// secTransport.master 必须与 MasterURL 一致：P2P 控制请求与 proof 绑定的是
// 构造时固定的这个 origin。
func newRegClient(t *testing.T, rt http.RoundTripper, runtime peertransport.RuntimeAPI, token string, spaceID uint64) (*Client, *clientP2P) {
	t.Helper()
	master, err := url.Parse("https://master.test")
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{
		MasterURL: "https://master.test",
		sec:       &secureSession{token: token, spaceID: spaceID, hasSpace: true},
		secTransport: &secureTransport{
			master: master,
			base:   rt,
			s:      &secureSession{token: token, spaceID: spaceID, hasSpace: true},
		},
	}
	p := &clientP2P{c: c, runtime: runtime, wake: make(chan struct{}, 1)}
	return c, p
}

// validPeerDirectory 构造通过 ValidateDirectory 的最小目录（1 个节点 endpoint + infra）。
func validPeerDirectory(t *testing.T) peerauth.Directory {
	t.Helper()
	infraID, infraPub := testPeerIdentity(t)
	nodeID, nodePub := testPeerIdentity(t)
	now := time.Now()
	return peerauth.Directory{
		Protocol: peerauth.Feature,
		Infrastructure: peerauth.Infrastructure{
			PeerID: infraID, PublicKey: infraPub, Addresses: []string{"/ip4/127.0.0.1/tcp/9000"},
		},
		Endpoints: []peerauth.Endpoint{{
			NodeID: 1, Addr: "127.0.0.1:9000", Role: peerauth.RoleNode,
			PeerID: nodeID, PublicKey: nodePub, BindingRevision: 1, Revision: 1,
			Addresses: []string{"/ip4/127.0.0.1/tcp/9000"}, ValidUntil: now.Add(time.Minute),
		}},
	}
}

func directoryJSON(t *testing.T, d peerauth.Directory) []byte {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ---- 1. 同 op 网络失败重试复用同一已签名请求 ----

func TestClientPeerRegistrationSameOpRetryReusesSignedRequest(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	rt := &stubRoundTripper{}
	var postBodies [][]byte
	rt.handler = func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/peers/client-self":
			return jsonResp(http.StatusOK, clientStateJSON(t, 3)), nil
		case req.Method == http.MethodPost && req.URL.Path == "/peers/client":
			postBodies = append(postBodies, bodyOf(req))
			if len(postBodies) == 1 {
				return nil, errors.New("connection reset by peer")
			}
			rev := regFromBody(t, postBodies[1]).ExpectedRevision + 1
			return jsonResp(http.StatusOK, clientEndpointJSON(t, peerID, pub, rev)), nil
		}
		return jsonResp(http.StatusNotFound, []byte(`{}`)), nil
	}

	_, p := newRegClient(t, rt, &stubPeerRuntime{peerID: peerID, pubKey: pub}, "token-a", 1)
	if err := p.doRegistration(context.Background(), "token-a", 1, true); err != nil {
		t.Fatalf("doRegistration 应重试后成功: %v", err)
	}
	if len(postBodies) != 2 {
		t.Fatalf("POST /peers/client 应恰好 2 次（1 次网络失败 + 1 次重试），got %d", len(postBodies))
	}
	if !bytes.Equal(postBodies[0], postBodies[1]) {
		t.Fatalf("网络重试必须复用同一已签名请求字节（同 op/同签名）\n第一次: %s\n第二次: %s", postBodies[0], postBodies[1])
	}
	first := regFromBody(t, postBodies[0])
	second := regFromBody(t, postBodies[1])
	if first.OperationID != second.OperationID || !bytes.Equal(first.Signature, second.Signature) {
		t.Fatalf("op id 与签名必须在网络重试间不变: %s vs %s", first.OperationID, second.OperationID)
	}
	if first.ExpectedRevision != 3 {
		t.Fatalf("expected revision = %d, want 3", first.ExpectedRevision)
	}
	if p.registeredRev != 4 || p.regSession != "token-a" || p.regSpace != 1 {
		t.Fatalf("登记结果未落库: rev=%d session=%q space=%d", p.registeredRev, p.regSession, p.regSpace)
	}
}

// ---- 2. 409 CAS：重读 self + 新 op（新 op id / 新 expected） ----

func TestClientPeerRegistration409CASStartsNewOperation(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	rt := &stubRoundTripper{}
	var postBodies [][]byte
	selfRevisions := []uint64{3, 5}
	selfIdx := 0
	rt.handler = func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/peers/client-self":
			rev := selfRevisions[selfIdx]
			selfIdx++
			return jsonResp(http.StatusOK, clientStateJSON(t, rev)), nil
		case req.Method == http.MethodPost && req.URL.Path == "/peers/client":
			postBodies = append(postBodies, bodyOf(req))
			if len(postBodies) == 1 {
				// 第一次：CAS 冲突，需重读 revision。
				return jsonResp(http.StatusConflict, nil), nil
			}
			rev := regFromBody(t, postBodies[1]).ExpectedRevision + 1
			return jsonResp(http.StatusOK, clientEndpointJSON(t, peerID, pub, rev)), nil
		}
		return jsonResp(http.StatusNotFound, []byte(`{}`)), nil
	}

	_, p := newRegClient(t, rt, &stubPeerRuntime{peerID: peerID, pubKey: pub}, "token-a", 1)
	if err := p.doRegistration(context.Background(), "token-a", 1, true); err != nil {
		t.Fatalf("doRegistration 应处理 409 后成功: %v", err)
	}
	if len(postBodies) != 2 {
		t.Fatalf("POST /peers/client 应 2 次（冲突 + 新 op），got %d", len(postBodies))
	}
	first := regFromBody(t, postBodies[0])
	second := regFromBody(t, postBodies[1])
	if first.OperationID == second.OperationID {
		t.Fatalf("409 后必须换新 op id: %s", first.OperationID)
	}
	if first.ExpectedRevision != 3 || second.ExpectedRevision != 5 {
		t.Fatalf("expected revision 应为 3 然后 5，got %d then %d", first.ExpectedRevision, second.ExpectedRevision)
	}
	if p.registeredRev != 6 {
		t.Fatalf("registeredRev = %d, want 6", p.registeredRev)
	}
}

// ---- 3. 登记在途 session 切换（真正并发 barrier）：不得覆盖新快照 ----

func TestClientPeerRegistrationSnapshotSwitchAbortsStore(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	rt := &stubRoundTripper{}
	c, p := newRegClient(t, rt, &stubPeerRuntime{peerID: peerID, pubKey: pub}, "token-a", 1)
	postStarted := make(chan struct{})
	flipDone := make(chan struct{})
	rt.handler = func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/peers/client-self":
			return jsonResp(http.StatusOK, clientStateJSON(t, 3)), nil
		case req.Method == http.MethodPost && req.URL.Path == "/peers/client":
			// 在途 barrier：登记 POST 挂起，直到独立 goroutine 切换会话。
			close(postStarted)
			<-flipDone
			rev := regFromBody(t, bodyOf(req)).ExpectedRevision + 1
			return jsonResp(http.StatusOK, clientEndpointJSON(t, peerID, pub, rev)), nil
		}
		return jsonResp(http.StatusNotFound, []byte(`{}`)), nil
	}

	regDone := make(chan error, 1)
	go func() { regDone <- p.doRegistration(context.Background(), "token-a", 1, true) }()
	<-postStarted
	// 真正并发的会话切换：独立 goroutine 在登记 POST 在途时改写 secureSession。
	go func() {
		c.sec.mu.Lock()
		c.sec.token = "token-b"
		c.sec.spaceID = 7
		c.sec.mu.Unlock()
		close(flipDone)
	}()
	err := <-regDone
	if err == nil || !strings.Contains(err.Error(), "snapshot changed") {
		t.Fatalf("session 切换应使登记中止（snapshot changed），got %v", err)
	}
	if p.registeredRev != 0 || p.regSession != "" || p.regSpace != 0 {
		t.Fatalf("旧快照登记结果不得落库: rev=%d session=%q space=%d", p.registeredRev, p.regSession, p.regSpace)
	}
}

// ---- 3b. 关停 + 在途登记（真正并发 barrier）：关停后慢结果不落库、登记被取消 ----

func TestClientPeerCloseCancelsInflightRegistration(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	rt := &stubRoundTripper{}
	c, p := newRegClient(t, rt, &stubPeerRuntime{peerID: peerID, pubKey: pub}, "token-a", 1)
	c.p2pMu.Lock()
	c.p2p = p
	c.p2pMu.Unlock()
	p.ctx, p.cancel = context.WithCancel(context.Background())

	postStarted := make(chan struct{})
	rt.handler = func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/peers/client-self":
			return jsonResp(http.StatusOK, clientStateJSON(t, 0)), nil
		case req.Method == http.MethodPost && req.URL.Path == "/peers/client":
			close(postStarted)
			// 尊重请求 ctx：CloseP2P 取消生命周期 ctx 时，在途登记立即中止。
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(5 * time.Second):
				t.Error("registration POST not cancelled by CloseP2P")
				return nil, errors.New("test timeout")
			}
		}
		return jsonResp(http.StatusNotFound, []byte(`{}`)), nil
	}

	regDone := make(chan error, 1)
	go func() { regDone <- p.ensureRegistered(context.Background(), "token-a", 1, true) }()
	<-postStarted // 登记在途（POST 挂起）
	// 并发关停：置 closed + 取消 p.ctx，在途登记应随生命周期 ctx 取消而中止。
	closeDone := make(chan struct{})
	go func() { _ = c.CloseP2P(); close(closeDone) }()

	err := <-regDone
	if err == nil {
		t.Fatal("关停后的在途登记必须失败（fail-closed/取消）")
	}
	<-closeDone
	if p.registeredRev != 0 || p.regSession != "" || p.regSpace != 0 {
		t.Fatalf("关停后慢结果不得落库: rev=%d session=%q space=%d", p.registeredRev, p.regSession, p.regSpace)
	}
}

// ---- 3c. 两个并发 CloseP2P 都 join 后台循环（第二个不得提前返回） ----

func TestClientCloseP2PDoubleCloseJoinsLoop(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	c, p := newRegClient(t, &stubRoundTripper{}, &stubPeerRuntime{peerID: peerID, pubKey: pub}, "token-a", 1)
	c.p2pMu.Lock()
	c.p2p = p
	c.p2pMu.Unlock()
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.started = true
	p.wg.Add(1)
	exited := make(chan struct{})
	go func() {
		defer p.wg.Done()
		defer close(exited)
		<-p.ctx.Done()
	}()

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.CloseP2P(); err != nil {
				t.Errorf("CloseP2P: %v", err)
			}
		}()
	}
	wg.Wait()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("后台循环未被两个并发 CloseP2P 之一 join")
	}
	// 关停后 ensureRegistered 必须 fail-closed（不静默降级普通 TCP）。
	if err := p.ensureRegistered(context.Background(), "token-a", 1, true); !errors.Is(err, errClientP2PClosed) {
		t.Fatalf("关停后 ensureRegistered 应拒绝，got %v", err)
	}
}

// ---- 4. EnableP2P 失败可重试恢复；成功后 CloseP2P 拒后续登记 ----

func TestClientEnableP2PFailureRecoversThenCloseRejects(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 默认（第一阶段）一律 500，使 ensureRegistration 失败。
		http.Error(w, "simulated failure", http.StatusInternalServerError)
	}))
	defer ts.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	c, err := NewSecure(ts.URL, &tls.Config{RootCAs: pool}, false)
	if err != nil {
		t.Fatal(err)
	}
	rt := &stubPeerRuntime{peerID: peerID, pubKey: pub}
	if err := c.SetSession("token-a"); err != nil {
		t.Fatal(err)
	}
	if err := c.UseSpace(1); err != nil {
		t.Fatal(err)
	}

	// 第一次 EnableP2P：登记 500 → 失败，且原样恢复。
	err = c.EnableP2P(context.Background(), rt)
	if err == nil {
		t.Fatal("登记 500 时 EnableP2P 应失败")
	}
	if c.p2p != nil {
		t.Fatal("失败后 c.p2p 应被清空")
	}
	if _, ok := c.secTransport.base.(*http.Transport); !ok {
		t.Fatalf("失败后 base 应恢复为原始 *http.Transport，got %T", c.secTransport.base)
	}
	if c.secTransport.peerID != nil || c.secTransport.ensureRegistered != nil {
		t.Fatal("失败后 peerID/ensureRegistered 钩子应被清除（可重试）")
	}

	// 第二阶段：登记与目录成功 → EnableP2P 应成功。
	dir := validPeerDirectory(t)
	dirRaw := directoryJSON(t, dir)
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/peers/client-self":
			_, _ = w.Write(clientStateJSON(t, 0))
		case r.Method == http.MethodPost && r.URL.Path == "/peers/client":
			var reg peerauth.ClientRegistration
			_ = json.NewDecoder(r.Body).Decode(&reg)
			_, _ = w.Write(clientEndpointJSON(t, peerID, pub, reg.ExpectedRevision+1))
		case r.Method == http.MethodGet && r.URL.Path == "/peers/directory":
			_, _ = w.Write(dirRaw)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
	if err := c.EnableP2P(context.Background(), rt); err != nil {
		t.Fatalf("恢复后 EnableP2P 应成功: %v", err)
	}
	if c.p2p == nil || c.secTransport.peerID == nil || c.secTransport.ensureRegistered == nil {
		t.Fatal("EnableP2P 成功后应安装 peerID/ensureRegistered 钩子")
	}

	// CloseP2P：不关整个传输，但后续 ensureRegistered 必须 fail-closed。
	if err := c.CloseP2P(); err != nil {
		t.Fatalf("CloseP2P: %v", err)
	}
	if err := c.secTransport.ensureRegistered(context.Background(), "token-a", 1, true); !errors.Is(err, errClientP2PClosed) {
		t.Fatalf("CloseP2P 后 ensureRegistered 应拒绝（fail-closed），got %v", err)
	}
}

// ---- 5. 并行 ensureRegistered 不竞态；关停在登记静默后串行发生 ----

func TestClientPeerParallelEnsureAndCloseWakeCancel(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	rt := &stubRoundTripper{}
	dir := validPeerDirectory(t)
	dirRaw := directoryJSON(t, dir)
	rt.handler = func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/peers/client-self":
			return jsonResp(http.StatusOK, clientStateJSON(t, 0)), nil
		case req.Method == http.MethodPost && req.URL.Path == "/peers/client":
			reg := regFromBody(t, bodyOf(req))
			return jsonResp(http.StatusOK, clientEndpointJSON(t, peerID, pub, reg.ExpectedRevision+1)), nil
		case req.Method == http.MethodGet && req.URL.Path == "/peers/directory":
			return jsonResp(http.StatusOK, dirRaw), nil
		}
		return jsonResp(http.StatusNotFound, []byte(`{}`)), nil
	}

	c, p := newRegClient(t, rt, &stubPeerRuntime{peerID: peerID, pubKey: pub}, "token-a", 1)
	c.p2pMu.Lock()
	c.p2p = p
	c.p2pMu.Unlock()
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.started = true
	p.wg.Add(1)
	go c.clientPeerLoop(p)

	// 并行登记：regMu 串行，仅首者真正 doRegistration，其余看到已登记返回 nil。
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.ensureRegistered(context.Background(), "token-a", 1, true); err != nil {
				t.Errorf("并行 ensureRegistered: %v", err)
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("并行 ensureRegistered 未完成（可能死锁）")
	}

	// 会话变化唤醒后，待全部登记静默再关停：CloseP2P 必须 join 后台循环，不得泄漏。
	// （真并发的关停 barrier 见下一个测试。）
	c.p2pSessionChanged()
	closed := make(chan struct{})
	go func() {
		_ = c.CloseP2P()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("CloseP2P 未 join 后台循环（可能泄漏 goroutine）")
	}
	if err := p.ensureRegistered(context.Background(), "token-a", 1, true); !errors.Is(err, errClientP2PClosed) {
		t.Fatalf("关停后 ensureRegistered 应拒绝，got %v", err)
	}
}

// ---- 6. 等 regMu 期间会话切换：旧快照凭据作废，显式失败不发任何请求 ----

func TestClientPeerEnsureRegisteredRejectsStaleSessionAfterRegMu(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	rt := &stubRoundTripper{}
	var hits atomic.Int64
	rt.handler = func(req *http.Request) (*http.Response, error) {
		hits.Add(1)
		return jsonResp(http.StatusOK, clientStateJSON(t, 3)), nil
	}
	c, p := newRegClient(t, rt, &stubPeerRuntime{peerID: peerID, pubKey: pub}, "token-a", 1)

	// 先占住 regMu，ensureRegistered 必然排队在其后；排队期间切换会话。
	p.regMu.Lock()
	done := make(chan error, 1)
	go func() { done <- p.ensureRegistered(context.Background(), "token-a", 1, true) }()
	c.sec.mu.Lock()
	c.sec.token = "token-b"
	c.sec.spaceID = 7
	c.sec.mu.Unlock()
	p.regMu.Unlock()

	err := <-done
	if !errors.Is(err, errClientPeerSession) {
		t.Fatalf("等锁期间切换会话必须显式失败（旧凭据作废），got %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("旧快照不得发出任何请求，master 收到 %d 个", n)
	}
	if p.registeredRev != 0 || p.regSession != "" {
		t.Fatalf("不得落库: rev=%d session=%q", p.registeredRev, p.regSession)
	}
}

// ---- 7. CloseP2P 的有界签名释放：proof/revision 绑定、本地登记态清零 ----

func TestClientCloseP2PReleasesRegistrationBounded(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	rt := &stubRoundTripper{}
	var releaseBodies [][]byte
	var selfAuths []string
	var registerHits atomic.Int64
	rt.handler = func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/peers/client-self":
			selfAuths = append(selfAuths, req.Header.Get("Authorization"))
			return jsonResp(http.StatusOK, clientStateJSON(t, 5)), nil
		case req.Method == http.MethodPost && req.URL.Path == "/peers/client":
			registerHits.Add(1)
			return jsonResp(http.StatusOK, clientEndpointJSON(t, peerID, pub, 6)), nil
		case req.Method == http.MethodPost && req.URL.Path == "/peers/client/release":
			releaseBodies = append(releaseBodies, bodyOf(req))
			return jsonResp(http.StatusOK, clientStateJSON(t, 6)), nil
		}
		return jsonResp(http.StatusNotFound, []byte(`{}`)), nil
	}
	c, p := newRegClient(t, rt, &stubPeerRuntime{peerID: peerID, pubKey: pub}, "token-a", 1)
	c.p2pMu.Lock()
	c.p2p = p
	c.p2pMu.Unlock()
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.mu.Lock()
	p.started = true
	p.registeredRev = 5
	p.regSession = "token-a"
	p.regSpace = 1
	p.mu.Unlock()

	if err := c.CloseP2P(); err != nil {
		t.Fatalf("CloseP2P: %v", err)
	}
	if len(releaseBodies) != 1 {
		t.Fatalf("CloseP2P 应恰好发 1 次释放请求，got %d", len(releaseBodies))
	}
	if registerHits.Load() != 0 {
		t.Fatalf("关停不得触发登记，POST /peers/client 收到 %d 次", registerHits.Load())
	}
	if len(selfAuths) != 1 || selfAuths[0] != "Bearer token-a" {
		t.Fatalf("释放前的 self 查询必须携带当前会话: %v", selfAuths)
	}
	var rel peerauth.ClientRegistration
	if err := json.Unmarshal(releaseBodies[0], &rel); err != nil {
		t.Fatal(err)
	}
	if rel.PeerID != peerID || rel.ExpectedRevision != 5 || !peerauth.ValidOperation(rel.OperationID) {
		t.Fatalf("释放请求绑定不符: peer=%s rev=%d op=%s", rel.PeerID, rel.ExpectedRevision, rel.OperationID)
	}
	if rel.NotAfter.IsZero() || !rel.NotAfter.After(time.Now().UTC()) || rel.NotAfter.After(time.Now().UTC().Add(peerauth.EndpointLease)) {
		t.Fatalf("释放 NotAfter 必须落在 (now, now+EndpointLease] 内: %v", rel.NotAfter)
	}
	// stub runtime 的 Sign 原样返回消息：签名必须等于以固定 origin 计算的 release proof。
	proof, err := peerauth.ClientReleaseProof("https://master.test", "token-a", 1, rel)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rel.Signature, proof) {
		t.Fatalf("释放签名必须是 ClientReleaseProof（绑定构造时 origin/会话/space）")
	}
	if p.registeredRev != 0 || p.regSession != "" || p.regSpace != 0 {
		t.Fatalf("释放成功后本地登记态应清零: rev=%d session=%q space=%d", p.registeredRev, p.regSession, p.regSpace)
	}
	if err := p.ensureRegistered(context.Background(), "token-a", 1, true); !errors.Is(err, errClientP2PClosed) {
		t.Fatalf("关停后 ensureRegistered 应拒绝，got %v", err)
	}
}

// ---- 7b. master 挂起时释放有界：CloseP2P 仍在超时内返回（TTL 兜底） ----

type hangingRoundTripper struct{ release chan struct{} }

func (h *hangingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-h.release:
		return jsonResp(http.StatusOK, []byte(`{}`)), nil
	}
}

func TestClientCloseP2PReleaseBoundedUnderHangingMaster(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	hang := &hangingRoundTripper{release: make(chan struct{})}
	defer close(hang.release) // 测试结束放行挂起的 handler
	old := clientPeerReleaseTimeout
	clientPeerReleaseTimeout = 250 * time.Millisecond
	defer func() { clientPeerReleaseTimeout = old }()

	c, p := newRegClient(t, hang, &stubPeerRuntime{peerID: peerID, pubKey: pub}, "token-a", 1)
	c.p2pMu.Lock()
	c.p2p = p
	c.p2pMu.Unlock()
	p.ctx, p.cancel = context.WithCancel(context.Background())

	start := time.Now()
	if err := c.CloseP2P(); err != nil {
		t.Fatalf("CloseP2P: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("master 挂起时 CloseP2P 必须有界返回（release timeout 250ms），耗时 %v", elapsed)
	}
}

// ---- 8. 控制请求与 proof 绑定构造时固定的 origin：改写 MasterURL 不漂移 ----

func TestClientPeerControlPinnedToConstructionOrigin(t *testing.T) {
	peerID, pub := testPeerIdentity(t)
	var registerHits atomic.Int64
	var selfMu sync.Mutex
	var selfAuths []string
	recordSelf := func(header string) {
		selfMu.Lock()
		defer selfMu.Unlock()
		selfAuths = append(selfAuths, header)
	}
	dir := validPeerDirectory(t)
	dirRaw := directoryJSON(t, dir)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/peers/client-self":
			recordSelf(r.Header.Get("Authorization"))
			_, _ = w.Write(clientStateJSON(t, 0))
		case r.Method == http.MethodPost && r.URL.Path == "/peers/client":
			registerHits.Add(1)
			var reg peerauth.ClientRegistration
			_ = json.NewDecoder(r.Body).Decode(&reg)
			_, _ = w.Write(clientEndpointJSON(t, peerID, pub, reg.ExpectedRevision+1))
		case r.Method == http.MethodGet && r.URL.Path == "/peers/directory":
			_, _ = w.Write(dirRaw)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer ts.Close()

	evilHits := make(chan struct{}, 16)
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits <- struct{}{}
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer evil.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	c, err := NewSecure(ts.URL, &tls.Config{RootCAs: pool}, false)
	if err != nil {
		t.Fatal(err)
	}
	rt := &stubPeerRuntime{peerID: peerID, pubKey: pub}
	if err := c.SetSession("token-a"); err != nil {
		t.Fatal(err)
	}
	if err := c.UseSpace(1); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableP2P(context.Background(), rt); err != nil {
		t.Fatalf("EnableP2P: %v", err)
	}
	defer func() { _ = c.CloseP2P() }()

	// 模拟 MasterURL 被改写：P2P 控制请求与 proof 必须仍落在构造时的 origin。
	c.MasterURL = evil.URL
	if err := c.UseSpace(2); err != nil {
		t.Fatal(err)
	}
	if err := c.secTransport.ensureRegistered(context.Background(), "token-a", 2, true); err != nil {
		t.Fatalf("改写 MasterURL 后重登记应仍成功（pinned origin）: %v", err)
	}
	select {
	case <-evilHits:
		t.Fatal("P2P 控制请求/会话 token 绝不发往改写后的 origin")
	default:
	}
	if registerHits.Load() != 2 {
		t.Fatalf("两次登记都应落在构造时 origin，POST /peers/client = %d", registerHits.Load())
	}
	for _, authHeader := range selfAuths {
		if authHeader != "Bearer token-a" {
			t.Fatalf("self 查询凭据漂移: %q", authHeader)
		}
	}
}
