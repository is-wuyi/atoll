package peer

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"atoll/client"
	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"
)

// userSpaceID 从登录结果取出与 login 内 UseSpace 一致的 space ID。
func userSpaceID(res client.LoginResult) uint64 {
	if res.Space != nil {
		return res.Space.ID
	}
	return res.User.PersonalSpaceID
}

// peerDirectory 经 master 真实 HTTPS 控制面取 peer 目录——与客户端 EnableP2P
// 的目录来源完全一致，不手工构造 addr-peer 映射。
func (m *peerMaster) peerDirectory(token string, spaceID uint64) peerauth.Directory {
	m.t.Helper()
	resp := m.rawJSON(http.MethodGet, "/peers/directory", token, spaceID, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		m.t.Fatalf("peers directory: %d", resp.StatusCode)
	}
	var d peerauth.Directory
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		m.t.Fatalf("decode directory: %v", err)
	}
	return d
}

// nodeEndpoint 在目录中查找指定逻辑 data 地址的节点端点（Role=RoleNode）。
func nodeEndpoint(t *testing.T, d peerauth.Directory, nodeAddr string) (peerauth.Endpoint, peerauth.Infrastructure) {
	t.Helper()
	for _, ep := range d.Endpoints {
		if ep.Role == peerauth.RoleNode && ep.Addr == nodeAddr {
			return ep, d.Infrastructure
		}
	}
	t.Fatalf("node endpoint for %q not found in directory (%d endpoints)", nodeAddr, len(d.Endpoints))
	return peerauth.Endpoint{}, peerauth.Infrastructure{}
}

// peerPathHTTPClient 基于已注册客户端的 runtime 构建走真实 peer 拨号的 HTTPS
// 客户端：resolver 用 rt.Dial，请求 ctx 上的 peerhttp.WithPath 钉死路径要求，
// 外层 TLS 信任测试 CA。observed 非 nil 时记录每条实际路径 Observation。
func (m *peerMaster) peerPathHTTPClient(rt peertransport.RuntimeAPI, ep peerauth.Endpoint, infra peerauth.Infrastructure, observed *[]peerhttp.Observation) *http.Client {
	m.t.Helper()
	resolver := func(ctx context.Context, _ string) (peerhttp.PeerDialer, error) {
		return func(dialCtx context.Context) peerhttp.PeerDial {
			path, required := peerhttp.RequiredPath(dialCtx)
			if !required {
				path = peerhttp.PathUnknown
			}
			res := rt.Dial(dialCtx, ep, infra, path)
			return res.PeerDial
		}, nil
	}
	base := &http.Transport{TLSClientConfig: m.pki.verifiedTLS(), DisableKeepAlives: true}
	tr, err := peerhttp.NewTransport(base, peerhttp.WithResolver(resolver))
	if err != nil {
		m.t.Fatalf("peerhttp transport: %v", err)
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// observedPath 返回最后一条 Observation 的实际路径（无则空串）。
func observedPath(observed []peerhttp.Observation) peerhttp.Path {
	if len(observed) == 0 {
		return ""
	}
	return observed[len(observed)-1].Path
}

// healthzWith 对节点 /healthz（鉴权豁免端点）发一次钉死路径的 GET；观察到的
// 实际路径追加到 observed。任何 transport 错误原样返回给调用方重试。
func healthzWith(httpc *http.Client, nodeAddr string, path peerhttp.Path, observed *[]peerhttp.Observation) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx = peerhttp.WithPath(ctx, path)
	if observed != nil {
		ctx = peerhttp.WithReporter(ctx, &peerhttp.Reporter{Observe: func(o peerhttp.Observation) {
			*observed = append(*observed, o)
		}})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+nodeAddr+"/healthz", nil)
	if err != nil {
		return nil, err
	}
	return httpc.Do(req)
}

// TestPeerStrictRelayCircuit 严格中继契约：WithPath(PathRelay) 的请求必须真实
// 走 circuit（Observation 报告 PathRelay="circuit"，peerhttp 对路径不符 fail
// closed），且经中继的数据流真的可用（/healthz 200）；同一客户端的 direct 钉
// 路径在 relay 已建立后依旧可用并报告 direct——两条路径共存，互不降级。
func TestPeerStrictRelayCircuit(t *testing.T) {
	pki := newTestPKI(t)
	m := newPeerMaster(t, pki)
	m.createUser("alice")

	node := m.startNode(filepath.Join(t.TempDir(), "node"), m.nodeInvite())
	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)

	d := m.peerDirectory(res.Token, userSpaceID(res))
	ep, infra := nodeEndpoint(t, d, node.nodeDataAddr())
	httpc := m.peerPathHTTPClient(cs.rt, ep, infra, nil)

	// relay：中继路径可能依赖节点预约与 relay host 建立的首拨开销，用有界重试
	// 等待就绪；重试只针对 transport 错误，路径不符由 peerhttp fail-closed 立即报错。
	var observed []peerhttp.Observation
	deadline := time.Now().Add(25 * time.Second)
	var resp *http.Response
	var lastErr error
	for time.Now().Before(deadline) {
		observed = nil
		r, err := healthzWith(httpc, node.nodeDataAddr(), peerhttp.PathRelay, &observed)
		if err == nil {
			resp = r
			break
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	if resp == nil {
		t.Fatalf("relay /healthz never succeeded within deadline: %v", lastErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relay /healthz status = %d, want 200", resp.StatusCode)
	}
	if got := observedPath(observed); got != peerhttp.PathRelay {
		t.Fatalf("WithPath(PathRelay) actually took path %q, want %q (circuit)", got, peerhttp.PathRelay)
	}

	// direct：relay 已建立后，direct 钉路径的数据流仍可用，且实际路径是 direct。
	var observedDirect []peerhttp.Observation
	respD, err := healthzWith(httpc, node.nodeDataAddr(), peerhttp.PathDirect, &observedDirect)
	if err != nil {
		t.Fatalf("direct /healthz after relay: %v", err)
	}
	defer respD.Body.Close()
	if respD.StatusCode != http.StatusOK {
		t.Fatalf("direct /healthz status = %d, want 200", respD.StatusCode)
	}
	if got := observedPath(observedDirect); got != peerhttp.PathDirect {
		t.Fatalf("WithPath(PathDirect) actually took path %q, want %q", got, peerhttp.PathDirect)
	}

	// 再走一次 relay：direct 连接的存在不得让严格中继退化或失败。
	var observedRelay2 []peerhttp.Observation
	respR2, err := healthzWith(httpc, node.nodeDataAddr(), peerhttp.PathRelay, &observedRelay2)
	if err != nil {
		t.Fatalf("second relay /healthz after direct: %v", err)
	}
	defer respR2.Body.Close()
	if respR2.StatusCode != http.StatusOK {
		t.Fatalf("second relay /healthz status = %d, want 200", respR2.StatusCode)
	}
	if got := observedPath(observedRelay2); got != peerhttp.PathRelay {
		t.Fatalf("second WithPath(PathRelay) took path %q, want %q", got, peerhttp.PathRelay)
	}
}

// TestPeerUnauthorizedSourceRejectedAtAuthLayer 负向失败定位在授权层：
// 已注册源（过 gate）无票 PUT 到达处理器（ledger source 为客户端真实 peer id）
// 被 401；未注册源连流都开不了且 ledger 计数不变——两者都与 planner 无关。
func TestPeerUnauthorizedSourceRejectedAtAuthLayer(t *testing.T) {
	pki := newTestPKI(t)
	m := newPeerMaster(t, pki)
	m.createUser("alice")

	var nLedger nodeLedger
	node := m.startNodeOpts(filepath.Join(t.TempDir(), "node"), m.nodeInvite(), nodeOpts{ledger: &nLedger})

	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)

	d := m.peerDirectory(res.Token, userSpaceID(res))
	ep, infra := nodeEndpoint(t, d, node.nodeDataAddr())
	httpc := m.peerPathHTTPClient(cs.rt, ep, infra, nil)

	objURL := "https://" + node.nodeDataAddr() + "/objects/12345"
	req, err := http.NewRequest(http.MethodPut, objURL, strings.NewReader("ticketless-payload"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatalf("ticketless PUT did not reach the node over the peer plane: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ticketless PUT status = %d, want 401 (authorization layer)", resp.StatusCode)
	}
	var ticketless reqRecord
	found := false
	for _, r := range nLedger.snapshot() {
		if r.method == http.MethodPut && strings.HasPrefix(r.path, "/objects/12345") {
			ticketless, found = r, true
		}
	}
	if !found {
		t.Fatalf("node ledger has no record of the PUT — request never reached the handler; ledger=%v", nLedger.snapshot())
	}
	// 源身份来自流（ConnContext），不是可伪造的 header。
	if ticketless.source != cs.rt.PeerID() {
		t.Fatalf("PUT reached the handler from source %q, want the client's real peer id %q", ticketless.source, cs.rt.PeerID())
	}

	// 未注册源：流层拒绝，ledger 计数不变。
	before := nLedger.len()
	rogueCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rogue, err := peertransport.New(rogueCtx, peertransport.Config{
		IdentityPath:    filepath.Join(t.TempDir(), "rogue.peer.key"),
		ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"},
		DirectTimeout:   5 * time.Second,
		RelayTimeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatalf("rogue runtime: %v", err)
	}
	defer rogue.Close()
	rogue.SetAuthorizer(func(_ context.Context, id string) bool { return id == node.rt.PeerID() })
	dres := rogue.Dial(rogueCtx, ep, infra, peerhttp.PathDirect)
	if dres.Conn != nil {
		_ = dres.Conn.Close()
		t.Fatal("unregistered source must not open a stream to the node")
	}
	if dres.Err == nil {
		t.Fatal("unregistered source dial must fail")
	}
	// gate 拒收后本栈表现为 "no usable connection to peer" 或 "open stream" 拒绝；
	// 前面的已注册 PUT 刚成功，排除了网络不可达。
	msg := dres.Err.Error()
	if !strings.Contains(msg, "no usable connection") && !strings.Contains(msg, "open stream") {
		t.Fatalf("expected a gate/authorization refusal shape, got: %v", dres.Err)
	}
	if delta := nLedger.len() - before; delta != 0 {
		t.Fatalf("node ledger changed during the rogue attempt (+%d): the rejection is not purely at the gate; %v", delta, nLedger.snapshot()[before:])
	}
}

// TestPeerRevokedSessionRejectedAtAuthLayer 会话吊销后 peer 文件操作必须在
// 授权层失败（401 链），而非 planner 先失败或静默成功；全新登录成功证明
// master 自身健康。
func TestPeerRevokedSessionRejectedAtAuthLayer(t *testing.T) {
	pki := newTestPKI(t)
	m := newPeerMaster(t, pki)
	m.createUser("alice")

	m.startNode(filepath.Join(t.TempDir(), "node"), m.nodeInvite())
	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)

	payload := []byte("revoked-session-payload")
	if _, err := cl.PutSmall("/revoked.bin", payload, 1, false); err != nil {
		t.Fatalf("PutSmall before logout: %v", err)
	}

	if err := cl.Logout(context.Background()); err != nil {
		t.Fatalf("logout: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	err := cl.Get("/revoked.bin", out)
	if err == nil {
		t.Fatal("Get after logout must fail")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected an auth-layer (401) failure after revocation, got: %v", err)
	}

	if _, res2 := m.login("alice"); res2.Token == "" {
		t.Fatal("fresh login after logout returned no token")
	}
}
