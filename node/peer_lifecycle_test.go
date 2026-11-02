package node

// node/peer_lifecycle_test.go —— 节点 peer 生命周期/授权/发布的定点测试。
//
// 覆盖主审复核点（全部经 stub RuntimeAPI + httptest master，不依赖真实 peer 网络）：
//  1. 未知源（刚登记客户端）在刷新节流窗口内仍被立即接受：节流被当作「等下一
//     slot」而不是「无权限」，refreshForAuthorize 等到 slot 后拿到含该源的新目录。
//  2. 目录刷新节流与负缓存：force 紧跟 force → errP2PRefreshThrottled；refreshForAuthorize
//     在已取消 ctx 下立即返回 ctx.Err（可中断不挂起）；负缓存容量封顶、过期失效、
//     空源不缓存。
//  3. center infra 源识别：Directory.Infrastructure.PeerID 在目录新鲜期内被 sourceKnown
//     接受（verify/pull/retire 控制连接），过期即拒绝；空源（普通 TCP 兼容）恒接受。
//  4. 发布响应校验：validateNodeEndpointResponse 全字段绑定，任何不匹配都拒绝。
//  5. peerControlDo 先读完响应体再取消：正常响应整体返回；超限触发 size-limit 错误；
//     慢体 + 短 ctx 被取消（不永久挂起），证明 body 读取受 ctx 界定且不悬空。

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

func nodePeerIdentity(t *testing.T) (string, []byte) {
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

// stubNodeRuntime 实现 peertransport.RuntimeAPI；AllowedPeer 按最近一次 SetDirectory
// 的目录成员判定（模拟真实 protocolGate 的纯内存目录检查，绝不回调 authorizer）。
// authorizer 会被 StartP2P 失败路径与 CloseP2P 并发安装：读写都经锁（与真实
// runtime 的原子/加锁安装语义一致）。
type stubNodeRuntime struct {
	peerID       string
	pubKey       []byte
	addresses    []string
	dir          peerauth.Directory
	authorizer   func(context.Context, string) bool
	authorizerMu sync.Mutex
}

func (r *stubNodeRuntime) PeerID() string                  { return r.peerID }
func (r *stubNodeRuntime) PublicKey() []byte               { return r.pubKey }
func (r *stubNodeRuntime) Sign(msg []byte) ([]byte, error) { return append([]byte(nil), msg...), nil }
func (r *stubNodeRuntime) Addresses() []string             { return r.addresses }
func (r *stubNodeRuntime) SetDirectory(d peerauth.Directory) error {
	r.dir = d
	return nil
}
func (r *stubNodeRuntime) SetAuthorizer(f func(context.Context, string) bool) {
	r.authorizerMu.Lock()
	defer r.authorizerMu.Unlock()
	r.authorizer = f
}

// Authorizer 返回最近安装的 authorizer（测试断言用，与 SetAuthorizer 同锁）。
func (r *stubNodeRuntime) Authorizer() func(context.Context, string) bool {
	r.authorizerMu.Lock()
	defer r.authorizerMu.Unlock()
	return r.authorizer
}
func (r *stubNodeRuntime) AllowedPeer(id string) bool {
	if r.dir.Infrastructure.PeerID == id {
		return true
	}
	for _, e := range r.dir.Endpoints {
		if e.PeerID == id {
			return true
		}
	}
	return false
}
func (r *stubNodeRuntime) Listener() (net.Listener, error)                             { return nil, errors.New("unused") }
func (r *stubNodeRuntime) ConnContext(ctx context.Context, _ net.Conn) context.Context { return ctx }
func (r *stubNodeRuntime) ReserveRelay(context.Context, peerauth.Infrastructure) (time.Time, error) {
	return time.Time{}, nil
}
func (r *stubNodeRuntime) PrepareInfrastructure(context.Context, peerauth.Infrastructure) error {
	return nil
}
func (r *stubNodeRuntime) EnableRelay() error { return nil }
func (r *stubNodeRuntime) Dial(context.Context, peerauth.Endpoint, peerauth.Infrastructure, peerhttp.Path) peertransport.DialResult {
	return peertransport.DialResult{}
}
func (r *stubNodeRuntime) Close() error { return nil }

// nodeValidDirectory 构造一个通过 ValidateDirectory 的最小目录（infra + 1 节点 endpoint），
// 并返回 infra 与节点端点的 peer id。
func nodeValidDirectory(t *testing.T) (peerauth.Directory, string, string) {
	t.Helper()
	infraID, infraPub := nodePeerIdentity(t)
	nodeID, nodePub := nodePeerIdentity(t)
	now := time.Now()
	dir := peerauth.Directory{
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
	return dir, infraID, nodeID
}

// nodeDirectoryWithClient 在 nodeValidDirectory 基础上追加一个客户端端点（source），
// 使其通过 ValidateDirectory 且 sourceKnown(source) 为真。
func nodeDirectoryWithClient(t *testing.T, source string, sourcePub []byte) peerauth.Directory {
	t.Helper()
	dir, _, _ := nodeValidDirectory(t)
	dir.Endpoints = append(dir.Endpoints, peerauth.Endpoint{
		Role: peerauth.RoleClient, PeerID: source, PublicKey: append([]byte(nil), sourcePub...),
		Revision: 1, ValidUntil: time.Now().Add(time.Minute),
	})
	return dir
}

func nodeDirectoryJSON(t *testing.T, d peerauth.Directory) []byte {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ---- 1. 未知源在节流窗口内被立即接受（刷新节流 ≠ 拒绝） ----

func TestNodeUnknownSourceImmediateForceRefresh(t *testing.T) {
	sourceID, sourcePub := nodePeerIdentity(t)
	dirBase, _, _ := nodeValidDirectory(t)
	dirWithSource := nodeDirectoryWithClient(t, sourceID, sourcePub)
	dirWithSourceRaw := nodeDirectoryJSON(t, dirWithSource)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/peers/directory" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write(dirWithSourceRaw)
	}))
	defer ts.Close()

	n := &Node{masterURL: ts.URL, httpClient: ts.Client()}
	rt := &stubNodeRuntime{}
	_ = rt.SetDirectory(dirBase)
	p := &nodeP2P{
		n:           n,
		runtime:     rt,
		negative:    make(map[string]time.Time),
		directory:   dirBase,
		directoryAt: time.Now(),
		lastForced:  time.Now().Add(-900 * time.Millisecond), // 仍在节流窗口内
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	defer p.cancel()

	if p.sourceKnown(sourceID) {
		t.Fatal("初始目录不含源，sourceKnown 应为假")
	}
	// 刚登记客户端入站：即使上一个强制刷新在节流窗口内，也必须等下一 slot 后接受，
	// 而不是把节流当作拒绝。
	if !p.authorizeSource(context.Background(), sourceID) {
		t.Fatal("节流窗口内的未知源必须被接受（等下一 slot 而非拒绝）")
	}
	if !p.sourceKnown(sourceID) {
		t.Fatal("授权后目录应已包含该源")
	}
}

// ---- 2. 刷新节流与负缓存 ----

func TestNodeRefreshThrottleAndNegativeCache(t *testing.T) {
	dirRaw := nodeDirectoryJSON(t, mustValidNodeDir(t))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(dirRaw)
	}))
	defer ts.Close()
	n := &Node{masterURL: ts.URL, httpClient: ts.Client()}
	rt := &stubNodeRuntime{}
	p := &nodeP2P{n: n, runtime: rt, negative: make(map[string]time.Time)}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	defer p.cancel()

	if err := p.refresh(context.Background(), true); err != nil {
		t.Fatalf("首刷: %v", err)
	}
	if err := p.refresh(context.Background(), true); !errors.Is(err, errP2PRefreshThrottled) {
		t.Fatalf("紧跟的强制刷新应被节流，got %v", err)
	}
	// 非强制刷新在新鲜期内不触发节流（直接命中缓存）。
	if err := p.refresh(context.Background(), false); err != nil {
		t.Fatalf("新鲜期非强制刷新应成功: %v", err)
	}

	// refreshForAuthorize 在已取消 ctx 下立即返回，不挂起。
	p.lastForced = time.Now()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.refreshForAuthorize(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("已取消 ctx 的 refreshForAuthorize 应返回 ctx.Err，got %v", err)
	}

	// 负缓存：容量封顶 + 过期失效 + 空源不缓存。
	neg := &nodeP2P{negative: make(map[string]time.Time)}
	for i := 0; i < peerNegativeCap+64; i++ {
		neg.markNegative(fmt.Sprintf("peer-%d", i))
	}
	if len(neg.negative) > peerNegativeCap {
		t.Fatalf("负缓存超容量: %d > %d", len(neg.negative), peerNegativeCap)
	}
	neg.markNegative("peer-a")
	if !neg.negativeHit("peer-a") {
		t.Fatal("TTL 内负缓存应命中")
	}
	neg.negative["peer-b"] = time.Now().Add(-time.Second)
	if neg.negativeHit("peer-b") {
		t.Fatal("过期负缓存应失效")
	}
	neg.markNegative("")
	if _, ok := neg.negative[""]; ok {
		t.Fatal("空源不得写入负缓存")
	}
}

func mustValidNodeDir(t *testing.T) peerauth.Directory {
	t.Helper()
	dir, _, _ := nodeValidDirectory(t)
	return dir
}

// ---- 3. center infra 源识别 ----

func TestNodeSourceKnownInfrastructure(t *testing.T) {
	dir, infraID, nodeID := nodeValidDirectory(t)
	p := &nodeP2P{directory: dir, directoryAt: time.Now()}

	if !p.sourceKnown(infraID) {
		t.Fatal("center infra peer 在新鲜期内必须被 sourceKnown 接受（控制连接）")
	}
	if !p.sourceKnown(nodeID) {
		t.Fatal("目录内节点端点必须被 sourceKnown 接受")
	}
	if !p.sourceKnown("") {
		t.Fatal("空源（普通 TCP 兼容）必须恒接受")
	}
	if p.sourceKnown("peer-unknown") {
		t.Fatal("未知源必须被 sourceKnown 拒绝")
	}

	// infra 的有效期 = 目录新鲜期：过期即拒（控制连接不能被陈旧 infra 冒充）。
	p.directoryAt = time.Now().Add(-3 * time.Minute)
	if p.sourceKnown(infraID) {
		t.Fatal("过期目录的 infra 源必须被拒绝")
	}
}

// ---- 4. 发布响应校验 ----

func TestNodePublicationValidation(t *testing.T) {
	peerID, pub := nodePeerIdentity(t)
	n := &Node{advertise: "127.0.0.1:9000"}
	n.nodeID.Store(42)
	p := &nodeP2P{runtime: &stubNodeRuntime{peerID: peerID, pubKey: pub}}
	req := peerauth.AddressPublication{
		PeerID: peerID, BindingRevision: 3, ExpectedRevision: 7,
		Addresses: []string{"127.0.0.1:9000"},
		NotAfter:  time.Now().UTC().Add(2 * time.Minute),
	}
	match := peerauth.Endpoint{
		Role: peerauth.RoleNode, NodeID: 42, PeerID: peerID, Addr: "127.0.0.1:9000",
		PublicKey: pub, BindingRevision: 3, Revision: 8,
		Addresses: []string{"127.0.0.1:9000"}, ValidUntil: time.Now().UTC().Add(time.Minute),
	}
	if err := validateNodeEndpointResponse(n, p, req, 7, match); err != nil {
		t.Fatalf("匹配响应应通过: %v", err)
	}

	mutate := func(f func(*peerauth.Endpoint)) peerauth.Endpoint {
		e := match
		e.Addresses = append([]string(nil), match.Addresses...)
		f(&e)
		return e
	}
	cases := []struct {
		name string
		e    peerauth.Endpoint
	}{
		{"role", mutate(func(e *peerauth.Endpoint) { e.Role = peerauth.RoleClient })},
		{"nodeID", mutate(func(e *peerauth.Endpoint) { e.NodeID = 43 })},
		{"peerID", mutate(func(e *peerauth.Endpoint) { e.PeerID = "peer-wrong" })},
		{"addr", mutate(func(e *peerauth.Endpoint) { e.Addr = "127.0.0.1:9999" })},
		{"pubkey", mutate(func(e *peerauth.Endpoint) { e.PublicKey = bytes.Repeat([]byte{1}, 32) })},
		{"bindingRevision", mutate(func(e *peerauth.Endpoint) { e.BindingRevision = 4 })},
		{"revision", mutate(func(e *peerauth.Endpoint) { e.Revision = 9 })},
		{"addresses", mutate(func(e *peerauth.Endpoint) { e.Addresses = []string{"127.0.0.1:9999"} })},
		{"validUntilPast", mutate(func(e *peerauth.Endpoint) { e.ValidUntil = time.Now().Add(-time.Minute) })},
		{"validUntilAfterNotAfter", mutate(func(e *peerauth.Endpoint) { e.ValidUntil = req.NotAfter.Add(time.Minute) })},
	}
	for _, tc := range cases {
		if err := validateNodeEndpointResponse(n, p, req, 7, tc.e); err == nil {
			t.Errorf("case %q: 不匹配响应应被拒绝", tc.name)
		}
	}
}

// ---- 5. peerControlDo：先读完响应体再取消 ----

func TestNodePeerControlReadsBodyBeforeCancel(t *testing.T) {
	payload := []byte(`{"revision":9}`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer ts.Close()
	n := &Node{masterURL: ts.URL, httpClient: ts.Client()}

	status, raw, err := n.peerControlDo(context.Background(), http.MethodGet, "/peers/client-self", nil, 1<<20)
	if err != nil {
		t.Fatalf("peerControlDo 应完整读回 body: %v", err)
	}
	if status != http.StatusOK || !bytes.Equal(raw, payload) {
		t.Fatalf("响应体未被完整读取: status=%d body=%q", status, raw)
	}

	// 超限响应触发 size-limit 错误（仍读到 limit+1，证明读完整而非悬空）。
	big := bytes.Repeat([]byte("x"), 4096)
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer ts2.Close()
	n2 := &Node{masterURL: ts2.URL, httpClient: ts2.Client()}
	if _, _, err := n2.peerControlDo(context.Background(), http.MethodGet, "/peers/directory", nil, 1024); err == nil ||
		!strings.Contains(err.Error(), "size limit") {
		t.Fatalf("超限响应应报 size limit，got %v", err)
	}

	// 慢体 + 短 ctx：读取被 ctx 界定，返回 ctx 错误而非永久挂起。
	ts3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("partial"))
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	defer ts3.Close()
	n3 := &Node{masterURL: ts3.URL, httpClient: ts3.Client()}
	shortCtx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err = n3.peerControlDo(shortCtx, http.MethodGet, "/peers/directory", nil, 1<<20)
	if err == nil {
		t.Fatal("短 ctx + 慢体应返回错误")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("peerControlDo 应随 ctx 取消，不永久挂起")
	}
}

// ---- 6. 关停确定性：两个并发 CloseP2P 都 join；StartP2P 在关停后被拒 ----

func TestNodeCloseP2PDoubleCloseJoinsPublisher(t *testing.T) {
	rt := &stubNodeRuntime{}
	p := &nodeP2P{n: &Node{}, runtime: rt, negative: make(map[string]time.Time)}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.started = true
	p.wg.Add(1)
	exited := make(chan struct{})
	go func() {
		defer p.wg.Done()
		defer close(exited)
		<-p.ctx.Done()
	}()
	n := &Node{p2p: p}

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := n.CloseP2P(); err != nil {
				t.Errorf("CloseP2P: %v", err)
			}
		}()
	}
	wg.Wait()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher 未被两个并发 CloseP2P 之一 join")
	}
	// 关停后必须安装拒绝型 authorizer：无残余 peer 权威。
	if rt.Authorizer() == nil {
		t.Fatal("关停后未安装 authorizer")
	}
	if rt.Authorizer()(context.Background(), "any-peer") {
		t.Fatal("关停后 authorizer 必须拒绝所有 peer")
	}
}

func TestNodeStartAfterCloseRefused(t *testing.T) {
	rt := &stubNodeRuntime{}
	n := &Node{p2p: &nodeP2P{n: nil, runtime: rt, negative: make(map[string]time.Time)}}
	n.p2p.n = n
	if err := n.CloseP2P(); err != nil {
		t.Fatalf("无 publisher 时 CloseP2P: %v", err)
	}
	if err := n.StartP2P(context.Background()); !errors.Is(err, errP2PClosed) {
		t.Fatalf("StartP2P 在关停后应被拒（errP2PClosed），got %v", err)
	}
}

// 编译期确保 stubNodeRuntime 满足 RuntimeAPI（防接口漂移）。
var _ peertransport.RuntimeAPI = (*stubNodeRuntime)(nil)

// ---- 7. Register 首次注册纳入关停屏障：CloseP2P 取消能中止在途注册 ----

func TestNodeRegisterLifecycleCancelAbortsFirstRegistration(t *testing.T) {
	regStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nodes/register" {
			once.Do(func() { close(regStarted) })
			// 屏障挂住 handler；客户端中止（连接关闭）时同步放行，任何失败/
			// 超时路径下清理都不死锁。
			select {
			case <-release:
			case <-r.Context().Done():
			}
			writeTestJSON(w, http.StatusCreated, map[string]uint64{"id": 1})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	// 先放行屏障、再关服务器（顺序敏感，不能用 LIFO defer）。
	t.Cleanup(func() {
		close(release)
		ts.Close()
	})
	n := New(t.TempDir(), ts.URL, "127.0.0.1:9000", 1<<20)

	regDone := make(chan error, 1)
	go func() { regDone <- n.Register() }()
	<-regStarted // 首次注册 HTTP 在途
	closeDone := make(chan struct{})
	go func() { _ = n.CloseP2P(); close(closeDone) }()

	// CloseP2P 取消生命周期 ctx：在途注册必须被中止并返回错误，且 CloseP2P
	// 等到注册退出（占位计数）后才返回。
	select {
	case err := <-regDone:
		if err == nil {
			t.Fatal("关停取消后首次注册必须失败")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CloseP2P 未中止在途首次注册（生命周期屏障未闭合）")
	}
	<-closeDone
	if err := n.Register(); !errors.Is(err, errNodeClosed) {
		t.Fatalf("CloseP2P 后 Register 应被拒（errNodeClosed），got %v", err)
	}
}

// ---- 8. CloseP2P join heartbeat：关停后心跳停止，Register 拒绝 ----

func TestNodeCloseP2PJoinsRegisterLoops(t *testing.T) {
	var beats atomic.Int64
	firstBeat := make(chan struct{})
	var once sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/nodes/register":
			writeTestJSON(w, http.StatusCreated, map[string]uint64{"id": 1})
		case r.Method == http.MethodPost && r.URL.Path == "/nodes/heartbeat":
			beats.Add(1)
			once.Do(func() { close(firstBeat) })
			writeTestJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer ts.Close()
	n := New(t.TempDir(), ts.URL, "127.0.0.1:9000", 1<<20)
	n.heartbeatInterval = 20 * time.Millisecond
	if err := n.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	select {
	case <-firstBeat:
	case <-time.After(2 * time.Second):
		t.Fatal("未观察到首次心跳")
	}
	if err := n.CloseP2P(); err != nil {
		t.Fatalf("CloseP2P: %v", err)
	}
	before := beats.Load()
	time.Sleep(150 * time.Millisecond) // 若循环仍活，应有 ~7 个 tick
	if after := beats.Load(); after != before {
		t.Fatalf("关停后心跳必须停止: %d -> %d", before, after)
	}
	if err := n.Register(); !errors.Is(err, errNodeClosed) {
		t.Fatalf("CloseP2P 后 Register 应被拒，got %v", err)
	}
}

// ---- 9. 关停后设备会话不再重建：challenge/kick/心跳全部冻结 ----

func TestNodeCloseStopsDeviceSessionRenewal(t *testing.T) {
	fm := newFakeSecMaster(t)
	n := newSecureNode(t, fm, "127.0.0.1:9105", "")
	n.heartbeatInterval = 20 * time.Millisecond
	if err := n.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	waitFor := func(cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("等待条件超时")
	}
	waitFor(func() bool {
		fm.mu.Lock()
		defer fm.mu.Unlock()
		return len(fm.heartbeats) > 0
	})

	if err := n.CloseP2P(); err != nil {
		t.Fatalf("CloseP2P: %v", err)
	}
	// 关停完成后才取基线：Close 排干在途请求时允许最后 1 次心跳/挑战发生。
	// 此后循环必须已死，基线之后的任何新请求都是关停失败。
	fm.mu.Lock()
	challenges := fm.chCount
	beats := len(fm.heartbeats)
	fm.mu.Unlock()
	time.Sleep(150 * time.Millisecond) // 若 renew/heartbeat 仍活，会产生新请求
	fm.mu.Lock()
	if fm.chCount != challenges {
		t.Fatalf("关停后不得发起新设备挑战: %d -> %d", challenges, fm.chCount)
	}
	if len(fm.heartbeats) != beats {
		t.Fatalf("关停后心跳必须停止: %d -> %d", beats, len(fm.heartbeats))
	}
	fm.mu.Unlock()

	// 关停后各路径显式拒绝，不再创建会话。
	if err := n.sec.establishSession(context.Background(), false); !errors.Is(err, errNodeClosed) {
		t.Fatalf("关停后 establishSession 应拒绝，got %v", err)
	}
	if err := n.sec.renewAfterRejection(context.Background(), "tok-stale"); err != nil {
		t.Fatalf("关停后 renewAfterRejection 应 no-op 返回 nil，got %v", err)
	}
	n.sec.kickRenewFor("tok-stale") // goLife 拒绝启动，不产生任何请求
	time.Sleep(80 * time.Millisecond)
	fm.mu.Lock()
	if fm.chCount != challenges {
		t.Fatalf("关停后 kickRenewFor 不得触发续期: %d -> %d", challenges, fm.chCount)
	}
	fm.mu.Unlock()
	if err := n.Register(); !errors.Is(err, errNodeClosed) {
		t.Fatalf("关停后 Register 应被拒，got %v", err)
	}
}

// ---- 10. StartP2P 在途 × CloseP2P 并发 barrier：取消中止启动且关停后拒重启 ----

func TestNodeStartP2PConcurrentCloseBarrier(t *testing.T) {
	peerID, pub := nodePeerIdentity(t)
	rt := &stubNodeRuntime{peerID: peerID, pubKey: pub, addresses: []string{"/ip4/127.0.0.1/tcp/9001"}}
	dirRaw := nodeDirectoryJSON(t, mustValidNodeDir(t))
	refreshStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/peers/directory" {
			once.Do(func() { close(refreshStarted) })
			// 屏障挂住 handler；客户端中止（连接关闭）时同步放行，清理不死锁。
			select {
			case <-release:
			case <-r.Context().Done():
			}
			_, _ = w.Write(dirRaw)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	// 先放行屏障、再关服务器（顺序敏感，不能用 LIFO defer）。
	t.Cleanup(func() {
		close(release)
		ts.Close()
	})

	n := &Node{masterURL: ts.URL, httpClient: ts.Client(), advertise: "127.0.0.1:9001"}
	n.nodeID.Store(42)
	n.sec = &nodeSecurity{node: n}
	n.sec.setPeerRuntime(rt)
	n.sec.peerBinding = &peerauth.Binding{PeerID: peerID, PublicKey: append([]byte(nil), pub...), Revision: 3}
	p := &nodeP2P{n: n, runtime: rt, negative: make(map[string]time.Time)}
	n.p2p = p

	startErr := make(chan error, 1)
	go func() { startErr <- n.StartP2P(context.Background()) }()
	<-refreshStarted // StartP2P 的首次目录刷新在途
	closeDone := make(chan struct{})
	go func() { _ = n.CloseP2P(); close(closeDone) }()

	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("并发关停下 StartP2P 必须失败（启动被取消）")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CloseP2P 未中止在途 StartP2P（barrier 未闭合）")
	}
	<-closeDone
	// 关停后无残余 peer 权威，且 StartP2P 被永久拒绝。
	if rt.Authorizer() == nil || rt.Authorizer()(context.Background(), "any-peer") {
		t.Fatal("关停后 authorizer 必须拒绝所有 peer")
	}
	if err := n.StartP2P(context.Background()); !errors.Is(err, errP2PClosed) {
		t.Fatalf("关停后 StartP2P 应被拒，got %v", err)
	}
}

// ---- 11. 同 peer 持久身份的绑定 revision 语义 ----

func TestNodePeerBindingRevisionSemantics(t *testing.T) {
	peerID, pub := nodePeerIdentity(t)
	rt := &stubNodeRuntime{peerID: peerID, pubKey: pub}
	binding := func(rev uint64) *peerauth.Binding {
		return &peerauth.Binding{PeerID: peerID, PublicKey: append([]byte(nil), pub...), Revision: rev}
	}
	// expected==0（本进程首次注册）：持久身份可能已在先前进程绑到更高 revision，
	// 任何正 current revision 都是合法 resume。
	if err := validatePeerSessionBinding(rt, binding(7), 0); err != nil {
		t.Fatalf("expected=0 应接受既有 revision>1（持久身份重启）: %v", err)
	}
	// expected>0（本进程已知绑定）：同 key resume 必须不变。
	if err := validatePeerSessionBinding(rt, binding(3), 3); err != nil {
		t.Fatalf("expected==current 应接受: %v", err)
	}
	if err := validatePeerSessionBinding(rt, binding(4), 3); err == nil {
		t.Fatal("expected>0 而 current 不同必须拒绝（不是任意 expected+1）")
	}
	if err := validatePeerSessionBinding(rt, nil, 0); err == nil {
		t.Fatal("缺 binding 必须拒绝")
	}
	if err := validatePeerSessionBinding(rt, binding(0), 0); err == nil {
		t.Fatal("revision 0 必须拒绝")
	}
	otherID, otherPub := nodePeerIdentity(t)
	if err := validatePeerSessionBinding(rt, &peerauth.Binding{PeerID: otherID, PublicKey: otherPub, Revision: 1}, 0); err == nil {
		t.Fatal("其它 peer 身份的 binding 必须拒绝")
	}
}

// ---- 12. relay 预约短周期有界刷新（中心重启丢预约按分钟级修复） ----

type relayCountRuntime struct {
	stubNodeRuntime
	mu    sync.Mutex
	calls int
	until time.Time
	err   error
}

func (r *relayCountRuntime) ReserveRelay(context.Context, peerauth.Infrastructure) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return time.Time{}, r.err
	}
	return r.until, nil
}

func (r *relayCountRuntime) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func TestNodeRelayReservationRefreshedBounded(t *testing.T) {
	dir := mustValidNodeDir(t)
	rr := &relayCountRuntime{stubNodeRuntime: stubNodeRuntime{}}
	rr.until = time.Now().Add(time.Hour)
	p := &nodeP2P{n: &Node{}, runtime: rr, negative: make(map[string]time.Time)}
	p.directory = dir
	p.directoryAt = time.Now()
	ctx := context.Background()

	// 预约未临期且刚刷新过 → 跳过。
	p.relayUntil = time.Now().Add(time.Hour)
	p.relayAt = time.Now()
	if err := p.n.reserveRelay(ctx, p); err != nil {
		t.Fatalf("fresh reservation 应跳过: %v", err)
	}
	if got := rr.callCount(); got != 0 {
		t.Fatalf("fresh reservation 不应触发 ReserveRelay，got %d", got)
	}

	// 超过短周期刷新窗（中心可能已重启丢预约）→ 重新预留并更新 relayAt。
	p.relayAt = time.Now().Add(-peerRelayReserveRefresh - time.Second)
	if err := p.n.reserveRelay(ctx, p); err != nil {
		t.Fatalf("periodic refresh: %v", err)
	}
	if got := rr.callCount(); got != 1 {
		t.Fatalf("刷新窗后应重预留，calls=%d", got)
	}
	if p.relayAt.IsZero() || time.Since(p.relayAt) > time.Minute {
		t.Fatalf("成功预留后必须更新 relayAt: %v", p.relayAt)
	}

	// 临期（30s 余量）→ 无论刷新窗都重预留。
	p.relayUntil = time.Now().Add(10 * time.Second)
	p.relayAt = time.Now()
	if err := p.n.reserveRelay(ctx, p); err != nil {
		t.Fatalf("临期重预留: %v", err)
	}
	if got := rr.callCount(); got != 2 {
		t.Fatalf("临期必须重预留，calls=%d", got)
	}

	// 预留失败：保存条件不变——不落任何新 until。
	p.relayUntil = time.Now().Add(time.Hour)
	p.relayAt = time.Now().Add(-peerRelayReserveRefresh - time.Second)
	relayUntilBefore := p.relayUntil
	rr.mu.Lock()
	rr.err = errors.New("relay hub down")
	rr.mu.Unlock()
	if err := p.n.reserveRelay(ctx, p); err == nil {
		t.Fatal("预留失败必须返回错误")
	}
	if !p.relayUntil.Equal(relayUntilBefore) {
		t.Fatalf("失败不得更新 relayUntil: %v", p.relayUntil)
	}
}

// ---- 13b. 首次 prepare / relay 预约的有界重试 ----

// firstSetupRuntime 记录 PrepareInfrastructure / ReserveRelay 的调用与错误脚本，
// 供首次 setup 有界重试的定点测试。脚本耗尽后默认成功；onPrepare/onReserve 为
// 每次真正调用前的事件钩子；prepareBarrier 非空时按调用次序接管该次结果
// （真在途屏障用）。
type firstSetupRuntime struct {
	stubNodeRuntime
	mu             sync.Mutex
	prepareCalls   int
	prepareErrs    []error
	lastInfra      peerauth.Infrastructure
	relayCalls     int
	relayErrs      []error
	relayUntil     time.Time
	onPrepare      func()
	prepareBarrier func(ctx context.Context, call int) error
	onReserve      func()
}

func (r *firstSetupRuntime) PrepareInfrastructure(ctx context.Context, infra peerauth.Infrastructure) error {
	r.mu.Lock()
	r.prepareCalls++
	call := r.prepareCalls
	r.lastInfra = infra
	hook := r.onPrepare
	barrier := r.prepareBarrier
	errs := r.prepareErrs
	r.mu.Unlock()
	if hook != nil {
		hook()
	}
	if barrier != nil {
		return barrier(ctx, call)
	}
	if len(errs) == 0 {
		return nil
	}
	return errs[0]
}

func (r *firstSetupRuntime) ReserveRelay(context.Context, peerauth.Infrastructure) (time.Time, error) {
	r.mu.Lock()
	r.relayCalls++
	hook := r.onReserve
	errs := r.relayErrs
	r.mu.Unlock()
	if hook != nil {
		hook()
	}
	if len(errs) == 0 {
		return r.relayUntil, nil
	}
	return time.Time{}, errs[0]
}

func (r *firstSetupRuntime) prepareCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prepareCalls
}

func (r *firstSetupRuntime) relayCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.relayCalls
}

func newRetryTestP2P() *nodeP2P {
	p := &nodeP2P{n: &Node{}, runtime: &stubNodeRuntime{}, negative: make(map[string]time.Time)}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p
}

// 暂时性网络错误按预算重试：前两次失败第三次成功；每次尝试 ctx 都有界（有
// deadline 且不超过单次/总预算），成功即停。
func TestNodeFirstSetupRetrySucceedsAfterTransientFailures(t *testing.T) {
	p := newRetryTestP2P()
	defer p.cancel()
	start := time.Now()
	var calls int
	var deadlines []time.Time
	err := p.withFirstSetupRetry(context.Background(), func(ctx context.Context) error {
		calls++
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("attempt ctx must carry a deadline (bounded attempt)")
		} else {
			deadlines = append(deadlines, dl)
		}
		if calls <= 2 {
			return errors.New("connection reset by peer")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("第三次尝试应成功: %v", err)
	}
	if calls != 3 {
		t.Fatalf("attempts = %d, want 3", calls)
	}
	for _, dl := range deadlines {
		if d := time.Until(dl); d > peerPrepareAttemptTimeout || d > peerFirstSetupTotalBudget {
			t.Fatalf("attempt deadline 超出单次/总预算: %v", d)
		}
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("两次退避（100/200ms）应真实发生，elapsed=%v", elapsed)
	}
}

// 永久身份/授权错误不重试：一次尝试后立刻失败暴露，错误链保持 errors.Is 可判。
func TestNodeFirstSetupRetryPermanentErrorsNotRetried(t *testing.T) {
	p := newRetryTestP2P()
	defer p.cancel()
	for _, sentinel := range []error{peertransport.ErrInfrastructureInvalid, peertransport.ErrPeerUnauthorized} {
		calls := 0
		err := p.withFirstSetupRetry(context.Background(), func(ctx context.Context) error {
			calls++
			return fmt.Errorf("prepare infrastructure: %w", sentinel)
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("%v: 错误链必须保持 sentinel 可判，got %v", sentinel, err)
		}
		if calls != 1 {
			t.Fatalf("%v: 永久错误不得重试，attempts=%d", sentinel, calls)
		}
	}
}

// 次数耗尽：持续暂时性错误恰好尝试 peerFirstSetupMaxAttempts 次后返回末次错误。
func TestNodeFirstSetupRetryExhaustsAttempts(t *testing.T) {
	p := newRetryTestP2P()
	defer p.cancel()
	transient := errors.New("relay hub unreachable")
	calls := 0
	err := p.withFirstSetupRetry(context.Background(), func(ctx context.Context) error {
		calls++
		return transient
	})
	if !errors.Is(err, transient) {
		t.Fatalf("应返回末次暂时性错误，got %v", err)
	}
	if calls != peerFirstSetupMaxAttempts {
		t.Fatalf("attempts = %d, want %d", calls, peerFirstSetupMaxAttempts)
	}
}

// 父 ctx 在尝试在途时取消：立刻终止，绝不开始下一次尝试。
func TestNodeFirstSetupRetryStopsOnParentCancel(t *testing.T) {
	p := newRetryTestP2P()
	defer p.cancel()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	calls := 0
	fn := func(ctx context.Context) error {
		calls++
		close(entered)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return errors.New("attempt did not observe parent cancel")
		}
	}
	errCh := make(chan error, 1)
	go func() { errCh <- p.withFirstSetupRetry(parent, fn) }()
	<-entered
	cancel()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("父 ctx 取消后必须返回错误")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("父 ctx 取消未立刻终止首次 retry")
	}
	if calls != 1 {
		t.Fatalf("取消后不得开始下一次尝试: %d", calls)
	}
}

// 尝试返回错误时父 ctx 已终止（外部取消/父 deadline 在错误前生效）：按 ctx
// 分类终止，不当临时故障再试；closed 同样立刻终止。
func TestNodeFirstSetupRetryStopsWhenParentCancelledOrClosed(t *testing.T) {
	p := newRetryTestP2P()
	defer p.cancel()
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := p.withFirstSetupRetry(parent, func(ctx context.Context) error {
		calls++
		cancel()
		return errors.New("transient-looking failure")
	})
	if err == nil || calls != 1 {
		t.Fatalf("父 ctx 终止后不得再试: calls=%d err=%v", calls, err)
	}

	closed := newRetryTestP2P()
	defer closed.cancel()
	closedCalls := 0
	err = closed.withFirstSetupRetry(context.Background(), func(ctx context.Context) error {
		closedCalls++
		closed.mu.Lock()
		closed.closed = true
		closed.mu.Unlock()
		return errors.New("transient-looking failure")
	})
	if err == nil || closedCalls != 1 {
		t.Fatalf("closed 后不得再试: calls=%d err=%v", closedCalls, err)
	}
}

// ---- 13c. StartP2P 首次 prepare 顺序与失败路径 ----

// nodeStartP2PFixture 装配最小可 StartP2P 的节点：httptest master 供目录/状态/
// 发布，stub runtime 供可编程 prepare/relay。publish 事件由 /peers/address 记录。
type nodeStartP2PFixture struct {
	t  *testing.T
	n  *Node
	rt *firstSetupRuntime
	p  *nodeP2P

	eventsMu sync.Mutex
	events   []string
}

func newStartP2PFixture(t *testing.T, peerID string, pub []byte, dir peerauth.Directory) *nodeStartP2PFixture {
	t.Helper()
	dirRaw := nodeDirectoryJSON(t, dir)
	f := &nodeStartP2PFixture{t: t}
	f.rt = &firstSetupRuntime{stubNodeRuntime: stubNodeRuntime{peerID: peerID, pubKey: pub, addresses: []string{"/ip4/127.0.0.1/tcp/9001"}}}
	f.rt.relayUntil = time.Now().Add(time.Hour)
	f.rt.onPrepare = func() { f.record("prepare") }
	f.rt.onReserve = func() { f.record("reserve") }

	// TLS master：PublicationProof 要求精确 HTTPS origin。
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/peers/directory":
			_, _ = w.Write(dirRaw)
		case r.Method == http.MethodGet && r.URL.Path == "/peers/self":
			writeTestJSON(w, http.StatusOK, peerauth.NodeState{EndpointRevision: 0})
		case r.Method == http.MethodPost && r.URL.Path == "/peers/address":
			var pubReq peerauth.AddressPublication
			_ = json.NewDecoder(r.Body).Decode(&pubReq)
			f.record("publish")
			writeTestJSON(w, http.StatusOK, peerauth.Endpoint{
				Role: peerauth.RoleNode, NodeID: 42, PeerID: pubReq.PeerID,
				Addr: "127.0.0.1:9001", PublicKey: append([]byte(nil), pub...),
				BindingRevision: pubReq.BindingRevision, Revision: pubReq.ExpectedRevision + 1,
				Addresses: pubReq.Addresses, ValidUntil: time.Now().Add(time.Minute),
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)

	n := &Node{masterURL: ts.URL, httpClient: ts.Client(), advertise: "127.0.0.1:9001"}
	n.nodeID.Store(42)
	n.sec = &nodeSecurity{node: n}
	n.sec.setPeerRuntime(f.rt)
	n.sec.peerBinding = &peerauth.Binding{PeerID: peerID, PublicKey: append([]byte(nil), pub...), Revision: 3}
	f.n = n
	f.p = &nodeP2P{n: n, runtime: f.rt, negative: make(map[string]time.Time)}
	n.p2p = f.p
	return f
}

func (f *nodeStartP2PFixture) record(event string) {
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	f.events = append(f.events, event)
}

func (f *nodeStartP2PFixture) snapshotEvents() []string {
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	return append([]string(nil), f.events...)
}

// 首次 setup 顺序契约：prepare 必须先于首次 publication 与 relay 预约；预约
// 仅在 ReserveRelay 真正成功后落库 relayUntil/relayAt。
func TestNodeStartP2PPreparesBeforePublishAndReserve(t *testing.T) {
	peerID, pub := nodePeerIdentity(t)
	dir, infraID, _ := nodeValidDirectory(t)
	f := newStartP2PFixture(t, peerID, pub, dir)

	if err := f.n.StartP2P(context.Background()); err != nil {
		t.Fatalf("StartP2P: %v", err)
	}
	// 关停 join publisher，之后断言终态。
	if err := f.n.CloseP2P(); err != nil {
		t.Fatalf("CloseP2P: %v", err)
	}

	events := f.snapshotEvents()
	if want := []string{"prepare", "publish", "reserve"}; !equalStrings(events, want) {
		t.Fatalf("首次 setup 事件 = %v, want %v", events, want)
	}
	f.rt.mu.Lock()
	infra := f.rt.lastInfra
	f.rt.mu.Unlock()
	if infra.PeerID != infraID {
		t.Fatalf("prepare 必须绑定当前目录的 infra 身份: got %q want %q", infra.PeerID, infraID)
	}
	f.p.mu.RLock()
	until, at := f.p.relayUntil, f.p.relayAt
	f.p.mu.RUnlock()
	if until.IsZero() || !until.Equal(f.rt.relayUntil) || at.IsZero() {
		t.Fatalf("成功预约后必须落库 relayUntil/relayAt: until=%v at=%v", until, at)
	}
}

// 永久 infra 错误：StartP2P 立刻失败（1 次尝试、不重试、不预约），生命周期按
// release 收尾（closed、拒绝型 authorizer、重启被拒）。
func TestNodeStartP2PPermanentPrepareFailureReleases(t *testing.T) {
	peerID, pub := nodePeerIdentity(t)
	dir, _, _ := nodeValidDirectory(t)
	f := newStartP2PFixture(t, peerID, pub, dir)
	f.rt.mu.Lock()
	f.rt.prepareErrs = []error{fmt.Errorf("infra has no public address: %w", peertransport.ErrInfrastructureInvalid)}
	f.rt.mu.Unlock()

	err := f.n.StartP2P(context.Background())
	if !errors.Is(err, peertransport.ErrInfrastructureInvalid) {
		t.Fatalf("StartP2P 必须透传永久 infra 错误，got %v", err)
	}
	if got := f.rt.prepareCount(); got != 1 {
		t.Fatalf("永久错误不得重试，prepare attempts=%d", got)
	}
	if got := f.rt.relayCount(); got != 0 {
		t.Fatalf("prepare 失败不得预约 relay，calls=%d", got)
	}
	if len(f.snapshotEvents()) != 1 {
		t.Fatalf("prepare 失败后不得 publication: events=%v", f.snapshotEvents())
	}
	// release 已收尾：无残余权威，重启被拒。
	if f.rt.Authorizer() == nil || f.rt.Authorizer()(context.Background(), "any-peer") {
		t.Fatal("StartP2P 失败后必须安装拒绝型 authorizer")
	}
	if err := f.n.StartP2P(context.Background()); !errors.Is(err, errP2PClosed) {
		t.Fatalf("失败后 StartP2P 应被拒（errP2PClosed），got %v", err)
	}
}

// CloseP2P 必须 join 在途的首次 retry（真并发屏障：Close 在 PrepareInfrastructure
// 挂起时发出，不是完成后冒充）。取消令在途尝试立刻返回错误，且不再有下一次
// 尝试；CloseP2P 只有在 retry 收尾（release 释放 wg 槽位）后才返回。
func TestNodeCloseP2PJoinsInflightFirstPrepareRetry(t *testing.T) {
	peerID, pub := nodePeerIdentity(t)
	dir, _, _ := nodeValidDirectory(t)
	f := newStartP2PFixture(t, peerID, pub, dir)
	var sawCancel atomic.Bool
	prepareEntered := make(chan struct{})
	var once sync.Once
	f.rt.prepareBarrier = func(ctx context.Context, call int) error {
		once.Do(func() { close(prepareEntered) })
		select {
		case <-ctx.Done():
			sawCancel.Store(true)
			return ctx.Err()
		case <-time.After(10 * time.Second):
			return errors.New("prepare was not cancelled by CloseP2P")
		}
	}

	startErr := make(chan error, 1)
	go func() { startErr <- f.n.StartP2P(context.Background()) }()
	select {
	case <-prepareEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("首次 prepare 未进入在途屏障")
	}
	closeDone := make(chan struct{})
	go func() { _ = f.n.CloseP2P(); close(closeDone) }()

	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("并发关停下 StartP2P 必须失败（首次 prepare 被取消）")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CloseP2P 未终止在途首次 prepare retry")
	}
	<-closeDone
	// join 证明：CloseP2P 只能在 release 释放 wg 槽位后返回，而 release 只能在
	// 在途尝试观察到取消并返回后发生。
	if !sawCancel.Load() {
		t.Fatal("CloseP2P 返回前在途 prepare 必须已观察到取消")
	}
	if got := f.rt.prepareCount(); got != 1 {
		t.Fatalf("取消后不得开始下一次尝试: %d", got)
	}
	if f.rt.Authorizer() == nil || f.rt.Authorizer()(context.Background(), "any-peer") {
		t.Fatal("关停后必须安装拒绝型 authorizer")
	}
	if err := f.n.StartP2P(context.Background()); !errors.Is(err, errP2PClosed) {
		t.Fatalf("关停后 StartP2P 应被拒，got %v", err)
	}
}

// ---- 13d. 稳态周期：prepare 失败时同一坏 infra 的预约不得伪记成功 ----

// 永久身份/授权错误：本周期跳过 reserve（relayUntil/relayAt 原样保留，不伪记）。
func TestNodePublisherCycleSkipsReserveAfterPermanentPrepareFailure(t *testing.T) {
	peerID, pub := nodePeerIdentity(t)
	dir, _, _ := nodeValidDirectory(t)
	f := newStartP2PFixture(t, peerID, pub, dir)
	f.p.ctx, f.p.cancel = context.WithCancel(context.Background())
	defer f.p.cancel()
	f.rt.mu.Lock()
	f.rt.prepareErrs = []error{fmt.Errorf("infra has no public address: %w", peertransport.ErrInfrastructureInvalid)}
	f.rt.mu.Unlock()
	// 预置过期预约：若无门控，reserve 必然会被尝试。
	sentinel := time.Now().Add(-time.Hour)
	f.p.mu.Lock()
	f.p.relayUntil = sentinel
	f.p.mu.Unlock()

	f.n.publisherCycle(context.Background(), f.p)

	if got := f.rt.relayCount(); got != 0 {
		t.Fatalf("永久 prepare 失败后本周期不得预约，relay calls=%d", got)
	}
	f.p.mu.RLock()
	until, at := f.p.relayUntil, f.p.relayAt
	f.p.mu.RUnlock()
	if !until.Equal(sentinel) || !at.IsZero() {
		t.Fatalf("失败不得伪记预约状态: until=%v at=%v", until, at)
	}
}

// 暂时性错误（含 tick 超时）：仍独立尝试预约修复，真成功才落库。
func TestNodePublisherCycleReservesAfterTransientPrepareFailure(t *testing.T) {
	peerID, pub := nodePeerIdentity(t)
	dir, _, _ := nodeValidDirectory(t)
	f := newStartP2PFixture(t, peerID, pub, dir)
	f.p.ctx, f.p.cancel = context.WithCancel(context.Background())
	defer f.p.cancel()
	f.rt.mu.Lock()
	f.rt.prepareErrs = []error{errors.New("center temporarily unreachable")}
	f.rt.mu.Unlock()

	f.n.publisherCycle(context.Background(), f.p)

	if got := f.rt.relayCount(); got != 1 {
		t.Fatalf("暂时性 prepare 失败仍应尝试预约修复，relay calls=%d", got)
	}
	f.p.mu.RLock()
	until, at := f.p.relayUntil, f.p.relayAt
	f.p.mu.RUnlock()
	if until.IsZero() || !until.Equal(f.rt.relayUntil) || at.IsZero() {
		t.Fatalf("真成功预约才落库: until=%v at=%v", until, at)
	}
}

func equalStrings(a, b []string) bool {
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

// ---- 13. EnableP2P 把生命周期锚到调用方 ctx：SIGTERM 中止在途首次注册 ----

func TestNodeEnableP2PAnchoredContextCancelsFirstRegistration(t *testing.T) {
	regStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nodes/register" {
			once.Do(func() { close(regStarted) })
			select {
			case <-release:
			case <-r.Context().Done():
			}
			writeTestJSON(w, http.StatusCreated, map[string]uint64{"id": 1})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	// 先放行屏障、再关服务器（顺序敏感，不能用 LIFO defer）。
	t.Cleanup(func() {
		close(release)
		ts.Close()
	})
	n := New(t.TempDir(), ts.URL, "127.0.0.1:9000", 1<<20)

	// EnableP2P 对调用方 ctx（CLI signal ctx）做同一锚定。
	ctx, cancel := context.WithCancel(context.Background())
	n.anchorLifeContext(ctx)

	regDone := make(chan error, 1)
	go func() { regDone <- n.Register() }()
	<-regStarted // 首次注册在途
	cancel()     // SIGTERM：不靠 CloseP2P，锚定 ctx 取消必须中止在途注册
	select {
	case err := <-regDone:
		if err == nil {
			t.Fatal("锚定 ctx 取消后首次注册必须失败")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("锚定 ctx 取消未中止在途首次注册")
	}
	// CloseP2P 仍可 join（占位计数已释放），后续 Register 拒绝。
	if err := n.CloseP2P(); err != nil {
		t.Fatalf("CloseP2P: %v", err)
	}
	if err := n.Register(); !errors.Is(err, errNodeClosed) {
		t.Fatalf("CloseP2P 后 Register 应被拒，got %v", err)
	}
}

// 锚定只生效一次且不复活已关停的生命周期。
func TestNodeAnchorLifeContextIdempotentAndClosedRefuses(t *testing.T) {
	n := &Node{}
	first, firstCancel := context.WithCancel(context.Background())
	defer firstCancel()
	n.anchorLifeContext(first)
	n.lifeMu.Lock()
	anchored := n.lifeCtx
	n.lifeMu.Unlock()
	second, secondCancel := context.WithCancel(context.Background())
	defer secondCancel()
	n.anchorLifeContext(second) // no-op：已有生命周期
	n.lifeMu.Lock()
	ctx := n.lifeCtx
	n.lifeMu.Unlock()
	if ctx != anchored {
		t.Fatal("重复锚定不得覆盖首个生命周期 ctx")
	}
	// 锚定的生命周期 ctx 是调用方 ctx 的子 ctx：父取消必须传播。
	firstCancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("锚定 ctx 必须随调用方 ctx 取消而取消")
	}
	// CloseP2P 提前取消的通道仍在：lifeCancel 独立于调用方 ctx。
	n.lifeMu.Lock()
	cancel := n.lifeCancel
	n.lifeMu.Unlock()
	if cancel == nil {
		t.Fatal("锚定必须同时安装 lifeCancel（CloseP2P 可提前取消）")
	}

	closed := &Node{}
	closed.lifeMu.Lock()
	closed.lifeClosed = true
	closed.lifeMu.Unlock()
	closed.anchorLifeContext(context.Background())
	closed.lifeMu.Lock()
	anchoredOn := closed.lifeOn
	closed.lifeMu.Unlock()
	if anchoredOn {
		t.Fatal("已关停节点不得重新锚定生命周期")
	}
}
