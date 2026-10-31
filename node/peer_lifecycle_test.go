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
