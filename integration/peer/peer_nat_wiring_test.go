package peer

// peer_nat_wiring_test.go —— 第三方 NAS 零 NAT 接线的真实组件回归。
//
// 全部走真实 Master 目录 + secure EnableP2P + 生产 resolver（不手工构造
// resolver 表）；观察经 cl.HTTP.Transport 的非 master 请求 ctxwrap 注入
// peerhttp.Reporter，master 请求原样透传避免票据污染，包装形态借用
// recoveryRoundTripper。每条断言只认真实组件产出的事实：失败必须有一次真实
// 失败的拨号/断裂作证，成功必须能对上 authority 收据与真实流身份——没有对应
// 失败/成功事实时绝不声称"已证"。
//
//  1. 目标节点公布端点不带任何 unsolicited-direct 地址（test-only
//     hiddenAddrsRuntime 只覆写公布面）但有 StartP2P 同步完成的授权 relay 预约：
//     默认 normal path 的 AEAD 双块 Put/Get 全程真实 circuit，逐请求校验实际
//     路径/Fallback/目标 PeerID/conn/stream/local/remote，authority Done 指向
//     真实节点，逐记录 AEAD Open 与整文件字节一致。
//  2. 同一客户端（缓存旧 transport 地址）对同身份重启的目标：PathDirect 钉死
//     请求使陈旧缓存只能以一次真实失败的直接拨号暴露（normal path 的 relay 兜
//     底按 PeerID 路由、不依赖刷新后的地址，会把目录强刷接线无声掩盖），且
//     client.resolve 只把最终成功的 PeerDial 返回给 peerhttp——失败的那次真实
//     dial 只能经 runtime Config.Observe 的事件看到；强刷后同一请求在新地址上
//     以同一身份完成。旧地址在 rt.Close 之前留存。
//  3. security 档计划写（legacy replicas 入参被计划写忽略）由 authority 证明
//     两节点各持一份真实 AEAD 副本后，源节点 handler 的真实 ResponseWriter.
//     Write 在 32KiB 后被同步门闩挂起（响应块绝无可能完整 flush），主线程
//     closeNode 真实 runtime 后放行：同一次 Get 内故障转移到幸存者，被摘除目标
//     的首个 GET 真实断裂（失败观察 + 唯一 RequestID + 独立真实 ConnID），最终
//     内容字节/CRC/AEAD 解密完整一致，节点 ledger 见两次真实流源。

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/client"
	"atoll/pkg/contentcrypto"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"
	"atoll/pkg/types"
)

// natObserver 记录非 master 请求的逐条 Observation。
type natObserver struct {
	mu       sync.Mutex
	observed []peerhttp.Observation
}

func (o *natObserver) reporter() *peerhttp.Reporter {
	return &peerhttp.Reporter{Observe: func(obs peerhttp.Observation) {
		o.mu.Lock()
		o.observed = append(o.observed, obs)
		o.mu.Unlock()
	}}
}

// wrap 借 recoveryRoundTripper 包装 cl.HTTP.Transport：master 请求原样透传，
// 其余只注入 Reporter（不钉路径，保持生产默认 normal path）。
func (o *natObserver) wrap(cl *client.Client, masterURL string) {
	base := cl.HTTP.Transport
	cl.HTTP.Transport = recoveryRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host == masterURL {
			return base.RoundTrip(r)
		}
		return base.RoundTrip(r.Clone(peerhttp.WithReporter(r.Context(), o.reporter())))
	})
}

// wrapDirect 同 wrap，但给非 master 请求钉死 peerhttp.PathDirect（peerhttp 对
// 路径不符 fail closed）。理由：normal path 下 circuit 兜底按 PeerID 经 relay
// 路由，陈旧缓存地址失败后仍能无声成功，"目录强刷后重新发现"就无法成立；
// PathDirect 让陈旧缓存必须以真实失败暴露，也让最终成功只能落在新地址上。
func (o *natObserver) wrapDirect(cl *client.Client, masterURL string) {
	base := cl.HTTP.Transport
	cl.HTTP.Transport = recoveryRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host == masterURL {
			return base.RoundTrip(r)
		}
		ctx := peerhttp.WithPath(r.Context(), peerhttp.PathDirect)
		return base.RoundTrip(r.Clone(peerhttp.WithReporter(ctx, o.reporter())))
	})
}

func (o *natObserver) snapshot() []peerhttp.Observation {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]peerhttp.Observation(nil), o.observed...)
}

func (o *natObserver) reset() {
	o.mu.Lock()
	o.observed = nil
	o.mu.Unlock()
}

// natDialLog 收集客户端 runtime 的真实拨号事件（peertransport.Config.Observe）。
// 必须用它而非 peerhttp 观察：client.resolve 内部"陈旧地址拨号失败→目录强刷→
// 重拨"只把最终成功的 PeerDial 返回给 peerhttp，失败的那次 dial 只在 runtime
// 层有事件。
type natDialLog struct {
	mu     sync.Mutex
	events []peertransport.RuntimeEvent
}

func (l *natDialLog) observe(e peertransport.RuntimeEvent) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *natDialLog) reset() {
	l.mu.Lock()
	l.events = nil
	l.mu.Unlock()
}

// dialsTo 返回 reset 之后发往指定对端身份的 dial 事件（按发生顺序）。
func (l *natDialLog) dialsTo(remotePeerID string) []peertransport.RuntimeEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []peertransport.RuntimeEvent
	for _, e := range l.events {
		if e.Kind == "dial" && e.RemotePeerID == remotePeerID {
			out = append(out, e)
		}
	}
	return out
}

// natObservedClientPeer 与 startClientPeer（peer_direct_test.go）同一生产装配，
// 仅给真实 runtime 额外配 Observe——Observe 只能随 peertransport.New 注入，是
// 生产字段，测试用它取真实 dial 尝试。
func (m *peerMaster) natObservedClientPeer(cl *clientSecure, log *natDialLog) *peertransport.Runtime {
	m.t.Helper()
	rt, err := peertransport.New(context.Background(), peertransport.Config{
		IdentityPath:    filepath.Join(m.t.TempDir(), "client.peer.key"),
		ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"},
		DirectTimeout:   10 * time.Second,
		RelayTimeout:    20 * time.Second,
		Observe:         log.observe,
	})
	if err != nil {
		m.t.Fatalf("client runtime: %v", err)
	}
	m.t.Cleanup(func() { _ = rt.Close() })
	if err := cl.c.EnableP2P(m.ctx, rt); err != nil {
		m.t.Fatalf("client EnableP2P: %v", err)
	}
	m.t.Cleanup(func() { _ = cl.c.CloseP2P() })
	return rt
}

// ---- 任务 1：无 unsolicited-direct 端点 + 授权 relay 预约的 AEAD 双块闭环 ----

// assertRelayOnlyObservations 校验默认 normal path 的逐请求事实：所有数据观察
// 落在 logical 目标、实际电路为 relay、Fallback=true；成功响应的 PeerID 是目标
// 真实身份且 conn/stream/local/remote 齐备。
func assertRelayOnlyObservations(t *testing.T, obs []peerhttp.Observation, node *peerNode, in types.Inode) {
	t.Helper()
	objects := make([]uint64, 0, len(in.Chunks))
	for _, chunk := range in.Chunks {
		objects = append(objects, types.ChunkObjID(chunk, in.ID))
	}
	if err := validateRelayOnlyObservations(obs, node.nodeDataAddr(), node.rt.PeerID(), objects); err != nil {
		t.Fatal(err)
	}
}

func validateRelayOnlyObservations(obs []peerhttp.Observation, target, peerID string, objects []uint64) error {
	expected := make(map[string]bool, 2*len(objects))
	for _, id := range objects {
		path := "/objects/" + strconv.FormatUint(id, 10)
		expected[http.MethodPut+" "+path] = true
		expected[http.MethodGet+" "+path] = true
	}
	if len(expected) == 0 {
		return fmt.Errorf("no authoritative objects to verify")
	}
	dials := map[string]peerhttp.Observation{}
	responses := map[string]bool{}
	attempts := map[string]int{}
	successes := map[string]int{}
	pendingFailure := map[string]bool{}
	transient := func(kind string) bool {
		return kind == peerhttp.ErrorRead || kind == peerhttp.ErrorConnect || kind == peerhttp.ErrorTimeout || kind == peerhttp.ErrorCanceled
	}
	for _, o := range obs {
		key := o.Method + " " + o.RequestPath
		if o.Master || o.Target != target || o.RequestID == "" || !expected[key] {
			return fmt.Errorf("observation has no matching object request: %+v", o)
		}
		if !o.Fallback {
			return fmt.Errorf("normal relay request omitted fallback: %+v", o)
		}
		if o.Phase == peerhttp.PhaseDial {
			if _, exists := dials[o.RequestID]; exists {
				return fmt.Errorf("duplicate request dial: %+v", o)
			}
			dials[o.RequestID] = o
			attempts[key]++
			if attempts[key] > 3 {
				return fmt.Errorf("object request exceeded its retry bound: %s", key)
			}
			if o.ErrorKind != peerhttp.ErrorNone {
				if !transient(o.ErrorKind) || o.Path != peerhttp.PathUnknown || o.Identity != "" || o.ConnectionID != "" || o.StreamID != "" || o.RemoteAddress != "" {
					return fmt.Errorf("failed dial claimed nonexistent connection facts: %+v", o)
				}
				pendingFailure[key] = true
				continue
			}
		} else if o.Phase == peerhttp.PhaseResponse {
			dial, ok := dials[o.RequestID]
			if !ok || dial.ErrorKind != peerhttp.ErrorNone || responses[o.RequestID] || dial.Method != o.Method || dial.RequestPath != o.RequestPath || dial.ConnectionID != o.ConnectionID || dial.StreamID != o.StreamID || dial.RemoteAddress != o.RemoteAddress {
				return fmt.Errorf("response was not bound to its accepted dial: %+v", o)
			}
			responses[o.RequestID] = true
		} else {
			return fmt.Errorf("unknown observation phase: %+v", o)
		}
		if o.Path != peerhttp.PathRelay || o.Identity != peerID || o.ConnectionID == "" || o.StreamID == "" || o.LocalAddress == "" || !strings.Contains(o.RemoteAddress, "/p2p-circuit") {
			return fmt.Errorf("accepted object stream lacks authenticated circuit facts: %+v", o)
		}
		if o.Phase != peerhttp.PhaseResponse {
			continue
		}
		if o.ErrorKind != peerhttp.ErrorNone {
			if !transient(o.ErrorKind) {
				return fmt.Errorf("unexpected response failure: %+v", o)
			}
			pendingFailure[key] = true
			continue
		}
		want := http.StatusOK
		if o.Method == http.MethodPut {
			want = http.StatusCreated
		}
		if o.Status != want {
			return fmt.Errorf("object request returned an unexpected receipt: %+v", o)
		}
		successes[key]++
		pendingFailure[key] = false
	}
	for key := range expected {
		if successes[key] != 1 || pendingFailure[key] {
			return fmt.Errorf("object request never completed after its last failure: %s successes=%d", key, successes[key])
		}
	}
	for id, dial := range dials {
		if dial.ErrorKind == peerhttp.ErrorNone && !responses[id] {
			return fmt.Errorf("accepted request has no response outcome: %s", id)
		}
	}
	return nil
}

func TestPeerNATRelayOnlyWiringAEADRoundTrip(t *testing.T) {
	pki := newTestPKI(t)
	kek, err := contentcrypto.NewKEKFromSecret("peer-nat-wiring-key", bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	m := newPeerMasterOpts(t, pki, masterOpts{contentKEK: kek})
	m.createUser("alice")

	var nLedger nodeLedger
	// relay 预约由 StartP2P 同步完成（startNode 返回即已预约）；预约本身由后续
	// circuit 拨号真实可用作证。
	node := m.startNodeOpts(filepath.Join(t.TempDir(), "node"), m.nodeInvite(), nodeOpts{hideTransportAddrs: true, ledger: &nLedger})

	cl, res := m.login("alice")
	// 经真实 master 控制面核验公布形态：端点绑定真实节点身份、无直接地址，且
	// master 公布 relay 基础设施（规划在空 direct 地址下仍然可行）。
	d := m.peerDirectory(res.Token, userSpaceID(res))
	ep, infra := nodeEndpoint(t, d, node.nodeDataAddr())
	if ep.PeerID != node.rt.PeerID() {
		t.Fatalf("目录端点身份不符: got %q want %q", ep.PeerID, node.rt.PeerID())
	}
	if len(ep.Addresses) != 0 {
		t.Fatalf("hidden-addr 节点端点仍公布了直接地址: %v", ep.Addresses)
	}
	if !infra.Relay {
		t.Fatal("master 目录未公布 relay 基础设施，circuit 不可达")
	}

	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)
	obs := &natObserver{}
	obs.wrap(cl, m.url)

	oldChunkSize := types.ChunkSize
	types.ChunkSize = 128 << 10
	t.Cleanup(func() { types.ChunkSize = oldChunkSize })
	payload := bytes.Repeat([]byte("nat-wiring-aead-two-blocks-"), 8000)[:192<<10]
	if err := cl.PutChunkedReader("/nat-relay.bin", int64(len(payload)), bytes.NewReader(payload), 1); err != nil {
		t.Fatalf("relay-only AEAD 双块上传: %v", err)
	}

	in := findFile(t, m.store, "nat-relay.bin")
	if len(in.Chunks) != 2 || in.Content == nil {
		t.Fatalf("应有 AEAD 双块清单: %+v", in)
	}
	logicalOffset := 0
	for _, chunk := range in.Chunks {
		// authority 收据必须指向真实节点，而非任意非零数字。
		if len(chunk.Done) != 1 || len(chunk.Replicas) != 1 || chunk.Done[0] != chunk.Replicas[0] || chunk.Done[0] != node.node.NodeIDForTest() {
			t.Fatalf("块 %d 收据不完整或不指向真实节点: done=%v replicas=%v nodeID=%d", chunk.Index, chunk.Done, chunk.Replicas, node.node.NodeIDForTest())
		}
		verifyAEADChunk(t, m, kek, node, chunk, payload[logicalOffset:logicalOffset+int(chunk.LogicalSize)])
		logicalOffset += int(chunk.LogicalSize)
	}

	out := filepath.Join(t.TempDir(), "out.bin")
	if err := cl.Get("/nat-relay.bin", out); err != nil {
		t.Fatalf("relay-only Get: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("relay-only 读回不一致: %v", err)
	}

	// 写路径真实流源是客户端 peer id（来自流身份，非 header）。
	for _, r := range nLedger.snapshot() {
		if r.method == http.MethodPut && strings.HasPrefix(r.path, "/objects/") && r.source != cs.rt.PeerID() {
			t.Fatalf("节点见到的 PUT 源 %q 不是客户端真实 peer id: %s", r.source, r.path)
		}
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	assertRelayOnlyObservations(t, obs.observed, node, in)
}

// ---- 任务 2：同 client 缓存复用，目标同身份重启后经目录强刷重新发现 ----

func TestPeerNATRestartSameIdentityCachedRediscovery(t *testing.T) {
	pki := newTestPKI(t)
	m := newPeerMaster(t, pki)
	m.createUser("alice")

	dataDir := filepath.Join(t.TempDir(), "node")
	invite := m.nodeInvite()
	n1 := m.startNodeOpts(dataDir, invite, nodeOpts{})
	logicalAddr := n1.nodeDataAddr()
	peerID1 := n1.rt.PeerID()

	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	dials := &natDialLog{}
	cs.rt = m.natObservedClientPeer(cs, dials)
	obs := &natObserver{}
	obs.wrapDirect(cl, m.url)

	payload := []byte("nat-restart-rediscovery-payload")
	cs.path = "/nat-restart.bin"
	if _, err := cl.PutSmall(cs.path, payload, 1, false); err != nil {
		t.Fatalf("PutSmall before restart: %v", err)
	}
	out1 := filepath.Join(t.TempDir(), "out1.bin")
	if err := cl.Get(cs.path, out1); err != nil {
		t.Fatalf("Get before restart: %v", err)
	}
	// 旧 transport 地址必须在 rt.Close 之前留存：Close 之后 Addresses() 可能为空，
	// 之后再取旧地址就只能拿到空表、"地址已变化"会变成无证据的空话。
	oldAddrs := append([]string(nil), n1.rt.Addresses()...)
	if len(oldAddrs) == 0 {
		t.Fatal("重启前节点 transport 地址为空，无法证明地址变化")
	}
	remoteBefore := ""
	for _, o := range obs.snapshot() {
		if o.Phase == peerhttp.PhaseResponse && o.Target == logicalAddr && o.ErrorKind == peerhttp.ErrorNone {
			remoteBefore = o.RemoteAddress
		}
	}
	if remoteBefore == "" {
		t.Fatalf("重启前未见明确目标 GET 的成功响应观察: %+v", obs.snapshot())
	}
	if !containsString(oldAddrs, remoteBefore) {
		t.Fatalf("重启前成功响应的 remote %q 不在节点公布的旧地址中: %v", remoteBefore, oldAddrs)
	}

	// 同一 dataDir、同一逻辑地址重启：同 NodeID/PeerID，新 transport 地址。
	m.closeNode(n1)
	n2 := m.startNodeAddr(dataDir, invite, logicalAddr, nodeOpts{})
	if n2.node.NodeIDForTest() != n1.node.NodeIDForTest() || n2.rt.PeerID() != peerID1 {
		t.Fatalf("重启改变了身份: nodeID %d->%d peer %q->%q", n1.node.NodeIDForTest(), n2.node.NodeIDForTest(), peerID1, n2.rt.PeerID())
	}
	if !transportAddrsChanged(oldAddrs, n2.rt.Addresses()) {
		t.Fatalf("重启后 transport 地址未变化: %v", n2.rt.Addresses())
	}

	// 同一客户端（缓存旧地址）重启后 Get：PathDirect 钉死下陈旧地址只能真实
	// 拨号失败，resolve 强刷目录后重拨新地址成功。请求前重置两类观察，保证
	// 下面的事件序列只属于这一次 Get。
	dials.reset()
	obs.reset()
	out2 := filepath.Join(t.TempDir(), "out2.bin")
	if err := cl.Get(cs.path, out2); err != nil {
		t.Fatalf("同 client 重启后 Get: %v", err)
	}
	got, err := os.ReadFile(out2)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("重启后读回不一致: %v", err)
	}

	// runtime 层真实拨号序列：第一个 dial 必须失败（缓存复用+强刷前的事实），
	// 其后才有成功 dial 落在新地址上——无失败事件就不能声称缓存复用已证。
	events := dials.dialsTo(peerID1)
	if len(events) < 2 {
		t.Fatalf("重启后应有失败+成功两次真实拨号事件: %+v", events)
	}
	if events[0].Success || events[0].ErrorKind == "" {
		t.Fatalf("第一次真实拨号未以失败记录（缓存复用未证实）: %+v", events[0])
	}
	success := peertransport.RuntimeEvent{}
	foundSuccess := false
	for _, e := range events[1:] {
		if e.Success {
			success = e
			foundSuccess = true
			break
		}
	}
	if !foundSuccess {
		t.Fatalf("失败拨号之后没有成功拨号事件: %+v", events)
	}
	if success.Path != peerhttp.PathDirect || success.Fallback {
		t.Fatalf("重拨必须是不带回退的直接拨号: %+v", success)
	}
	newAddrs := n2.rt.Addresses()
	if !containsString(newAddrs, success.RemoteAddress) || containsString(oldAddrs, success.RemoteAddress) {
		t.Fatalf("重拨必须落在新 transport 地址上: got %q new=%v old=%v", success.RemoteAddress, newAddrs, oldAddrs)
	}

	// peerhttp 层：同一 Get 只报最终成功——resolve 吞掉中间失败，这正是必须用
	// runtime Observe 取失败事实的原因；响应事实与成功 dial 事件逐项对上。
	remoteAfter := ""
	for _, o := range obs.snapshot() {
		if o.Master || o.Target != logicalAddr {
			t.Fatalf("Get 观察落在非目标: %+v", o)
		}
		if o.Phase == peerhttp.PhaseDial {
			if o.ErrorKind != peerhttp.ErrorNone {
				t.Fatalf("peerhttp 不应见到 resolve 内部的中间失败: %+v", o)
			}
			if o.Path != peerhttp.PathDirect {
				t.Fatalf("direct 钉死下接受的连接必须是 direct: %+v", o)
			}
			continue
		}
		if o.Phase != peerhttp.PhaseResponse {
			continue
		}
		if o.Identity != peerID1 {
			t.Fatalf("重启后 serving PeerID 应为同一目标身份: got %q", o.Identity)
		}
		if o.Path != peerhttp.PathDirect {
			t.Fatalf("重启后实际路径 %q, want direct", o.Path)
		}
		if o.RequestID == "" {
			t.Fatalf("响应观察缺 RequestID: %+v", o)
		}
		remoteAfter = o.RemoteAddress
	}
	if remoteAfter == "" {
		t.Fatalf("重启后未见成功响应观察: %+v", obs.snapshot())
	}
	if remoteAfter != success.RemoteAddress {
		t.Fatalf("响应事实与成功 dial 事件不一致: response=%q dial=%q", remoteAfter, success.RemoteAddress)
	}
	if remoteAfter == remoteBefore {
		t.Fatalf("重启后必须经新 transport 地址完成: before=%q after=%q", remoteBefore, remoteAfter)
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ---- 任务 3：双节点 ≥2 Done，读中摘除源目标，同一 Get 故障转移到幸存者 ----

// natServerGate 仅测试：源节点 handler 真实 ResponseWriter.Write 的同步门闩。
// 必须设在服务端——客户端对 GET 响应做 io.ReadAll，若只数客户端已读字节，服务
// 端可把整块推入接收缓冲造成"先 EOF 成功"的假象；挂起真实 Write 才保证本块
// 无法完整 flush。字节只统计 handler 真实交给底层 writer 的部分（不预读、不伪
// 造进度）；阻塞尊重请求 ctx 取消。经 nodeOpts.handlerWrapper（仅测试注入点）
// 挂接，data/peer 两面共用同一最终 handler，请求从任一面到达都生效。
type natServerGate struct {
	threshold   int64
	mu          sync.Mutex
	served      map[string]int64
	crossed     bool
	node        string
	path        string
	signal      chan struct{}
	releaseCh   chan struct{}
	releaseOnce sync.Once
}

func newNatServerGate(threshold int64) *natServerGate {
	return &natServerGate{threshold: threshold, served: map[string]int64{}, signal: make(chan struct{}), releaseCh: make(chan struct{})}
}

// wrapNode 返回标记为 tag 的节点的 handler 包装：只门闩真实对象 GET。
func (g *natServerGate) wrapNode(tag string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/objects/") {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(&natGatedWriter{ResponseWriter: w, gate: g, tag: tag, path: r.URL.Path, ctx: r.Context()}, r)
		})
	}
}

func (g *natServerGate) record(tag string, n int) {
	g.mu.Lock()
	g.served[tag] += int64(n)
	g.mu.Unlock()
}

// cross 记录首个越阈点并通知主线程；release 后幸存者的完整响应会再次越阈，
// 只记字节不再触发。
func (g *natServerGate) cross(tag, path string) {
	g.mu.Lock()
	first := !g.crossed
	g.crossed = true
	if first {
		g.node, g.path = tag, path
	}
	g.mu.Unlock()
	if first {
		close(g.signal)
	}
}

// release 幂等放行被门闩挂起的服务端写；失败路径 cleanup 必须先于节点
// Server.Shutdown（注册晚于节点启动，LIFO 保证），否则关闭会挂住。
func (g *natServerGate) release() { g.releaseOnce.Do(func() { close(g.releaseCh) }) }

func (g *natServerGate) firedNode() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.node
}

func (g *natServerGate) firedPath() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.path
}

func (g *natServerGate) servedBytes(tag string) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.served[tag]
}

type natGatedWriter struct {
	http.ResponseWriter
	gate   *natServerGate
	tag    string
	path   string
	ctx    context.Context
	passed int64
	gated  bool
}

// Write 把真实 handler 写出的字节逐段交给底层 writer：阈值内的部分原样放行，
// 越阈后挂起后续写直至 release 或请求 ctx 取消。返回值只计真实交给底层的字节，
// 不虚报消费量。
func (w *natGatedWriter) Write(p []byte) (int, error) {
	consumed := 0
	if !w.gated {
		room := w.gate.threshold - w.passed
		if room > 0 {
			n := int64(len(p))
			if n > room {
				n = room
			}
			wn, err := w.ResponseWriter.Write(p[:n])
			consumed += wn
			w.passed += int64(wn)
			w.gate.record(w.tag, wn)
			if err != nil || wn < int(n) {
				return consumed, err
			}
			p = p[wn:]
		}
		if len(p) > 0 || w.passed >= w.gate.threshold {
			w.gated = true
			w.gate.cross(w.tag, w.path)
		}
		if len(p) == 0 {
			return consumed, nil
		}
	}
	select {
	case <-w.gate.releaseCh:
	case <-w.ctx.Done():
		return consumed, w.ctx.Err()
	}
	wn, err := w.ResponseWriter.Write(p)
	consumed += wn
	w.passed += int64(wn)
	w.gate.record(w.tag, wn)
	return consumed, err
}

// ledgerHasGetObject 报告 ledger 是否存在 GET 指定对象路径且流源为 source 的记录。
func ledgerHasGetObject(l *nodeLedger, path, source string) bool {
	for _, r := range l.snapshot() {
		if r.method == http.MethodGet && r.path == path && r.source == source {
			return true
		}
	}
	return false
}

type natReadBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

func (b *natReadBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.release)
	}
	return n, err
}

func (b *natReadBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

func TestPeerNATMidGetNodeLossFailsOverToSurvivor(t *testing.T) {
	pki := newTestPKI(t)
	kek, err := contentcrypto.NewKEKFromSecret("peer-nat-failover-key", bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	m := newPeerMasterOpts(t, pki, masterOpts{contentKEK: kek, maxReplicas: 2})
	m.createUser("alice")

	var led1, led2 nodeLedger
	gate := newNatServerGate(32 << 10)
	n1 := m.startNodeOpts(filepath.Join(t.TempDir(), "n1"), m.nodeInvite(),
		nodeOpts{ledger: &led1, handlerWrapper: gate.wrapNode("n1")})
	n2 := m.startNodeOpts(filepath.Join(t.TempDir(), "n2"), m.nodeInvite(),
		nodeOpts{ledger: &led2, handlerWrapper: gate.wrapNode("n2")})
	byTag := map[string]*peerNode{"n1": n1, "n2": n2}
	// 失败路径下门闩放行必须先于 closeNode 的 Server.Shutdown（LIFO：本清理
	// 晚于节点注册，先执行），任何 Fatalf 都不会把节点关闭挂死在活跃 handler 上。
	t.Cleanup(gate.release)

	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)
	obs := &natObserver{}
	obs.wrap(cl, m.url)

	// security 档（路径继承至根）：计划写的布局由 master 决定，PutChunkedReader
	// 的 legacy replicas 入参被计划写忽略——刻意传 1，2 副本只能来自 authority
	// 布局，下面的断言因此不受入参污染。
	if _, err := cl.SetProtection("/", types.ProtectionSecurity); err != nil {
		t.Fatalf("SetProtection security: %v", err)
	}

	oldChunkSize := types.ChunkSize
	types.ChunkSize = 512 << 10
	t.Cleanup(func() { types.ChunkSize = oldChunkSize })
	payload := bytes.Repeat([]byte("nat-midget-failover-identity-"), 40000)[:1<<20]
	if err := cl.PutChunkedReader("/nat-failover.bin", int64(len(payload)), bytes.NewReader(payload), 1); err != nil {
		t.Fatalf("双副本 AEAD 上传: %v", err)
	}
	in := findFile(t, m.store, "nat-failover.bin")
	if len(in.Chunks) != 2 {
		t.Fatalf("应有双块清单: chunks=%d", len(in.Chunks))
	}
	nodeIDs := map[uint64]bool{n1.node.NodeIDForTest(): true, n2.node.NodeIDForTest(): true}
	logicalOffset := 0
	for _, chunk := range in.Chunks {
		// authority 实证 2 副本：布局与 Done 收据都是两个不同真实节点——单目标
		// 或单入参都不构成 2 副本证据。
		if len(chunk.Replicas) != 2 || len(chunk.Done) != 2 {
			t.Fatalf("块 %d 副本/Done 应为两节点: replicas=%v done=%v", chunk.Index, chunk.Replicas, chunk.Done)
		}
		if chunk.Replicas[0] == chunk.Replicas[1] || !nodeIDs[chunk.Replicas[0]] || !nodeIDs[chunk.Replicas[1]] {
			t.Fatalf("块 %d 副本未落在两个真实节点上: %v (nodes %v)", chunk.Index, chunk.Replicas, nodeIDs)
		}
		for _, id := range chunk.Done {
			if !nodeIDs[id] {
				t.Fatalf("块 %d Done 收据指向未知节点 %d", chunk.Index, id)
			}
		}
		// 两份真实副本都逐记录 AEAD Open 校验（CRC + 解密 + 字节一致）。
		want := payload[logicalOffset : logicalOffset+int(chunk.LogicalSize)]
		verifyAEADChunk(t, m, kek, n1, chunk, want)
		verifyAEADChunk(t, m, kek, n2, chunk, want)
		logicalOffset += int(chunk.LogicalSize)
	}
	chunk0ID := types.ChunkObjID(in.Chunks[0], in.ID)
	chunk0Path := "/objects/" + strconv.FormatUint(chunk0ID, 10)

	getCtx, cancelGet := context.WithCancel(m.ctx)
	base := cl.HTTP.Transport
	cl.HTTP.Transport = recoveryRoundTripper(func(req *http.Request) (*http.Response, error) {
		ctx, cancel := context.WithCancel(req.Context())
		stop := context.AfterFunc(getCtx, cancel)
		response, err := base.RoundTrip(req.Clone(ctx))
		if err != nil || response == nil || response.Body == nil {
			stop()
			cancel()
			return response, err
		}
		response.Body = &natReadBody{ReadCloser: response.Body, release: func() { stop(); cancel() }}
		return response, nil
	})
	getErr := make(chan error, 1)
	getDone := make(chan struct{})
	// 失败也先释放 handler、取消并 join，再恢复全局和关闭节点。
	t.Cleanup(func() {
		gate.release()
		cancelGet()
		<-getDone
	})
	out := filepath.Join(t.TempDir(), "out.bin")
	go func() {
		defer close(getDone)
		getErr <- cl.Get("/nat-failover.bin", out)
	}()

	select {
	case <-gate.signal:
	case err := <-getErr:
		t.Fatalf("Get 在门闩触发前返回 (err=%v)——源服务端写门闩未生效", err)
	case <-time.After(45 * time.Second):
		t.Fatal("45s 内源节点未写出 >=32KiB 真实字节（门闩未触发）")
	}
	closedNode, ok := byTag[gate.firedNode()]
	if !ok {
		t.Fatalf("门闩节点 %q 不是已知节点", gate.firedNode())
	}
	if gate.firedPath() != chunk0Path {
		t.Fatalf("门闩落在 %q, want 首块 %q", gate.firedPath(), chunk0Path)
	}
	survivor := n1
	if closedNode == n1 {
		survivor = n2
	}
	if got := gate.servedBytes(gate.firedNode()); got < 32<<10 || got >= int64(in.Chunks[0].Size) {
		t.Fatalf("源 handler 真实写出字节应落在 [32KiB, 块 stored %d): %d", in.Chunks[0].Size, got)
	}

	// 主线程摘除源目标（真实 closeNode：data/peer server + CloseP2P + rt.Close），
	// 再放行被挂起的服务端写——旧流真实断裂，绝不透明迁移。
	m.closeNode(closedNode)
	gate.release()

	select {
	case err := <-getErr:
		if err != nil {
			t.Fatalf("同一 Get 内故障转移失败: %v", err)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("Get 未在故障转移后完成")
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("故障转移后内容不一致: %v", err)
	}

	// 被中断块的 GET 响应观察恰好两条：被摘除目标失败在先、幸存者完整在后；
	// 两条是独立请求（唯一 RequestID、真实独立 ConnID/StreamID——旧流断裂后
	// 新建电路，而非不透明复用）。PUT 与 GET 共用对象路径，必须按方法区分。
	var first, second *peerhttp.Observation
	responses := 0
	for _, o := range obs.snapshot() {
		if o.Method != http.MethodGet || o.Phase != peerhttp.PhaseResponse || o.RequestPath != chunk0Path {
			continue
		}
		responses++
		cp := o
		switch responses {
		case 1:
			first = &cp
		case 2:
			second = &cp
		default:
			t.Fatalf("被中断块出现第三条 GET 响应观察: %+v", o)
		}
	}
	if first == nil || second == nil {
		t.Fatalf("缺少被中断块的两条 GET 响应观察: %+v", obs.snapshot())
	}
	if first.Target != closedNode.nodeDataAddr() || second.Target != survivor.nodeDataAddr() {
		t.Fatalf("GET 观察目标不符: first=%q second=%q", first.Target, second.Target)
	}
	if first.Identity != closedNode.rt.PeerID() {
		t.Fatalf("首个 GET 的真实服务身份 %q, want 被摘除目标 %q", first.Identity, closedNode.rt.PeerID())
	}
	if first.ErrorKind == peerhttp.ErrorNone {
		t.Fatalf("被摘除目标的首个 GET 不得记为成功: %+v", first)
	}
	if second.Identity != survivor.rt.PeerID() {
		t.Fatalf("完成 GET 的真实服务身份 %q, want 幸存者 %q", second.Identity, survivor.rt.PeerID())
	}
	if second.ErrorKind != peerhttp.ErrorNone || second.Status != http.StatusOK {
		t.Fatalf("幸存者 GET 未成功完成: %+v", second)
	}
	if first.RequestID == "" || second.RequestID == "" || first.RequestID == second.RequestID {
		t.Fatalf("两条 GET 必须是两个唯一请求: %q vs %q", first.RequestID, second.RequestID)
	}
	if first.ConnectionID == "" || second.ConnectionID == "" || first.ConnectionID == second.ConnectionID || first.StreamID == second.StreamID {
		t.Fatalf("两条 GET 必须落在真实独立连接上: %+v vs %+v", first, second)
	}
	// 两条 GET 都真实到达节点（流级源 = 客户端 peer id，非 header 伪造）。
	closedLed, survivorLed := &led1, &led2
	if closedNode == n2 {
		closedLed, survivorLed = &led2, &led1
	}
	if !ledgerHasGetObject(closedLed, chunk0Path, cs.rt.PeerID()) {
		t.Fatal("被摘除节点未见首个 GET 的真实流源记录")
	}
	if !ledgerHasGetObject(survivorLed, chunk0Path, cs.rt.PeerID()) {
		t.Fatal("幸存节点未见完成 GET 的真实流源记录")
	}
}
