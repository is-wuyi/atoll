package node

// legacy 直写先 PUT 后 commit：仅 sentinel errLegacyContentUncommitted 在预算内
// 等待（不消耗传输/网络错误的原 3 次预算）。三个确定性场景：迟 commit 复制仍
// 完成（>原 3 次窗口、真实字节+Done）、永不提交有界放弃零 payload、非 sentinel
// 错误恰好原 3 次。计数翻转触发提交态，不 sleep 整个预算。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/types"
)

// replicationStubMaster 按 committed 标志返回合法的 legacy 复制计划并接收
// verified 回执。回执只有在对象身份/size/checksum 与提交态一致且节点在副本集
// 内才记 Done（镜像 master handleVerifiedReplica 的闸，缺字段/伪造一律 409，
// node 侧按 4xx 停止，不得误判成功）。commitAfterGets>0 时第 N 次取计划后自动
// 翻转提交态：计数翻转的确定性迟 commit，不依赖墙钟。
type replicationStubMaster struct {
	mu              sync.Mutex
	srv             *httptest.Server
	planGets        int
	committed       bool
	commitAfterGets int
	force500        bool
	doneSet         map[uint64]bool

	objectID uint64
	size     int64
	checksum uint32
	replicas []uint64
	targets  []types.NodeInfo
	sources  []types.NodeInfo
}

func newReplicationStubMaster(t *testing.T, objectID uint64, size int64, checksum uint32, targets, sources []types.NodeInfo) *replicationStubMaster {
	t.Helper()
	m := &replicationStubMaster{
		doneSet:  map[uint64]bool{},
		objectID: objectID,
		size:     size,
		checksum: checksum,
		replicas: []uint64{1, 2, 3},
		targets:  targets,
		sources:  sources,
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *replicationStubMaster) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/files/replication":
		m.mu.Lock()
		m.planGets++
		if m.commitAfterGets > 0 && m.planGets > m.commitAfterGets {
			m.committed = true
		}
		committed, force500 := m.committed, m.force500
		objectID, size, checksum := m.objectID, m.size, m.checksum
		m.mu.Unlock()
		if force500 {
			http.Error(w, "master down", http.StatusInternalServerError)
			return
		}
		// 未提交态：Size=0 且无校验和——sentinel 的精确触发条件；提交态带
		// 真实 size/CRC 与主副本 Done。
		d := types.ObjectIntegrity{ObjectID: objectID, Replicas: m.replicas}
		if committed {
			d.Size = size
			d.ChecksumKnown = true
			d.Checksum = checksum
			d.Done = []uint64{1}
		}
		writeJSON(w, http.StatusOK, types.ReplicationPlan{
			Protocol: types.IntegrityProtocol,
			Object:   d,
			Targets:  m.targets,
			Sources:  m.sources,
		})
	case r.Method == http.MethodPost && r.URL.Path == "/files/replicated/verified":
		var req struct {
			Object types.ObjectIntegrity `json:"object"`
			NodeID uint64                `json:"node_id"`
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err := json.Unmarshal(raw, &req); err != nil || req.NodeID == 0 {
			http.Error(w, "bad receipt", http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		objectID, size, checksum := m.objectID, m.size, m.checksum
		m.mu.Unlock()
		// 闸与生产一致：身份/size/checksum 匹配且节点是副本成员才记 Done。
		if req.Object.ObjectID != objectID ||
			!req.Object.ChecksumKnown || req.Object.Checksum != checksum ||
			req.Object.Size != size ||
			!types.ContainsUint64(m.replicas, req.NodeID) {
			httpError(w, http.StatusConflict, "receipt does not match committed object")
			return
		}
		m.mu.Lock()
		m.doneSet[req.NodeID] = true
		m.mu.Unlock()
		// 生产 handleVerifiedReplica 200 返回 {"marked":true}；node 侧仅按状态
		// 码判定成功，此处同形。
		writeJSON(w, http.StatusOK, map[string]bool{"marked": true})
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (m *replicationStubMaster) snapshot() (planGets int, committed bool, done int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.planGets, m.committed, len(m.doneSet)
}

// pushLedger 包在从副本真实 handler 外：记录到达的 replicate push 次数与字节，
// 证明确实有 2 次 push 且字节数正确，而非仅凭回执。
type pushLedger struct {
	inner  http.Handler
	pushes atomic.Int64
	bytes  atomic.Int64
}

func (h *pushLedger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/replicate/") {
		h.pushes.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, types.ChunkSize+1<<20))
		if err == nil {
			h.bytes.Add(int64(len(body)))
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	}
	h.inner.ServeHTTP(w, r)
}

// putLegacyObject 走真实 PUT /objects 入口（handlePut 存对象后自行 spawn
// replicateToPeers，与生产同一入口）。
func putLegacyObject(t *testing.T, serverURL string, objectID uint64, content []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut,
		serverURL+"/objects/"+strconv.FormatUint(objectID, 10), bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", types.CRC32C(content)))
	req.ContentLength = int64(len(content))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT /objects/%d: status %d", objectID, resp.StatusCode)
	}
}

// ---- 1. 迟 commit：超过原 3 次窗口后才提交，复制仍完成 ----

func TestLegacyReplicationWaitsForLateCommit(t *testing.T) {
	content := bytes.Repeat([]byte("integrity-"), 5000) // 50000B，与回归用例同量级
	const objectID = uint64(2)

	var nodeAddrs [3]string
	var nodeURLs [3]string
	ledgers := make([]*pushLedger, 3)
	nodes := make([]*Node, 3)
	for i := range nodes {
		nodes[i] = New(t.TempDir(), "", "", 1<<30) // masterURL 在 stub 创建后回填
		nodes[i].SetNodeIDForTest(uint64(i + 1))
		ledgers[i] = &pushLedger{inner: nodes[i].Handler()}
		srv := httptest.NewServer(ledgers[i])
		t.Cleanup(srv.Close)
		nodeURLs[i] = srv.URL                       // client 直连用完整 URL
		nodeAddrs[i] = srv.Listener.Addr().String() // master 计划里的 addr 是 host:port
	}
	master := newReplicationStubMaster(t, objectID, int64(len(content)), types.CRC32C(content),
		[]types.NodeInfo{{ID: 2, Addr: nodeAddrs[1]}, {ID: 3, Addr: nodeAddrs[2]}},
		[]types.NodeInfo{{ID: 1, Addr: nodeAddrs[0]}})
	// 计数翻转：前 3 次计划取数未提交（覆盖原实现 0/1/3s 的整个窗口），第 4 次
	// 起已提交——原实现第 3 次后放弃必然失败；预算 15s + 退避封顶 2s（生产为 0
	// → 30s 默认），成功路径计划取数必然 > 3。
	master.commitAfterGets = 3
	for _, n := range nodes {
		n.masterURL = master.srv.URL
	}
	nodes[0].legacyUncommittedWait = 15 * time.Second

	putLegacyObject(t, nodeURLs[0], objectID, content)

	deadline := time.Now().Add(25 * time.Second)
	for {
		_, _, done := master.snapshot()
		if done == 3 {
			break
		}
		if time.Now().After(deadline) {
			planGets, committed, done := master.snapshot()
			t.Fatalf("迟 commit 后复制未完成: planGets=%d committed=%v done=%d", planGets, committed, done)
		}
		time.Sleep(50 * time.Millisecond)
	}

	planGets, _, done := master.snapshot()
	if planGets <= 3 {
		t.Fatalf("计划取数应超过原 3 次硬上限（证明等待生效），got %d", planGets)
	}
	if done != 3 {
		t.Fatalf("verified 回执应集齐 3 节点，got %d", done)
	}
	// push 台账：两次从副本 push，字节与内容等长。
	for i, lg := range ledgers[1:] {
		if got := lg.pushes.Load(); got != 1 {
			t.Fatalf("从副本 %d 应恰好 1 次 push，got %d", i+2, got)
		}
		if got := lg.bytes.Load(); got != int64(len(content)) {
			t.Fatalf("从副本 %d push 字节应 %d，got %d", i+2, len(content), got)
		}
	}
	// 从副本落盘逐字节一致（真实 handler CRC 校验之外的双保险）。
	for i, n := range nodes[1:] {
		got, err := os.ReadFile(n.objectPathForTest(objectID))
		if err != nil {
			t.Fatalf("从副本 %d 无对象: %v", i+2, err)
		}
		if !bytes.Equal(got, content) {
			t.Fatalf("从副本 %d 内容不符: %d 字节", i+2, len(got))
		}
	}
}

// ---- 2. 永不提交：预算内有界放弃，零 payload ----

func TestLegacyReplicationGivesUpAfterBudgetWhenNeverCommitted(t *testing.T) {
	const objectID = uint64(2)
	var pushHits atomic.Int64
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/replicate/") {
			pushHits.Add(1)
		}
		http.Error(w, "unexpected", http.StatusNotFound)
	}))
	t.Cleanup(targetSrv.Close)

	master := newReplicationStubMaster(t, objectID, 0, 0,
		[]types.NodeInfo{{ID: 2, Addr: targetSrv.Listener.Addr().String()}},
		[]types.NodeInfo{{ID: 1, Addr: "127.0.0.1:1"}})

	primary := New(t.TempDir(), master.srv.URL, "", 1<<30)
	primary.SetNodeIDForTest(1)
	primary.legacyUncommittedWait = 600 * time.Millisecond // 注入短预算

	start := time.Now()
	primary.replicateToPeers(objectID) // 同步调用：返回即预算结束
	elapsed := time.Since(start)

	// 预算即硬上界：见过 sentinel 后元数据请求按 remaining 收窄，截止后不再
	// 发起新请求，总耗时不应显著超过预算。
	if elapsed >= 2*time.Second {
		t.Fatalf("预算 600ms 应有界返回，实际 %v", elapsed)
	}
	if pushHits.Load() != 0 {
		t.Fatalf("永不提交不得推送 payload，push=%d", pushHits.Load())
	}
	master.mu.Lock()
	gets := master.planGets
	master.mu.Unlock()
	if gets < 1 || gets > 3 {
		t.Fatalf("未提交等待的取数应收敛在预算内（1~3 次），got %d", gets)
	}
}

// ---- 3. 非 sentinel 错误：恰好原 3 次尝试，不进入等待预算 ----

func TestLegacyReplicationNonSentinelErrorKeepsThreeAttempts(t *testing.T) {
	const objectID = uint64(2)
	master := newReplicationStubMaster(t, objectID, 0, 0,
		[]types.NodeInfo{{ID: 2, Addr: "127.0.0.1:1"}},
		[]types.NodeInfo{{ID: 1, Addr: "127.0.0.1:1"}})
	master.mu.Lock()
	master.force500 = true
	master.mu.Unlock()

	primary := New(t.TempDir(), master.srv.URL, "", 1<<30)
	primary.SetNodeIDForTest(1)
	primary.legacyUncommittedWait = 30 * time.Second // 即便预算很长，500 也不等待

	start := time.Now()
	primary.replicateToPeers(objectID)
	elapsed := time.Since(start)

	master.mu.Lock()
	gets := master.planGets
	master.mu.Unlock()
	if gets != 3 {
		t.Fatalf("非 sentinel 错误应恰好原 3 次尝试，got %d", gets)
	}
	if elapsed >= 10*time.Second {
		t.Fatalf("500 错误不得进入等待预算，实际 %v", elapsed)
	}
}

// ---- 4. committed plan 后普通错误跨越短预算：仍原 3 次，不被 precommit 预算吞掉 ----

func TestLegacyReplicationOrdinaryErrorsOutliveShortBudget(t *testing.T) {
	content := bytes.Repeat([]byte("integrity-"), 5000)
	const objectID = uint64(2)
	crc := types.CRC32C(content)

	// 目标节点：committed 后每次 push 都失败（普通错误）。
	var pushHits atomic.Int64
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/replicate/") {
			pushHits.Add(1)
			http.Error(w, "replicate failed", http.StatusInternalServerError)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(targetSrv.Close)

	master := newReplicationStubMaster(t, objectID, int64(len(content)), crc,
		[]types.NodeInfo{{ID: 2, Addr: targetSrv.Listener.Addr().String()}},
		[]types.NodeInfo{{ID: 1, Addr: "127.0.0.1:1"}})
	// 首次 sentinel → 第 2 次取计划已提交；预算 3s 会在普通重试期间耗尽——
	// 等待阶段必须已经终止，3 次 push 全部发生。
	master.commitAfterGets = 1

	primary := New(t.TempDir(), master.srv.URL, "", 1<<30)
	primary.SetNodeIDForTest(1)
	primary.legacyUncommittedWait = 3 * time.Second
	// 直接入库（不经 handlePut：那会 spawn 第二个 replicate 循环干扰计数）。
	if _, _, err := primary.storeObject(objectID, bytes.NewReader(content), crc); err != nil {
		t.Fatalf("storeObject: %v", err)
	}

	start := time.Now()
	primary.replicateToPeers(objectID)
	elapsed := time.Since(start)

	master.mu.Lock()
	gets := master.planGets
	master.mu.Unlock()
	if gets < 3 {
		t.Fatalf("普通重试应各自重新取计划（1 sentinel + ≥3 committed），got %d", gets)
	}
	if got := pushHits.Load(); got != 3 {
		t.Fatalf("普通错误应恰好 3 次 push（不被 precommit 预算截断），got %d", got)
	}
	// 3 次尝试含 1s/2s 退避，必然越过 3s 预算起点；总耗时有界（< 原预算+冗余）。
	if elapsed >= 20*time.Second {
		t.Fatalf("普通错误路径应有界返回，实际 %v", elapsed)
	}
}
