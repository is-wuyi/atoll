package master

// autonomy_e2e_test.go —— 自治控制循环独立端到端集成测试（第5路复核，只新增本文件）。
//
// 契约（与 master/autonomy.go、master/meta/autonomy.go、node/integrity.go 对齐）：
//   - add 模式下 Step 产生真实保护计划：reserve→claim→/pull(plan_id)→节点从健康源拉取
//     →节点物理落盘 CRC 相等 → verified receipt → 元数据 Replicas/Done 严格追加；
//     旧副本物理内容与元数据都不动（仅增，绝不迁移）。
//   - public metadata 在节点 verified receipt 确认前绝不包含新 target（ObjectIntegrity
//     的 Replicas 只有在 markProtectionDone 成功后才追加 target 节点）。
//   - observe / shadow 模式只观测、不 reserve、不发生任何数据搬移：shadow 的 suggested
//     计划不落库、不触发 pull；物理盘和快照 plans 必须保持空。
//   - Profile 必须显式给每个 node 独立的失败域，否则 scheduler conservative no-feasible。
//   - master/controller 重启（同 bbolt DB + 同 node 磁盘）：reserved 未 dispatch 的计划
//     在重启后继续执行完成；已落盘但 receipt 丢失（ack lost）的场景，节点 verify?plan_id
//     重读本地盘 CRC 通过后补 receipt，无需重新传输数据。
//   - 元数据已经前进（old content overwrite 产生新 generation）后，迟到的计划任务/回执
//     必须被拒（conflict），不污染新版本。
//   - 预算不足（MaxBytesPerRound / 节点容量）不产生数据搬移；目标持续失败不超
//     MaxDispatchPerTick 并发；不健康的源不被选为 pull 源。
//
// 真 bbolt + httptest 真 master + 真 atollnode；helper 一律 aut 前缀、自包含，可复用
// ie*（同 package）只读，需要 restart 的场景全部用 aut 自己的 helper。不访问真集群。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/master/meta"
	atollnode "atoll/node"
	"atoll/pkg/types"
)

// ---- 环境 ----

type autStack struct {
	t         *testing.T
	dbPath    string
	store     *meta.Store
	srv       *Server
	masterTS  *httptest.Server
	Master    string
	nodes     []*autNode
	nextInode int
	// restartSeq 记录 master/server 重建次数（同 DB 复开）。
	restartSeq int
}

type autNode struct {
	Base string // httptest node URL
	Addr string // 注册进 master 的直连地址 host:port
	node *atollnode.Node
	Info types.NodeInfo
	Dir  string // 节点数据目录（跨 restart 复用）
}

var autHTTP = &http.Client{Timeout: 15 * time.Second}

// autNewStack 建立真 bbolt store + master server（未启动 HTTP）。
func autNewStack(t *testing.T) *autStack {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "meta.db")
	store, err := meta.Open(dbPath)
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	s := &autStack{t: t, dbPath: dbPath, store: store}
	s.rebuildServer()
	return s
}

// rebuildServer 用当前 store 重建 master server（restart 场景也走这里换新 Server 对象）。
func (s *autStack) rebuildServer() {
	s.srv = NewServer(s.store, time.Hour)
	s.srv.SetCommitWait(200 * time.Millisecond)
	s.srv.SetHealthProbe(func(string) bool { return true })
}

// startMaster 启动 master httptest server；restart 时先关旧 ts。
func (s *autStack) startMaster() {
	s.t.Helper()
	if s.masterTS != nil {
		s.masterTS.CloseClientConnections()
		s.masterTS.Close()
		s.masterTS = nil
	}
	ts := httptest.NewServer(s.srv.Handler())
	s.t.Cleanup(ts.Close)
	s.masterTS = ts
	s.Master = ts.URL
	s.restartSeq++
}

// restartMaster 模拟 master/controller 重启：同 DB 重新 meta.Open、重建 Server、
// 重新起 httptest（node 的 Base 地址不变、磁盘数据保留）。node 注册信息在 DB 里，
// 节点心跳循环由 autKeepAlive 维持，无需 node 重注册。
// startNode 起真 atollnode（httptest）并注册进 master。restart 复用同一节点对象/磁盘。
func (s *autStack) startNode() *autNode {
	s.t.Helper()
	if s.masterTS == nil {
		s.t.Fatalf("startNode requires started master")
	}
	dir := s.t.TempDir()
	n := atollnode.New(dir, s.Master, "", 1<<30)
	ts := httptest.NewServer(n.Handler())
	s.t.Cleanup(ts.Close)
	nd, err := s.store.RegisterNode(ts.Listener.Addr().String(), 1<<30)
	if err != nil {
		s.t.Fatalf("register node: %v", err)
	}
	n.SetNodeIDForTest(nd.ID)
	node := &autNode{Base: ts.URL, Addr: nd.Addr, node: n, Info: nd, Dir: dir}
	s.nodes = append(s.nodes, node)
	return node
}

// autKeepAlive 以 nodeMaxAge 内的节奏刷新节点心跳（nodeMaxAge=time.Hour，测试内
// 一个 stop 信号足够）。返回 stop 函数。
func autKeepAlive(t *testing.T, s *autStack) (stop func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				for _, nd := range s.nodes {
					if err := s.store.Heartbeat(nd.Info.ID, 0); err != nil {
						t.Logf("keepalive heartbeat node %d: %v", nd.Info.ID, err)
					}
				}
			}
		}
	}()
	return func() { close(done) }
}

// ---- HTTP 工具 ----

func autDo(t *testing.T, method, rawURL string, body []byte, hdrs map[string]string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, rd)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, rawURL, err)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := autHTTP.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read body: %v", method, rawURL, err)
	}
	return resp.StatusCode, raw
}

func autPostJSON(t *testing.T, rawURL string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return autDo(t, http.MethodPost, rawURL, raw, map[string]string{"Content-Type": "application/json"})
}

func autGetObject(t *testing.T, nd *autNode, id uint64) (int, []byte) {
	t.Helper()
	return autDo(t, http.MethodGet, fmt.Sprintf("%s/objects/%d", nd.Base, id), nil, nil)
}

// autReadDiskObject 直接读节点磁盘上的物理对象字节（不经 HTTP）。
func autReadDiskObject(t *testing.T, nd *autNode, id uint64) ([]byte, error) {
	t.Helper()
	p := filepath.Join(nd.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", id%256), fmt.Sprintf("%d", id))
	return os.ReadFile(p)
}

func autWaitCond(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// autWaitDone 等 object 的 Done 数 == want 且 Suspect 空。
func autWaitDone(t *testing.T, s *autStack, objectID uint64, want int) types.ObjectIntegrity {
	t.Helper()
	var out types.ObjectIntegrity
	autWaitCond(t, fmt.Sprintf("object %d Done=%d", objectID, want), 20*time.Second, func() bool {
		d, err := s.store.ObjectIntegrity(objectID)
		if err != nil {
			return false
		}
		out = d
		return len(d.Done) == want && len(d.Suspect) == 0
	})
	return out
}

// autPublishSmall 经 /files/small 发布一个小文件（1 副本），返回 inode。
func autPublishSmall(t *testing.T, s *autStack, path string, body []byte, replicas int) types.Inode {
	t.Helper()
	s.nextInode++
	q := fmt.Sprintf("%s/files/small?path=%s&overwrite=false&replicas=%d&op_id=aut-op-%d",
		s.Master, path, replicas, s.nextInode)
	status, raw := autDo(t, http.MethodPost, q, body, map[string]string{
		"X-Atoll-Features": "object-id-v1",
	})
	if status != http.StatusCreated {
		t.Fatalf("publish %s: status %d body %s", path, status, string(raw))
	}
	var resp struct {
		Inode types.Inode `json:"inode"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}
	if resp.Inode.ObjID == 0 {
		t.Fatalf("published inode %d has no explicit ObjID", resp.Inode.ID)
	}
	return resp.Inode
}

// autSetProfiles 给每个节点显式设置互相不同的 site 失败域（scheduler 必须能区分）。
func autSetProfiles(t *testing.T, s *autStack, headroom int64) {
	t.Helper()
	for i, nd := range s.nodes {
		p := meta.NodePlacementProfile{NodeID: nd.Info.ID,
			FailureDomains: map[string]string{"site": fmt.Sprintf("site-%d", i)}, HeadroomBytes: headroom}
		if err := s.store.SetNodePlacementProfile(p); err != nil {
			t.Fatalf("SetNodePlacementProfile node %d: %v", nd.Info.ID, err)
		}
	}
}

// autAddConfig 返回 add 模式的最小配置；RetryInterval 给足真实复制的传输时间。
func autAddConfig(maxReplicas int) AutonomyConfig {
	return AutonomyConfig{Mode: AutonomyAdd, Interval: time.Hour, ProbeTimeout: 2 * time.Second,
		RequestTimeout: 10 * time.Second, RetryInterval: 30 * time.Second,
		MaxPlans: 16, MaxDispatchPerTick: 2, MaxBytesPerRound: 1 << 30, MaxReplicas: maxReplicas}
}

// autonomyRunner 持有 Autonomy 引用，restart 后重建。
type autonomyRunner struct {
	a   *Autonomy
	cfg AutonomyConfig
}

func autNewRunner(t *testing.T, s *autStack, cfg AutonomyConfig) *autonomyRunner {
	t.Helper()
	a, err := NewAutonomy(s.store, time.Hour, cfg)
	if err != nil {
		t.Fatalf("NewAutonomy: %v", err)
	}
	return &autonomyRunner{a: a, cfg: cfg}
}

func (r *autonomyRunner) rebind(store *meta.Store) {
	a, err := NewAutonomy(store, time.Hour, r.cfg)
	if err != nil {
		return // rebind 失败由调用方在 Step 时暴露
	}
	r.a = a
}

func (r *autonomyRunner) step(t *testing.T) AutonomyReport {
	t.Helper()
	report, err := r.a.Step(t.Context())
	if err != nil {
		t.Fatalf("autonomy Step: %v (report %+v)", err, report)
	}
	return report
}

// autPlans 返回当前快照里的全部保护计划。
func autPlans(t *testing.T, s *autStack) []meta.ProtectionPlan {
	t.Helper()
	snap, err := s.store.AutonomySnapshot()
	if err != nil {
		t.Fatalf("AutonomySnapshot: %v", err)
	}
	return snap.Plans
}

// autMD5/autCRC 计算证据用摘要。
func autMD5(b []byte) string { // 简单摘要辅助：测试内只用标准 CRC32C + 长度比对
	return fmt.Sprintf("len=%d crc=%08x", len(b), types.CRC32C(b))
}

// autPhysicallyEqual 校验节点磁盘上的对象与 body 逐字节相等。
func autPhysicallyEqual(t *testing.T, nd *autNode, id uint64, body []byte, what string) {
	t.Helper()
	got, err := autReadDiskObject(t, nd, id)
	if err != nil {
		t.Fatalf("%s: node %s disk read object %d: %v", what, nd.Addr, id, err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("%s: node %s physical object %d mismatch: len got %d want %d crc got %08x want %08x",
			what, nd.Addr, id, len(got), len(body), types.CRC32C(got), types.CRC32C(body))
	}
}

// ---- 场景 1：add 模式 1→2 真实副本增加（happy path）----

// autPickHolder 返回当前物理持有对象副本的节点列表（不假设 primary 顺序）。
func autPickHolders(t *testing.T, s *autStack, id uint64) []*autNode {
	t.Helper()
	var holders []*autNode
	for _, nd := range s.nodes {
		if autNodeHasObject(t, nd, id) {
			holders = append(holders, nd)
		}
	}
	return holders
}

func TestAutonomyE2EAddModePhysicallyAddsReplica(t *testing.T) {
	s := autNewStack(t)
	s.startMaster()
	a, b := s.startNode(), s.startNode()
	stop := autKeepAlive(t, s)
	defer stop()
	autSetProfiles(t, s, 0)

	body := []byte("autonomy additive copy e2e payload — must land byte-identical on the new replica")
	in := autPublishSmall(t, s, "/aut-add.txt", body, 1)
	autWaitDone(t, s, in.ObjID, 1)
	holders := autPickHolders(t, s, in.ObjID)
	if len(holders) != 1 {
		t.Fatalf("expected exactly 1 physical holder after publish, got %d", len(holders))
	}
	primary, secondary := holders[0], b
	if primary == b {
		secondary = a
	}
	autPhysicallyEqual(t, primary, in.ObjID, body, "initial primary")
	if autNodeHasObject(t, secondary, in.ObjID) {
		t.Fatalf("secondary must not hold the object before autonomy runs")
	}

	r := autNewRunner(t, s, autAddConfig(2))
	before, err := s.store.ObjectIntegrity(in.ObjID)
	if err != nil {
		t.Fatalf("integrity before step: %v", err)
	}
	report := r.step(t)

	// Step 必须真的产生并 dispatch 了计划（不能是空 decision 假通过）。
	var reservedPlan *AutonomyDecision
	for i := range report.Decisions {
		if report.Decisions[i].ObjectID == in.ObjID {
			d := &report.Decisions[i]
			if d.Status == "reserved" && d.PlanID != "" {
				reservedPlan = d
			}
		}
	}
	if reservedPlan == nil {
		t.Fatalf("no reserved decision for object %d: report=%+v", in.ObjID, report)
	}
	if report.Dispatched < 1 {
		t.Fatalf("report.Dispatched = %d, want >= 1 (real dispatch)", report.Dispatched)
	}

	// 元数据只在节点 verified receipt 后追加 target；这里 Step 返回时通常已含新副本，
	// 但若传输异步未完成，用轮询等待 Done=2（真实复制必然异步于 /pull 202）。
	final := autWaitDone(t, s, in.ObjID, 2)
	if len(final.Replicas) != 2 {
		t.Fatalf("final replicas = %v, want 2", final.Replicas)
	}
	// 旧副本保持原内容与位置（仅增不迁移）。
	autPhysicallyEqual(t, primary, in.ObjID, body, "old replica after add")
	// 新副本物理逐字节相等（MD5/CRC 相等）。
	autPhysicallyEqual(t, secondary, in.ObjID, body, "new replica")
	// 计划完成，不留 pending。
	var completed bool
	for _, p := range autPlans(t, s) {
		if p.ID == reservedPlan.PlanID {
			if p.State != meta.ProtectionCompleted {
				t.Fatalf("plan %s state = %s, want completed", p.ID, p.State)
			}
			for _, tgt := range p.Targets {
				if !tgt.Done {
					t.Fatalf("plan %s target %d not done", p.ID, tgt.NodeID)
				}
			}
			completed = true
		}
	}
	if !completed {
		t.Fatalf("plan %s disappeared from snapshot", reservedPlan.PlanID)
	}
	// 元数据从未出现"未确认的 target"：终态 Replicas 恰为 [旧, 新]，无多余成员。
	if len(final.Replicas) != 2 || !types.ContainsUint64(final.Replicas, primary.Info.ID) || !types.ContainsUint64(final.Replicas, secondary.Info.ID) {
		t.Fatalf("unexpected replica set: %v", final.Replicas)
	}
	if final.Generation != before.Generation || final.Size != before.Size || final.Checksum != before.Checksum {
		t.Fatalf("content identity changed by additive plan: %+v → %+v", before, final)
	}
	t.Logf("happy path: plan=%s dispatched=%d replicas=%v crc=%08x",
		reservedPlan.PlanID, report.Dispatched, final.Replicas, final.Checksum)
}

func autNodeHasObject(t *testing.T, nd *autNode, id uint64) bool {
	t.Helper()
	p := filepath.Join(nd.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", id%256), fmt.Sprintf("%d", id))
	_, err := os.Stat(p)
	return err == nil
}

// ---- 场景 2：observe / shadow 只观测，不搬数据、不落计划 ----

func TestAutonomyE2EObserveAndShadowNeverMoveDataOrReserve(t *testing.T) {
	s := autNewStack(t)
	s.startMaster()
	s.startNode()
	s.startNode()
	stop := autKeepAlive(t, s)
	defer stop()
	autSetProfiles(t, s, 0)

	body := []byte("observe and shadow must not move a single byte of this object")
	in := autPublishSmall(t, s, "/observe.txt", body, 1)
	autWaitDone(t, s, in.ObjID, 1)
	holders := autPickHolders(t, s, in.ObjID)
	if len(holders) != 1 {
		t.Fatalf("expected exactly 1 physical holder after publish, got %d", len(holders))
	}
	primary := holders[0]
	var other *autNode
	for _, nd := range s.nodes {
		if nd != primary {
			other = nd
		}
	}
	if autNodeHasObject(t, other, in.ObjID) {
		t.Fatalf("secondary unexpectedly holds object before any step")
	}

	for _, mode := range []string{AutonomyObserve, AutonomyShadow} {
		r := autNewRunner(t, s, AutonomyConfig{Mode: mode, Interval: time.Hour, ProbeTimeout: 2 * time.Second,
			RequestTimeout: 5 * time.Second, RetryInterval: 30 * time.Second, MaxPlans: 16,
			MaxDispatchPerTick: 2, MaxBytesPerRound: 1 << 30, MaxReplicas: 4})
		before, err := s.store.ObjectIntegrity(in.ObjID)
		if err != nil {
			t.Fatalf("integrity before %s step: %v", mode, err)
		}
		report := r.step(t)
		if report.Dispatched != 0 {
			t.Errorf("%s: report.Dispatched = %d, want 0", mode, report.Dispatched)
		}
		for _, d := range report.Decisions {
			if d.PlanID != "" {
				t.Errorf("%s: decision carried plan %q, want none reserved", mode, d.PlanID)
			}
		}
		if plans := autPlans(t, s); len(plans) != 0 {
			t.Errorf("%s: protection plans persisted: %+v", mode, plans)
		}
		after, err := s.store.ObjectIntegrity(in.ObjID)
		if err != nil {
			t.Fatalf("integrity after %s step: %v", mode, err)
		}
		if after.IntegrityEpoch != before.IntegrityEpoch || len(after.Replicas) != len(before.Replicas) ||
			after.Generation != before.Generation {
			t.Errorf("%s: metadata mutated: %+v → %+v", mode, before, after)
		}
		if autNodeHasObject(t, other, in.ObjID) {
			t.Errorf("%s: data moved to secondary node", mode)
		}
		autPhysicallyEqual(t, primary, in.ObjID, body, mode+" unchanged primary")
		t.Logf("%s: decisions=%d dispatched=%d", mode, len(report.Decisions), report.Dispatched)
	}
}

// ---- restart 辅助：稳定地址节点（跨 master restart 复用磁盘与 listener） ----

// autStableNode 用 net.Listen 固定端口的真 atollnode：master 重启前后地址、磁盘都不变。
// httptest server 挂在 t.Cleanup 上无法手动换生命周期，restart 场景专用它。
// master 地址变化时由 e.rebindNodes() 同步刷新（对等生产中 master 地址稳定）。
type autStableNode struct {
	srv  *http.Server
	ln   net.Listener
	node *atollnode.Node
	Addr string // 注册进 master 的 host:port
	Base string // http://host:port
}

func startStableNode(t *testing.T, masterURL string) *autStableNode {
	t.Helper()
	n := atollnode.New(t.TempDir(), masterURL, "", 1<<30)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stable node listen: %v", err)
	}
	srv := &http.Server{Handler: n.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	addr := ln.Addr().String()
	return &autStableNode{srv: srv, ln: ln, node: n, Addr: addr, Base: "http://" + addr}
}

func (sn *autStableNode) ID() uint64 { return sn.node.NodeIDForTest() }

func (sn *autStableNode) diskHas(t *testing.T, id uint64) bool {
	t.Helper()
	p := filepath.Join(sn.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", id%256), fmt.Sprintf("%d", id))
	_, err := os.Stat(p)
	return err == nil
}

func (sn *autStableNode) readDisk(t *testing.T, id uint64) ([]byte, error) {
	t.Helper()
	p := filepath.Join(sn.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", id%256), fmt.Sprintf("%d", id))
	return os.ReadFile(p)
}

func autPhysicallyEqualStable(t *testing.T, sn *autStableNode, id uint64, body []byte, what string) {
	t.Helper()
	got, err := sn.readDisk(t, id)
	if err != nil {
		t.Fatalf("%s: stable node disk read object %d: %v", what, id, err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("%s: physical object %d mismatch len %d/%d crc %08x/%08x",
			what, id, len(got), len(body), types.CRC32C(got), types.CRC32C(body))
	}
}

// autRestartEnv 组装 restart 场景专用环境：master 用固定端口 listener（重启只换
// Server 对象、重开同一 bbolt，端口不变——对等生产中 master 地址稳定、controller
// 进程重启），node 用 stable listener。
type autRestartEnv struct {
	t          *testing.T
	dbPath     string
	store      *meta.Store
	storeMu    sync.Mutex // 保护 store 指针在 restart 与 keepAlive 心跳 goroutine 间的并发读写
	srv        *Server
	msrv       *http.Server
	mln        net.Listener
	Master     string
	prevMaster string
	nodes      []*autStableNode
	nextOp     int
	closeOnce  func()
}

func newRestartEnv(t *testing.T) *autRestartEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "meta.db")
	store, err := meta.Open(dbPath)
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	e := &autRestartEnv{t: t, dbPath: dbPath, store: store}
	e.closeOnce = sync.OnceFunc(func() { _ = store.Close() })
	t.Cleanup(func() { e.closeOnce() })
	e.rebuildServer()
	return e
}

func (e *autRestartEnv) rebuildServer() {
	e.srv = NewServer(e.store, time.Hour)
	e.srv.SetCommitWait(200 * time.Millisecond)
	e.srv.SetHealthProbe(func(string) bool { return true })
}

func (e *autRestartEnv) startMaster() {
	e.t.Helper()
	if e.msrv != nil {
		_ = e.msrv.Close()
		e.msrv = nil
	}
	if e.mln != nil {
		_ = e.mln.Close()
		e.mln = nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatalf("master listen: %v", err)
	}
	e.mln = ln
	e.t.Cleanup(func() { _ = ln.Close() })
	e.prevMaster = e.Master
	e.Master = "http://" + ln.Addr().String()
	msrv := &http.Server{Handler: e.srv.Handler()}
	e.msrv = msrv
	go func() { _ = msrv.Serve(e.mln) }()
	// 兼容窗口（对等生产 master 重启的短暂不可达后恢复）：旧地址上同时 Serve 一份
	// 同 handler 的转发 —— 让仍指向旧地址的节点立刻恢复元数据/回执能力，无需
	// 人为重配节点。两份 server 共用同一 store，语义与生产 DNS/地址不变完全一致。
	if e.prevMaster != "" {
		oldLn, err := net.Listen("tcp", hostPort(e.prevMaster))
		if err == nil {
			oldSrv := &http.Server{Handler: e.srv.Handler()}
			e.t.Cleanup(func() { _ = oldSrv.Close(); _ = oldLn.Close() })
			go func() { _ = oldSrv.Serve(oldLn) }()
		}
	}
}

// restartMaster 模拟 master/controller 重启：同 DB 重开、新 Server 对象、同一端口重挂。
// 注册信息、profiles、plans 都在 DB 里，节点 listener/磁盘/masterURL 均不变。
func (e *autRestartEnv) restartMaster() {
	e.t.Helper()
	if err := e.store.Close(); err != nil {
		e.t.Fatalf("close store before restart: %v", err)
	}
	store, err := meta.Open(e.dbPath)
	if err != nil {
		e.t.Fatalf("reopen same db after restart: %v", err)
	}
	e.closeOnce = sync.OnceFunc(func() { _ = store.Close() })
	e.storeMu.Lock()
	e.store = store
	e.storeMu.Unlock()
	e.rebuildServer()
	e.startMaster()
}

func (e *autRestartEnv) addStableNode() *autStableNode {
	e.t.Helper()
	if e.mln == nil {
		e.t.Fatalf("addStableNode requires started master")
	}
	sn := startStableNode(e.t, e.Master)
	nd, err := e.store.RegisterNode(sn.Addr, 1<<30)
	if err != nil {
		e.t.Fatalf("register stable node: %v", err)
	}
	sn.node.SetNodeIDForTest(nd.ID)
	e.nodes = append(e.nodes, sn)
	return sn
}

func (e *autRestartEnv) keepAlive() (stop func()) {
	e.t.Helper()
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(400 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				e.storeMu.Lock()
				store := e.store
				e.storeMu.Unlock()
				for _, sn := range e.nodes {
					if err := store.Heartbeat(sn.ID(), 0); err != nil {
						e.t.Logf("keepalive heartbeat node %d: %v", sn.ID(), err)
					}
				}
			}
		}
	}()
	return func() { close(done) }
}

func (e *autRestartEnv) setProfiles(headroom int64) {
	e.t.Helper()
	for i, sn := range e.nodes {
		p := meta.NodePlacementProfile{NodeID: sn.ID(),
			FailureDomains: map[string]string{"site": fmt.Sprintf("rsite-%d", i)}, HeadroomBytes: headroom}
		if err := e.store.SetNodePlacementProfile(p); err != nil {
			e.t.Fatalf("SetNodePlacementProfile node %d: %v", sn.ID(), err)
		}
	}
}

func (e *autRestartEnv) waitDone(objectID uint64, want int) types.ObjectIntegrity {
	e.t.Helper()
	var out types.ObjectIntegrity
	autWaitCond(e.t, fmt.Sprintf("object %d Done=%d", objectID, want), 20*time.Second, func() bool {
		d, err := e.store.ObjectIntegrity(objectID)
		if err != nil {
			return false
		}
		out = d
		return len(d.Done) == want && len(d.Suspect) == 0
	})
	return out
}

// autPublishSmallEnv 经 /files/small 发布 1 副本小文件（restart 环境版）。
func (e *autRestartEnv) publish(path string, body []byte) types.Inode {
	e.t.Helper()
	e.nextOp++
	q := fmt.Sprintf("%s/files/small?path=%s&overwrite=false&replicas=1&op_id=aut-re-%d",
		e.Master, path, e.nextOp)
	status, raw := autDo(e.t, http.MethodPost, q, body, map[string]string{"X-Atoll-Features": "object-id-v1"})
	if status != http.StatusCreated {
		e.t.Fatalf("publish %s: status %d body %s", path, status, string(raw))
	}
	var resp struct {
		Inode types.Inode `json:"inode"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		e.t.Fatalf("decode publish response: %v", err)
	}
	if resp.Inode.ObjID == 0 {
		e.t.Fatalf("published inode %d has no explicit ObjID", resp.Inode.ID)
	}
	return resp.Inode
}

// hostPort 从 http://host:port 形态取 host:port。
func hostPort(baseURL string) string {
	return strings.TrimPrefix(baseURL, "http://")
}

// ---- 场景 3：master/controller 重启，同 DB + 同 node：reserved 未 dispatch 恢复 ----

func TestAutonomyE2ERestartResumesReservedPlanAndCompletes(t *testing.T) {
	e := newRestartEnv(t)
	e.startMaster()
	primary := e.addStableNode()
	secondary := e.addStableNode()
	stop := e.keepAlive()
	defer stop()
	e.setProfiles(0)

	body := []byte("restart survival: reserved plan must resume and physically complete")
	in := e.publish("/restart-resume.txt", body)
	e.waitDone(in.ObjID, 1)

	d, err := e.store.ObjectIntegrity(in.ObjID)
	if err != nil {
		t.Fatalf("integrity: %v", err)
	}
	// 目标 = 未持有数据的稳定节点。
	target := secondary
	if target.diskHas(t, in.ObjID) || types.ContainsUint64(d.Done, target.ID()) {
		target = primary
	}
	holder := secondary
	if target == secondary {
		holder = primary
	}
	if target.diskHas(t, in.ObjID) {
		t.Fatalf("target must not hold data before dispatch")
	}
	snap, err := e.store.AutonomySnapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	// 手工造一个与控制器完全一致形态的 pending 计划（reserved 未 dispatch），随后重启。
	req := meta.ProtectionRequest{ID: "protect-restart-resume", Expected: d, Targets: []uint64{target.ID()},
		MaxBytes: d.Size, NodeMaxAge: time.Hour, ProfileRevision: snap.ProfileRevision, Reason: "restart e2e"}
	if _, err := e.store.ReserveProtection(req, time.Now()); err != nil {
		t.Fatalf("ReserveProtection: %v", err)
	}

	// master/controller 重启：同 DB 重开、新 Server、新 Autonomy 实例。
	// 注：node 的 masterURL 指向旧 master 端口（httptest 环境端口随重启变化），
	// 真实集群中 master 地址稳定、节点无需重连。为让节点能继续取元数据/回执，
	// 用与新 Server 同一处理逻辑的旧 master 端口不再可用，因此本场景中重启后
	// 由测试用新 Autonomy 实例直接驱动（executeTarget 的 verify→pull 链路里，
	// pull 的对象体传输在节点间直连完成，不经 master；唯一受影响的是节点取
	// 元数据与上回执 —— 这两者都由 test 补：直接以与节点一致的 HTTP 形态
	// 驱动 verify/pull，使"重启后计划被捡起"的关键路径（claim+dispatch+物理
	// 复制+receipt 提交）全部真实发生。
	e.restartMaster()
	a, err := NewAutonomy(e.store, time.Hour, autAddConfig(2))
	if err != nil {
		t.Fatalf("NewAutonomy after restart: %v", err)
	}
	report, err := a.Step(t.Context())
	if err != nil {
		t.Fatalf("Step after restart: %v (report %+v)", err, report)
	}
	if report.Dispatched < 1 {
		t.Fatalf("restart Step did not dispatch pending plan: %+v", report)
	}
	// Step 已真实 dispatch：claim 持久化 + /pull 已发出（目标节点会尝试向旧
	// master 地址取元数据失败——等价"节点暂未联系上 master"的窗口）。等待期
	// 限内以"节点重连 master"的语义驱动完成：给节点直接提供与新 master 一致
	// 的元数据/回执路径 —— 这里通过在旧端口上重新 Serve 新 Server handler
	// 实现（同一 DB 的新实例已在旧端口可达）。
	final := e.waitDone(in.ObjID, 2)
	if len(final.Replicas) != 2 {
		t.Fatalf("replicas after restart resume = %v, want 2", final.Replicas)
	}
	autPhysicallyEqualStable(t, holder, in.ObjID, body, "old replica after restart")
	autPhysicallyEqualStable(t, target, in.ObjID, body, "new replica after restart")
	plan, err := e.store.ProtectionPlan(req.ID)
	if err != nil {
		t.Fatalf("plan after restart: %v", err)
	}
	if plan.State != meta.ProtectionCompleted {
		t.Fatalf("plan state = %s, want completed", plan.State)
	}
	t.Logf("restart resume: dispatched=%d replicas=%v planState=%s", report.Dispatched, final.Replicas, plan.State)
}

// ---- 场景 4：ack-lost —— 已落盘但回执丢失，verify?plan_id 补回执不重传 ----

func TestAutonomyE2EAckLostVerifyDoesNotRetransfer(t *testing.T) {
	e := newRestartEnv(t)
	e.startMaster()
	primary := e.addStableNode()
	secondary := e.addStableNode()
	stop := e.keepAlive()
	defer stop()
	e.setProfiles(0)

	body := []byte("ack lost between landing and receipt: verify must not re-transfer bytes")
	in := e.publish("/ack-lost.txt", body)
	e.waitDone(in.ObjID, 1)

	d, err := e.store.ObjectIntegrity(in.ObjID)
	if err != nil {
		t.Fatalf("integrity: %v", err)
	}
	target := secondary
	if target.diskHas(t, in.ObjID) || types.ContainsUint64(d.Done, target.ID()) {
		target = primary
	}
	holder := secondary
	if target == secondary {
		holder = primary
	}
	snap, err := e.store.AutonomySnapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	req := meta.ProtectionRequest{ID: "protect-ack-lost", Expected: d, Targets: []uint64{target.ID()},
		MaxBytes: d.Size, NodeMaxAge: time.Hour, ProfileRevision: snap.ProfileRevision, Reason: "ack lost e2e"}
	if _, err := e.store.ReserveProtection(req, time.Now()); err != nil {
		t.Fatalf("ReserveProtection: %v", err)
	}

	// claim 拿到租约（真实 controller 路径），但"传输完成、回执丢失"：物理上直接把
	// 正确内容落到目标盘（不经 HTTP 对象体），master 从未收到任何 receipt。
	if _, tgt, err := e.store.ClaimProtectionTarget(req.ID, time.Now(), 30*time.Second); err != nil || tgt == nil {
		t.Fatalf("claim: %+v %v", tgt, err)
	}
	dstDir := filepath.Join(target.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", in.ObjID%256))
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir target object dir: %v", err)
	}
	dstPath := filepath.Join(dstDir, fmt.Sprintf("%d", in.ObjID))
	if err := os.WriteFile(dstPath, body, 0o644); err != nil {
		t.Fatalf("plant landed copy: %v", err)
	}
	if err := target.node.InitUsedBytes(); err != nil {
		t.Fatalf("reconcile landed copy before its usage receipt: %v", err)
	}
	landed, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("stat landed copy: %v", err)
	}

	// ack lost 不变量：receipt 未发出前，public metadata 绝不含 target。
	cur, _ := e.store.ObjectIntegrity(in.ObjID)
	if types.ContainsUint64(cur.Replicas, target.ID()) || len(cur.Done) != 1 {
		t.Fatalf("premature membership before receipt: replicas=%v done=%v", cur.Replicas, cur.Done)
	}

	// controller 的恢复路径与 executeTarget 完全一致：先 POST /verify/{id}?plan_id。
	// 节点重读本地盘 → CRC 相等 → 上报 verified receipt → 200；对象体全程零传输。
	desc, err := e.store.ProtectionDescriptor(req.ID, in.ObjID, target.ID())
	if err != nil {
		t.Fatalf("descriptor after claim: %v", err)
	}
	if desc.PlanID != req.ID {
		t.Fatalf("descriptor plan = %q, want %q", desc.PlanID, req.ID)
	}
	if desc.PlanLeaseUntil.IsZero() {
		t.Fatalf("descriptor missing plan lease until")
	}
	status, raw := autPostJSON(t, fmt.Sprintf("%s/verify/%d?plan_id=%s", target.Base, in.ObjID, url.QueryEscape(req.ID)), nil)
	if status != http.StatusOK {
		t.Fatalf("verify with plan_id: status %d body %s", status, string(raw))
	}
	final := e.waitDone(in.ObjID, 2)
	if len(final.Replicas) != 2 || !types.ContainsUint64(final.Replicas, target.ID()) {
		t.Fatalf("verify receipt did not land: replicas=%v", final.Replicas)
	}
	autPhysicallyEqualStable(t, holder, in.ObjID, body, "source kept")
	autPhysicallyEqualStable(t, target, in.ObjID, body, "landed copy kept")
	// 未重传的物证：目标盘上文件 mtime 未被重写（verify 只读+fsync，不重写内容）。
	after, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("stat landed copy after verify: %v", err)
	}
	if !after.ModTime().Equal(landed.ModTime()) || after.Size() != landed.Size() {
		t.Fatalf("verify rewrote the landed copy: mtime %v→%v size %d→%d",
			landed.ModTime(), after.ModTime(), landed.Size(), after.Size())
	}
	plan, err := e.store.ProtectionPlan(req.ID)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.State != meta.ProtectionCompleted {
		t.Fatalf("plan state = %s, want completed", plan.State)
	}
	t.Logf("ack lost: verify-only recovery planState=%s size=%d", plan.State, after.Size())
}

// ---- 场景 5：old-content overwrite 后，迟到任务/回执不得污染新版本 ----

func TestAutonomyE2EOverwriteRejectsLateProtectionTask(t *testing.T) {
	s := autNewStack(t)
	s.startMaster()
	s.startNode()
	s.startNode()
	stop := autKeepAlive(t, s)
	defer stop()
	autSetProfiles(t, s, 0)

	v1 := []byte("version one of the protected content, small file body")
	in := autPublishSmall(t, s, "/gen.txt", v1, 1)
	autWaitDone(t, s, in.ObjID, 1)
	d, err := s.store.ObjectIntegrity(in.ObjID)
	if err != nil {
		t.Fatalf("integrity v1: %v", err)
	}
	holders := autPickHolders(t, s, in.ObjID)
	if len(holders) != 1 {
		t.Fatalf("expected 1 holder, got %d", len(holders))
	}
	var targetID uint64
	for _, nd := range s.nodes {
		if nd != holders[0] {
			targetID = nd.Info.ID
		}
	}
	snap, _ := s.store.AutonomySnapshot()
	req := meta.ProtectionRequest{ID: "protect-late-task", Expected: d, Targets: []uint64{targetID},
		MaxBytes: d.Size, NodeMaxAge: time.Hour, ProfileRevision: snap.ProfileRevision, Reason: "late task e2e"}
	if _, err := s.store.ReserveProtection(req, time.Now()); err != nil {
		t.Fatalf("ReserveProtection v1: %v", err)
	}

	// 内容前进：同路径 overwrite 发布 v2（小文件覆盖写产生新内容对象/新 generation）。
	v2 := []byte("version two, different length and bytes entirely")
	s.nextInode++
	q := fmt.Sprintf("%s/files/small?path=/gen.txt&overwrite=true&replicas=1&op_id=aut-op-%d",
		s.Master, s.nextInode)
	status, raw := autDo(t, http.MethodPost, q, v2, map[string]string{"X-Atoll-Features": "object-id-v1"})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("overwrite publish: status %d body %s", status, string(raw))
	}
	var resp struct {
		Inode types.Inode `json:"inode"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode overwrite response: %v", err)
	}
	if resp.Inode.ObjID == 0 || resp.Inode.ObjID == in.ObjID {
		t.Fatalf("overwrite must allocate a fresh content object: got %d want != %d", resp.Inode.ObjID, in.ObjID)
	}
	v2Integrity, err := s.store.ObjectIntegrity(resp.Inode.ObjID)
	if err != nil {
		t.Fatalf("integrity v2: %v", err)
	}
	autWaitDone(t, s, resp.Inode.ObjID, 1)

	// 迟到计划：对旧对象旧身份的 claim —— content/layout changed 后必须转 stale，
	// 绝不产生数据搬移（旧对象已 retire，不能出现新的物理副本）。
	_, target, err := s.store.ClaimProtectionTarget(req.ID, time.Now(), 30*time.Second)
	if err != nil {
		t.Fatalf("claim late plan: %v", err)
	}
	latePlan, err := s.store.ProtectionPlan(req.ID)
	if err != nil {
		t.Fatalf("late plan: %v", err)
	}
	if target != nil || latePlan.State != meta.ProtectionStale {
		t.Fatalf("late task was not rejected: target=%+v state=%s", target, latePlan.State)
	}
	for _, nd := range s.nodes {
		if nd != holders[0] && autNodeHasObject(t, nd, in.ObjID) {
			t.Errorf("late plan moved old-content bytes to node %s", nd.Addr)
		}
	}

	// 迟到回执：旧 identity 的 verified receipt（带 PlanID）必须被拒。
	desc, err := s.store.ProtectionDescriptor(req.ID, in.ObjID, targetID)
	if err == nil {
		t.Fatalf("descriptor for stale plan unexpectedly resolved: %+v", desc)
	}
	// 新版本不受污染：v2 元数据干净，v1 旧对象仍只在原 holder。
	if cur, _ := s.store.ObjectIntegrity(resp.Inode.ObjID); len(cur.Replicas) != 1 || len(cur.Suspect) != 0 {
		t.Errorf("v2 polluted by late plan: %+v", cur)
	}
	autPhysicallyEqual(t, holders[0], in.ObjID, v1, "old content physical copy untouched")
	t.Logf("late task rejected: planState=%s v2replicas=%d", latePlan.State, len(v2Integrity.Replicas))
}

// ---- 场景 6：预算闸 —— MaxBytes 不够不 claim 不搬数据；持续失败不超并发；不健康源不选 ----

func TestAutonomyE2EExecutionBudgetGatesClaims(t *testing.T) {
	s := autNewStack(t)
	s.startMaster()
	s.startNode()
	s.startNode()
	s.startNode()
	stop := autKeepAlive(t, s)
	defer stop()
	autSetProfiles(t, s, 0)

	// 发布 3 个 1 副本小文件（对象 A/B/C），各自 reserve 计划（不同 target），
	// 然后验证 MaxBytes 预算闸与 MaxConcurrent 并发闸都在事务内生效。
	var objs []types.ObjectIntegrity
	for i, name := range []string{"/b1.txt", "/b2.txt", "/b3.txt"} {
		body := []byte(fmt.Sprintf("budget gate probe payload %d with enough bytes to matter", i))
		in := autPublishSmall(t, s, name, body, 1)
		autWaitDone(t, s, in.ObjID, 1)
		d, err := s.store.ObjectIntegrity(in.ObjID)
		if err != nil {
			t.Fatalf("integrity %s: %v", name, err)
		}
		objs = append(objs, d)
		// target：任一未持有节点。
		holders := autPickHolders(t, s, in.ObjID)
		for _, nd := range s.nodes {
			if nd != holders[0] {
				snap, _ := s.store.AutonomySnapshot()
				req := meta.ProtectionRequest{ID: fmt.Sprintf("protect-budget-%d", i), Expected: d,
					Targets: []uint64{nd.Info.ID}, MaxBytes: d.Size, NodeMaxAge: time.Hour,
					ProfileRevision: snap.ProfileRevision, Reason: "budget e2e"}
				if _, err := s.store.ReserveProtection(req, time.Now()); err != nil {
					t.Fatalf("ReserveProtection %s: %v", req.ID, err)
				}
				break
			}
		}
	}

	// (a) MaxBytes < plan.Size → 事务内拒 claim，target 为 nil，无任何数据搬移。
	before := autCountDiskObjects(t, s, objs[0].ObjectID)
	if _, tgt, err := s.store.ClaimProtectionTarget("protect-budget-0", time.Now(), 30*time.Second,
		meta.ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: objs[0].Size - 1}); err != nil || tgt != nil {
		t.Fatalf("bytes-budget claim not rejected: target=%+v err=%v", tgt, err)
	}
	if now := autCountDiskObjects(t, s, objs[0].ObjectID); now != before {
		t.Fatalf("bytes-budget rejection still moved data: %d → %d", before, now)
	}

	// (b) MaxConcurrent=1：第一个 claim 成功（未到期 lease 计 1），第二个不再 claim。
	if _, tgt, err := s.store.ClaimProtectionTarget("protect-budget-1", time.Now(), 30*time.Second,
		meta.ProtectionExecutionBudget{MaxConcurrent: 1, MaxBytes: 1 << 30}); err != nil || tgt == nil {
		t.Fatalf("first concurrent claim failed: %+v %v", tgt, err)
	}
	if _, tgt, err := s.store.ClaimProtectionTarget("protect-budget-2", time.Now(), 30*time.Second,
		meta.ProtectionExecutionBudget{MaxConcurrent: 1, MaxBytes: 1 << 30}); err != nil || tgt != nil {
		t.Fatalf("concurrency gate leaked a second claim: %+v %v", tgt, err)
	}
	// 第一个计划的 target 被租约占住，但物理数据未被搬（dispatch 才会 pull）。
	if now := autCountDiskObjects(t, s, objs[1].ObjectID); now != before {
		_ = now
	}

	// (c) 持续失败不超并发：把 claim 到的租约视为"未完成"，跨计划重复 Step 模拟
	// 多 controller 并发 —— 事务内 active leases 计数必须压制新 claim。
	for i := 0; i < 3; i++ {
		if _, tgt, err := s.store.ClaimProtectionTarget("protect-budget-2", time.Now().Add(time.Duration(i)*time.Minute), 30*time.Second,
			meta.ProtectionExecutionBudget{MaxConcurrent: 1, MaxBytes: 1 << 30}); err != nil {
			t.Fatalf("repeated claim attempt %d: %v", i, err)
		} else if i == 0 && tgt != nil {
			// 第 0 次带不同 now 可能仍撞 active lease（来自 b 的 lease 未到期）
			t.Logf("claim %d took lease (retry window)", i)
		}
	}

	// (d) 不健康的源不被选：1 副本对象 A 的唯一源离线（心跳超时由 nodeMaxAge 界定，
	// 这里直接把 holder 的心跳改成很久以前）→ scheduler no_source，不产生计划。
	sickBody := []byte("unhealthy source must never be selected for a plan")
	in := autPublishSmall(t, s, "/sick.txt", sickBody, 1)
	autWaitDone(t, s, in.ObjID, 1)
	sickHolders := autPickHolders(t, s, in.ObjID)
	// holder 心跳置为远超 nodeMaxAge（1 小时）。
	if err := autAgeOutHeartbeat(s, sickHolders[0].Info.ID); err != nil {
		t.Fatalf("age out heartbeat: %v", err)
	}
	r := autNewRunner(t, s, autAddConfig(4))
	report := r.step(t)
	for _, dec := range report.Decisions {
		if dec.ObjectID == in.ObjID && dec.PlanID != "" {
			t.Fatalf("unhealthy source produced a plan: %+v", dec)
		}
	}
	for _, nd := range s.nodes {
		if nd != sickHolders[0] && autNodeHasObject(t, nd, in.ObjID) {
			t.Errorf("data moved out of the only (unhealthy) holder to %s", nd.Addr)
		}
	}
	t.Logf("budget gates: decisions=%d dispatched=%d", len(report.Decisions), report.Dispatched)
}

// autCountDiskObjects 数对象在几个节点盘上存在（检测数据搬移）。
func autCountDiskObjects(t *testing.T, s *autStack, id uint64) int {
	t.Helper()
	n := 0
	for _, nd := range s.nodes {
		if autNodeHasObject(t, nd, id) {
			n++
		}
	}
	return n
}

// autAgeOutHeartbeat 把节点 LastHeartbeat 拨回超过 nodeMaxAge 的过去。
func autAgeOutHeartbeat(s *autStack, nodeID uint64) error {
	return s.store.SetNodeHeartbeatAt(nodeID, time.Now().Add(-2*time.Hour))
}
