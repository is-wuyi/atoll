package master

// small_publish_test.go —— 小文件不可变对象发布（explicit ObjID）回归测试。
//
// 契约（v2-4 small 发布重构）：
//   - 新写入分配独立的、不可复用的内容 ObjID（与 FileID 不同命名空间），
//     pending/reserved 登记先于节点 PUT，提交是事务内 CAS；
//   - 并发同目标不同 op/body：恰好一个 201、另一个 409，无幽灵 file；
//   - 同 op_id 并发同 payload：一 201 一 200 回放，inode/gen/objID 完全一致；
//     op_id 复用于不同 path/body 必须 409；
//   - 节点落盘后 ack 丢失（503）：旧 ObjID/元数据原样可读；
//   - 旧对象回收走 retired + 宽限，正常覆盖不立即 DELETE；针对旧物理 ObjID 的
//     迟到 DELETE 不得伤害最新版本；
//   - GC 两轮确认不得删除已提交的新 ObjID 对象与上传中的 reserved 对象；
//   - 旧客户端（无 X-Atoll-Features: object-id-v1 头）small 写一律 426；
//     explicit ObjID 的 /meta lookup 必须带头，legacy 旧布局（ObjID=0）不带头仍可读；
//   - 节点 PUT 在途期间 namespace 变化（rename/delete/symlink）不得复活旧 path
//     或损坏新位置。
//
// 全部通过公开 HTTP API（master /files/small /meta /entry/* /files/* /admin/gc +
// 真实 node /objects/*）驱动；真实 bbolt 元数据 + 真实 node 落盘，httptest 承载；
// 同步 channel barrier 制造交错，所有等待都带超时，失败路径必能退出。
// 不连真集群、不长时间 sleep。
//
// 注：部分用例在旧实现（原地覆盖 / 无 pending / 无 CAS / 无 426）上预期 RED，
// 主实现落地后转 GREEN（由基线 + 新代码对照运行证明）。helper 一律以 sp 前缀命名，
// 避免与本包既有测试 helper 冲突。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/master/meta"
	atollnode "atoll/node"
	"atoll/pkg/types"
)

// features 协议头。等价 types.FeaturesHeader / types.ObjectIDFeature（常量落地前
// 先硬编码字符串，保证测试可独立编译运行）。
const (
	spFeaturesHeader  = "X-Atoll-Features"
	spObjectIDFeature = "object-id-v1"
)

// spHTTP 所有测试共用的 HTTP 客户端：全程超时兜底，绝不永久挂起。
var spHTTP = &http.Client{Timeout: 15 * time.Second}

// ---- 通用 HTTP 工具 ----

// spDo 发一次请求，返回 (status, body)。transport 错误记 t.Errorf 并返回 -1
// （可安全地在 goroutine 中调用，不用 t.Fatal）。
func spDo(t *testing.T, method, rawURL string, body []byte, features bool) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		t.Errorf("new request %s %s: %v", method, rawURL, err)
		return -1, nil
	}
	if features {
		req.Header.Set(spFeaturesHeader, spObjectIDFeature)
	}
	resp, err := spHTTP.Do(req)
	if err != nil {
		t.Errorf("%s %s: %v", method, rawURL, err)
		return -1, nil
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("%s %s: read body: %v", method, rawURL, err)
		return resp.StatusCode, nil
	}
	return resp.StatusCode, raw
}

// spPostJSON 发 JSON POST（仅测试 goroutine 调用，可 Fatal）。
func spPostJSON(t *testing.T, rawURL string, body any, features bool) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return spDo(t, http.MethodPost, rawURL, raw, features)
}

// spWantStatus 断言状态码并返回是否相符。
func spWantStatus(t *testing.T, what string, got, want int) bool {
	t.Helper()
	if got != want {
		t.Errorf("%s: status = %d, want %d", what, got, want)
		return false
	}
	return true
}

// spPublishResult 是一次 /files/small 请求的结果快照。
type spPublishResult struct {
	Status   int
	Inode    types.Inode
	body     []byte // 该次发布的请求体（用于与最终对象字节对照）
	Err      string // transport/解码错误（goroutine 中不得触碰 t，带回来由测试 goroutine 上报）
	BodySnip string // 响应体片段（诊断意外状态码用）
}

// spSmallReq 调 POST /files/small。replicas<=0 时按 1。
// 注意：本函数会在测试 goroutine 之外运行，绝不触碰 testing.T（测试结束后调用
// t.Errorf 会 panic）；失败信息装进 Err 由调用方上报。
func spSmallReq(base, path string, body []byte, opID string, overwrite, features bool, replicas int) spPublishResult {
	if replicas <= 0 {
		replicas = 1
	}
	q := url.Values{}
	q.Set("path", path)
	q.Set("overwrite", strconv.FormatBool(overwrite))
	q.Set("replicas", strconv.Itoa(replicas))
	if opID != "" {
		q.Set("op_id", opID)
	}
	req, err := http.NewRequest(http.MethodPost, base+"/files/small?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return spPublishResult{Status: -1, body: body, Err: err.Error()}
	}
	if features {
		req.Header.Set(spFeaturesHeader, spObjectIDFeature)
	}
	resp, err := spHTTP.Do(req)
	if err != nil {
		return spPublishResult{Status: -1, body: body, Err: err.Error()}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return spPublishResult{Status: resp.StatusCode, body: body, Err: err.Error()}
	}
	res := spPublishResult{Status: resp.StatusCode, body: body, BodySnip: string(raw)}
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		var out struct {
			Inode types.Inode `json:"inode"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			res.Err = "decode /files/small response: " + err.Error()
		} else {
			res.Inode = out.Inode
		}
	}
	return res
}

// spReport 把 goroutine 携回的发布结果错误上报（仅测试 goroutine 调用）。
func spReport(t *testing.T, what string, r spPublishResult) {
	t.Helper()
	if r.Err != "" {
		t.Errorf("%s: %s", what, r.Err)
	}
}

// spDrainPublish 放行闸门并等在途发布结束（超时上界覆盖 spHTTP 15s 客户端超时），
// 保证 Fatal 之前没有 goroutine 还可能触碰测试状态或挂住 httptest.Close。
func spDrainPublish(t *testing.T, g *spPutGate, res <-chan spPublishResult) {
	t.Helper()
	if g != nil {
		g.open()
	}
	if res != nil {
		spRecv(t, res, 16*time.Second)
	}
}

// spLookupResp 是 GET /meta 的响应。
type spLookupResp struct {
	Inode types.Inode `json:"inode"`
	Nodes []struct {
		types.NodeInfo
		Done bool `json:"done"`
	} `json:"nodes"`
}

// spLookup 查询元数据。非 200 时 resp 为零值。
func spLookup(t *testing.T, base, path string, features bool) (int, spLookupResp) {
	t.Helper()
	st, raw := spDo(t, http.MethodGet, base+"/meta?"+url.Values{"path": {path}}.Encode(), nil, features)
	var out spLookupResp
	if st == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Errorf("decode /meta %s: %v", path, err)
		}
	}
	return st, out
}

// spChildren 列出目录子项。
func spChildren(t *testing.T, base, path string) (int, []types.Inode) {
	t.Helper()
	st, raw := spDo(t, http.MethodGet, base+"/dirs/children?"+url.Values{"path": {path}}.Encode(), nil, true)
	var kids []types.Inode
	if st == http.StatusOK {
		if err := json.Unmarshal(raw, &kids); err != nil {
			t.Errorf("decode children %s: %v", path, err)
		}
	}
	return st, kids
}

// spReadObject 从节点读对象字节（新客户端语义：带 features 头）。
func spReadObject(t *testing.T, nodeBase string, id uint64, features bool) (int, []byte) {
	t.Helper()
	return spDo(t, http.MethodGet, fmt.Sprintf("%s/objects/%d", nodeBase, id), nil, features)
}

// spDeleteObject 显式删除节点上的物理对象（模拟迟到的回收 DELETE）。
func spDeleteObject(t *testing.T, nodeBase string, id uint64) int {
	t.Helper()
	st, _ := spDo(t, http.MethodDelete, fmt.Sprintf("%s/objects/%d", nodeBase, id), nil, true)
	return st
}

// spPutObject 向节点 PUT 对象（带 CRC 头，模拟客户端/主副本直写）。
func spPutObject(t *testing.T, nodeBase string, id uint64, body []byte) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/objects/%d", nodeBase, id), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new PUT: %v", err)
	}
	req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", types.CRC32C(body)))
	req.Header.Set(spFeaturesHeader, spObjectIDFeature)
	resp, err := spHTTP.Do(req)
	if err != nil {
		t.Errorf("PUT object %d: %v", id, err)
		return -1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// spGCReport 是 /admin/gc 报告中测试关心的字段子集。
type spGCReport struct {
	NodeID  uint64 `json:"node_id"`
	Deleted int    `json:"deleted"`
	Orphans []struct {
		ID uint64 `json:"id"`
	} `json:"orphans"`
}

// spGCRun 触发一轮 GC（同一 scanner 实例内两轮才构成两轮确认）。
func spGCRun(t *testing.T, base string, execute bool) []spGCReport {
	t.Helper()
	st, raw := spPostJSON(t, base+"/admin/gc", map[string]bool{"execute": execute}, false)
	if !spWantStatus(t, "POST /admin/gc", st, http.StatusOK) {
		return nil
	}
	var reps []spGCReport
	if err := json.Unmarshal(raw, &reps); err != nil {
		t.Errorf("decode gc reports: %v", err)
	}
	return reps
}

// ---- barrier：扣住 master→node 的 PUT，制造「数据已落盘、元数据未提交」窗口 ----

// spPutGate 是节点代理中的 PUT 闸门：arm(n) 后前 n 个对象 PUT 会先转发给真实
// node 落盘（数据已在盘上），再扣住响应直到 open()。 arrived 记录被扣对象 ID。
type spPutGate struct {
	mu        sync.Mutex
	armed     bool
	remaining int
	arrived   chan uint64
	release   chan struct{}
	openOnce  sync.Once
}

func spNewPutGate() *spPutGate {
	return &spPutGate{arrived: make(chan uint64, 8), release: make(chan struct{})}
}

func (g *spPutGate) arm(n int) {
	g.mu.Lock()
	g.armed = true
	g.remaining = n
	g.mu.Unlock()
}

// open 放行所有被扣请求；t.Cleanup 兜底调用，失败路径不会挂死。
func (g *spPutGate) open() { g.openOnce.Do(func() { close(g.release) }) }

func (g *spPutGate) markArrived(id uint64) {
	select {
	case g.arrived <- id:
	default:
	}
}

// takeArrival 等一个被扣住的 PUT（带超时；false = 实现在 PUT 之前就已放行/拒绝）。
func (g *spPutGate) takeArrival(timeout time.Duration) (uint64, bool) {
	select {
	case id := <-g.arrived:
		return id, true
	case <-time.After(timeout):
		return 0, false
	}
}

func (g *spPutGate) wantHold(method, path string) bool {
	if method != http.MethodPut || !strings.HasPrefix(path, "/objects/") {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.armed || g.remaining <= 0 {
		return false
	}
	g.remaining--
	return true
}

// spWaitPutArrivals 尽力等待 n 个 PUT 到达：首个最多等 5s，后续每个只给 grace
// （实现可能在 PUT 前就串行化/拒绝，此时不白等）。返回实际等到的个数。
func spWaitPutArrivals(t *testing.T, g *spPutGate, n int, grace time.Duration) int {
	t.Helper()
	got := 0
	for i := 0; i < n; i++ {
		wait := grace
		if i == 0 {
			wait = 5 * time.Second
		}
		if _, ok := g.takeArrival(wait); !ok {
			break
		}
		got++
	}
	return got
}

// spRecv 带 super timeout 地收一个结果，避免挂死的 handler 拖死测试。
func spRecv[T any](t *testing.T, ch <-chan T, wait time.Duration) (T, bool) {
	t.Helper()
	select {
	case v := <-ch:
		return v, true
	case <-time.After(wait):
		var zero T
		return zero, false
	}
}

// ---- 测试环境：真实 bbolt + master + 真实 node（httptest 承载）----

type spStack struct {
	t      *testing.T
	store  *meta.Store
	srv    *Server
	Master string // master httptest 基址（startMaster 后非空）
}

func spNewStack(t *testing.T) *spStack {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	srv := NewServer(store, time.Hour) // 心跳 1h 内都算存活
	srv.SetCommitWait(200 * time.Millisecond)
	srv.SetHealthProbe(func(string) bool { return true })
	return &spStack{t: t, store: store, srv: srv}
}

func (s *spStack) startMaster() string {
	s.t.Helper()
	ts := httptest.NewServer(s.srv.Handler())
	s.t.Cleanup(ts.Close)
	s.Master = ts.URL
	return ts.URL
}

// spNodeT 是一个真实存储节点（atollnode）+ 注册信息。
type spNodeT struct {
	Base string
	node *atollnode.Node
	Info types.NodeInfo
}

// startNode 启动真实 node 并注册进 store。gate/wrap 可为 nil（直通）。
// wrap(w, r, inner) 返回 true 表示已自行应答（故障注入钩子）。
// setNodeID 时把 store 分配的节点 ID 告知 node（replicate/report 需要）。
func (s *spStack) startNode(masterURL string, gate *spPutGate, wrap func(http.ResponseWriter, *http.Request, http.Handler) bool, setNodeID bool) *spNodeT {
	s.t.Helper()
	n := atollnode.New(filepath.Join(s.t.TempDir(), "nodedata"), masterURL, "", 1<<30)
	inner := n.Handler()
	var h http.Handler = inner
	if gate != nil || wrap != nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if wrap != nil && wrap(w, r, inner) {
				return
			}
			if gate != nil && gate.wantHold(r.Method, r.URL.Path) {
				rec := httptest.NewRecorder()
				inner.ServeHTTP(rec, r) // 真实落盘在先
				id, _ := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/objects/"), 10, 64)
				gate.markArrived(id)
				select {
				case <-gate.release:
				case <-r.Context().Done():
					return
				}
				// 补发真实响应（含状态码与头）。
				for k, vs := range rec.Header() {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(rec.Code)
				w.Write(rec.Body.Bytes())
				return
			}
			inner.ServeHTTP(w, r)
		})
	}
	ts := httptest.NewServer(h)
	s.t.Cleanup(ts.Close)
	nd, err := s.store.RegisterNode(ts.Listener.Addr().String(), 1<<30)
	if err != nil {
		s.t.Fatalf("register node: %v", err)
	}
	if setNodeID {
		n.SetNodeIDForTest(nd.ID)
	}
	return &spNodeT{Base: ts.URL, node: n, Info: nd}
}

// ---- 1. 同名 overwrite=false 并发创建：仅 1 个 201、另 409、无幽灵 file ----

func TestSmallPublishConcurrentCreateOnlyOneWinnerNoGhost(t *testing.T) {
	s := spNewStack(t)
	base := s.startMaster()
	gate := spNewPutGate()
	defer gate.open() // Fatalf/Goexit 时立即放行，master 侧 30s PUT 不残留
	t.Cleanup(gate.open)
	nd := s.startNode("", gate, nil, false)

	gate.arm(2)
	res := make(chan spPublishResult, 2)
	go func() { res <- spSmallReq(base, "/solo", []byte("AAAA"), "sp-create-a", false, true, 1) }()
	go func() { res <- spSmallReq(base, "/solo", []byte("BBBB"), "sp-create-b", false, true, 1) }()

	// 两个 PUT 都到达节点（真正并发交错）；若实现先在元数据层串行化/拒绝，超时放行。
	spWaitPutArrivals(t, gate, 2, 1500*time.Millisecond)
	gate.open()

	ra, oka := spRecv(t, res, 16*time.Second)
	rb, okb := spRecv(t, res, 16*time.Second)
	if !oka || !okb {
		t.Fatalf("两个并发创建未在时限内返回（master 卡死？）")
	}
	spReport(t, "并发创建 A", ra)
	spReport(t, "并发创建 B", rb)
	created, rejected := 0, 0
	var winner spPublishResult
	for _, r := range []spPublishResult{ra, rb} {
		switch r.Status {
		case http.StatusCreated:
			created++
			winner = r
		case http.StatusConflict:
			rejected++
		default:
			t.Errorf("并发 overwrite=false 创建出现意外状态 %d", r.Status)
		}
	}
	if created != 1 || rejected != 1 {
		t.Fatalf("同名 overwrite=false 并发创建必须 1 个 201 + 1 个 409，得到 201×%d 409×%d", created, rejected)
	}
	// 无幽灵 file：命名空间恰好一个条目，且与 201 返回的 inode 快照一致。
	st, kids := spChildren(t, base, "/")
	if !spWantStatus(t, "GET /dirs/children", st, http.StatusOK) {
		t.FailNow()
	}
	if len(kids) != 1 || kids[0].Name != "solo" || kids[0].ID != winner.Inode.ID {
		t.Fatalf("目录应只含获胜文件一份（无幽灵）: kids=%+v winner=%+v", kids, winner.Inode)
	}
	lst, lu := spLookup(t, base, "/solo", true)
	if !spWantStatus(t, "GET /meta /solo", lst, http.StatusOK) {
		t.FailNow()
	}
	if lu.Inode.ID != winner.Inode.ID || lu.Inode.ObjID != winner.Inode.ObjID {
		t.Fatalf("最终元数据必须与 201 快照一致: lookup=%+v snapshot=%+v", lu.Inode, winner.Inode)
	}
	if lu.Inode.ObjID == 0 || lu.Inode.ObjID == lu.Inode.ID {
		t.Fatalf("新写入必须分配独立 ObjID（不得为 0 或复用 FileID）: %+v", lu.Inode)
	}
	code, got := spReadObject(t, nd.Base, types.ObjIDFor(lu.Inode), true)
	if code != http.StatusOK || !bytes.Equal(got, winner.body) {
		t.Fatalf("获胜 ObjID 对象字节不符: code=%d got=%q want=%q", code, got, winner.body)
	}
}

// ---- 2. 并发覆盖交错：提交结果必须与唯一成功者返回的快照一致（CAS） ----

func TestSmallPublishConcurrentOverwriteCommittedSnapshotConsistent(t *testing.T) {
	s := spNewStack(t)
	base := s.startMaster()
	gate := spNewPutGate()
	defer gate.open() // Fatalf/Goexit 时立即放行，master 侧 30s PUT 不残留
	t.Cleanup(gate.open)
	nd := s.startNode("", gate, nil, false)

	v0 := spSmallReq(base, "/shared", []byte("ORIG"), "sp-orig", false, true, 1)
	if !spWantStatus(t, "初始 small 写", v0.Status, http.StatusCreated) {
		t.FailNow()
	}

	// A 与 B 并发覆盖：先到 PUT 者被扣住（数据落盘但未提交），后到者完整走完。
	gate.arm(1)
	res := make(chan spPublishResult, 2)
	go func() { res <- spSmallReq(base, "/shared", []byte("AAAA"), "sp-ow-a", true, true, 1) }()
	go func() { res <- spSmallReq(base, "/shared", []byte("BBBB"), "sp-ow-b", true, true, 1) }()
	spWaitPutArrivals(t, gate, 1, 5*time.Second)

	early, ok := spRecv(t, res, 16*time.Second) // 未被扣住者先完成
	if !ok {
		spDrainPublish(t, gate, res)
		t.Fatalf("先完成的覆盖写未在时限内返回")
	}
	spReport(t, "先完成的覆盖写", early)
	if early.Status != http.StatusCreated {
		spDrainPublish(t, gate, res)
		t.Fatalf("先完成的覆盖写应 201，得到 %d", early.Status)
	}
	gate.open()
	late, ok := spRecv(t, res, 16*time.Second) // 被扣住者在目标已变化后放行
	if !ok {
		t.Fatalf("被扣住的覆盖写未在时限内返回")
	}
	spReport(t, "被扣住的覆盖写", late)
	if late.Status != http.StatusConflict {
		t.Fatalf("目标已变化的迟到覆盖写必须 CAS 409，得到 %d（body=%q）", late.Status, late.body)
	}

	// 最终元数据 = 唯一成功者（early）返回的 inode 快照。
	lst, lu := spLookup(t, base, "/shared", true)
	if !spWantStatus(t, "GET /meta /shared", lst, http.StatusOK) {
		t.FailNow()
	}
	want := early.Inode
	if lu.Inode.ID != want.ID || lu.Inode.ObjID != want.ObjID ||
		lu.Inode.Generation != want.Generation || lu.Inode.Size != want.Size ||
		lu.Inode.Checksum != want.Checksum {
		t.Fatalf("最终元数据与 201 快照不一致:\n lookup =%+v\n snapshot=%+v", lu.Inode, want)
	}
	// 元数据 ObjID 指向的物理对象承载的正是成功版本的字节，CRC 相符。
	code, got := spReadObject(t, nd.Base, types.ObjIDFor(lu.Inode), true)
	if code != http.StatusOK || !bytes.Equal(got, early.body) || types.CRC32C(got) != lu.Inode.Checksum {
		t.Fatalf("提交的 ObjID 对象必须承载成功版本字节: code=%d got=%q crc=%08x want_body=%q",
			code, got, types.CRC32C(got), early.body)
	}
	_, kids := spChildren(t, base, "/")
	if len(kids) != 1 || kids[0].ID != want.ID || kids[0].Name != "shared" {
		t.Fatalf("命名空间必须恰好是成功版本一份: kids=%+v", kids)
	}
}

// ---- 3. 节点落盘后 ack 丢失（伪造 503）：旧 ObjID/元数据仍可读 ----

func TestSmallPublishLostAckAfterNodePersistKeepsOldObjectReadable(t *testing.T) {
	s := spNewStack(t)
	base := s.startMaster()
	var inject atomic.Bool
	wrap := func(w http.ResponseWriter, r *http.Request, inner http.Handler) bool {
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/objects/") {
			return false
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read put body: %v", err)
			return false
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		if !inject.CompareAndSwap(true, false) {
			return false
		}
		rec := httptest.NewRecorder()
		inner.ServeHTTP(rec, r) // 真实落盘
		if rec.Code != http.StatusCreated {
			t.Errorf("节点未持久化新对象就返回: %d", rec.Code)
		}
		http.Error(w, "lost ack after store", http.StatusServiceUnavailable) // 伪造 ack 丢失
		return true
	}
	nd := s.startNode("", nil, wrap, false)

	v1 := spSmallReq(base, "/file", []byte("OLD!"), "sp-old", false, true, 1)
	if !spWantStatus(t, "初始 small 写", v1.Status, http.StatusCreated) {
		t.FailNow()
	}
	old := v1.Inode

	inject.Store(true)
	failed := spSmallReq(base, "/file", []byte("NEW!"), "sp-new", true, true, 1)
	if !spWantStatus(t, "注入 503 的覆盖写", failed.Status, http.StatusServiceUnavailable) {
		t.FailNow()
	}

	// 元数据必须仍是旧版本（同 FileID/ObjID/Generation/大小/CRC）。
	lst, lu := spLookup(t, base, "/file", true)
	if !spWantStatus(t, "GET /meta /file", lst, http.StatusOK) {
		t.FailNow()
	}
	if lu.Inode.ID != old.ID || lu.Inode.ObjID != old.ObjID || lu.Inode.Generation != old.Generation ||
		lu.Inode.Size != old.Size || lu.Inode.Checksum != old.Checksum {
		t.Fatalf("失败覆盖不得动元数据:\n before=%+v\n after =%+v", old, lu.Inode)
	}
	code, got := spReadObject(t, nd.Base, types.ObjIDFor(old), true)
	if code != http.StatusOK || !bytes.Equal(got, []byte("OLD!")) || types.CRC32C(got) != old.Checksum {
		t.Fatalf("旧对象必须原样可读: code=%d got=%q crc=%08x", code, got, types.CRC32C(got))
	}

	// 恢复：同路径再次覆盖正常成功，切换到全新对象。
	fixed := spSmallReq(base, "/file", []byte("FIXED!"), "sp-fix", true, true, 1)
	if !spWantStatus(t, "恢复覆盖写", fixed.Status, http.StatusCreated) {
		t.FailNow()
	}
	if types.ObjIDFor(fixed.Inode) == types.ObjIDFor(old) {
		t.Fatalf("恢复写入必须使用新 ObjID（不可原地复用）: %+v", fixed.Inode)
	}
	code2, got2 := spReadObject(t, nd.Base, types.ObjIDFor(fixed.Inode), true)
	if code2 != http.StatusOK || !bytes.Equal(got2, []byte("FIXED!")) {
		t.Fatalf("恢复后读取不符: code=%d got=%q", code2, got2)
	}
}

// ---- 4. small → chunked → small：针对旧物理 ObjID 的迟到 DELETE 不伤最新 ----

func TestSmallPublishLateDeleteOfRetiredObjectCannotHarmLatest(t *testing.T) {
	s := spNewStack(t)
	base := s.startMaster()
	nd := s.startNode(base, nil, nil, true) // 需 nodeID（/files/replicated 成员校验）

	v1 := spSmallReq(base, "/file", []byte("one"), "sp-v1", false, true, 1)
	if !spWantStatus(t, "small v1", v1.Status, http.StatusCreated) {
		t.FailNow()
	}
	first := v1.Inode
	oldObj := types.ObjIDFor(first)

	// small → chunked（真实分块链路：staging → assign → PUT → replicated → commit）。
	st, raw := spPostJSON(t, base+"/files", map[string]any{
		"path": "/file", "replicas": 1, "overwrite": true, "chunked": true,
	}, true)
	if !spWantStatus(t, "POST /files chunked", st, http.StatusCreated) {
		t.FailNow()
	}
	var created struct {
		Inode types.Inode `json:"inode"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("decode staging: %v", err)
	}
	chunkBody := []byte("two-chunk-bytes")
	st, raw = spPostJSON(t, base+"/files/chunks", map[string]any{
		"inode_id": created.Inode.ID, "index": 0,
		"size": len(chunkBody), "replicas": 1, "checksum": types.CRC32C(chunkBody),
	}, true)
	if !spWantStatus(t, "POST /files/chunks", st, http.StatusOK) {
		t.FailNow()
	}
	var assigned struct {
		Chunk types.ChunkInfo `json:"chunk"`
	}
	if err := json.Unmarshal(raw, &assigned); err != nil {
		t.Fatalf("decode assign: %v", err)
	}
	chunkID := assigned.Chunk.ID
	if chunkID == 0 {
		t.Fatalf("块表必须自描述对象 ID: %+v", assigned.Chunk)
	}
	if code := spPutObject(t, nd.Base, chunkID, chunkBody); code != http.StatusCreated {
		t.Fatalf("PUT chunk = %d", code)
	}
	if st, _ := spPostJSON(t, base+"/files/replicated", map[string]uint64{
		"inode_id": chunkID, "node_id": nd.Info.ID,
	}, false); st != http.StatusOK {
		t.Fatalf("POST /files/replicated = %d", st)
	}
	if st, raw := spPostJSON(t, base+"/files/commit", map[string]any{
		"inode_id": created.Inode.ID, "name": "file",
		"size": len(chunkBody), "chunk_count": 1,
	}, true); st != http.StatusOK {
		t.Fatalf("commit chunked = %d: %s", st, raw)
	}
	code, got := spReadObject(t, nd.Base, chunkID, true)
	if code != http.StatusOK || !bytes.Equal(got, chunkBody) {
		t.Fatalf("chunked 版本对象不符: code=%d got=%q", code, got)
	}

	// chunked → small（再覆盖回小文件通道）。
	v3 := spSmallReq(base, "/file", []byte("three"), "sp-v3", true, true, 1)
	if !spWantStatus(t, "small v3", v3.Status, http.StatusCreated) {
		t.FailNow()
	}
	latest := v3.Inode
	latestObj := types.ObjIDFor(latest)
	if latest.ID != first.ID {
		t.Fatalf("覆盖写必须保留文件身份: first=%d latest=%d", first.ID, latest.ID)
	}
	if latestObj == oldObj || latestObj == chunkID {
		t.Fatalf("每次发布必须使用全新对象: latest=%d old=%d chunk=%d", latestObj, oldObj, chunkID)
	}

	// 显式对旧物理对象发起迟到 DELETE（retired/宽限内的回收动作晚到模拟）；
	// 节点 DELETE 幂等，master 是否已提前回收不影响本断言。
	if code := spDeleteObject(t, nd.Base, oldObj); code != http.StatusOK {
		t.Errorf("迟到 DELETE 旧 small 对象 = %d", code)
	}
	if code := spDeleteObject(t, nd.Base, chunkID); code != http.StatusOK {
		t.Errorf("迟到 DELETE 旧 chunk 对象 = %d", code)
	}

	// 最新版本完好：元数据指向最新 ObjID，字节与 CRC 无损。
	lst, lu := spLookup(t, base, "/file", true)
	if !spWantStatus(t, "GET /meta /file", lst, http.StatusOK) {
		t.FailNow()
	}
	if lu.Inode.Chunked || types.ObjIDFor(lu.Inode) != latestObj {
		t.Fatalf("最新元数据必须指向 small 最新对象: %+v", lu.Inode)
	}
	code2, got2 := spReadObject(t, nd.Base, latestObj, true)
	if code2 != http.StatusOK || !bytes.Equal(got2, []byte("three")) || types.CRC32C(got2) != lu.Inode.Checksum {
		t.Fatalf("迟到的旧对象删除破坏了最新版本: code=%d got=%q", code2, got2)
	}
}

// ---- 5. op_id 幂等：并发同 op 回放同快照；复用于不同操作必须 409 ----

func TestSmallPublishOpIDConcurrentReplayAndMismatchConflict(t *testing.T) {
	s := spNewStack(t)
	base := s.startMaster()
	gate := spNewPutGate()
	defer gate.open() // Fatalf/Goexit 时立即放行，master 侧 30s PUT 不残留
	t.Cleanup(gate.open)
	nd := s.startNode("", gate, nil, false)

	// (a) 同 op_id 并发同 payload：一 201 一 200 回放，inode/gen/objID 完全一致。
	gate.arm(2)
	res := make(chan spPublishResult, 2)
	go func() { res <- spSmallReq(base, "/replay", []byte("SAME"), "sp-op-1", false, true, 1) }()
	go func() { res <- spSmallReq(base, "/replay", []byte("SAME"), "sp-op-1", false, true, 1) }()
	spWaitPutArrivals(t, gate, 2, 1500*time.Millisecond)
	gate.open()

	ra, oka := spRecv(t, res, 16*time.Second)
	rb, okb := spRecv(t, res, 16*time.Second)
	if !oka || !okb {
		t.Fatalf("同 op_id 并发请求未在时限内返回")
	}
	spReport(t, "同 op 并发 A", ra)
	spReport(t, "同 op 并发 B", rb)
	created := 0
	for _, r := range []spPublishResult{ra, rb} {
		if r.Status != http.StatusCreated && r.Status != http.StatusOK {
			t.Fatalf("同 op_id 并发同 payload 必须全部成功（201/200 回放），得到 %d（body=%q）", r.Status, r.body)
		}
		if r.Status == http.StatusCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("同 op_id 并发必须恰好一次真实执行（201），得到 %d", created)
	}
	if ra.Inode.ID != rb.Inode.ID || ra.Inode.Generation != rb.Inode.Generation || ra.Inode.ObjID != rb.Inode.ObjID {
		t.Fatalf("回放必须返回同一 inode/gen/objID:\n A=%+v\n B=%+v", ra.Inode, rb.Inode)
	}
	if ra.Inode.ObjID == 0 {
		t.Fatalf("回放快照缺 ObjID: %+v", ra.Inode)
	}
	st, kids := spChildren(t, base, "/")
	if !spWantStatus(t, "GET /dirs/children", st, http.StatusOK) {
		t.FailNow()
	}
	if len(kids) != 1 || kids[0].ID != ra.Inode.ID {
		t.Fatalf("同 op_id 并发只允许产生一个文件: kids=%+v", kids)
	}

	// (b) 同 op_id 不同 path → 409，且不得产生新文件。
	mis := spSmallReq(base, "/elsewhere", []byte("zzz"), "sp-op-1", false, true, 1)
	if !spWantStatus(t, "op_id 挪用（不同 path）", mis.Status, http.StatusConflict) {
		t.Fatalf("响应体: %s", mis.BodySnip)
	}
	if st2, _ := spLookup(t, base, "/elsewhere", true); st2 != http.StatusNotFound {
		t.Fatalf("被拒的 op_id 挪用不得产生新文件: /elsewhere status=%d", st2)
	}

	// (c) 同 op_id 同 path 不同 body → 409，原内容不变。
	evil := spSmallReq(base, "/replay", []byte("EVIL"), "sp-op-1", true, true, 1)
	if !spWantStatus(t, "op_id 挪用（不同 body）", evil.Status, http.StatusConflict) {
		t.FailNow()
	}
	lst, lu := spLookup(t, base, "/replay", true)
	if !spWantStatus(t, "GET /meta /replay", lst, http.StatusOK) {
		t.FailNow()
	}
	if lu.Inode.ID != ra.Inode.ID || lu.Inode.ObjID != ra.Inode.ObjID || lu.Inode.Generation != ra.Inode.Generation {
		t.Fatalf("被拒挪用不得改动元数据: %+v vs %+v", lu.Inode, ra.Inode)
	}
	code, got := spReadObject(t, nd.Base, types.ObjIDFor(lu.Inode), true)
	if code != http.StatusOK || !bytes.Equal(got, []byte("SAME")) {
		t.Fatalf("被拒挪用不得改动对象内容: code=%d got=%q", code, got)
	}
}

// ---- 6a. 新 ObjID 小文件三节点复制；删主副本后其余副本可读 ----

func TestSmallPublishThreeNodeReplicationSurvivesPrimaryLoss(t *testing.T) {
	s := spNewStack(t)
	base := s.startMaster()
	var nodes []*spNodeT
	for i := 0; i < 3; i++ {
		nodes = append(nodes, s.startNode(base, nil, nil, true))
	}

	r := spSmallReq(base, "/rep", []byte("REPLICATED"), "sp-rep", false, true, 3)
	if !spWantStatus(t, "replicas=3 small 写", r.Status, http.StatusCreated) {
		t.FailNow()
	}
	objID := types.ObjIDFor(r.Inode)
	if objID == 0 || objID == r.Inode.ID {
		t.Fatalf("必须使用独立 ObjID: %+v", r.Inode)
	}

	// 三节点最终都持有该对象（异步复制，限时轮询；节点侧重试退避 1s+2s，
	// 正常 2-6s 内完成；20s 上限只为真正 broken 时尽快失败）。
	missing := map[string]bool{}
	for _, n := range nodes {
		missing[n.Base] = true
	}
	deadline := time.Now().Add(20 * time.Second)
	for len(missing) > 0 && time.Now().Before(deadline) {
		for nodeBase := range missing {
			code, got := spReadObject(t, nodeBase, objID, true)
			if code == http.StatusOK && bytes.Equal(got, []byte("REPLICATED")) {
				delete(missing, nodeBase)
			}
		}
		if len(missing) > 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("三节点复制未在时限内完成，缺副本: %v", missing)
	}

	// 删除主副本上的物理对象，其余副本仍可读且内容/CRC 完整。
	lst, lu := spLookup(t, base, "/rep", true)
	if !spWantStatus(t, "GET /meta /rep", lst, http.StatusOK) {
		t.FailNow()
	}
	if len(lu.Inode.Replicas) == 0 || len(lu.Nodes) == 0 {
		t.Fatalf("lookup 缺副本信息: %+v", lu)
	}
	primaryID := lu.Inode.Replicas[0]
	primaryBase := ""
	for _, n := range nodes {
		if n.Info.ID == primaryID {
			primaryBase = n.Base
		}
	}
	if primaryBase == "" {
		t.Fatalf("找不到主副本节点 %d", primaryID)
	}
	if code := spDeleteObject(t, primaryBase, objID); code != http.StatusOK {
		t.Fatalf("删除主副本对象 = %d", code)
	}
	if code, _ := spReadObject(t, primaryBase, objID, true); code != http.StatusNotFound {
		t.Fatalf("主副本对象应已删除: code=%d", code)
	}
	served := 0
	for _, n := range nodes {
		code, got := spReadObject(t, n.Base, objID, true)
		if code == http.StatusOK {
			served++
			if !bytes.Equal(got, []byte("REPLICATED")) || types.CRC32C(got) != lu.Inode.Checksum {
				t.Fatalf("副本 %s 内容损坏: %q", n.Base, got)
			}
		}
	}
	if served < 2 {
		t.Fatalf("删除主副本后至少 2 个副本可读，实际 %d", served)
	}
}

// ---- 6b. GC 两轮确认不得删除已提交的新 ObjID 对象 ----

func TestSmallPublishGCTwoRoundsSparesCommittedObject(t *testing.T) {
	s := spNewStack(t)
	base := s.startMaster()
	scanner := NewScanner(s.store, time.Hour, time.Hour, time.Hour)
	s.srv.SetScanner(scanner)
	nd := s.startNode("", nil, nil, false)

	r := spSmallReq(base, "/gc-keep", []byte("PRECIOUS"), "sp-gc", false, true, 1)
	if !spWantStatus(t, "small 写", r.Status, http.StatusCreated) {
		t.FailNow()
	}
	objID := types.ObjIDFor(r.Inode)
	if code, _ := spReadObject(t, nd.Base, objID, true); code != http.StatusOK {
		t.Fatalf("对象应已在节点上: code=%d", code)
	}

	rep1 := spGCRun(t, base, true)
	rep2 := spGCRun(t, base, true)

	code, got := spReadObject(t, nd.Base, objID, true)
	if code != http.StatusOK || !bytes.Equal(got, []byte("PRECIOUS")) {
		t.Fatalf("GC 两轮后已提交的新 ObjID 对象被误删: code=%d got=%q", code, got)
	}
	for i, rep := range [][]spGCReport{rep1, rep2} {
		for _, nr := range rep {
			if nr.Deleted != 0 {
				t.Errorf("GC 第 %d 轮删除了 %d 个对象（新模型下不该有孤儿）", i+1, nr.Deleted)
			}
			for _, o := range nr.Orphans {
				if o.ID == objID {
					t.Errorf("GC 第 %d 轮把已提交对象 %d 当孤儿", i+1, objID)
				}
			}
		}
	}
	if lst, _ := spLookup(t, base, "/gc-keep", true); lst != http.StatusOK {
		t.Fatalf("GC 后元数据不可读: %d", lst)
	}
}

// ---- 6c. GC 两轮确认不得删除上传中的 reserved/pending 对象 ----

func TestSmallPublishGCTwoRoundsSparesInflightPendingObject(t *testing.T) {
	s := spNewStack(t)
	base := s.startMaster()
	scanner := NewScanner(s.store, time.Hour, time.Hour, time.Hour)
	s.srv.SetScanner(scanner)
	gate := spNewPutGate()
	defer gate.open() // Fatalf/Goexit 时立即放行，master 侧 30s PUT 不残留
	t.Cleanup(gate.open)
	nd := s.startNode("", gate, nil, false)

	// 发布在途：pending 登记先于 PUT；对象已落盘、元数据未提交。
	gate.arm(1)
	res := make(chan spPublishResult, 1)
	go func() { res <- spSmallReq(base, "/inflight", []byte("PENDING"), "sp-pending", false, true, 1) }()
	objID, ok := gate.takeArrival(5 * time.Second)
	if !ok {
		spDrainPublish(t, gate, res)
		t.Fatalf("发布未在时限内到达节点 PUT（pending 登记应先于 PUT）")
	}
	if code, _ := spReadObject(t, nd.Base, objID, true); code != http.StatusOK {
		spDrainPublish(t, gate, res)
		t.Fatalf("在途对象应已落盘: code=%d", code)
	}

	// 元数据未提交的窗口内，GC 连续两轮执行都不得删除该对象。
	spGCRun(t, base, true)
	code1, _ := spReadObject(t, nd.Base, objID, true)
	rep2 := spGCRun(t, base, true)
	code2, _ := spReadObject(t, nd.Base, objID, true)
	if code1 != http.StatusOK || code2 != http.StatusOK {
		spDrainPublish(t, gate, res)
		t.Fatalf("上传中的 reserved 对象被 GC 删除: 第1轮后=%d 第2轮后=%d", code1, code2)
	}
	for _, nr := range rep2 {
		if nr.Deleted != 0 {
			t.Errorf("GC 第 2 轮删除了 %d 个对象（含 reserved 对象）", nr.Deleted)
		}
	}

	// 放行后发布完成，对象即受元数据保护。
	gate.open()
	r, ok := spRecv(t, res, 16*time.Second)
	if !ok {
		t.Fatalf("发布未在时限内完成")
	}
	spReport(t, "放行后的发布", r)
	if !spWantStatus(t, "放行后的 small 写", r.Status, http.StatusCreated) {
		t.FailNow()
	}
	if types.ObjIDFor(r.Inode) != objID {
		t.Fatalf("提交的 ObjID 必须是 PUT 的对象: inode=%+v put=%d", r.Inode, objID)
	}
	if lst, lu := spLookup(t, base, "/inflight", true); lst != http.StatusOK || lu.Inode.ID != r.Inode.ID {
		t.Fatalf("发布完成后元数据不可读: status=%d", lst)
	}
	spGCRun(t, base, true)
	code3, got := spReadObject(t, nd.Base, objID, true)
	if code3 != http.StatusOK || !bytes.Equal(got, []byte("PENDING")) {
		t.Fatalf("提交后 GC 误删对象: code=%d got=%q", code3, got)
	}
}

// ---- 7. 旧客户端（无 features 头）：small 写 426；explicit lookup 426；legacy 仍 200 ----

func TestSmallPublishLegacyClientWithoutFeaturesHeaderGets426(t *testing.T) {
	s := spNewStack(t)
	base := s.startMaster()
	nd := s.startNode("", nil, nil, false)

	// (1) 无 features 头的 small 新建 → 426，且不得产生任何副作用。
	r := spSmallReq(base, "/upgrade", []byte("x"), "sp-legacy-1", false, false, 1)
	if !spWantStatus(t, "无 features 头 small 新建", r.Status, http.StatusUpgradeRequired) {
		t.FailNow()
	}
	if st, kids := spChildren(t, base, "/"); st != http.StatusOK || len(kids) != 0 {
		t.Fatalf("被拒请求不得产生命名空间副作用: kids=%+v", kids)
	}
	// (2) 带头 → 201。
	ok := spSmallReq(base, "/upgrade", []byte("x"), "sp-new-1", false, true, 1)
	if !spWantStatus(t, "带头 small 新建", ok.Status, http.StatusCreated) {
		t.FailNow()
	}
	// (3) explicit ObjID 的 /meta lookup：无头 426、带头 200。
	if st, _ := spDo(t, http.MethodGet, base+"/meta?path=/upgrade", nil, false); st != http.StatusUpgradeRequired {
		t.Fatalf("explicit obj lookup 无头应 426，得到 %d", st)
	}
	lst, lu := spLookup(t, base, "/upgrade", true)
	if !spWantStatus(t, "带头 explicit lookup", lst, http.StatusOK) {
		t.FailNow()
	}
	if lu.Inode.ObjID == 0 {
		t.Fatalf("新写入应有显式 ObjID: %+v", lu.Inode)
	}
	// (4) legacy 旧布局（ObjID=0）：不带头仍可读（滚动升级兼容）。
	st, raw := spPostJSON(t, base+"/files", map[string]any{
		"path": "/legacy-layout", "replicas": 1, "overwrite": false,
	}, false)
	if !spWantStatus(t, "legacy POST /files", st, http.StatusCreated) {
		t.FailNow()
	}
	var legacy struct {
		Inode types.Inode `json:"inode"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("decode legacy create: %v", err)
	}
	if code := spPutObject(t, nd.Base, legacy.Inode.ID, []byte("legacy-bytes")); code != http.StatusCreated {
		t.Fatalf("legacy PUT = %d", code)
	}
	if st, _ := spPostJSON(t, base+"/files/commit", map[string]any{
		"inode_id": legacy.Inode.ID, "size": len("legacy-bytes"),
	}, false); st != http.StatusOK {
		t.Fatalf("legacy commit = %d", st)
	}
	if stNo, _ := spLookup(t, base, "/legacy-layout", false); stNo != http.StatusOK {
		t.Fatalf("legacy 布局 lookup 不带头应 200，得到 %d", stNo)
	}
	if stH, luL := spLookup(t, base, "/legacy-layout", true); stH != http.StatusOK || luL.Inode.ObjID != 0 {
		t.Fatalf("legacy 布局带头 lookup 应 200 且 ObjID=0: status=%d inode=%+v", stH, luL.Inode)
	}
	// (5) 无 features 头的覆盖写同样 426（small 写始终要求升级）。
	r2 := spSmallReq(base, "/upgrade", []byte("y"), "sp-legacy-2", true, false, 1)
	if !spWantStatus(t, "无 features 头 small 覆盖", r2.Status, http.StatusUpgradeRequired) {
		t.FailNow()
	}
}

// ---- 8. 节点 PUT 在途期间 namespace 变化：不得复活旧 path 或损坏新位置 ----

func TestSmallPublishNamespaceMutationDuringPublishNoResurrectionNoCorruption(t *testing.T) {
	t.Run("rename", func(t *testing.T) { spNamespaceMutationCase(t, "rename") })
	t.Run("delete", func(t *testing.T) { spNamespaceMutationCase(t, "delete") })
	t.Run("symlink", func(t *testing.T) { spNamespaceMutationCase(t, "symlink") })
}

func spNamespaceMutationCase(t *testing.T, mutation string) {
	s := spNewStack(t)
	base := s.startMaster()
	gate := spNewPutGate()
	defer gate.open() // Fatalf/Goexit 时立即放行，master 侧 30s PUT 不残留
	t.Cleanup(gate.open)
	nd := s.startNode("", gate, nil, false)

	v1 := spSmallReq(base, "/f", []byte("V1"), "sp-ns-v1", false, true, 1)
	if !spWantStatus(t, "初始 small 写", v1.Status, http.StatusCreated) {
		t.FailNow()
	}
	old := v1.Inode

	// 覆盖写在途（数据已落盘、元数据未提交）期间做 namespace 变更。
	gate.arm(1)
	res := make(chan spPublishResult, 1)
	go func() { res <- spSmallReq(base, "/f", []byte("V2"), "sp-ns-v2", true, true, 1) }()
	if _, ok := gate.takeArrival(5 * time.Second); !ok {
		spDrainPublish(t, gate, res)
		t.Fatalf("覆盖写未在时限内到达节点 PUT")
	}

	switch mutation {
	case "rename":
		if st, _ := spPostJSON(t, base+"/entry/rename", map[string]string{"path": "/f", "new_name": "g"}, false); st != http.StatusOK {
			spDrainPublish(t, gate, res)
			t.Fatalf("在途发布期间 rename = %d", st)
		}
	case "delete":
		if st, _ := spDo(t, http.MethodDelete, base+"/entry?path=/f", nil, false); st != http.StatusOK {
			spDrainPublish(t, gate, res)
			t.Fatalf("在途发布期间 delete = %d", st)
		}
	case "symlink":
		if st, _ := spDo(t, http.MethodDelete, base+"/entry?path=/f", nil, false); st != http.StatusOK {
			spDrainPublish(t, gate, res)
			t.Fatalf("symlink 场景前置 delete = %d", st)
		}
		if st, _ := spPostJSON(t, base+"/files/symlink", map[string]string{"path": "/f", "target": "../elsewhere"}, false); st != http.StatusCreated {
			spDrainPublish(t, gate, res)
			t.Fatalf("在途发布期间 create symlink = %d", st)
		}
	}
	gate.open()

	pub, ok := spRecv(t, res, 16*time.Second)
	if !ok {
		t.Fatalf("放行后发布未在时限内返回")
	}
	spReport(t, "在途发布", pub)

	// (1) children 不得出现同一 inode 的双重挂载（改名后的 inode 被旧名重新挂回）。
	_, kids := spChildren(t, base, "/")
	seen := map[uint64]string{}
	for _, k := range kids {
		if prev, dup := seen[k.ID]; dup {
			t.Errorf("children 双重挂载: %q 与 %q 共用 inode %d", prev, k.Name, k.ID)
		}
		seen[k.ID] = k.Name
	}
	// (2) 旧路径 /f 的终态必须自洽，且绝不指向旧 inode。
	stF, luF := spLookup(t, base, "/f", true)
	switch {
	case stF == http.StatusOK:
		if luF.Inode.ID == old.ID {
			t.Errorf("旧 path /f 复活了已被 %s 的旧 inode %d", mutation, old.ID)
		}
		switch luF.Inode.Type {
		case types.TypeFile:
			code, got := spReadObject(t, nd.Base, types.ObjIDFor(luF.Inode), true)
			if code != http.StatusOK || !bytes.Equal(got, []byte("V2")) || types.CRC32C(got) != luF.Inode.Checksum {
				t.Errorf("/f 上的文件字节错误: code=%d got=%q", code, got)
			}
			if pub.Status == http.StatusCreated &&
				(luF.Inode.ID != pub.Inode.ID || luF.Inode.ObjID != pub.Inode.ObjID) {
				t.Errorf("201 快照与最终元数据不一致: /f=%+v pub=%+v", luF.Inode, pub.Inode)
			}
		case types.TypeSymlink:
			if luF.Inode.Target != "../elsewhere" {
				t.Errorf("符号链接目标被破坏: %q", luF.Inode.Target)
			}
			if pub.Status == http.StatusCreated {
				t.Errorf("发布返回 201 但 /f 仍是符号链接")
			}
		default:
			t.Errorf("/f 出现意外类型 %v", luF.Inode.Type)
		}
	case stF == http.StatusNotFound:
		if pub.Status == http.StatusCreated {
			t.Errorf("发布返回 201 但 /f 不存在（快照 inode=%d obj=%d）", pub.Inode.ID, pub.Inode.ObjID)
		}
	default:
		t.Fatalf("/f 查询出现意外状态 %d", stF)
	}
	// (3) 发布声明成功时快照必须是独立新对象。
	if pub.Status == http.StatusCreated && (pub.Inode.ObjID == 0 || pub.Inode.ObjID == old.ObjID) {
		t.Errorf("成功发布必须使用全新 ObjID: %+v", pub.Inode)
	}
	// (4) rename 场景：新位置 /g 必须完好。
	if mutation == "rename" {
		stG, luG := spLookup(t, base, "/g", true)
		if stG != http.StatusOK || luG.Inode.ID != old.ID {
			t.Fatalf("新位置 /g 损坏: status=%d inode=%+v (want id=%d)", stG, luG.Inode, old.ID)
		}
		code, got := spReadObject(t, nd.Base, types.ObjIDFor(luG.Inode), true)
		if code != http.StatusOK || !bytes.Equal(got, []byte("V1")) || types.CRC32C(got) != luG.Inode.Checksum {
			t.Fatalf("新位置 /g 内容损坏: code=%d got=%q", code, got)
		}
	}
}
