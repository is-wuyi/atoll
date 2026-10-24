package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"atoll/master"
	"atoll/master/meta"
	"atoll/node"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

// ---- 节点侧 lab 包装：物理来源录制 + 故障注入 + 事件导出 ----
//
// 事件只记录 start/end(UTC)、monotonic 时长、body 字节数、nodeID/label、
// 方法与对象路由（含 Range 头原值用于区分 master 探测）；绝不记录
// Authorization 头或任何对象内容。active GET 用原子计数。

type labEvent struct {
	StartUTC   string `json:"start_utc"`
	EndUTC     string `json:"end_utc"`
	DurationMS int64  `json:"duration_ms"`
	Bytes      int64  `json:"body_bytes"`
	NodeID     uint64 `json:"node_id"`
	Label      string `json:"label"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Range      string `json:"range,omitempty"`
	Fault      string `json:"fault,omitempty"`
}

// nodeFault 是一次注入声明：kind=read_delay|drop|ack_error；
// target=get|replicate|all；object_id=0 表示全局。read_delay/drop 只作用于
// 完整对象 GET（无 Range 头），master 的 1 字节 Range 探测不受影响、
// 事件里以 range 字段可区分；ack_error 只作用于 PUT /replicate。
type nodeFault struct {
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	ObjectID uint64 `json:"object_id"`
	DelayMS  int    `json:"delay_ms"`
}

type nodeLab struct {
	label     string
	nodeID    atomic.Int64
	maxEvents int

	mu         sync.Mutex
	events     []labEvent
	dropped    int
	activeGets atomic.Int64
	gets       atomic.Int64
	puts       atomic.Int64
	replicates atomic.Int64
	fault      atomic.Pointer[nodeFault]
}

func newNodeLab(label string, maxEvents int) *nodeLab {
	if maxEvents <= 0 {
		maxEvents = 4096
	}
	return &nodeLab{label: label, maxEvents: maxEvents}
}

// classifyObjectRoute 识别要录制的数据面路由：
// GET /objects/{id}、PUT /objects/{id}（客户端入口）、PUT /replicate/{id}（腿接收）。
func classifyObjectRoute(method, path string) (uint64, string) {
	switch {
	case method == http.MethodGet && strings.HasPrefix(path, "/objects/"):
	case method == http.MethodPut && (strings.HasPrefix(path, "/objects/") || strings.HasPrefix(path, "/replicate/")):
	default:
		return 0, ""
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(path, "/objects/"), "/replicate/")
	id, err := strconv.ParseUint(rest, 10, 64)
	if err != nil || id == 0 {
		return 0, ""
	}
	switch {
	case method == http.MethodGet:
		return id, "get"
	case strings.HasPrefix(path, "/replicate/"):
		return id, "replicate"
	default:
		return id, "put"
	}
}

// WrapNode 在生产 node.Handler() 外包上录制与 lab 路由；/lab/* 由同一把
// 共享随机 Bearer 门控。计数 ResponseWriter 实现 Unwrap()，计划写租约依赖的
// http.NewResponseController(...).SetReadDeadline 才能穿透包装层。
func (l *nodeLab) WrapNode(n *node.Node, token auth.Token) http.Handler {
	lab := http.NewServeMux()
	lab.HandleFunc("GET /lab/status", l.handleStatus)
	lab.HandleFunc("GET /lab/events", l.handleEvents)
	lab.HandleFunc("POST /lab/fault", l.handleFault)
	lab.HandleFunc("DELETE /lab/fault", l.handleFaultClear)
	gated := auth.Wrap(lab, token)
	inner := n.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/lab/") {
			gated.ServeHTTP(w, r)
			return
		}
		objID, kind := classifyObjectRoute(r.Method, r.URL.Path)
		if kind == "" {
			inner.ServeHTTP(w, r)
			return
		}
		l.record(w, r, objID, kind, inner)
	})
}

func (l *nodeLab) record(w http.ResponseWriter, r *http.Request, objID uint64, kind string, inner http.Handler) {
	switch kind {
	case "get":
		l.gets.Add(1)
		l.activeGets.Add(1)
	case "put":
		l.puts.Add(1)
	case "replicate":
		l.replicates.Add(1)
	}
	ev := labEvent{StartUTC: time.Now().UTC().Format(time.RFC3339Nano),
		NodeID: uint64(l.nodeID.Load()), Label: l.label, Method: r.Method, Path: r.URL.Path,
		Range: r.Header.Get("Range")}
	started := time.Now()
	if kind == "get" {
		defer l.activeGets.Add(-1)
	}
	defer func() {
		ev.DurationMS = time.Since(started).Milliseconds()
		ev.EndUTC = time.Now().UTC().Format(time.RFC3339Nano)
		l.append(ev)
	}()

	fault := l.matchFault(kind, objID, ev.Range)
	if fault != nil {
		ev.Fault = fault.Kind
		switch fault.Kind {
		case "drop": // 连接中断：不进生产 handler，事件由 defer 落盘
			panic(http.ErrAbortHandler)
		case "read_delay": // 仅完整 GET：拖延源服务，不改结果；随客户端取消提前结束
			select {
			case <-time.After(time.Duration(fault.DelayMS) * time.Millisecond):
			case <-r.Context().Done():
			}
		}
	}
	if fault != nil && fault.Kind == "ack_error" && kind != "get" {
		// “半途确认”：数据照常入库、回执照发（生产路径完整执行），
		// 仅把 201 翻成 503，让发起方按失败重试（重试幂等收敛，无内容分叉）。
		cw := &countWriter{ResponseWriter: w, flipTo503: true}
		inner.ServeHTTP(cw, r)
		return
	}
	if kind == "get" {
		cw := &countWriter{ResponseWriter: w}
		if fault != nil && fault.Kind == "ack_error" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(cw, r)
		ev.Bytes = cw.n
		return
	}
	body := &countingBody{ReadCloser: r.Body}
	r.Body = body
	inner.ServeHTTP(w, r)
	ev.Bytes = body.n
}

// matchFault：get 的 read_delay/drop 只命中完整对象 GET（Range 为空）。
func (l *nodeLab) matchFault(kind string, objID uint64, rangeHeader string) *nodeFault {
	f := l.fault.Load()
	if f == nil {
		return nil
	}
	if f.ObjectID != 0 && f.ObjectID != objID {
		return nil
	}
	switch f.Target {
	case "all":
	case "get":
		if kind != "get" {
			return nil
		}
	case "replicate":
		if kind != "replicate" {
			return nil
		}
	default:
		return nil
	}
	if kind == "get" && f.Kind != "ack_error" && rangeHeader != "" {
		return nil // master Range 探测不受延迟/中断影响
	}
	return f
}

func (l *nodeLab) append(ev labEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) >= l.maxEvents {
		l.events = l.events[1:]
		l.dropped++
	}
	l.events = append(l.events, ev)
}

func (l *nodeLab) handleStatus(w http.ResponseWriter, _ *http.Request) {
	l.mu.Lock()
	fault := l.fault.Load()
	var f *nodeFault
	if fault != nil {
		cp := *fault
		f = &cp
	}
	l.mu.Unlock() // 必须解锁：此后每次 poll 才不会把事件录制/导出永久锁死
	writeJSONLab(w, http.StatusOK, map[string]any{
		"label": l.label, "node_id": l.nodeID.Load(),
		"active_gets": l.activeGets.Load(),
		"totals":      map[string]int64{"gets": l.gets.Load(), "puts": l.puts.Load(), "replicates": l.replicates.Load()},
		"dropped":     l.dropped, "events": len(l.events), "fault": f, "now_utc": time.Now().UTC(),
	})
}

func (l *nodeLab) handleEvents(w http.ResponseWriter, _ *http.Request) {
	l.mu.Lock()
	snapshot := append([]labEvent(nil), l.events...)
	l.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	for _, ev := range snapshot {
		_ = enc.Encode(ev)
	}
}

func (l *nodeLab) handleFault(w http.ResponseWriter, r *http.Request) {
	var f nodeFault
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		writeJSONLab(w, http.StatusBadRequest, map[string]string{"error": "bad fault json"})
		return
	}
	if f.Kind != "read_delay" && f.Kind != "drop" && f.Kind != "ack_error" {
		writeJSONLab(w, http.StatusBadRequest, map[string]string{"error": "kind 需为 read_delay|drop|ack_error"})
		return
	}
	if f.Target != "get" && f.Target != "replicate" && f.Target != "all" {
		writeJSONLab(w, http.StatusBadRequest, map[string]string{"error": "target 需为 get|replicate|all"})
		return
	}
	if f.Kind == "read_delay" && (f.DelayMS <= 0 || f.DelayMS > 60_000) {
		writeJSONLab(w, http.StatusBadRequest, map[string]string{"error": "read_delay 需要 0<delay_ms≤60000（lab 上限，防误配无限拖延）"})
		return
	}
	l.fault.Store(&f)
	writeJSONLab(w, http.StatusOK, map[string]any{"set": true, "fault": f})
}

func (l *nodeLab) handleFaultClear(w http.ResponseWriter, _ *http.Request) {
	l.fault.Store(nil)
	writeJSONLab(w, http.StatusOK, map[string]bool{"set": false})
}

// countWriter 统计写出字节；实现 Unwrap() 透传 ResponseController，
// 实现 Flush() 保留流式语义；ack_error 时把 201 翻成 503。
type countWriter struct {
	http.ResponseWriter
	n         int64
	flipTo503 bool
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}

func (c *countWriter) WriteHeader(code int) {
	if c.flipTo503 && code == http.StatusCreated {
		code = http.StatusServiceUnavailable
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *countWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *countWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// countingBody 统计 handler 实际读入的请求体字节。
type countingBody struct {
	io.ReadCloser
	n int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	return n, err
}

func writeJSONLab(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- master 侧 lab 控制面：直接调用生产 Store/Autonomy ----

type masterLab struct {
	store      *meta.Store
	autonomy   *master.Autonomy
	nodeMaxAge time.Duration
}

// Routes 返回 master 的 /lab/* 路由（调用方负责 auth.Wrap 同一共享 token）。
func (m *masterLab) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /lab/status", m.handleStatus)
	mux.HandleFunc("POST /lab/profiles", m.handleProfiles)
	mux.HandleFunc("POST /lab/reserve", m.handleReserve)
	mux.HandleFunc("POST /lab/step", m.handleStep)
	return mux
}

func (m *masterLab) handleStatus(w http.ResponseWriter, _ *http.Request) {
	snapshot, err := m.store.AutonomySnapshot()
	if err != nil {
		writeJSONLab(w, http.StatusInternalServerError, map[string]string{"error": "snapshot unavailable"})
		return
	}
	// 共享验证字段：plans[].targets[].next_attempt（租约 expiry）、source_id、
	// source_addr、attempts、done、last_error；now_utc 供跨机比对时钟差。
	writeJSONLab(w, http.StatusOK, map[string]any{
		"now_utc": time.Now().UTC(), "nodes": snapshot.Nodes, "profiles": snapshot.Profiles,
		"plans": snapshot.Plans, "objects": snapshot.Objects, "capacity": snapshot.Capacity,
		"profile_revision": snapshot.ProfileRevision,
	})
}

func (m *masterLab) handleProfiles(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Profiles []meta.NodePlacementProfile `json:"profiles"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Profiles) == 0 {
		writeJSONLab(w, http.StatusBadRequest, map[string]string{"error": "profiles 数组必填"})
		return
	}
	type profileResult struct {
		NodeID uint64 `json:"node_id"`
		Error  string `json:"error,omitempty"`
	}
	results := make([]profileResult, 0, len(req.Profiles))
	for _, p := range req.Profiles {
		err := m.store.SetNodePlacementProfile(p)
		if err == nil {
			err = m.store.EnsureDurable()
		}
		e := ""
		if err != nil {
			e = err.Error()
		}
		results = append(results, profileResult{NodeID: p.NodeID, Error: e})
	}
	writeJSONLab(w, http.StatusOK, map[string]any{"results": results})
}

func (m *masterLab) handleReserve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path     string   `json:"path"`
		TargetID uint64   `json:"target_id"`
		Targets  []uint64 `json:"targets"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSONLab(w, http.StatusBadRequest, map[string]string{"error": "path 必填"})
		return
	}
	targets := req.Targets
	if req.TargetID != 0 {
		targets = append(targets, req.TargetID)
	}
	if len(targets) == 0 {
		writeJSONLab(w, http.StatusBadRequest, map[string]string{"error": "target_id 或 targets 必填"})
		return
	}
	in, err := m.store.ResolvePath(req.Path)
	if err != nil || in.Type != types.TypeFile {
		writeJSONLab(w, http.StatusNotFound, map[string]string{"error": "path 不是文件"})
		return
	}
	// admission 与 dispatch 分离：这里只做持久 ReserveProtection（真实
	// ObjectIntegrity 身份 + 容量/心跳/profile revision 校验），绝不模拟 Done；
	// 派工由 /lab/step 走生产 autonomy.Step（claim 源绑定 → /pull → 真 verify 回执）。
	// 注意：plan id 每次请求随机生成，重复 reserve 同一对象会被 meta 层以
	// “已存在 pending plan”拒绝——本端点不是请求级幂等；调用方（drive/主线程）
	// 通过重取 /lab/status 采纳既有 pending 计划（adopt-pending，当前 lab 语义）。
	snapshot, err := m.store.AutonomySnapshot()
	if err != nil {
		writeJSONLab(w, http.StatusInternalServerError, map[string]string{"error": "snapshot unavailable"})
		return
	}
	var objIDs []uint64
	if in.Chunked {
		for _, ch := range in.Chunks {
			objIDs = append(objIDs, types.ChunkObjID(ch, in.ID))
		}
	} else {
		objIDs = append(objIDs, types.ObjIDFor(in))
	}
	type reserveResult struct {
		ObjectID uint64 `json:"object_id"`
		PlanID   string `json:"plan_id"`
		State    string `json:"state"`
		Error    string `json:"error,omitempty"`
	}
	results := make([]reserveResult, 0, len(objIDs))
	for _, objID := range objIDs {
		res := reserveResult{ObjectID: objID}
		d, err := m.store.ObjectIntegrity(objID)
		if err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}
		covered := true
		for _, t := range targets {
			if !types.ContainsUint64(d.Replicas, t) {
				covered = false
			}
		}
		if covered {
			res.State = "already_present"
			results = append(results, res)
			continue
		}
		planReq := meta.ProtectionRequest{ID: fmt.Sprintf("lab-%s-o%d", randHex(4), objID),
			Expected: d, Targets: targets,
			MaxBytes: d.Size*int64(len(targets)) + d.Size, NodeMaxAge: m.nodeMaxAge,
			ProfileRevision: snapshot.ProfileRevision, Reason: "transferlab add-replica"}
		plan, err := m.store.ReserveProtection(planReq, time.Now())
		if err != nil {
			res.Error = err.Error()
		} else {
			res.PlanID, res.State = plan.ID, plan.State
		}
		results = append(results, res)
	}
	writeJSONLab(w, http.StatusOK, map[string]any{"results": results})
}

func (m *masterLab) handleStep(w http.ResponseWriter, r *http.Request) {
	if m.autonomy == nil {
		writeJSONLab(w, http.StatusConflict, map[string]string{"error": "autonomy 未启用"})
		return
	}
	report, err := m.autonomy.Step(r.Context())
	if err != nil {
		writeJSONLab(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSONLab(w, http.StatusOK, report)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}
