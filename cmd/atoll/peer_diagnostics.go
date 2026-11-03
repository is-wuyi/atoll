package main

// 私有 peer 诊断采集（-p2p-diagnostics）：runtime 连接/遍历事实与客户端请求
// 路径事实进入有界内存缓冲，进程收尾一次性写出 0600 私有 JSON。文件只新建
// （O_CREATE|O_EXCL，不覆盖、不跟随符号链接）；事件数与精确编码字节双上限，
// 超限计 dropped；字段是白名单事实，不采 query/body/token/原始错误文本。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"atoll/client"
	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"
)

const (
	// 诊断是排查工具不是审计日志：事件数上限按批处理量级取 8192，字节上限
	// 4MiB 保证文件永远可一次读入。二者先到先停，超限只计 dropped。
	peerDiagMaxEvents = 8192
	peerDiagMaxBytes  = 4 << 20
	// 信封头部（format/时间戳/dropped 位数）的预留：append 预算扣掉它，flush
	// 仍对最终 payload 硬检查，绝不写出超限文件。
	peerDiagEnvelopeHeadroom = 1024
	// 候选地址是遍历事实：数量与长度都必须有界，截断只影响展示完整度。
	peerDiagMaxCandidates  = 16
	peerDiagMaxStringBytes = 512
	// peerDiagFormat 让读取方绑定字段语义版本，格式演进时读取方先拒绝旧文件。
	peerDiagFormat = "atoll-peer-diagnostics/1"
)

// peerDiagRecord 是一条有界事实。runtime 与 http 两种来源刻意不合并成同一组
// 字段：payload 成功（PhaseResponse/Status）与路径事实（Path/Identity）是两回
// 事，合并会制造从未发生过的"成功路径"证据。Fallback/FallbackUpgraded 只按
// 事件原样入档，绝不解释成操作最终成功。
type peerDiagRecord struct {
	Source  string                      `json:"source"`
	Runtime *peertransport.RuntimeEvent `json:"runtime,omitempty"`
	HTTP    *peerhttp.Observation       `json:"http,omitempty"`
	CLI     *peerDiagCLIResult          `json:"cli,omitempty"`
}

// peerDiagCLIResult 是 CLI 层的独立结果事件：流层 socket EOF 只证明流读完，
// 不等于 CRC/AEAD/commit 完成——成功与失败都由 CLI 自身终判定记一条。只记
// 操作名与有界结果类别，绝不入档对象密钥、路径或原始错误文本。
type peerDiagCLIResult struct {
	Op        string    `json:"op"`
	Ok        bool      `json:"ok"`
	ErrorKind string    `json:"error_kind,omitempty"`
	At        time.Time `json:"at"`
}

// peerDiagFile 是落盘信封（也是读取方的解码形态）。runtime 关停结果只以布尔
// 进入文件——原始错误文本可能携带任意内容，绝不入盘，只经返回值上抛 stderr。
type peerDiagFile struct {
	Format         string            `json:"format"`
	StartedAt      time.Time         `json:"started_at"`
	ClosedAt       time.Time         `json:"closed_at"`
	RuntimeCloseOK bool              `json:"runtime_close_ok"`
	Dropped        uint64            `json:"dropped"`
	Events         []json.RawMessage `json:"events"`
}

// peerDiagnosticsSink 收集两类事实：runtime 连接/遍历事件与客户端请求路径
// 观察。全部状态都在 mu 之后；回调路径做钳制、一次编码与内存追加（持锁微秒
// 级，无磁盘 I/O），磁盘只在收尾 flush 一次。
type peerDiagnosticsSink struct {
	path      string
	startedAt time.Time

	mu      sync.Mutex
	records []json.RawMessage
	bytes   int
	dropped uint64
	flushed bool
}

// diagnosticsPath 读取 -p2p-diagnostics 的值；空串表示不采集。
func (p *p2pCLIFlags) diagnosticsPath() string {
	if p == nil || p.diagnostics == nil {
		return ""
	}
	return strings.TrimSpace(*p.diagnostics)
}

// openPeerDiagnosticsSink 校验诊断输出目标：必须是尚不存在的新文件（已存在
// 拒绝；Lstat 不跟随，符号链接一律拒绝），父目录必须已存在且绝不由此创建。
// 此时并不建文件——O_EXCL 在 flush 时才是"绝不覆盖"的权威执行点。
func openPeerDiagnosticsSink(rawPath string) (*peerDiagnosticsSink, error) {
	path, err := filepath.Abs(rawPath)
	if err != nil {
		return nil, fmt.Errorf("resolve diagnostics path: %w", err)
	}
	dir := filepath.Dir(path)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("diagnostics parent directory %q must already exist", dir)
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("diagnostics file %q already exists; refusing to overwrite", path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("diagnostics file %q: %w", path, err)
	}
	return &peerDiagnosticsSink{path: path, startedAt: time.Now().UTC(), records: make([]json.RawMessage, 0, 64)}, nil
}

// runtimeObserve 是 peertransport.Config.Observe 的落点：只收有界事实字段。
func (s *peerDiagnosticsSink) runtimeObserve(ev peertransport.RuntimeEvent) {
	ev.Kind = diagClamp(ev.Kind)
	ev.RequestID = diagClamp(ev.RequestID)
	ev.LocalPeerID = diagClamp(ev.LocalPeerID)
	ev.RemotePeerID = diagClamp(ev.RemotePeerID)
	ev.ConnectionID = diagClamp(ev.ConnectionID)
	ev.StreamID = diagClamp(ev.StreamID)
	ev.LocalAddress = diagClamp(ev.LocalAddress)
	ev.RemoteAddress = diagClamp(ev.RemoteAddress)
	ev.ErrorKind = diagClamp(ev.ErrorKind)
	ev.Path = peerhttp.Path(diagClamp(string(ev.Path)))
	ev.ProbeStatus = diagClamp(ev.ProbeStatus)
	ev.Reachability = diagClamp(ev.Reachability)
	ev.Side = diagClamp(ev.Side)
	ev.Candidates = diagClampCandidates(ev.Candidates)
	s.append(peerDiagRecord{Source: "runtime", Runtime: &ev})
}

// httpObserve 是请求级 peerhttp.Reporter 的落点：Observation 本身就是白名单
// 结构（RequestPath 只含 URL path，ErrorKind 只是有界类别），这里只做钳制。
func (s *peerDiagnosticsSink) httpObserve(o peerhttp.Observation) {
	o.Scheme = diagClamp(o.Scheme)
	o.Target = diagClamp(o.Target)
	o.Path = peerhttp.Path(diagClamp(string(o.Path)))
	o.RequestID = diagClamp(o.RequestID)
	o.Method = diagClamp(o.Method)
	o.RequestPath = diagClamp(o.RequestPath)
	o.Identity = diagClamp(o.Identity)
	o.ConnectionID = diagClamp(o.ConnectionID)
	o.StreamID = diagClamp(o.StreamID)
	o.LocalAddress = diagClamp(o.LocalAddress)
	o.RemoteAddress = diagClamp(o.RemoteAddress)
	o.Phase = diagClamp(o.Phase)
	o.ErrorKind = diagClamp(o.ErrorKind)
	s.append(peerDiagRecord{Source: "http", HTTP: &o})
}

// cliResult 记录一条 CLI 层独立结果事件：操作级终判（成功与失败都记），与
// 流层观察分开存放。
func (s *peerDiagnosticsSink) cliResult(op string, err error) {
	rec := peerDiagCLIResult{Op: diagClamp(op), Ok: err == nil, At: time.Now().UTC()}
	if err != nil {
		rec.ErrorKind = diagOutcomeKind(err)
	}
	s.append(peerDiagRecord{Source: "cli", CLI: &rec})
}

// diagOutcomeKind 把 CLI 终判映射到有界类别；原始错误文本绝不入档。
func diagOutcomeKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	default:
		return "operation_failed"
	}
}

// recordPeerDiagnosticsResult 在 CLI put/get 最终判定处（成功与失败都算）补记
// 操作级结果事件；诊断未启用时是 no-op。
func recordPeerDiagnosticsResult(rt peertransport.RuntimeAPI, op string, err error) {
	dw, ok := rt.(*diagnosticRuntime)
	if !ok || dw.sink == nil {
		return
	}
	dw.sink.cliResult(op, err)
}

// append 把一条已钳制的记录编码后存入有界缓冲。字节数取 json.Marshal 的真实
// 编码长度（控制字符转义可膨胀 6 倍，估算上界不可信），预算再为信封头部留出
// 冗余；flush 仍对最终 payload 硬检查。flush 之后的迟到回调直接丢弃——文件已
// 定稿，无界追加只会破坏有界承诺。
func (s *peerDiagnosticsSink) append(rec peerDiagRecord) {
	raw, err := json.Marshal(rec)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flushed {
		return
	}
	if err != nil {
		// 白名单结构化字段不会失败；防御性计一次丢弃而不是中断回调方。
		s.dropped++
		return
	}
	size := len(raw) + 1 // 事件数组里的分隔逗号
	if len(s.records) >= peerDiagMaxEvents || s.bytes+size > peerDiagMaxBytes-peerDiagEnvelopeHeadroom {
		s.dropped++
		return
	}
	s.records = append(s.records, raw)
	s.bytes += size
}

// diagClamp 把任意字符串钳到有界长度：诊断字段永远是有界事实，不是原文。
func diagClamp(s string) string {
	if len(s) <= peerDiagMaxStringBytes {
		return s
	}
	return s[:peerDiagMaxStringBytes]
}

// diagClampCandidates 只保留前 16 个候选、每个钳到 512 字节，并复制出新切片：
// 存档不与生产方（事件回调）共享底层数组。
func diagClampCandidates(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	if len(in) > peerDiagMaxCandidates {
		in = in[:peerDiagMaxCandidates]
	}
	out := make([]string, len(in))
	for i, c := range in {
		out[i] = diagClamp(c)
	}
	return out
}

// reporter 返回挂到请求上下文的观察器。单个实例被所有请求共享：Observe 装入
// 后不可变，并发安全由 sink 的锁保证。
func (s *peerDiagnosticsSink) reporter() *peerhttp.Reporter {
	return &peerhttp.Reporter{Observe: s.httpObserve}
}

// flush 一次性写出信封，只允许在 runtime Close（事件源已 join）之后调用一次。
// 文件必须新建（O_EXCL 拒绝已存在与符号链接竞态），0600 私有权限；任何写失败
// 原样返回，绝不虚报成功。
func (s *peerDiagnosticsSink) flush(runtimeCloseOK bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flushed {
		return nil
	}
	s.flushed = true
	envelope := peerDiagFile{
		Format:         peerDiagFormat,
		StartedAt:      s.startedAt,
		ClosedAt:       time.Now().UTC(),
		RuntimeCloseOK: runtimeCloseOK,
		Dropped:        s.dropped,
		Events:         s.records,
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode diagnostics: %w", err)
	}
	// 写出前的硬检查：预算冗余被极端情形吃掉时丢尾部事件并如实计入 dropped，
	// 最终 payload 超过上限则报错，绝不写出超限文件或盲报边界。
	for len(payload) > peerDiagMaxBytes && len(envelope.Events) > 0 {
		envelope.Events = envelope.Events[:len(envelope.Events)-1]
		envelope.Dropped++
		if payload, err = json.Marshal(envelope); err != nil {
			return fmt.Errorf("encode diagnostics: %w", err)
		}
	}
	if len(payload) > peerDiagMaxBytes {
		return fmt.Errorf("diagnostics payload %d exceeds the %d byte limit", len(payload), peerDiagMaxBytes)
	}
	// O_CREATE|O_EXCL 对符号链接路径直接 EEXIST：启动时的 Lstat 只是提前失败，
	// 这一步才裁决整个生命周期的竞态。
	file, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create diagnostics file: %w", err)
	}
	_, writeErr := file.Write(payload)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write diagnostics file: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close diagnostics file: %w", closeErr)
	}
	return nil
}

// diagnosticRuntime 包住真实 runtime：事件回调已接线，Close 先关 runtime
// （join 全部事件源）再一次性落盘。Close 幂等：重复调用返回首次结果，绝不二次
// flush。runtime 关停错误与落盘错误分开保存：落盘错误决定 CLI 退出码，二者
// 经 Close 的返回值 join 上抛，绝不互相掩盖。
type diagnosticRuntime struct {
	peertransport.RuntimeAPI
	sink *peerDiagnosticsSink

	closeOnce sync.Once
	closeErr  error
	flushErr  error
}

func (d *diagnosticRuntime) Close() error {
	d.closeOnce.Do(func() {
		rtErr := d.RuntimeAPI.Close()
		// runtime Close 返回后不再有 Observe 回调，此刻落盘是完整快照。
		d.flushErr = d.sink.flush(rtErr == nil)
		d.closeErr = errors.Join(rtErr, d.flushErr)
	})
	return d.closeErr
}

// diagnosticsOutputPath 返回诊断 sink 的私有输出路径；未启用时为空串。
func diagnosticsOutputPath(rt peertransport.RuntimeAPI) string {
	dw, ok := rt.(*diagnosticRuntime)
	if !ok || dw.sink == nil {
		return ""
	}
	return dw.sink.path
}

// diagnosticsFlushError 返回诊断落盘错误；未启用或尚未落盘时为 nil。
func diagnosticsFlushError(rt peertransport.RuntimeAPI) error {
	dw, ok := rt.(*diagnosticRuntime)
	if !ok {
		return nil
	}
	return dw.flushErr
}

// peerDiagnosticsCloseExit 报告一次 peer 关停是否必须把 CLI 退出码改为 1：
// 仅当诊断已启用且落盘失败。其余关停错误维持既有行为（日志可见、退出码不变），
// 不改无诊断路径的退出语义。
func peerDiagnosticsCloseExit(rt peertransport.RuntimeAPI, closeErr error) bool {
	if closeErr == nil {
		return false
	}
	return diagnosticsFlushError(rt) != nil
}

// announcePeerDiagnostics 只提示私有输出路径，绝不 dump 内容。stdout 可用
// （client 命令）走 stdout；serve 模式角色（master/node/mount 的 run 无 stdout
// 通道）走 log。
func announcePeerDiagnostics(rt peertransport.RuntimeAPI, stdout io.Writer) {
	path := diagnosticsOutputPath(rt)
	if path == "" {
		return
	}
	if stdout != nil {
		fmt.Fprintf(stdout, "peer 诊断输出（私有 0600，仅事实事件）: %s\n", path)
		return
	}
	log.Printf("peer 诊断输出（私有 0600，仅事实事件）: %s", path)
}

// closePeerRuntime 关闭 runtime 并把结果上抛到日志：诊断落盘失败绝不能静默，
// 否则文件缺失无法解释。用于装配失败路径（进程本就以错误退出）。
func closePeerRuntime(rt peertransport.RuntimeAPI) {
	if rt == nil {
		return
	}
	if err := rt.Close(); err != nil {
		log.Printf("peer runtime close: %v", err)
	}
}

// peerDiagnosticsRoundTripper 是 request-only 包装：只为非 master（节点数据面）
// 请求注入 WithRequestID/WithReporter；master 控制与元数据请求原样透传。它委托
// 原有 secure transport——换票/会话注入一字不动，票据语义保持。request 级
// reporter 另有 ControlContext 双保险：peer 控制请求在 client 层已被剥除。
type peerDiagnosticsRoundTripper struct {
	inner        http.RoundTripper
	masterScheme string
	masterHost   string
	reporter     *peerhttp.Reporter
	nextID       atomic.Uint64
}

// newPeerDiagnosticsRoundTripper 以构造时固定的 master origin 分类请求。无法
// 识别 master（masterURL 为空/不可解析）时不观察任何请求——诊断绝不冒险碰
// 控制面。
func newPeerDiagnosticsRoundTripper(inner http.RoundTripper, masterURL string, reporter *peerhttp.Reporter) *peerDiagnosticsRoundTripper {
	rt := &peerDiagnosticsRoundTripper{inner: inner, reporter: reporter}
	if origin, err := peerauth.CanonicalOrigin(masterURL); err == nil {
		u, _ := url.Parse(origin)
		rt.masterScheme = u.Scheme
		rt.masterHost = u.Host
	}
	return rt
}

func (d *peerDiagnosticsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if d.isMaster(req) {
		return d.inner.RoundTrip(req)
	}
	// 显式 RequestID 让 runtime dial 事件与 peerhttp 观察共享同一关联键
	//（runtime 的 dial 事件只读 ctx 里的 RequestID，不会自动分配）。
	ctx := peerhttp.WithRequestID(req.Context(), d.requestID())
	ctx = peerhttp.WithReporter(ctx, d.reporter)
	return d.inner.RoundTrip(req.WithContext(ctx))
}

// isMaster 用构造时固定的 master origin 精确匹配（scheme+host:port）。无法
// 分类（master 未识别或 req 残缺）一律按 master 处理——原样透传、不观察。
func (d *peerDiagnosticsRoundTripper) isMaster(req *http.Request) bool {
	if req == nil || req.URL == nil || d.masterHost == "" {
		return true
	}
	origin, err := peerauth.CanonicalOrigin(req.URL.Scheme + "://" + req.URL.Host)
	if err != nil {
		return true
	}
	return origin == d.masterScheme+"://"+d.masterHost
}

func (d *peerDiagnosticsRoundTripper) requestID() string {
	return fmt.Sprintf("cli-%d", d.nextID.Add(1))
}

// CloseIdleConnections 透传：http.Client 的空闲连接回收必须继续到达真实
// transport。
func (d *peerDiagnosticsRoundTripper) CloseIdleConnections() {
	if c, ok := d.inner.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// attachClientDiagnostics 在 P2P 启用成功后把请求级观察挂上出站 HTTP（仅诊断
// 开启时生效）。mount 的 FUSE 数据面走 ObjectTransport（另一实例），不在本次
// CLI 观察范围。
func attachClientDiagnostics(c *client.Client, rt peertransport.RuntimeAPI) {
	if c == nil || c.HTTP == nil || c.HTTP.Transport == nil {
		return
	}
	dw, ok := rt.(*diagnosticRuntime)
	if !ok || dw.sink == nil {
		return
	}
	// master/node 分类绑定构造时固定的 pinned origin，与 secureTransport 与 peer
	// 控制同源，绝不跟随可变导出的 c.MasterURL（分歧时 master 控制请求会被误
	// 注入 reporter、节点请求漏观察）。pinned 为空（无 secure 构造）时 wrapper
	// 已有不观察任何请求的 fail-closed 语义——诊断绝不冒险碰控制面。
	c.HTTP.Transport = newPeerDiagnosticsRoundTripper(c.HTTP.Transport, c.PinnedMasterOrigin(), dw.sink.reporter())
}
