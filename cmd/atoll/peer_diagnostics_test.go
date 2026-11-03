package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/client"
	"atoll/pkg/peerauth"
	"atoll/pkg/peerhttp"
	"atoll/pkg/peertransport"
)

// stubDiagRuntime 只实现 Close：diagnosticRuntime 的生命周期契约（flush once、
// 幂等、错误上抛）不依赖真实 runtime 的其他方法。
type stubDiagRuntime struct {
	peertransport.RuntimeAPI
	mu     sync.Mutex
	closes int
	err    error
}

func (s *stubDiagRuntime) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes++
	return s.err
}

func (s *stubDiagRuntime) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

// decodedPeerDiagFile 是解码后的信封：事件从 RawMessage 展开成类型化记录。
type decodedPeerDiagFile struct {
	Format         string
	StartedAt      time.Time
	ClosedAt       time.Time
	RuntimeCloseOK bool
	Dropped        uint64
	Events         []peerDiagRecord
}

// readPeerDiagEnvelope 解码并返回诊断信封；解码失败即测试失败。
func readPeerDiagEnvelope(t *testing.T, path string) decodedPeerDiagFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read diagnostics: %v", err)
	}
	var file peerDiagFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode diagnostics: %v (raw: %s)", err, raw)
	}
	env := decodedPeerDiagFile{
		Format:         file.Format,
		StartedAt:      file.StartedAt,
		ClosedAt:       file.ClosedAt,
		RuntimeCloseOK: file.RuntimeCloseOK,
		Dropped:        file.Dropped,
	}
	for _, rawEvent := range file.Events {
		var rec peerDiagRecord
		if err := json.Unmarshal(rawEvent, &rec); err != nil {
			t.Fatalf("decode diagnostics event: %v (raw: %s)", err, rawEvent)
		}
		env.Events = append(env.Events, rec)
	}
	return env
}

func mustSink(t *testing.T, path string) *peerDiagnosticsSink {
	t.Helper()
	sink, err := openPeerDiagnosticsSink(path)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}
	return sink
}

// TestPeerDiagnosticsSinkBoundsAndDrops 验证有界承诺：事件数与估算字节双上限、
// 超限计 dropped、候选截断 16×512。
func TestPeerDiagnosticsSinkBoundsAndDrops(t *testing.T) {
	dir := t.TempDir()

	t.Run("event cap counts drops", func(t *testing.T) {
		sink := mustSink(t, filepath.Join(dir, "events.json"))
		for i := 0; i < peerDiagMaxEvents; i++ {
			sink.runtimeObserve(peertransport.RuntimeEvent{Time: time.Now().UTC(), Kind: "dial"})
		}
		sink.mu.Lock()
		records, dropped := len(sink.records), sink.dropped
		sink.mu.Unlock()
		if records != peerDiagMaxEvents || dropped != 0 {
			t.Fatalf("records=%d dropped=%d, want full buffer and no drops", records, dropped)
		}
		sink.runtimeObserve(peertransport.RuntimeEvent{Kind: "dial"})
		sink.mu.Lock()
		defer sink.mu.Unlock()
		if len(sink.records) != peerDiagMaxEvents || sink.dropped != 1 {
			t.Fatalf("over-cap event must be dropped: records=%d dropped=%d", len(sink.records), sink.dropped)
		}
	})

	t.Run("byte cap engages before event cap", func(t *testing.T) {
		sink := mustSink(t, filepath.Join(dir, "bytes.json"))
		big := strings.Repeat("a", peerDiagMaxStringBytes)
		for i := 0; i < peerDiagMaxEvents; i++ {
			sink.runtimeObserve(peertransport.RuntimeEvent{Kind: "holepunch", Candidates: []string{big, big, big}})
		}
		sink.mu.Lock()
		defer sink.mu.Unlock()
		if sink.bytes > peerDiagMaxBytes {
			t.Fatalf("byte budget exceeded: %d > %d", sink.bytes, peerDiagMaxBytes)
		}
		if sink.dropped == 0 || len(sink.records) >= peerDiagMaxEvents {
			t.Fatalf("byte cap must stop the buffer first: records=%d dropped=%d", len(sink.records), sink.dropped)
		}
	})

	t.Run("candidates clamped to 16 x 512", func(t *testing.T) {
		sink := mustSink(t, filepath.Join(dir, "clamps.json"))
		long := strings.Repeat("b", 600)
		candidates := make([]string, 0, 20)
		for i := 0; i < 20; i++ {
			candidates = append(candidates, long)
		}
		sink.runtimeObserve(peertransport.RuntimeEvent{Kind: "dcutr", Candidates: candidates})
		sink.mu.Lock()
		stored := append([]json.RawMessage(nil), sink.records...)
		sink.mu.Unlock()
		if len(stored) != 1 {
			t.Fatalf("records=%d, want 1", len(stored))
		}
		var rec peerDiagRecord
		if err := json.Unmarshal(stored[0], &rec); err != nil {
			t.Fatalf("decode stored record: %v", err)
		}
		got := rec.Runtime.Candidates
		if len(got) != peerDiagMaxCandidates {
			t.Fatalf("candidates=%d, want %d", len(got), peerDiagMaxCandidates)
		}
		for _, c := range got {
			if len(c) > peerDiagMaxStringBytes {
				t.Fatalf("candidate length %d exceeds %d", len(c), peerDiagMaxStringBytes)
			}
		}
	})
}

// TestPeerDiagnosticsRejectsExistingTarget 目标必须是新文件：已存在拒绝、符号
// 链接拒绝（Lstat 不跟随）、父目录缺失拒绝且绝不创建父目录。
func TestPeerDiagnosticsRejectsExistingTarget(t *testing.T) {
	dir := t.TempDir()

	existing := filepath.Join(dir, "exists.json")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openPeerDiagnosticsSink(existing); err == nil {
		t.Fatal("existing target must be refused")
	}

	dangling := filepath.Join(dir, "dangling.json")
	if err := os.Symlink(filepath.Join(dir, "missing-target"), dangling); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := openPeerDiagnosticsSink(dangling); err == nil {
		t.Fatal("symlinked target must be refused (no follow)")
	}

	missingParent := filepath.Join(dir, "no-such-dir", "diag.json")
	if _, err := openPeerDiagnosticsSink(missingParent); err == nil {
		t.Fatal("missing parent directory must be refused")
	}
	if _, err := os.Stat(filepath.Join(dir, "no-such-dir")); !os.IsNotExist(err) {
		t.Fatal("parent directory must not be created by the diagnostics layer")
	}
}

// TestPeerDiagnosticsFlushEnvelope 一次性落盘：信封字段真实、0600 私有、flush
// 幂等且 flush 后的迟到事件不再入盘。
func TestPeerDiagnosticsFlushEnvelope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "diag.json")
	sink := mustSink(t, path)

	sink.runtimeObserve(peertransport.RuntimeEvent{
		Time: time.Now().UTC(), Kind: "autonat_client", Success: false, ErrorKind: "probe_not_public",
	})
	sink.httpObserve(peerhttp.Observation{
		Target: "127.0.0.1:9000", Path: peerhttp.PathDirect, Phase: peerhttp.PhaseDial,
		Identity: "12D3KooW-test", RequestID: "cli-1", Method: "PUT", RequestPath: "/objects/x",
	})
	if err := sink.flush(true); err != nil {
		t.Fatalf("flush: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	env := readPeerDiagEnvelope(t, path)
	if env.Format != peerDiagFormat {
		t.Fatalf("format=%q, want %q", env.Format, peerDiagFormat)
	}
	if !env.RuntimeCloseOK || env.Dropped != 0 || len(env.Events) != 2 {
		t.Fatalf("unexpected envelope: closeOK=%v dropped=%d events=%d", env.RuntimeCloseOK, env.Dropped, len(env.Events))
	}
	if env.Events[0].Source != "runtime" || env.Events[0].Runtime.Kind != "autonat_client" {
		t.Fatalf("runtime record lost: %+v", env.Events[0])
	}
	if env.Events[1].Source != "http" || env.Events[1].HTTP.Phase != peerhttp.PhaseDial || env.Events[1].HTTP.RequestID != "cli-1" {
		t.Fatalf("http record lost: %+v", env.Events[1])
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("diagnostics file must be private 0600: %v %v", info, err)
	}
	// flush 幂等：二次 flush 不改文件；迟到事件不入盘（文件字节保持不变）。
	if err := sink.flush(false); err != nil {
		t.Fatalf("second flush must be a no-op, got %v", err)
	}
	sink.runtimeObserve(peertransport.RuntimeEvent{Kind: "late"})
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(after) {
		t.Fatal("flushed file must stay untouched after late events")
	}
}

// TestPeerDiagnosticsExactByteBudgetWithControlChars 控制字符转义膨胀（最高 6
// 倍）必须按 json.Marshal 的真实编码长度计费：字节数与逐条编码完全一致。
func TestPeerDiagnosticsExactByteBudgetWithControlChars(t *testing.T) {
	dir := t.TempDir()
	sink := mustSink(t, filepath.Join(dir, "diag.json"))
	// 512 个控制字符：JSON 编码后膨胀到 6 倍长度。
	evil := strings.Repeat("\x00\x01\x1f", peerDiagMaxStringBytes/3)
	sink.runtimeObserve(peertransport.RuntimeEvent{Kind: evil, RequestID: evil})
	sink.runtimeObserve(peertransport.RuntimeEvent{Kind: "dial"})
	raw0, err := json.Marshal(peerDiagRecord{Source: "runtime", Runtime: &peertransport.RuntimeEvent{
		Kind: diagClamp(evil), RequestID: diagClamp(evil),
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw1, err := json.Marshal(peerDiagRecord{Source: "runtime", Runtime: &peertransport.RuntimeEvent{Kind: "dial"}})
	if err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if want := len(raw0) + 1 + len(raw1) + 1; sink.bytes != want {
		t.Fatalf("accounted bytes=%d, want exact %d", sink.bytes, want)
	}
}

// TestPeerDiagnosticsFlushRefusesRacedTarget 占用竞态：sink 创建后目标被外部
// 抢先创建（或换成符号链接）→ flush 必须失败并留下原文件，绝不覆盖。
func TestPeerDiagnosticsFlushRefusesRacedTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "diag.json")
	sink := mustSink(t, path)
	sink.runtimeObserve(peertransport.RuntimeEvent{Kind: "dial"})
	if err := os.WriteFile(path, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sink.flush(true); err == nil {
		t.Fatal("flush must fail when the target already exists")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "outside" {
		t.Fatalf("pre-existing file must stay untouched: %q %v", got, err)
	}
	// 符号链接同样拒绝：O_EXCL 对链接路径直接 EEXIST。
	path2 := filepath.Join(dir, "link.json")
	sink2 := mustSink(t, path2)
	if err := os.Symlink(filepath.Join(dir, "elsewhere.json"), path2); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := sink2.flush(true); err == nil {
		t.Fatal("flush must refuse a symlinked target")
	}
	if _, err := os.Stat(filepath.Join(dir, "elsewhere.json")); !os.IsNotExist(err) {
		t.Fatal("symlink target must not be created (no follow)")
	}
}

// TestPeerDiagnosticsCloseExitVerdict 退出码裁决：仅诊断落盘失败改为 true；
// 其余关停错误维持 false（旧退出行为）。
func TestPeerDiagnosticsCloseExitVerdict(t *testing.T) {
	dir := t.TempDir()

	// 诊断启用 + 落盘失败 → 必须改判退出码。
	failed := mustSink(t, filepath.Join(dir, "fail.json"))
	if err := os.WriteFile(filepath.Join(dir, "fail.json"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rtFail := &diagnosticRuntime{RuntimeAPI: &stubDiagRuntime{}, sink: failed}
	if err := rtFail.Close(); err == nil {
		t.Fatal("flush failure must surface from Close")
	}
	if !peerDiagnosticsCloseExit(rtFail, rtFail.Close()) {
		t.Fatal("flush failure must flip the exit verdict")
	}
	if diagnosticsFlushError(rtFail) == nil {
		t.Fatal("flush error must be retrievable")
	}

	// 诊断启用 + 落盘成功但 runtime 关停失败 → 维持旧退出行为（仅日志）。
	okSink := mustSink(t, filepath.Join(dir, "ok.json"))
	rtRT := &diagnosticRuntime{RuntimeAPI: &stubDiagRuntime{err: errors.New("host close failed")}, sink: okSink}
	if err := rtRT.Close(); err == nil {
		t.Fatal("runtime close error must surface")
	}
	if peerDiagnosticsCloseExit(rtRT, rtRT.Close()) {
		t.Fatal("runtime-only close failure must not flip the exit verdict")
	}
	if diagnosticsFlushError(rtRT) != nil {
		t.Fatal("no flush error expected when the file was written")
	}

	// 非 wrapper runtime / 无错误 → 永不改判。
	if peerDiagnosticsCloseExit(&stubDiagRuntime{}, errors.New("close failed")) {
		t.Fatal("non-wrapped runtime must keep the old exit behavior")
	}
	if peerDiagnosticsCloseExit(nil, nil) {
		t.Fatal("no close error must never flip the verdict")
	}
}

// TestPeerDiagnosticsRuntimeCloseFlushesOnce Close 契约：先关 runtime（join 事件
// 源）再 flush 一次；runtime 关停失败如实上抛并记为 close_ok=false；重复 Close
// 返回首次结果且不二次 flush。
func TestPeerDiagnosticsRuntimeCloseFlushesOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "diag.json")
	sink := mustSink(t, path)
	sink.runtimeObserve(peertransport.RuntimeEvent{Kind: "dial", RequestID: "cli-9"})

	inner := &stubDiagRuntime{err: errors.New("host close failed")}
	rt := &diagnosticRuntime{RuntimeAPI: inner, sink: sink}
	first := rt.Close()
	if first == nil || !strings.Contains(first.Error(), "host close failed") {
		t.Fatalf("runtime close error must surface: %v", first)
	}
	env := readPeerDiagEnvelope(t, path)
	if env.RuntimeCloseOK {
		t.Fatal("failed runtime close must be recorded as close_ok=false")
	}
	if len(env.Events) != 1 || env.Events[0].Runtime.RequestID != "cli-9" {
		t.Fatalf("collected events lost: %+v", env.Events)
	}
	// 幂等：重复 Close 返回同一结果，runtime 不再被关第二次，文件不变。
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if second := rt.Close(); second == nil || second.Error() != first.Error() {
		t.Fatalf("repeated close must return the saved error: %v", second)
	}
	if inner.closeCount() != 1 {
		t.Fatalf("inner close count=%d, want 1", inner.closeCount())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(after) {
		t.Fatal("repeated close must not flush again")
	}

	// 成功路径：close_ok=true，Close 返回 nil。
	path2 := filepath.Join(dir, "ok.json")
	sink2 := mustSink(t, path2)
	ok := (&diagnosticRuntime{RuntimeAPI: &stubDiagRuntime{}, sink: sink2}).Close()
	if ok != nil {
		t.Fatalf("clean close must return nil: %v", ok)
	}
	if env := readPeerDiagEnvelope(t, path2); !env.RuntimeCloseOK {
		t.Fatal("clean close must be recorded as close_ok=true")
	}
}

// roundTripFunc 让测试注入最内层 transport。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestPeerDiagnosticsRoundTripperObservesNodeOnly 全链路（wrapper → 真实
// peerhttp.Transport）：master 请求原样透传零观察；节点数据请求被观察且
// RequestID 关联、query 不入档。
func TestPeerDiagnosticsRoundTripperObservesNodeOnly(t *testing.T) {
	dir := t.TempDir()
	sink := mustSink(t, filepath.Join(dir, "diag.json"))
	const masterOrigin = "https://127.0.0.1:9420"
	base := &http.Transport{}
	peer, err := peerhttp.NewTransport(base, peerhttp.WithMaster(masterOrigin))
	if err != nil {
		t.Fatalf("peerhttp transport: %v", err)
	}
	wrapper := newPeerDiagnosticsRoundTripper(peer, masterOrigin, sink.reporter())

	// master（元数据/控制）请求：走 base，拒绝连接即证明未走 peer 路径，且
	// 不产生任何观察——报告器绝不挂上控制面。
	masterReq, err := http.NewRequest(http.MethodGet, masterOrigin+"/meta", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.RoundTrip(masterReq); err == nil {
		t.Fatal("master request must reach the base transport (refused here)")
	}
	sink.mu.Lock()
	records := len(sink.records)
	sink.mu.Unlock()
	if records != 0 {
		t.Fatalf("master request must not be observed, got %d records", records)
	}

	// 节点数据请求：观察一条 PhaseDial 失败（连接拒绝），携带 wrapper 分配的
	// RequestID；URL query 是敏感面，绝不允许进入存档。
	nodeReq, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:1/objects/abc?token=secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrapper.RoundTrip(nodeReq); err == nil {
		t.Fatal("node request to a closed port must fail")
	}
	sink.mu.Lock()
	stored := append([]json.RawMessage(nil), sink.records...)
	sink.mu.Unlock()
	if len(stored) != 1 {
		t.Fatalf("node request must produce exactly one observation, got %d", len(stored))
	}
	var rec peerDiagRecord
	if err := json.Unmarshal(stored[0], &rec); err != nil {
		t.Fatalf("decode observation: %v", err)
	}
	o := rec.HTTP
	if o == nil || o.Phase != peerhttp.PhaseDial || o.RequestID != "cli-1" || o.Method != http.MethodGet {
		t.Fatalf("unexpected observation: %+v", o)
	}
	encoded := stored[0]
	if o.RequestPath != "/objects/abc" || strings.Contains(string(encoded), "secret") {
		t.Fatalf("query must never reach the record: %+v", o)
	}
	if o.Target != "127.0.0.1:1" {
		t.Fatalf("target=%q, want 127.0.0.1:1", o.Target)
	}
}

// TestPeerDiagnosticsNewPeerRuntimeRecordsDialEvents 装配契约：诊断开启时
// runtime 被包成 wrapper、cfg.Observe 已接线（真实拨号产生带 RequestID 的
// dial 事件）、Close 落盘完整信封。
func TestPeerDiagnosticsNewPeerRuntimeRecordsDialEvents(t *testing.T) {
	dir := t.TempDir()
	diagPath := filepath.Join(dir, "diag.json")
	fs := flag.NewFlagSet("diag-wiring", flag.ContinueOnError)
	p := addP2PFlags(fs)
	if err := fs.Parse([]string{"-p2p", "-p2p-listen", "/ip4/127.0.0.1/tcp/0", "-p2p-public-only=false", "-p2p-diagnostics", diagPath}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cliRT, err := newPeerRuntime(ctx, p, filepath.Join(t.TempDir(), "cli.key"))
	if err != nil {
		t.Fatalf("runtime: %v", err)
	}
	if _, ok := cliRT.(*diagnosticRuntime); !ok {
		_ = cliRT.Close()
		t.Fatal("diagnostics-enabled runtime must be wrapped")
	}
	if diagnosticsOutputPath(cliRT) != diagPath {
		t.Fatalf("output path = %q, want %q", diagnosticsOutputPath(cliRT), diagPath)
	}

	srvRT, err := peertransport.New(ctx, peertransport.Config{
		IdentityPath:    filepath.Join(t.TempDir(), "srv.key"),
		ListenAddresses: []string{"/ip4/127.0.0.1/tcp/0"},
		DirectTimeout:   5 * time.Second,
		RelayTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("server runtime: %v", err)
	}
	defer srvRT.Close()
	// ProtoID 流处理器只在 Listener() 创建时安装：服务端必须先开监听，客户端
	// 的协议协商才有着落。
	srvLn, err := srvRT.Listener()
	if err != nil {
		t.Fatalf("server listener: %v", err)
	}
	defer srvLn.Close()
	srvRT.SetAuthorizer(func(_ context.Context, id string) bool { return id == cliRT.PeerID() })
	cliRT.SetAuthorizer(func(_ context.Context, id string) bool { return id == srvRT.PeerID() })

	endpoint := peerauth.Endpoint{
		PeerID:     srvRT.PeerID(),
		PublicKey:  srvRT.PublicKey(),
		Addresses:  srvRT.Addresses(),
		ValidUntil: time.Now().Add(time.Minute),
	}
	dialCtx := peerhttp.WithRequestID(context.Background(), "obj-req-1")
	result := cliRT.Dial(dialCtx, endpoint, peerauth.Infrastructure{}, peerhttp.PathDirect)
	if result.Err != nil || result.Conn == nil {
		t.Fatalf("peer dial: err=%v conn=%v", result.Err, result.Conn)
	}
	_ = result.Conn.Close()
	if err := cliRT.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	env := readPeerDiagEnvelope(t, diagPath)
	for _, rec := range env.Events {
		if rec.Runtime != nil && rec.Runtime.Kind == "dial" && rec.Runtime.RequestID == "obj-req-1" {
			if !env.RuntimeCloseOK {
				t.Fatal("clean close must be recorded")
			}
			return
		}
	}
	t.Fatalf("dial event with the request id is missing: %+v", env)
}

// TestPeerDiagnosticsStartupFailureFlushesRecord 启动失败也要留下有界记录：
// runtime 创建失败时信封已落盘且 close_ok=false。
func TestPeerDiagnosticsStartupFailureFlushesRecord(t *testing.T) {
	dir := t.TempDir()
	diagPath := filepath.Join(dir, "diag.json")
	fs := flag.NewFlagSet("diag-startup", flag.ContinueOnError)
	p := addP2PFlags(fs)
	if err := fs.Parse([]string{"-p2p", "-p2p-listen", "/ip4/127.0.0.1/tcp/0", "-p2p-public-only=false", "-p2p-diagnostics", diagPath}); err != nil {
		t.Fatal(err)
	}
	// 身份文件父路径是普通文件 → peertransport.New 必然失败。
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newPeerRuntime(context.Background(), p, filepath.Join(blocker, "peer.key")); err == nil {
		t.Fatal("runtime create must fail when the identity parent is a file")
	}
	env := readPeerDiagEnvelope(t, diagPath)
	if env.RuntimeCloseOK {
		t.Fatal("startup failure must be recorded as close_ok=false")
	}
	if len(env.Events) != 0 || env.Dropped != 0 {
		t.Fatalf("startup record must be empty and bounded: %+v", env)
	}
}

// TestPeerDiagnosticsCLIResultEvent CLI 终判是独立事件：成功与失败都记、与流
// 层观察分开、只含操作名与有界类别（原始错误文本绝不入档）；未启用诊断时是
// no-op。
func TestPeerDiagnosticsCLIResultEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "diag.json")
	sink := mustSink(t, path)
	sink.httpObserve(peerhttp.Observation{Target: "127.0.0.1:9000", Phase: peerhttp.PhaseDial})
	// 非 wrapper runtime：record 必须是 no-op（无 panic、无记录）。
	recordPeerDiagnosticsResult(&stubDiagRuntime{}, "put", nil)

	rt := &diagnosticRuntime{RuntimeAPI: &stubDiagRuntime{}, sink: sink}
	recordPeerDiagnosticsResult(rt, "put", nil)
	recordPeerDiagnosticsResult(rt, "get", errors.New("get 失败: 404 with token=secret-value"))
	if err := rt.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	env := readPeerDiagEnvelope(t, path)
	if len(env.Events) != 3 {
		t.Fatalf("events=%d, want 3 (one stream observation + two CLI results)", len(env.Events))
	}
	if env.Events[0].CLI != nil || env.Events[0].HTTP == nil {
		t.Fatalf("stream observation must stay separate: %+v", env.Events[0])
	}
	if env.Events[1].CLI == nil || env.Events[1].CLI.Op != "put" || !env.Events[1].CLI.Ok || env.Events[1].CLI.ErrorKind != "" {
		t.Fatalf("put result lost: %+v", env.Events[1])
	}
	failed := env.Events[2].CLI
	if failed == nil || failed.Op != "get" || failed.Ok {
		t.Fatalf("get failure result lost: %+v", failed)
	}
	if failed.ErrorKind != "operation_failed" {
		t.Fatalf("failure kind=%q, want operation_failed", failed.ErrorKind)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "404") {
		t.Fatalf("raw error material must never reach the file: %s", raw)
	}

	// 有界类别映射：canceled 与 deadline。
	if got := diagOutcomeKind(context.Canceled); got != "canceled" {
		t.Fatalf("canceled kind=%q", got)
	}
	if got := diagOutcomeKind(context.DeadlineExceeded); got != "deadline_exceeded" {
		t.Fatalf("deadline kind=%q", got)
	}
	if got := diagOutcomeKind(nil); got != "" {
		t.Fatalf("nil kind=%q", got)
	}
}

// TestPeerDiagnosticsClientTransportWrapped client 装配契约：诊断开启时
// c.HTTP.Transport 被替换为 request-only wrapper 且委托原 transport；关闭诊断
// 或未启用时一律不动。
func TestPeerDiagnosticsClientTransportWrapped(t *testing.T) {
	cl, err := client.NewSecure("https://127.0.0.1:9420", nil, false)
	if err != nil {
		t.Fatalf("NewSecure: %v", err)
	}
	orig := cl.HTTP.Transport

	dir := t.TempDir()
	sink := mustSink(t, filepath.Join(dir, "diag.json"))
	rt := &diagnosticRuntime{RuntimeAPI: &stubDiagRuntime{}, sink: sink}
	attachClientDiagnostics(cl, rt)
	wrapped, ok := cl.HTTP.Transport.(*peerDiagnosticsRoundTripper)
	if !ok {
		t.Fatalf("client transport must be wrapped, got %T", cl.HTTP.Transport)
	}
	if wrapped.inner != orig {
		t.Fatal("wrapper must delegate to the original secure transport")
	}
	if wrapped.masterHost != "127.0.0.1:9420" || wrapped.masterScheme != "https" {
		t.Fatalf("master origin not classified: %q %q", wrapped.masterScheme, wrapped.masterHost)
	}
	if diagnosticsOutputPath(rt) != filepath.Join(dir, "diag.json") {
		t.Fatalf("output path = %q", diagnosticsOutputPath(rt))
	}

	// 分类必须绑定构造时固定的 pinned origin，而非可变导出的 MasterURL：装配后
	// 即便调用方改写 MasterURL（导出字段可变），master/node 分类仍不得跟随。
	clM, err := client.NewSecure("https://127.0.0.1:9420", nil, false)
	if err != nil {
		t.Fatalf("NewSecure: %v", err)
	}
	clM.MasterURL = "https://other.example:9999"
	dirM := t.TempDir()
	sinkM := mustSink(t, filepath.Join(dirM, "diag.json"))
	rtM := &diagnosticRuntime{RuntimeAPI: &stubDiagRuntime{}, sink: sinkM}
	attachClientDiagnostics(clM, rtM)
	wrappedM, ok := clM.HTTP.Transport.(*peerDiagnosticsRoundTripper)
	if !ok {
		t.Fatalf("client transport must be wrapped, got %T", clM.HTTP.Transport)
	}
	if wrappedM.masterHost != "127.0.0.1:9420" || wrappedM.masterScheme != "https" {
		t.Fatalf("classification must use the pinned origin, got %q %q", wrappedM.masterScheme, wrappedM.masterHost)
	}

	// 未启用诊断（非 wrapper runtime）：transport 原样保留。
	cl2, err := client.NewSecure("https://127.0.0.1:9420", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	orig2 := cl2.HTTP.Transport
	attachClientDiagnostics(cl2, &stubDiagRuntime{})
	if cl2.HTTP.Transport != orig2 {
		t.Fatal("non-wrapped runtime must not touch the client transport")
	}
	// wrapper 但 sink 为 nil（防御）：同样不动。
	cl3, err := client.NewSecure("https://127.0.0.1:9420", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	orig3 := cl3.HTTP.Transport
	attachClientDiagnostics(cl3, &diagnosticRuntime{RuntimeAPI: &stubDiagRuntime{}})
	if cl3.HTTP.Transport != orig3 {
		t.Fatal("wrapper without sink must not touch the client transport")
	}
	// nil 组合绝不 panic。
	attachClientDiagnostics(nil, rt)
	attachClientDiagnostics(cl, nil)
}
