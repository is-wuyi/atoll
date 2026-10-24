package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"atoll/client"
	"atoll/master/meta"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

// 退出码：0 全过；1 基建错误；2 配置/预检失败；3 诚实跳过；4 断言失败。
const (
	exitPass   = 0
	exitInfra  = 1
	exitConfig = 2
	exitSkip   = 3
	exitFail   = 4
)

// gateTransport 是 drive 的客户端策略层：非入口节点地址一律拒绝。仅作用于
// drive 进程的 HTTP 客户端，绝不影响节点间生产传输；A→B 链路观测由节点心跳自动上报。
type gateTransport struct {
	inner http.RoundTripper
	deny  map[string]bool
}

func (t *gateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.deny[req.URL.Host] {
		// RoundTripper 契约：错误路径也必须关闭请求 Body，及时释放缓冲；
		// 拒绝发生在建连前，无需排空内容。
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("transferlab: 地址 %s 被单入口拓扑禁用（client 策略）", req.URL.Host)
	}
	return t.inner.RoundTrip(req)
}

// masterStatus 是 GET /lab/status 的共享验证视图（含计划 lease expiry 与 SourceID）。
type masterStatus struct {
	NowUTC          time.Time                   `json:"now_utc"`
	Nodes           []types.NodeInfo            `json:"nodes"`
	Plans           []meta.ProtectionPlan       `json:"plans"`
	Objects         []types.ObjectIntegrity     `json:"objects"`
	Profiles        []meta.NodePlacementProfile `json:"profiles"`
	ProfileRevision uint64                      `json:"profile_revision"`
}

type labClient struct {
	base string
	http *http.Client
}

func newLabClient(cfg *Config) *labClient {
	return &labClient{base: strings.TrimRight(cfg.Master, "/"),
		http: &http.Client{Timeout: 60 * time.Second, Transport: &auth.Transport{Token: auth.Token(cfg.Token)}}}
}

func (l *labClient) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, l.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := l.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("lab %s %s: 读取响应: %w", method, path, err)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("lab %s %s: http %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

type scenarioResult struct {
	Name       string         `json:"name"`
	Status     string         `json:"status"` // passed|skipped|failed
	Reason     string         `json:"reason,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at"`
}

type driveReport struct {
	StartedAt  string           `json:"started_at"`
	FinishedAt string           `json:"finished_at"`
	Exit       int              `json:"exit"`
	Scenarios  []scenarioResult `json:"scenarios"`
	Notes      []string         `json:"notes,omitempty"`
}

// preflight 用配置预算估算硬上界：单块 PUT 受 client 150s ioTimeout 封顶；
// 上传+复制腿受传输计划 300s TTL 约束。超界拒绝启动并给出建议组合。
func preflight(cfg *Config) error {
	if cfg.SampleBytes <= types.ChunkSize {
		return fmt.Errorf("sample_bytes=%d 必须大于 64MiB（不改全局 ChunkSize 才能测真实多块）", cfg.SampleBytes)
	}
	if cfg.SampleBytes > types.ChunkSize*int64(types.MaxChunksPerFile) {
		return fmt.Errorf("sample_bytes=%d 超过分块上限", cfg.SampleBytes)
	}
	perStream := cfg.ClientUploadBPS / uint64(max(min(cfg.ClientConcurrent, 2), 1))
	if chunkSec := float64(types.ChunkSize) / float64(perStream); chunkSec > 140 {
		return fmt.Errorf("client_upload_bps=%d 太低：64MiB 块约需 %.0fs，逼近 150s ioTimeout；建议 ≥2MiB/s 或先用 80MiB 样本", cfg.ClientUploadBPS, chunkSec)
	}
	minNodeUp := uint64(0)
	for _, n := range cfg.Nodes {
		if minNodeUp == 0 || n.UploadBPS < minNodeUp {
			minNodeUp = n.UploadBPS
		}
	}
	estimate := float64(cfg.SampleBytes) * (1/float64(cfg.ClientUploadBPS) + 1/float64(minNodeUp))
	if estimate > 270 {
		return fmt.Errorf("样本 %.0fMiB 串行估时 %.0fs 超出传输计划 300s TTL 安全余量：提高 budget（如 up≥2MiB/s）或缩小 sample_bytes", float64(cfg.SampleBytes)/MiB, estimate)
	}
	return nil
}

func runDrive(cfg *Config, stderr io.Writer) int {
	rep := &driveReport{StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Exit: exitPass}
	defer func() {
		rep.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if raw, err := json.MarshalIndent(rep, "", "  "); err == nil {
			_ = os.WriteFile(cfg.ReportPath, raw, 0o600)
		}
	}()
	if err := preflight(cfg); err != nil {
		fmt.Fprintln(stderr, "预检失败:", err)
		rep.Exit = exitConfig
		return rep.Exit
	}
	lab := newLabClient(cfg)
	var status masterStatus
	if err := lab.do(http.MethodGet, "/lab/status", nil, &status); err != nil {
		fmt.Fprintln(stderr, "master /lab/status 不可达:", err)
		rep.Exit = exitInfra
		return rep.Exit
	}
	if err := applyProfiles(lab, cfg, status, stderr); err != nil {
		fmt.Fprintln(stderr, "应用节点 profile 失败:", err)
		rep.Exit = exitInfra
		return rep.Exit
	}
	logf(stderr, "预检通过：样本 %.0fMiB（%d 块），client up=%dB/s down=%dB/s",
		float64(cfg.SampleBytes)/MiB, chunkCount(cfg.SampleBytes), cfg.ClientUploadBPS, cfg.ClientDownloadBPS)
	for _, name := range cfg.Scenarios {
		var res scenarioResult
		switch name {
		case "one-ingress":
			res = scenarioOneIngress(cfg, lab, stderr)
		case "protection":
			res = scenarioProtection(cfg, lab, &status, stderr)
		}
		rep.Scenarios = append(rep.Scenarios, res)
		logf(stderr, "场景 %s => %s %s", name, res.Status, res.Reason)
		if res.Status == "failed" && rep.Exit < exitFail {
			rep.Exit = exitFail
		}
		if res.Status == "skipped" && rep.Exit == exitPass {
			rep.Exit = exitSkip
		}
	}
	events, err := collectNodeEvents(cfg)
	if err == nil {
		writeEventsFile(cfg, events, rep)
	} else {
		rep.Notes = append(rep.Notes, "事件收集不完整: "+err.Error())
	}
	return rep.Exit
}

// ---- 场景 1：单入口复制（f9b7a73 写规划闭环）----
//
// planner 未选 ≥2 确认则诚实 skip。named return：defer 写入的 FinishedAt
// 才会真正进入返回值（unnamed return 会在 defer 前拷贝，时间戳全部丢失）。
func scenarioOneIngress(cfg *Config, lab *labClient, stderr io.Writer) (res scenarioResult) {
	res = scenarioResult{Name: "one-ingress", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Detail: map[string]any{}}
	fail := func(format string, a ...any) {
		res.Status, res.Reason = "failed", fmt.Sprintf(format, a...)
	}
	defer func() { res.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano) }()
	remote := cfg.RemoteDir + "/one-ingress.bin"
	deny := map[string]bool{}
	for _, n := range cfg.Nodes {
		if n.Label != cfg.Ingress {
			deny[n.Addr] = true
		}
	}
	c := client.NewWithToken(cfg.Master, auth.Token(cfg.Token))
	if err := c.SetTransferBudget(types.TransferBudget{
		UploadBPS: cfg.ClientUploadBPS, DownloadBPS: cfg.ClientDownloadBPS, MaxConcurrent: cfg.ClientConcurrent,
	}); err != nil {
		fail("client 预算被拒: %v", err)
		return res
	}
	c.HTTP = &http.Client{Transport: &gateTransport{inner: &auth.Transport{Token: auth.Token(cfg.Token)}, deny: deny}}
	if _, _, err := c.Lookup(remote); err == nil {
		logf(stderr, "样本 %s 已存在（分场景调用），跳过生成与上传，仅做验证", remote)
		res.Detail["reused_existing"] = true
	} else {
		if _, err := c.Mkdir(cfg.RemoteDir); err != nil {
			logf(stderr, "mkdir 提示（目录可能已存在）: %v", err)
		}
		if _, err := c.SetProtection(cfg.RemoteDir, types.ProtectionSecurity); err != nil {
			fail("设置 security 档: %v", err)
			return res
		}
		logf(stderr, "生成确定性样本 %.0fMiB（每块独立种子）…", float64(cfg.SampleBytes)/MiB)
		// 临时文件一律 CreateTemp（私有、唯一名），不落固定路径——
		// 固定 os.TempDir() 名会覆写同机其他测试/用户的同名文件。
		tmpFile, err := os.CreateTemp("", "transferlab-sample-*.bin")
		if err != nil {
			fail("样本临时文件: %v", err)
			return res
		}
		tmp := tmpFile.Name()
		tmpFile.Close()
		defer os.Remove(tmp)
		if _, _, err := writeSampleFile(tmp, cfg.SampleBytes, sampleSeed(cfg)); err != nil {
			fail("样本生成: %v", err)
			return res
		}
		time.Sleep(cfg.ObserveWait.D()) // 等节点心跳把 A→B 观测报到 master（10s 抑制窗）
		logf(stderr, "开始规划上传（真实 client 分块入口，仅入口节点可达）…")
		var upErr error
		for attempt := 1; attempt <= 3; attempt++ {
			upErr = c.PutChunkedWithMinCopies(tmp, remote, 2, 0, false)
			if upErr == nil || !strings.Contains(upErr.Error(), "no feasible") {
				break // 仅观测未就绪导致的 no-feasible 值得重试
			}
			logf(stderr, "第 %d 次规划不可行（节点观测可能未上报），5s 后重试", attempt)
			time.Sleep(5 * time.Second)
		}
		if upErr != nil {
			fail("上传(实测): %v", upErr)
			return res
		}
	}
	in, _, err := c.Lookup(remote)
	if err != nil {
		fail("lookup: %v", err)
		return res
	}
	if len(in.Chunks) < 2 {
		fail("样本 %d 字节只产生 %d 块，未形成多块对象", cfg.SampleBytes, len(in.Chunks))
		return res
	}
	// 确认集合 ≥2：Done 集是 commit 的实际结果；不足即诚实 skip，绝不降档重试。
	chunks := map[string]any{}
	for _, ch := range in.Chunks {
		objID := types.ChunkObjID(ch, in.ID)
		chunks[strconv.FormatUint(objID, 10)] = map[string]any{
			"object_id": objID, "size": ch.Size, "replicas": ch.Replicas, "done": ch.Done}
		if len(ch.Done) < 2 {
			res.Status, res.Reason = "skipped", fmt.Sprintf("块 %d 的 Done=%v 少于 2（security 档未选出双确认）", ch.Index, ch.Done)
			res.Detail["chunks"] = chunks
			return res
		}
	}
	res.Detail["chunks"] = chunks
	// 物理来源事件关联：入口节点应有等字节 PUT /objects；非入口应有等字节
	// PUT /replicate 且没有客户端 PUT（证明单入口与节点间腿真实发生）。
	events, evErr := collectNodeEvents(cfg)
	if evErr != nil {
		fail("拉取节点事件: %v", evErr)
		return res
	}
	legProof := map[string]any{}
	for _, ch := range in.Chunks {
		objID := types.ChunkObjID(ch, in.ID)
		objPath, repPath := "/objects/"+strconv.FormatUint(objID, 10), "/replicate/"+strconv.FormatUint(objID, 10)
		if findEvent(events, cfg.Ingress, "PUT", objPath, ch.Size) == nil {
			fail("块 %d：入口节点 %s 缺少等字节客户端 PUT", ch.Index, cfg.Ingress)
			return res
		}
		for _, label := range nodeLabels(cfg, ch.Done, lab) {
			if label == cfg.Ingress {
				continue
			}
			if findEvent(events, label, "PUT", objPath, ch.Size) != nil {
				fail("块 %d：非入口节点 %s 出现客户端 PUT，单入口被破坏", ch.Index, label)
				return res
			}
			ev := findEvent(events, label, "PUT", repPath, ch.Size)
			if ev == nil {
				fail("块 %d：非入口节点 %s 缺少等字节 PUT /replicate", ch.Index, label)
				return res
			}
			legProof["chunk-"+strconv.Itoa(ch.Index)+"->"+label] = map[string]string{
				"start_utc": ev.StartUTC, "end_utc": ev.EndUTC, "duration_ms": strconv.FormatInt(ev.DurationMS, 10),
				"body_bytes": strconv.FormatInt(ev.Bytes, 10)}
		}
	}
	res.Detail["ingress_leg_events"] = legProof
	// 整文件 sha256 读回（不受单入口 gate 的第二客户端）。
	readback, err := os.CreateTemp("", "transferlab-readback-*.bin")
	if err != nil {
		fail("读回临时文件: %v", err)
		return res
	}
	tmpOut := readback.Name()
	readback.Close()
	defer os.Remove(tmpOut)
	full := client.NewWithToken(cfg.Master, auth.Token(cfg.Token))
	if err := full.Get(remote, tmpOut); err != nil {
		fail("读回: %v", err)
		return res
	}
	want := sampleExpect(cfg)
	if got, err := sha256File(tmpOut); err != nil || got != want.file {
		fail("整文件 sha256 不一致: got %s (err=%v)", got, err)
		return res
	}
	res.Detail["sha256"] = want.file
	res.Status = "passed"
	return res
}

// ---- 场景 2：A/B 已发布 → C 第三（admission 与 dispatch 分离）----
//
// /lab/reserve 只做持久 ReserveProtection（真实 ObjectIntegrity + 容量/心跳/
// profile revision 校验），/lab/step 走生产 autonomy.Step（claim 源绑定 → /pull →
// 真 verify 回执）。C 上逐块 sha256+CRC32C 实测；多源分布只报告不作硬断言。
func scenarioProtection(cfg *Config, lab *labClient, status *masterStatus, stderr io.Writer) (res scenarioResult) {
	res = scenarioResult{Name: "protection", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Detail: map[string]any{}}
	fail := func(format string, a ...any) {
		res.Status, res.Reason = "failed", fmt.Sprintf(format, a...)
	}
	defer func() { res.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano) }()
	remote := cfg.RemoteDir + "/one-ingress.bin"
	full := client.NewWithToken(cfg.Master, auth.Token(cfg.Token))
	in, _, err := full.Lookup(remote)
	if err != nil {
		res.Status, res.Reason = "skipped", "未找到 one-ingress 产物（先跑 one-ingress 场景）: "+err.Error()
		return res
	}
	target := pickMissingTarget(cfg, status, in)
	if target == nil {
		res.Status, res.Reason = "skipped", "没有存活且未持块的节点可当第三副本（C 未入网或布局已覆盖全部节点）"
		return res
	}
	logf(stderr, "第三副本目标：%s (node %d @ %s)", target.label, target.id, target.addr)
	objIDs := map[uint64]bool{}
	for _, ch := range in.Chunks {
		objIDs[types.ChunkObjID(ch, in.ID)] = true
	}
	var reserveOut struct {
		Results []struct {
			ObjectID uint64 `json:"object_id"`
			PlanID   string `json:"plan_id"`
			State    string `json:"state"`
			Error    string `json:"error"`
		} `json:"results"`
	}
	if err := lab.do(http.MethodPost, "/lab/reserve", map[string]any{"path": remote, "target_id": target.id}, &reserveOut); err != nil {
		fail("reserve: %v", err)
		return res
	}
	planIDs := map[string]bool{}
	var reserveErrors []string
	for _, r := range reserveOut.Results {
		if r.Error != "" {
			reserveErrors = append(reserveErrors, fmt.Sprintf("obj %d: %s", r.ObjectID, r.Error))
		}
		if r.PlanID != "" {
			planIDs[r.PlanID] = true
		}
	}
	// 采纳同对象的既有 pending 计划（主线程可能已先行 reserve）。
	var fresh masterStatus
	if err := lab.do(http.MethodGet, "/lab/status", nil, &fresh); err == nil {
		for _, p := range fresh.Plans {
			if p.State == meta.ProtectionPending && objIDs[p.Expected.ObjectID] {
				planIDs[p.ID] = true
			}
		}
		*status = fresh
	}
	if len(planIDs) == 0 {
		res.Status, res.Reason = "skipped", "reserve 无可执行计划: "+strings.Join(reserveErrors, "; ")
		return res
	}
	res.Detail["plan_ids"] = keysOf(planIDs)
	if len(reserveErrors) > 0 {
		res.Detail["reserve_errors"] = reserveErrors
	}
	// dispatch 循环：显式 /lab/step（生产 claim），租约 NextAttempt 到期后再派。
	deadline := time.Now().Add(cfg.ScenarioDeadline.D())
	for {
		if err := lab.do(http.MethodPost, "/lab/step", nil, nil); err != nil {
			fail("step: %v", err)
			return res
		}
		var now masterStatus
		if err := lab.do(http.MethodGet, "/lab/status", nil, &now); err != nil {
			fail("status: %v", err)
			return res
		}
		*status = now
		pendingUntil := time.Time{}
		allDone := true
		for _, p := range now.Plans {
			if !planIDs[p.ID] || p.State == meta.ProtectionCompleted {
				continue
			}
			allDone = false
			for _, t := range p.Targets {
				if !t.Done && time.Now().Before(t.NextAttempt) && (pendingUntil.IsZero() || t.NextAttempt.Before(pendingUntil)) {
					pendingUntil = t.NextAttempt
				}
			}
		}
		if allDone {
			break
		}
		if time.Now().After(deadline) {
			fail("派工超时：计划未全部 completed（见 status 的 lease/LastError）")
			return res
		}
		wait := cfg.StepInterval.D()
		if !pendingUntil.IsZero() && time.Until(pendingUntil) > wait {
			wait = time.Until(pendingUntil)
		}
		logf(stderr, "计划未齐，%.0fs 后继续 step（等租约到期）", wait.Seconds())
		time.Sleep(wait)
	}
	// 实测验证：目标节点逐块 sha256（种子可复算）+ CRC32C（元数据），再整文件 sha256。
	expect := sampleExpect(cfg)
	chunkProof := map[string]any{}
	for i, ch := range in.Chunks {
		objID := types.ChunkObjID(ch, in.ID)
		data, err := fetchObject(target.addr, auth.Token(cfg.Token), objID, ch.Size)
		if err != nil {
			fail("块 %d 从目标 %s 读取: %v", ch.Index, target.label, err)
			return res
		}
		if types.CRC32C(data) != ch.Checksum {
			fail("块 %d CRC32C 与元数据不符", ch.Index)
			return res
		}
		proof := map[string]string{"crc32c": fmt.Sprintf("%08x", ch.Checksum)}
		if i < len(expect.chunks) {
			sum := sha256.Sum256(data)
			proof["sha256"] = hex.EncodeToString(sum[:])
			if proof["sha256"] != expect.chunks[i] {
				fail("块 %d sha256 与确定性生成器不符", ch.Index)
				return res
			}
		}
		chunkProof["chunk-"+strconv.Itoa(ch.Index)] = proof
	}
	res.Detail["target_chunk_hashes"] = chunkProof
	in2, _, err := full.Lookup(remote)
	if err != nil {
		fail("复查 lookup: %v", err)
		return res
	}
	doneOnTarget := 0
	for _, ch := range in2.Chunks {
		if types.ContainsUint64(ch.Done, target.id) {
			doneOnTarget++
		}
	}
	res.Detail["done_on_target"] = fmt.Sprintf("%d/%d", doneOnTarget, len(in2.Chunks))
	if doneOnTarget != len(in2.Chunks) {
		fail("目标节点未进入全部块的 Done 集合")
		return res
	}
	verifyFile, err := os.CreateTemp("", "transferlab-verify-*.bin")
	if err != nil {
		fail("验证临时文件: %v", err)
		return res
	}
	tmpOut := verifyFile.Name()
	verifyFile.Close()
	defer os.Remove(tmpOut)
	if err := full.Get(remote, tmpOut); err != nil {
		fail("整文件读回: %v", err)
		return res
	}
	if got, err := sha256File(tmpOut); err != nil || got != expect.file {
		fail("整文件 sha256 不一致: got %s (err=%v)", got, err)
		return res
	}
	res.Detail["sha256"] = expect.file
	res.Detail["source_distribution"] = sourceDistribution(*status, keysOf(planIDs))
	res.Status = "passed"
	return res
}

// ---- 共用小件 ----

type targetRef struct {
	label string
	id    uint64
	addr  string
}

// applyProfiles 一次性为所有已注册节点写 placement profile（site=标签、预算来自
// cfg.nodes，与各 node 本地预算同源）。在 reserve 之前完成、之后不再改动。
// meta.SetNodePlacementProfile 即使内容相同也会 bump profile revision 并使既有
// pending 计划失效——所以与 /lab/status 现值逐一比对，只写确实有差异的节点；
// 全部一致则跳过 POST（二跑 protection 时保护既有 pending 计划不被 stale）。
func applyProfiles(lab *labClient, cfg *Config, status masterStatus, stderr io.Writer) error {
	current := map[uint64]meta.NodePlacementProfile{}
	for _, p := range status.Profiles {
		current[p.NodeID] = p
	}
	profiles := []meta.NodePlacementProfile{}
	matched := 0
	for _, ref := range cfg.Nodes {
		for _, n := range status.Nodes {
			if n.Addr != ref.Addr {
				continue
			}
			matched++
			want := meta.NodePlacementProfile{NodeID: n.ID,
				FailureDomains: map[string]string{"site": ref.Label},
				UploadBPS:      ref.UploadBPS, DownloadBPS: ref.DownloadBPS,
				MaxTransferConcurrency: max(ref.MaxConcurrent, 1)}
			if cur, ok := current[n.ID]; ok && profileEqual(cur, want) {
				continue
			}
			profiles = append(profiles, want)
		}
	}
	if matched == 0 {
		return errors.New("没有任何已注册节点匹配 cfg.nodes 地址")
	}
	if len(profiles) == 0 {
		logf(stderr, "profile 与 /lab/status 现值全部一致，跳过重写（保护既有 pending 计划的 revision）")
		return nil
	}
	// 有差异要重写：revision 必然前移，既有 pending 计划会被 fence——显式声明，
	// 绝不悄悄让旧计划失效；受影响的计划需重新 reserve/采纳。
	if pendingCount := countPendingPlans(status); pendingCount > 0 {
		logf(stderr, "警告：本次将更新 %d 个节点的 profile，revision 前移会使 %d 个 pending 计划 stale，需重新 reserve/step", len(profiles), pendingCount)
	}
	var out struct {
		Results []struct {
			NodeID uint64 `json:"node_id"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	if err := lab.do(http.MethodPost, "/lab/profiles", map[string]any{"profiles": profiles}, &out); err != nil {
		return err
	}
	for _, r := range out.Results {
		if r.Error != "" {
			return fmt.Errorf("node %d profile: %s", r.NodeID, r.Error)
		}
	}
	return nil
}

// profileEqual 逐字段深比较（含 HeadroomBytes 与空/nil 故障域：maps.Equal 对
// nil 与空 map 视为等价——二者语义均为“无域”，want 侧恒为 {"site":label}）。
func profileEqual(a, b meta.NodePlacementProfile) bool {
	return a.NodeID == b.NodeID && a.HeadroomBytes == b.HeadroomBytes &&
		a.UploadBPS == b.UploadBPS && a.DownloadBPS == b.DownloadBPS &&
		a.MaxTransferConcurrency == b.MaxTransferConcurrency &&
		maps.Equal(a.FailureDomains, b.FailureDomains)
}

func countPendingPlans(status masterStatus) int {
	n := 0
	for _, p := range status.Plans {
		if p.State == meta.ProtectionPending {
			n++
		}
	}
	return n
}

// pickMissingTarget 找一个存活且不持有该文件任何块的节点当第三副本。
func pickMissingTarget(cfg *Config, status *masterStatus, in types.Inode) *targetRef {
	holders := map[uint64]bool{}
	for _, ch := range in.Chunks {
		for _, id := range ch.Replicas {
			holders[id] = true
		}
	}
	byAddr := map[string]types.NodeInfo{}
	for _, n := range status.Nodes {
		byAddr[n.Addr] = n
	}
	for _, ref := range cfg.Nodes {
		n, ok := byAddr[ref.Addr]
		if !ok || holders[n.ID] {
			continue
		}
		if n.LastHeartbeat.IsZero() || time.Since(n.LastHeartbeat) > 60*time.Second {
			continue // 心跳过期不当目标，与生产口径一致
		}
		return &targetRef{label: ref.Label, id: n.ID, addr: ref.Addr}
	}
	return nil
}

// collectNodeEvents 从每个配置节点拉 NDJSON 事件（未启动节点返回部分结果+错误）。
func collectNodeEvents(cfg *Config) (map[string][]labEvent, error) {
	out := map[string][]labEvent{}
	var firstErr error
	httpc := &http.Client{Timeout: 30 * time.Second, Transport: &auth.Transport{Token: auth.Token(cfg.Token)}}
	for _, ref := range cfg.Nodes {
		resp, err := httpc.Get("http://" + ref.Addr + "/lab/events")
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", ref.Label, err)
			}
			continue
		}
		// 非 200（401/连接旧进程等）如实上报，绝不吞成下游 decode 错误。
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: lab/events http %d", ref.Label, resp.StatusCode)
			}
			continue
		}
		var evs []labEvent
		dec := json.NewDecoder(resp.Body)
		for {
			var ev labEvent
			if err := dec.Decode(&ev); err != nil {
				if !errors.Is(err, io.EOF) && firstErr == nil {
					firstErr = err
				}
				break
			}
			evs = append(evs, ev)
		}
		resp.Body.Close()
		out[ref.Label] = evs
	}
	return out, firstErr
}

// writeEventsFile 把全部节点事件按 {label, event} 落 NDJSON（主线程归档用）。
func writeEventsFile(cfg *Config, events map[string][]labEvent, rep *driveReport) {
	f, err := os.Create(cfg.ReportPath + ".events.ndjson")
	if err != nil {
		rep.Notes = append(rep.Notes, "事件文件创建失败: "+err.Error())
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	total := 0
	for label, evs := range events {
		total += len(evs)
		for _, ev := range evs {
			_ = enc.Encode(map[string]any{"label": label, "event": ev})
		}
	}
	rep.Notes = append(rep.Notes, fmt.Sprintf("已归档 %d 条节点事件到 %s.events.ndjson", total, cfg.ReportPath))
}

func findEvent(events map[string][]labEvent, label, method, path string, size int64) *labEvent {
	for _, ev := range events[label] {
		if ev.Method == method && ev.Path == path && ev.Bytes == size && ev.Fault == "" {
			cp := ev
			return &cp
		}
	}
	return nil
}

var (
	labelCacheMu sync.Mutex
	labelCache   map[uint64]string
)

// nodeLabels 把 node ID 翻成 cfg 标签；首次调用经 /lab/status 建立地址映射并缓存。
func nodeLabels(cfg *Config, ids []uint64, lab *labClient) []string {
	labelCacheMu.Lock()
	defer labelCacheMu.Unlock()
	if labelCache == nil && lab != nil {
		var st masterStatus
		if err := lab.do(http.MethodGet, "/lab/status", nil, &st); err == nil {
			m := map[uint64]string{}
			for _, ref := range cfg.Nodes {
				for _, n := range st.Nodes {
					if n.Addr == ref.Addr {
						m[n.ID] = ref.Label
					}
				}
			}
			labelCache = m
		}
	}
	out := []string{}
	for _, id := range ids {
		if label, ok := labelCache[id]; ok {
			out = append(out, label)
		}
	}
	return out
}

func sourceDistribution(status masterStatus, planIDs []string) map[string]int {
	out := map[string]int{}
	for _, p := range status.Plans {
		if !slices.Contains(planIDs, p.ID) {
			continue
		}
		for _, t := range p.Targets {
			if t.SourceID != 0 {
				out[strconv.FormatUint(t.SourceID, 10)]++
			}
		}
	}
	return out
}

func keysOf(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func chunkCount(size int64) int { return int((size + types.ChunkSize - 1) / types.ChunkSize) }

// fetchObject 从节点直读对象并校验长度。
func fetchObject(addr string, token auth.Token, objID uint64, want int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/objects/%d", addr, objID), nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 120 * time.Second, Transport: &auth.Transport{Token: token}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, want+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != want {
		return nil, fmt.Errorf("长度 %d != 元数据 %d", len(data), want)
	}
	return data, nil
}

// ---- 确定性样本：每块独立种子（xorshift64），流式生成不驻留内存 ----

type chunkGen struct{ state uint64 }

func seedState(seed string) uint64 {
	sum := sha256.Sum256([]byte(seed))
	return uint64(sum[0])<<56 | uint64(sum[1])<<48 | uint64(sum[2])<<40 | uint64(sum[3])<<32 |
		uint64(sum[4])<<24 | uint64(sum[5])<<16 | uint64(sum[6])<<8 | uint64(sum[7])
}

func (g *chunkGen) Read(p []byte) (int, error) {
	for i := 0; i < len(p); i += 8 {
		g.state ^= g.state << 13
		g.state ^= g.state >> 7
		g.state ^= g.state << 17
		for j := 0; j < 8 && i+j < len(p); j++ {
			p[i+j] = byte(g.state >> (8 * j))
		}
	}
	return len(p), nil
}

func sampleSeed(cfg *Config) string {
	return "transferlab|one-ingress|" + strconv.FormatInt(cfg.SampleBytes, 10)
}

// eachChunk 按块迭代确定性样本流（种子含块下标，跨机可复算）。
func eachChunk(size int64, seed string, sink func(index int, r io.Reader) error) error {
	for written, index := int64(0), 0; written < size; index++ {
		n := min(types.ChunkSize, size-written)
		g := &chunkGen{state: seedState(fmt.Sprintf("%s|chunk-%d", seed, index))}
		if err := sink(index, io.LimitReader(g, n)); err != nil {
			return err
		}
		written += n
	}
	return nil
}

// writeSampleFile 落盘确定性样本并返回（整文件 sha256, 每 chunk sha256）。
func writeSampleFile(path string, size int64, seed string) (string, []string, error) {
	f, err := os.Create(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	fileHash, hashes := sha256.New(), []string{}
	buf := make([]byte, MiB)
	err = eachChunk(size, seed, func(_ int, r io.Reader) error {
		chunkHash := sha256.New()
		if _, err := io.CopyBuffer(io.MultiWriter(f, fileHash, chunkHash), r, buf); err != nil {
			return err
		}
		hashes = append(hashes, hex.EncodeToString(chunkHash.Sum(nil)))
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if err := f.Sync(); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(fileHash.Sum(nil)), hashes, f.Close()
}

// sampleExpect 不落盘复算期望哈希（种子确定，跨进程/跨机一致）。
func sampleExpect(cfg *Config) sampleDigest {
	fileHash, hashes := sha256.New(), []string{}
	_ = eachChunk(cfg.SampleBytes, sampleSeed(cfg), func(_ int, r io.Reader) error {
		chunkHash := sha256.New()
		_, _ = io.CopyBuffer(io.MultiWriter(fileHash, chunkHash), r, make([]byte, MiB))
		hashes = append(hashes, hex.EncodeToString(chunkHash.Sum(nil)))
		return nil
	})
	return sampleDigest{file: hex.EncodeToString(fileHash.Sum(nil)), chunks: hashes}
}

type sampleDigest struct {
	file   string
	chunks []string
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func logf(stderr io.Writer, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if stderr != nil {
		fmt.Fprintln(stderr, msg)
	} else {
		fmt.Println(msg)
	}
}
