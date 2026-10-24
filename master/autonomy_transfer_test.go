package master

// master/autonomy_transfer_test.go —— 多源块调度物理 e2e（A/B → C）。
// 契约：先只起 A/B 发布多块文件，C 入网成为所有块的共同缺块目标 → 每块 ReserveProtection
// → controller claim→/pull → 同一 C 拿到完整副本并 verified receipt 自确认；两个源都被
// 用到、父文件 Generation/块表不变、旧副本逐字节不动。公平份额：先全部预留再派工，首条
// 流不饿死第二个源，同一实际流速双侧持久化且总速率不越过声明预算，源/目标本地 Limiter
// 真实限速。源失效：拒绝派工、
// 绝不偷换绑定，换源只在新有效 claim。ack loss：verify?plan_id 补回执零重传。
// 复用 autonomy_e2e_test.go 的 aut* 帮手（同 package 只读），不访问真集群。

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"atoll/client"
	"atoll/master/meta"
	atollnode "atoll/node"
	"atoll/pkg/types"
)

// autSetRateProfiles 给每个节点写互相不同的 site 失败域 + 声明速率/并发预算。
func autSetRateProfiles(t *testing.T, s *autStack, up, down uint64, slots int) {
	t.Helper()
	for i, nd := range s.nodes {
		p := meta.NodePlacementProfile{NodeID: nd.Info.ID,
			FailureDomains: map[string]string{"site": fmt.Sprintf("site-%d", i)},
			UploadBPS:      up, DownloadBPS: down, MaxTransferConcurrency: slots}
		if err := s.store.SetNodePlacementProfile(p); err != nil {
			t.Fatalf("SetNodePlacementProfile node %d: %v", nd.Info.ID, err)
		}
	}
}

// autStartBudgetNode 起一个带本地传输预算的节点（预算只允许在注册前一次性配置）。
func autStartBudgetNode(t *testing.T, s *autStack, budget types.TransferBudget) *autNode {
	t.Helper()
	if s.masterTS == nil {
		t.Fatal("startNode requires started master")
	}
	dir := s.t.TempDir()
	n := atollnode.New(dir, s.Master, "", 1<<30)
	if err := n.ConfigureTransferBudget(budget); err != nil {
		t.Fatalf("ConfigureTransferBudget: %v", err)
	}
	ts := httptest.NewServer(n.Handler())
	t.Cleanup(ts.Close)
	nd, err := s.store.RegisterNode(ts.Listener.Addr().String(), 1<<30)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	n.SetNodeIDForTest(nd.ID)
	node := &autNode{Base: ts.URL, Addr: nd.Addr, node: n, Info: nd, Dir: dir}
	s.nodes = append(s.nodes, node)
	return node
}

// autShrinkChunks 缩小全局块尺寸并在测试结束后还原，用于构造真实多块文件。
func autShrinkChunks(t *testing.T, size int64) {
	t.Helper()
	old := types.ChunkSize
	types.ChunkSize = size
	t.Cleanup(func() { types.ChunkSize = old })
}

// autPublishChunked 用真 client 分块发布多块文件（replicas=2），返回 inode 与每块期望内容。
func autPublishChunked(t *testing.T, s *autStack, path string, payload []byte) (types.Inode, [][]byte) {
	t.Helper()
	local := filepath.Join(t.TempDir(), "upload.bin")
	if err := os.WriteFile(local, payload, 0o644); err != nil {
		t.Fatalf("write local upload: %v", err)
	}
	c := client.New(s.Master)
	if err := c.PutChunked(local, path, 2); err != nil {
		t.Fatalf("PutChunked: %v", err)
	}
	in, _, err := c.Lookup(path)
	if err != nil {
		t.Fatalf("Lookup %s: %v", path, err)
	}
	if len(in.Chunks) < 2 {
		t.Fatalf("expected a multichunk inode, got %d chunks", len(in.Chunks))
	}
	var want [][]byte
	var offset int64
	for _, ch := range in.Chunks {
		n := ch.LogicalSize
		if n == 0 { // plain 几何下 LogicalSize 省略，物理 Size 即逻辑长度
			n = ch.Size
		}
		if n <= 0 || offset+n > int64(len(payload)) {
			t.Fatalf("bad chunk extent: size=%d offset=%d total=%d", n, offset, len(payload))
		}
		want = append(want, payload[offset:offset+n])
		offset += n
	}
	if offset != int64(len(payload)) {
		t.Fatalf("chunks cover %d of %d bytes", offset, len(payload))
	}
	return in, want
}

// autChunkObjectID 返回块的实际对象 ID（与 master 扫描同走 ChunkObjID 规则）。
func autChunkObjectID(in types.Inode, index int) uint64 {
	return types.ChunkObjID(in.Chunks[index], in.ID)
}

// autHoldersAndTarget 断言对象物理副本恰落在两个节点上，返回（持有者, 唯一缺块节点）。
func autHoldersAndTarget(t *testing.T, s *autStack, id uint64) ([2]*autNode, *autNode) {
	t.Helper()
	var holders []*autNode
	for _, nd := range s.nodes {
		if autNodeHasObject(t, nd, id) {
			holders = append(holders, nd)
		}
	}
	if len(holders) != 2 {
		t.Fatalf("object %d physical holders = %d, want exactly 2 (deterministic A/B layout)", id, len(holders))
	}
	var missing *autNode
	for _, nd := range s.nodes {
		found := false
		for _, h := range holders {
			if h == nd {
				found = true
			}
		}
		if !found {
			if missing != nil {
				t.Fatalf("object %d: more than one node lacks the object", id)
			}
			missing = nd
		}
	}
	if missing == nil {
		t.Fatalf("object %d: every node holds a replica, want exactly one target", id)
	}
	return [2]*autNode{holders[0], holders[1]}, missing
}

// autStepUntilDone 反复驱动自治 Step 直到全部对象 Done 达到 want（派工受 MaxDispatchPerTick 限流）。
func autStepUntilDone(t *testing.T, r *autonomyRunner, s *autStack, ids []uint64, want int) {
	t.Helper()
	allDone := func() bool {
		for _, id := range ids {
			d, err := s.store.ObjectIntegrity(id)
			if err != nil || len(d.Done) != want || len(d.Suspect) != 0 {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(45 * time.Second)
	for !allDone() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for Done=%d on objects %v", want, ids)
		}
		r.step(t)
		time.Sleep(100 * time.Millisecond)
	}
}

// ---- 场景 1：物理 A/B → C 全多块复制，确定性多源派工 + 目标自确认 ----

func TestAutonomyTransferE2EMultiSourceMultichunk(t *testing.T) {
	s := autNewStack(t)
	s.startMaster()
	// 先只起 A/B：每块唯一确定地落在这一对节点上；C 之后再入网成为共同缺块目标。
	a, b := s.startNode(), s.startNode()
	autShrinkChunks(t, 16<<10)

	payload := bytes.Repeat([]byte("atoll multi-source A/B->C multichunk payload;"), 1100) // ~50KB
	in, want := autPublishChunked(t, s, "/trf-multi.bin", payload)
	ids := make([]uint64, len(in.Chunks))
	for i := range in.Chunks {
		ids[i] = autChunkObjectID(in, i)
		autWaitDone(t, s, ids[i], 2)
		autPhysicallyEqual(t, a, ids[i], want[i], "holder A pre-check")
		autPhysicallyEqual(t, b, ids[i], want[i], "holder B pre-check")
	}
	before, err := s.store.ObjectIntegrity(ids[0])
	if err != nil {
		t.Fatalf("integrity before: %v", err)
	}

	// C 入网：全部块的唯一缺块节点。三个节点各配独立失败域（资格闸的输入）。
	c := s.startNode()
	stop := autKeepAlive(t, s)
	defer stop()
	autSetProfiles(t, s, 0)

	// 每块显式预留保护计划（controller reserve→dispatch 时序），目标都是 C；
	// 全部预留完成后再 claim，排队块才进入份额分母。
	snap, err := s.store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		d, err := s.store.ObjectIntegrity(id)
		if err != nil {
			t.Fatal(err)
		}
		req := meta.ProtectionRequest{ID: fmt.Sprintf("trf-multi-%d", i), Expected: d,
			Targets: []uint64{c.Info.ID}, MaxBytes: d.Size, NodeMaxAge: time.Hour,
			ProfileRevision: snap.ProfileRevision, Reason: "multi-source multichunk e2e"}
		if _, err := s.store.ReserveProtection(req, time.Now()); err != nil {
			t.Fatalf("ReserveProtection chunk %d: %v", i, err)
		}
	}
	r := autNewRunner(t, s, autAddConfig(3))
	autStepUntilDone(t, r, s, ids, 3)

	// 同一个 C 物理拿到每一块；A/B 旧副本逐字节不动，父文件 Generation 不变。
	for i, id := range ids {
		autPhysicallyEqual(t, c, id, want[i], "target chunk")
		autPhysicallyEqual(t, a, id, want[i], "holder A kept chunk")
		autPhysicallyEqual(t, b, id, want[i], "holder B kept chunk")
	}
	after, err := s.store.ObjectIntegrity(ids[0])
	if err != nil {
		t.Fatalf("integrity after: %v", err)
	}
	if after.Generation != before.Generation || after.Size != before.Size || after.Checksum != before.Checksum {
		t.Fatalf("content identity changed: %+v -> %+v", before, after)
	}
	// 每块计划完成且自确认；源只允许 A/B 且两个源都被用到，块全部落到同一个 C。
	sources := map[uint64]bool{}
	planned := 0
	for _, p := range autPlans(t, s) {
		if !containsUint64(ids, p.Expected.ObjectID) {
			continue
		}
		planned++
		if p.State != meta.ProtectionCompleted {
			t.Fatalf("plan %s state = %s, want completed", p.ID, p.State)
		}
		for _, tg := range p.Targets {
			if tg.NodeID != c.Info.ID {
				t.Fatalf("plan %s target %d, want common target %d", p.ID, tg.NodeID, c.Info.ID)
			}
			if !tg.Done || tg.SourceID == 0 || tg.SourceAddr == "" {
				t.Fatalf("plan %s target not durably self-confirmed: %+v", p.ID, tg)
			}
			if tg.SourceID != a.Info.ID && tg.SourceID != b.Info.ID {
				t.Fatalf("plan %s bound non-holder source %d", p.ID, tg.SourceID)
			}
			sources[tg.SourceID] = true
		}
	}
	if planned != len(ids) {
		t.Fatalf("plans for chunk objects = %d, want %d", planned, len(ids))
	}
	if len(sources) != 2 || !sources[a.Info.ID] || !sources[b.Info.ID] {
		t.Fatalf("multi-source dispatch must use exactly both holders: %v", sources)
	}
	// 父文件版本不变：块表（对象 ID 与几何）逐块一致。
	afterIn, _, err := client.New(s.Master).Lookup("/trf-multi.bin")
	if err != nil {
		t.Fatalf("lookup after: %v", err)
	}
	if afterIn.Generation != in.Generation || afterIn.Size != in.Size || len(afterIn.Chunks) != len(in.Chunks) {
		t.Fatalf("file version changed: generation %d -> %d, size %d -> %d, chunks %d -> %d",
			in.Generation, afterIn.Generation, in.Size, afterIn.Size, len(in.Chunks), len(afterIn.Chunks))
	}
	for i := range in.Chunks {
		if autChunkObjectID(afterIn, i) != ids[i] || afterIn.Chunks[i].Size != in.Chunks[i].Size {
			t.Fatalf("chunk %d identity changed", i)
		}
	}
	t.Logf("multichunk: %d chunks, sources used %v, target %d", len(ids), sources, c.Info.ID)
}

func containsUint64(list []uint64, v uint64) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ---- 场景 2：绑定源失效 → 拒绝派工且绝不偷换绑定，新有效 lease 才重绑健康源 ----

func TestAutonomyTransferE2ESourceFailureRebindsOnNewLease(t *testing.T) {
	s := autNewStack(t)
	s.startMaster()
	for i := 0; i < 3; i++ {
		s.startNode()
	}
	// 不起 keepalive：心跳只来自注册时刻（1h 窗口内），失效由测试显式制造。
	autSetProfiles(t, s, 0)

	body := []byte("bound source failure must refuse dispatch, never rotate to another source")
	in := autPublishSmall(t, s, "/trf-fault.txt", body, 2)
	autWaitDone(t, s, in.ObjID, 2)
	holders, target := autHoldersAndTarget(t, s, in.ObjID)
	d, err := s.store.ObjectIntegrity(in.ObjID)
	if err != nil {
		t.Fatalf("integrity: %v", err)
	}
	snap, err := s.store.AutonomySnapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	req := meta.ProtectionRequest{ID: "trf-fault", Expected: d, Targets: []uint64{target.Info.ID},
		MaxBytes: d.Size, NodeMaxAge: time.Hour, ProfileRevision: snap.ProfileRevision, Reason: "source failure e2e"}
	if _, err := s.store.ReserveProtection(req, time.Now()); err != nil {
		t.Fatalf("ReserveProtection: %v", err)
	}
	now := time.Now()
	budget := meta.ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: d.Size, NodeMaxAge: time.Hour}
	_, first, err := s.store.ClaimProtectionTarget(req.ID, now, 2*time.Second, budget)
	if err != nil || first == nil || first.SourceID == 0 {
		t.Fatalf("first claim: target=%+v err=%v", first, err)
	}
	if first.SourceID != holders[0].Info.ID && first.SourceID != holders[1].Info.ID {
		t.Fatalf("first binding %d is not a holder", first.SourceID)
	}
	deadSource := first.SourceID

	r := autNewRunner(t, s, autAddConfig(3))
	if err := autAgeOutHeartbeat(s, deadSource); err != nil {
		t.Fatalf("age out bound source: %v", err)
	}
	plan, err := s.store.ProtectionPlan(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.a.executeTarget(t.Context(), plan, *first); err == nil {
		t.Fatal("executeTarget must refuse a lease whose bound source lost liveness")
	}
	// 失败绝不偷换绑定：绑定只能随新租约变更。
	afterFail, err := s.store.ProtectionPlan(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterFail.Targets[0].SourceID != deadSource {
		t.Fatalf("binding rotated on failure: %d -> %d (forbidden fallback)", deadSource, afterFail.Targets[0].SourceID)
	}
	if err := s.store.RecordProtectionError(req.ID, target.Info.ID, "bound source lost liveness"); err != nil {
		t.Fatal(err)
	}

	// 新有效租约才重绑：死的源被资格闸排除，绑定落到另一个健康持有者。
	if err := autAgeOutHeartbeat(s, deadSource); err != nil {
		t.Fatal(err)
	}
	_, second, err := s.store.ClaimProtectionTarget(req.ID, now.Add(3*time.Second), 30*time.Second, budget)
	if err != nil || second == nil {
		t.Fatalf("rebind claim: target=%+v err=%v", second, err)
	}
	var liveHolder *autNode
	for _, h := range holders {
		if h.Info.ID != deadSource {
			liveHolder = h
		}
	}
	if second.SourceID != liveHolder.Info.ID || second.Attempts != 2 {
		t.Fatalf("rebind = (source %d attempts %d), want source %d attempts 2", second.SourceID, second.Attempts, liveHolder.Info.ID)
	}
	plan, err = s.store.ProtectionPlan(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.a.executeTarget(t.Context(), plan, *second); err != nil {
		t.Fatalf("dispatch with rebound source: %v", err)
	}
	autWaitDone(t, s, in.ObjID, 3)
	autPhysicallyEqual(t, target, in.ObjID, body, "rebound replica")
	autPhysicallyEqual(t, liveHolder, in.ObjID, body, "live holder kept")
	final, err := s.store.ProtectionPlan(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != meta.ProtectionCompleted {
		t.Fatalf("plan state = %s, want completed", final.State)
	}
	t.Logf("rebind: dead=%d rebound=%d attempts=%d", deadSource, second.SourceID, second.Attempts)
}

// ---- 场景 3：公平份额速率——首条流不饿死第二个源，总速率不越过声明预算 ----

func TestAutonomyTransferE2EFairShareRates(t *testing.T) {
	s := autNewStack(t)
	s.startMaster()
	const rate = 1 << 20 // 每节点声明的上/下行预算
	// A/B 先带本地传输预算入网再发布：源侧上行 GET 由真实共享 Limiter 限速，
	// 双端执行预算都是真的，不是只有 profile 账面。
	localBudget := types.TransferBudget{UploadBPS: rate, DownloadBPS: rate, MaxConcurrent: 4}
	a := autStartBudgetNode(t, s, localBudget)
	b := autStartBudgetNode(t, s, localBudget)
	// 两个对象都唯一确定地落在 {A,B} 上；C 之后再入网成为共同缺块节点，
	// 两条保护计划共享同一目标（公平份额交互的前提）。
	var objs []types.ObjectIntegrity
	var bodies [][]byte
	for i := 0; i < 2; i++ {
		body := bytes.Repeat([]byte(fmt.Sprintf("fair share rates object %d;", i)), 400)
		in := autPublishSmall(t, s, fmt.Sprintf("/trf-fair-%d.txt", i), body, 2)
		autWaitDone(t, s, in.ObjID, 2)
		for _, h := range []*autNode{a, b} {
			autPhysicallyEqual(t, h, in.ObjID, body, "fair share holder")
		}
		d, err := s.store.ObjectIntegrity(in.ObjID)
		if err != nil {
			t.Fatal(err)
		}
		objs = append(objs, d)
		bodies = append(bodies, body)
	}
	// C 同样携带本地预算（接收端必须能强制执行持久化流速）。
	c := autStartBudgetNode(t, s, localBudget)
	stop := autKeepAlive(t, s)
	defer stop()
	autSetRateProfiles(t, s, rate, rate, 4)

	snap, err := s.store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	// 先全部预留再派工：排队块进入份额分母，首条流拿不到整段预算。
	var plans []meta.ProtectionPlan
	for i, d := range objs {
		req := meta.ProtectionRequest{ID: fmt.Sprintf("trf-fair-%d", i), Expected: d,
			Targets: []uint64{c.Info.ID}, MaxBytes: d.Size, NodeMaxAge: time.Hour,
			ProfileRevision: snap.ProfileRevision, Reason: "fair share e2e"}
		p, err := s.store.ReserveProtection(req, time.Now())
		if err != nil {
			t.Fatalf("ReserveProtection %s: %v", req.ID, err)
		}
		plans = append(plans, p)
	}
	now := time.Now()
	execBudget := meta.ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: objs[0].Size + objs[1].Size, NodeMaxAge: time.Hour}
	var bound []meta.ProtectionTarget
	for i, p := range plans {
		_, tg, err := s.store.ClaimProtectionTarget(p.ID, now, 30*time.Second, execBudget)
		if err != nil || tg == nil {
			t.Fatalf("claim %d starved: target=%+v err=%v", i, tg, err)
		}
		if tg.UploadBPS == 0 || tg.UploadBPS != tg.DownloadBPS {
			t.Fatalf("claim %d rates = (%d,%d), want the same positive actual flow on both sides",
				i, tg.UploadBPS, tg.DownloadBPS)
		}
		if tg.SourceID != a.Info.ID && tg.SourceID != b.Info.ID {
			t.Fatalf("claim %d bound non-holder source %d", i, tg.SourceID)
		}
		bound = append(bound, *tg)
	}
	if bound[0].SourceID == bound[1].SourceID {
		t.Fatalf("second flow starved onto the same source %d", bound[1].SourceID)
	}
	// 总持久化速率不越过任何端点的声明预算（C 下行合计、各源上行合计）。
	downSum := bound[0].DownloadBPS + bound[1].DownloadBPS
	if downSum > rate {
		t.Fatalf("target ingress %d exceeds declared budget %d", downSum, rate)
	}
	upBySource := map[uint64]uint64{}
	for _, tg := range bound {
		upBySource[tg.SourceID] += tg.UploadBPS
	}
	for id, up := range upBySource {
		if up > rate {
			t.Fatalf("source %d egress %d exceeds declared budget %d", id, up, rate)
		}
	}
	// 描述符是速率的唯一权威：保护票据校验通过且携带同一份流速。
	tr, err := s.store.ProtectionTransfer(plans[0].ID, objs[0].ObjectID, c.Info.ID)
	if err != nil || tr == nil {
		t.Fatalf("ProtectionTransfer: %+v %v", tr, err)
	}
	if tr.UploadBPS != bound[0].UploadBPS || tr.DownloadBPS != bound[0].DownloadBPS {
		t.Fatalf("descriptor rates = (%d,%d), want bound (%d,%d)",
			tr.UploadBPS, tr.DownloadBPS, bound[0].UploadBPS, bound[0].DownloadBPS)
	}
	// 限速下的真实传输仍然完成（小对象秒级）。
	r := autNewRunner(t, s, autAddConfig(3))
	for i, p := range plans {
		fresh, err := s.store.ProtectionPlan(p.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.a.executeTarget(t.Context(), fresh, bound[i]); err != nil {
			t.Fatalf("dispatch fair share flow %d: %v", i, err)
		}
	}
	for i, d := range objs {
		autWaitDone(t, s, d.ObjectID, 3)
		autPhysicallyEqual(t, c, d.ObjectID, bodies[i], "fair share replica")
	}
	t.Logf("fair share: down sum %d <= %d, sources %v", downSum, rate, upBySource)
}

// ---- 场景 4：多块 ack loss——已落盘但回执丢失，verify 补回执不重传 ----

func TestAutonomyTransferE2EAckLostMultichunkVerify(t *testing.T) {
	s := autNewStack(t)
	s.startMaster()
	for i := 0; i < 3; i++ {
		s.startNode()
	}
	stop := autKeepAlive(t, s)
	defer stop()
	autSetProfiles(t, s, 0)
	autShrinkChunks(t, 16<<10)

	payload := bytes.Repeat([]byte("ack lost between landing and receipt on a multichunk file;"), 900)
	in, want := autPublishChunked(t, s, "/trf-ack.bin", payload)
	ids := make([]uint64, len(in.Chunks))
	type chunkLayout struct {
		holders [2]*autNode
		target  *autNode
	}
	layouts := make([]chunkLayout, len(in.Chunks))
	for i := range in.Chunks {
		ids[i] = autChunkObjectID(in, i)
		autWaitDone(t, s, ids[i], 2)
		h, miss := autHoldersAndTarget(t, s, ids[i])
		layouts[i] = chunkLayout{holders: h, target: miss}
	}

	// 块 0 真实 claim 后传输"完成、回执丢失"：内容直接落到缺块节点盘上，无 receipt。
	lost := ids[0]
	d, err := s.store.ObjectIntegrity(lost)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.store.AutonomySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	req := meta.ProtectionRequest{ID: "trf-ack-lost-chunk", Expected: d,
		Targets: []uint64{layouts[0].target.Info.ID}, MaxBytes: d.Size, NodeMaxAge: time.Hour,
		ProfileRevision: snap.ProfileRevision, Reason: "multichunk ack lost"}
	if _, err := s.store.ReserveProtection(req, time.Now()); err != nil {
		t.Fatalf("ReserveProtection: %v", err)
	}
	if _, tg, err := s.store.ClaimProtectionTarget(req.ID, time.Now(), 30*time.Second,
		meta.ProtectionExecutionBudget{MaxConcurrent: 4, MaxBytes: d.Size, NodeMaxAge: time.Hour}); err != nil || tg == nil {
		t.Fatalf("claim: %+v %v", tg, err)
	}
	dstDir := filepath.Join(layouts[0].target.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", lost%256))
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dstPath := filepath.Join(dstDir, fmt.Sprint(lost))
	if err := os.WriteFile(dstPath, want[0], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := layouts[0].target.node.InitUsedBytes(); err != nil {
		t.Fatalf("reconcile landed chunk: %v", err)
	}
	landed, err := os.Stat(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := s.store.ObjectIntegrity(lost)
	if types.ContainsUint64(cur.Replicas, layouts[0].target.Info.ID) {
		t.Fatalf("premature membership before receipt: %v", cur.Replicas)
	}
	// 恢复路径：verify?plan_id 重读本地盘 CRC 相等后补 verified receipt，块内容零重传。
	status, raw := autPostJSON(t, fmt.Sprintf("%s/verify/%d?plan_id=%s",
		layouts[0].target.Base, lost, url.QueryEscape(req.ID)), nil)
	if status != http.StatusOK {
		t.Fatalf("verify with plan_id: status %d body %s", status, string(raw))
	}
	autWaitDone(t, s, lost, 3)
	plan, err := s.store.ProtectionPlan(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.State != meta.ProtectionCompleted {
		t.Fatalf("plan state = %s, want completed", plan.State)
	}
	autPhysicallyEqual(t, layouts[0].target, lost, want[0], "landed chunk kept")
	after, err := os.Stat(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(landed.ModTime()) || after.Size() != landed.Size() {
		t.Fatalf("verify rewrote the landed chunk: mtime %v -> %v size %d -> %d",
			landed.ModTime(), after.ModTime(), landed.Size(), after.Size())
	}

	// 其余块走 controller 的 reserve→dispatch 路径完成多块复制。
	rest := ids[1:]
	for i, id := range rest {
		d, err := s.store.ObjectIntegrity(id)
		if err != nil {
			t.Fatal(err)
		}
		req := meta.ProtectionRequest{ID: fmt.Sprintf("trf-ack-rest-%d", i), Expected: d,
			Targets: []uint64{layouts[i+1].target.Info.ID}, MaxBytes: d.Size, NodeMaxAge: time.Hour,
			ProfileRevision: snap.ProfileRevision, Reason: "multichunk ack lost rest"}
		if _, err := s.store.ReserveProtection(req, time.Now()); err != nil {
			t.Fatalf("ReserveProtection rest chunk %d: %v", i, err)
		}
	}
	r := autNewRunner(t, s, autAddConfig(3))
	autStepUntilDone(t, r, s, rest, 3)
	for i, id := range rest {
		autPhysicallyEqual(t, layouts[i+1].target, id, want[i+1], "planner chunk")
	}
	t.Logf("ack lost multichunk: chunk %d recovered by verify only, %d chunks via controller", lost, len(rest))
}
