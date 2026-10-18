package node

// 仅增保护计划（plan_id）在 node 数据面的小接入测试：
//   - 合法计划 pull/verify：请求带 plan_id、按 descriptor 校验落盘、回执 plan-bound；
//   - 计划不匹配/缺失、非计划响应意外带 PlanID：拒绝，不落盘、无回执（上下文防串味）；
//   - 未分配源/非成员节点拒绝；checksum=0 但 checksum_known=true 支持；
//   - 计划对象无记录校验和（length-only）直接拒绝，绝不降级 present 回执；
//   - 取消的请求 context、不带 plan_id 的原 normal 路径均不回归。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"atoll/pkg/types"
)

// ---- 计划感知假 master ----

// planFakeMaster 按 object_id 原样返回预置计划（含 PlanID，用于模拟 master 的
// 各种响应），并记录 /files/replication 的 query 与两种回执体。
type planFakeMaster struct {
	mu       sync.Mutex
	plans    map[uint64]types.ReplicationPlan
	queries  []url.Values
	verified []map[string]any
	present  []map[string]any
}

func (m *planFakeMaster) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/files/replication":
			q := r.URL.Query()
			id, _ := strconv.ParseUint(q.Get("object_id"), 10, 64)
			m.mu.Lock()
			m.queries = append(m.queries, q)
			plan, ok := m.plans[id]
			m.mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(plan)
		case r.Method == http.MethodPost && r.URL.Path == "/files/replicated/verified":
			m.record(w, r, &m.verified)
		case r.Method == http.MethodPost && r.URL.Path == "/files/replicated/present":
			m.record(w, r, &m.present)
		case r.Method == http.MethodPost:
			// /files/objects/suspect 等默认接受。
			io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
}

func (m *planFakeMaster) record(w http.ResponseWriter, r *http.Request, dst *[]map[string]any) {
	var body map[string]any
	json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	m.mu.Lock()
	*dst = append(*dst, body)
	m.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, `{"marked":true}`)
}

func (m *planFakeMaster) setPlan(id uint64, plan types.ReplicationPlan) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.plans[id] = plan
}

func (m *planFakeMaster) receipts() (verified, present []map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]map[string]any(nil), m.verified...), append([]map[string]any(nil), m.present...)
}

func (m *planFakeMaster) requestedPlanIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.queries))
	for _, q := range m.queries {
		out = append(out, q.Get("plan_id"))
	}
	return out
}

// receiptPlanID 提取回执体 object.plan_id（omitempty：非计划回执无该键 → ""）。
func receiptPlanID(body map[string]any) string {
	obj, _ := body["object"].(map[string]any)
	s, _ := obj["plan_id"].(string)
	return s
}

// ---- fixture ----

func attachPlanMaster(t *testing.T, n *Node) *planFakeMaster {
	t.Helper()
	m := &planFakeMaster{plans: map[uint64]types.ReplicationPlan{}}
	srv := httptest.NewServer(m.handler())
	n.SetNodeIDForTest(2)
	n.masterURL = srv.URL
	t.Cleanup(srv.Close)
	return m
}

func planForObject(id uint64, data []byte, planID string, replicas []uint64, sources []types.NodeInfo) types.ReplicationPlan {
	return types.ReplicationPlan{
		Protocol: types.IntegrityProtocol,
		Object: types.ObjectIntegrity{
			PlanID:         planID,
			PlanLeaseUntil: time.Now().Add(time.Minute),
			ObjectID:       id,
			InodeID:        id,
			Size:           int64(len(data)),
			Checksum:       types.CRC32C(data),
			ChecksumKnown:  true,
			Replicas:       replicas,
		},
		Sources: sources,
	}
}

func putToSource(t *testing.T, sourceTS *httptest.Server, id uint64, data []byte) string {
	t.Helper()
	if code := putObjectTo(t, sourceTS.URL, id, data, types.CRC32C(data)); code != http.StatusCreated {
		t.Fatalf("source PUT %d = %d", id, code)
	}
	return strings.TrimPrefix(sourceTS.URL, "http://")
}

func sendPull(t *testing.T, targetTS *httptest.Server, req map[string]any) {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := http.Post(targetTS.URL+"/pull", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /pull = %d, want 202", resp.StatusCode)
	}
}

func waitForObject(t *testing.T, baseURL string, id uint64, want []byte) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("%s/objects/%d", baseURL, id))
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && bytes.Equal(body, want) {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("object %d 未按 descriptor 落盘", id)
}

// waitForPullIdle 等异步 pull 结束（去重键释放；回执在返回前已发出），再判定
// 「未落盘/无回执」或断言回执内容，避免与 goroutine 收尾竞态。
func waitForPullIdle(t *testing.T, n *Node, id uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, busy := n.pulling.Load(id); !busy {
			time.Sleep(50 * time.Millisecond)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pull %d 未结束", id)
}

func assertNoReceipts(t *testing.T, m *planFakeMaster, why string) {
	t.Helper()
	verified, present := m.receipts()
	if len(verified) != 0 || len(present) != 0 {
		t.Fatalf("%s: 不应产生回执, verified=%d present=%d", why, len(verified), len(present))
	}
}

// ---- 核心用例 ----

// 合法计划 pull：请求带 plan_id（含需编码字符），按 descriptor 落盘，
// 回执带同一 plan_id 且只走 verified，绝无 length-only present。
func TestProtectionPlanPullStoresAndReportsPlanBoundReceipt(t *testing.T) {
	data := []byte("protected plan payload")
	objID := uint64(400)
	_, sourceTS := newTestNode(t)
	sourceAddr := putToSource(t, sourceTS, objID, data)

	target, targetTS := newTestNode(t)
	m := attachPlanMaster(t, target)
	const planID = "plan aa&b=1" // 空格/&/=：query 必须 urlencode
	m.setPlan(objID, planForObject(objID, data, planID, []uint64{1, 2}, []types.NodeInfo{{ID: 1, Addr: sourceAddr}}))

	sendPull(t, targetTS, map[string]any{
		"inode_id": objID, "source_addr": sourceAddr,
		"checksum": types.CRC32C(data), "plan_id": planID,
	})
	waitForObject(t, targetTS.URL, objID, data)
	waitForPullIdle(t, target, objID)

	ids := m.requestedPlanIDs()
	if len(ids) == 0 || ids[len(ids)-1] != planID {
		t.Fatalf("master 收到的 plan_id = %v, want %q 原样（query 需正确编码）", ids, planID)
	}
	verified, present := m.receipts()
	if len(verified) != 1 {
		t.Fatalf("verified 回执 = %d, want 1", len(verified))
	}
	if got := receiptPlanID(verified[0]); got != planID {
		t.Fatalf("回执 plan_id = %q, want %q（plan-bound receipt）", got, planID)
	}
	if len(present) != 0 {
		t.Fatalf("计划流程不允许 length-only present 回执: %v", present)
	}
}

// 请求 plan_id 与 master 响应 PlanID 不一致（伪造/过期）：拒绝，不落盘、无任何回执。
func TestProtectionPlanPullRejectsPlanMismatch(t *testing.T) {
	data := []byte("plan payload two")
	objID := uint64(400)
	_, sourceTS := newTestNode(t)
	sourceAddr := putToSource(t, sourceTS, objID, data)
	target, targetTS := newTestNode(t)
	m := attachPlanMaster(t, target)
	m.setPlan(objID, planForObject(objID, data, "plan-real", []uint64{1, 2}, []types.NodeInfo{{ID: 1, Addr: sourceAddr}}))

	sendPull(t, targetTS, map[string]any{"inode_id": objID, "source_addr": sourceAddr, "plan_id": "plan-forged"})
	waitForPullIdle(t, target, objID)
	if objectExists(targetTS.URL, objID) {
		t.Fatal("plan 不匹配不允许落盘")
	}
	assertNoReceipts(t, m, "plan mismatch")
}

// 非 plan 请求但 master 响应带 PlanID：上下文防串味，同样拒绝。
func TestNormalPullRejectsUnexpectedPlanInResponse(t *testing.T) {
	data := []byte("plan payload three")
	objID := uint64(400)
	_, sourceTS := newTestNode(t)
	sourceAddr := putToSource(t, sourceTS, objID, data)
	target, targetTS := newTestNode(t)
	m := attachPlanMaster(t, target)
	m.setPlan(objID, planForObject(objID, data, "plan-real", []uint64{1, 2}, []types.NodeInfo{{ID: 1, Addr: sourceAddr}}))

	sendPull(t, targetTS, map[string]any{"inode_id": objID, "source_addr": sourceAddr}) // 无 plan_id
	waitForPullIdle(t, target, objID)
	if objectExists(targetTS.URL, objID) {
		t.Fatal("非计划响应意外带 PlanID 必须拒绝")
	}
	assertNoReceipts(t, m, "unexpected plan context")
}

// /verify/{id}?plan_id=：对象已在本机（重启/回执丢失场景），带 plan_id 校验并补回执，
// 不重复传内容；回执 plan-bound。
func TestProtectionPlanVerifyExistingObjectWithPlanID(t *testing.T) {
	data := []byte("already stored payload")
	objID := uint64(401)
	target, targetTS := newTestNode(t)
	m := attachPlanMaster(t, target)
	m.setPlan(objID, planForObject(objID, data, "plan-xyz", []uint64{1, 2}, nil))
	if _, _, err := target.storeObject(objID, bytes.NewReader(data), types.CRC32C(data)); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(targetTS.URL+"/verify/401?plan_id=plan-xyz", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify with plan_id = %d, want 200", resp.StatusCode)
	}
	verified, present := m.receipts()
	if len(verified) != 1 || receiptPlanID(verified[0]) != "plan-xyz" {
		t.Fatalf("verify 回执应 plan-bound: verified=%v", verified)
	}
	if len(present) != 0 {
		t.Fatalf("计划 verify 不允许 length-only 回执: %v", present)
	}
}

// verify 缺 plan_id（响应带 PlanID 被拒）/ 错 plan_id：409，无回执。
func TestProtectionPlanVerifyRejectsWrongOrMissingPlan(t *testing.T) {
	data := []byte("verify guard payload")
	objID := uint64(401)
	target, _ := newTestNode(t)
	m := attachPlanMaster(t, target)
	m.setPlan(objID, planForObject(objID, data, "plan-xyz", []uint64{1, 2}, nil))
	if _, _, err := target.storeObject(objID, bytes.NewReader(data), types.CRC32C(data)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"missing plan_id", "/verify/401"},
		{"wrong plan_id", "/verify/401?plan_id=plan-other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.url, nil)
			req.SetPathValue("id", "401") // 直连 handler 调用需手动填充路径参数
			rec := httptest.NewRecorder()
			target.handleVerifyObject(rec, req)
			if rec.Code != http.StatusConflict {
				t.Fatalf("%s: code = %d, want 409", tc.name, rec.Code)
			}
			assertNoReceipts(t, m, tc.name)
		})
	}
}

// 计划 pull 的源必须在计划 Sources 且是 Object.Replicas 成员：未分配源拒绝。
func TestProtectionPlanPullRejectsUnassignedSource(t *testing.T) {
	data := []byte("unassigned source payload")
	_, sourceTS := newTestNode(t)
	sourceAddr := putToSource(t, sourceTS, 402, data)
	target, targetTS := newTestNode(t)
	m := attachPlanMaster(t, target)
	m.setPlan(402, planForObject(402, data, "plan-u", []uint64{1, 2}, []types.NodeInfo{{ID: 1, Addr: sourceAddr}}))

	// 源地址不在计划 Sources。
	sendPull(t, targetTS, map[string]any{"inode_id": 402, "source_addr": "127.0.0.1:1", "plan_id": "plan-u"})
	waitForPullIdle(t, target, 402)
	if objectExists(targetTS.URL, 402) {
		t.Fatal("未分配源不允许 pull 落盘")
	}
	assertNoReceipts(t, m, "unassigned source addr")

	// 源节点不在 Object.Replicas（非成员）：peer 校验拒绝。
	m.setPlan(403, types.ReplicationPlan{
		Protocol: types.IntegrityProtocol,
		Object: types.ObjectIntegrity{
			PlanID: "plan-u", PlanLeaseUntil: time.Now().Add(time.Minute),
			ObjectID: 403, InodeID: 403,
			Size: int64(len(data)), Checksum: types.CRC32C(data), ChecksumKnown: true,
			Replicas: []uint64{1, 2},
		},
		Sources: []types.NodeInfo{{ID: 9, Addr: sourceAddr}}, // ID 9 不是成员
	})
	sendPull(t, targetTS, map[string]any{"inode_id": 403, "source_addr": sourceAddr, "plan_id": "plan-u"})
	waitForPullIdle(t, target, 403)
	if objectExists(targetTS.URL, 403) {
		t.Fatal("非成员节点不允许作为计划源")
	}
	assertNoReceipts(t, m, "non-member source")
}

// checksum=0 但 checksum_known=true（真实 CRC 恰为 0）必须支持，回执走 verified + plan_id。
func TestProtectionPlanPullSupportsChecksumZeroKnown(t *testing.T) {
	zeroBytes := []byte{0xab, 0x9b, 0xe0, 0x9b} // CRC32C == 0
	if types.CRC32C(zeroBytes) != 0 {
		t.Fatal("invalid zero CRC fixture")
	}
	objID := uint64(404)
	_, sourceTS := newTestNode(t)
	sourceAddr := putToSource(t, sourceTS, objID, zeroBytes)
	target, targetTS := newTestNode(t)
	m := attachPlanMaster(t, target)
	m.setPlan(objID, types.ReplicationPlan{
		Protocol: types.IntegrityProtocol,
		Object: types.ObjectIntegrity{
			PlanID: "plan-zero", PlanLeaseUntil: time.Now().Add(time.Minute),
			ObjectID: objID, InodeID: objID,
			Size: int64(len(zeroBytes)), Checksum: 0, ChecksumKnown: true,
			Replicas: []uint64{1, 2},
		},
		Sources: []types.NodeInfo{{ID: 1, Addr: sourceAddr}},
	})

	sendPull(t, targetTS, map[string]any{
		"inode_id": objID, "source_addr": sourceAddr, "checksum": uint32(0), "plan_id": "plan-zero",
	})
	waitForObject(t, targetTS.URL, objID, zeroBytes)
	waitForPullIdle(t, target, objID)
	verified, present := m.receipts()
	if len(verified) != 1 || receiptPlanID(verified[0]) != "plan-zero" {
		t.Fatalf("checksum0-known 计划回执应 verified + plan-bound: %v", verified)
	}
	if len(present) != 0 {
		t.Fatalf("不应降级 length-only: %v", present)
	}
}

// 计划对象无记录校验和（legacy length-only）：计划流程直接拒绝，
// 不落盘、不产生任何回执（verified 与 present 都不允许）。
func TestProtectionPlanRejectsLengthOnlyObject(t *testing.T) {
	data := []byte("legacy")
	objID := uint64(405)
	_, sourceTS := newTestNode(t)
	sourceAddr := putToSource(t, sourceTS, objID, data)
	target, targetTS := newTestNode(t)
	m := attachPlanMaster(t, target)
	m.setPlan(objID, types.ReplicationPlan{
		Protocol: types.IntegrityProtocol,
		Object: types.ObjectIntegrity{
			PlanID: "plan-legacy", ObjectID: objID, InodeID: objID,
			Size: int64(len(data)), Checksum: 0, ChecksumKnown: false,
			Replicas: []uint64{1, 2},
		},
		Sources: []types.NodeInfo{{ID: 1, Addr: sourceAddr}},
	})

	sendPull(t, targetTS, map[string]any{"inode_id": objID, "source_addr": sourceAddr, "plan_id": "plan-legacy"})
	waitForPullIdle(t, target, objID)
	if objectExists(targetTS.URL, objID) {
		t.Fatal("无校验和对象不允许进入计划流程")
	}
	assertNoReceipts(t, m, "length-only plan")

	req := httptest.NewRequest(http.MethodPost, "/verify/405?plan_id=plan-legacy", nil)
	req.SetPathValue("id", "405")
	rec := httptest.NewRecorder()
	target.handleVerifyObject(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("length-only plan verify = %d, want 409", rec.Code)
	}
	assertNoReceipts(t, m, "length-only plan verify")
}

// 旧 normal pull 路径不回归：无 plan_id → 正常落盘，回执 verified 且不带 plan_id。
func TestNormalPullReceiptStaysUnplanned(t *testing.T) {
	data := []byte("plain pull payload")
	objID := uint64(406)
	_, sourceTS := newTestNode(t)
	sourceAddr := putToSource(t, sourceTS, objID, data)
	target, targetTS := newTestNode(t)
	m := attachPlanMaster(t, target)
	m.setPlan(objID, planForObject(objID, data, "", []uint64{1, 2}, []types.NodeInfo{{ID: 1, Addr: sourceAddr}}))

	sendPull(t, targetTS, map[string]any{"inode_id": objID, "source_addr": sourceAddr})
	waitForObject(t, targetTS.URL, objID, data)
	waitForPullIdle(t, target, objID)
	verified, present := m.receipts()
	if len(verified) != 1 {
		t.Fatalf("normal pull verified 回执 = %d, want 1", len(verified))
	}
	if got := receiptPlanID(verified[0]); got != "" {
		t.Fatalf("normal 回执不应带 plan_id, got %q", got)
	}
	if len(present) != 0 {
		t.Fatalf("normal verified 流程不应有 present: %v", present)
	}
}

// /verify 的父 context 接线：已取消的请求 context 立即失败、无回执（取消不回归）。
func TestVerifyObjectHonorsCancelledContext(t *testing.T) {
	data := []byte("cancelled verify payload")
	objID := uint64(407)
	target, _ := newTestNode(t)
	m := attachPlanMaster(t, target)
	m.setPlan(objID, planForObject(objID, data, "plan-c", []uint64{1, 2}, nil))
	if _, _, err := target.storeObject(objID, bytes.NewReader(data), types.CRC32C(data)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/verify/%d?plan_id=plan-c", objID), nil).WithContext(ctx)
	req.SetPathValue("id", strconv.FormatUint(objID, 10))
	rec := httptest.NewRecorder()
	target.handleVerifyObject(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("cancelled verify = %d, want 409", rec.Code)
	}
	assertNoReceipts(t, m, "cancelled verify")
}

// 租约（PlanLeaseUntil）fail-closed：计划 pull/verify 对 zero 或已过期租约一律拒绝，
// 不开新网络流、不落盘、无回执（master 侧过期 claim 会拒 descriptor，node 侧同步兜底）。
func TestProtectionPlanRejectsExpiredOrMissingLease(t *testing.T) {
	data := []byte("lease bound payload")
	for _, tc := range []struct {
		name  string
		lease time.Time
	}{
		{"zero lease", time.Time{}},
		{"expired lease", time.Now().Add(-time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objID := uint64(410)
			_, sourceTS := newTestNode(t)
			sourceAddr := putToSource(t, sourceTS, objID, data)
			target, targetTS := newTestNode(t)
			m := attachPlanMaster(t, target)
			plan := planForObject(objID, data, "plan-lease", []uint64{1, 2}, []types.NodeInfo{{ID: 1, Addr: sourceAddr}})
			plan.Object.PlanLeaseUntil = tc.lease
			m.setPlan(objID, plan)
			// 对象已在本机：pull 与 verify 两条路径都必须拒绝。
			if _, _, err := target.storeObject(objID, bytes.NewReader(data), types.CRC32C(data)); err != nil {
				t.Fatal(err)
			}

			sendPull(t, targetTS, map[string]any{"inode_id": objID, "source_addr": sourceAddr, "plan_id": "plan-lease"})
			waitForPullIdle(t, target, objID)
			assertNoReceipts(t, m, tc.name+" pull")

			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/verify/%d?plan_id=plan-lease", objID), nil)
			req.SetPathValue("id", strconv.FormatUint(objID, 10))
			rec := httptest.NewRecorder()
			target.handleVerifyObject(rec, req)
			if rec.Code != http.StatusConflict {
				t.Fatalf("%s verify = %d, want 409", tc.name, rec.Code)
			}
			assertNoReceipts(t, m, tc.name+" verify")
		})
	}
}

// planDeadline 的纯函数测试：min(base, lease) 只收窄不放宽。
func TestPlanDeadlineNarrowsToLease(t *testing.T) {
	now := time.Now()
	if _, err := planDeadline(time.Minute, time.Time{}); !errors.Is(err, errLeaseExpired) {
		t.Fatalf("zero lease 应判过期: %v", err)
	}
	if _, err := planDeadline(time.Minute, now.Add(-time.Second)); !errors.Is(err, errLeaseExpired) {
		t.Fatalf("过期 lease 应判过期: %v", err)
	}
	// lease 比基础超时近 → 取 lease。
	d, err := planDeadline(time.Minute, now.Add(5*time.Second))
	if err != nil || time.Since(d) > -4*time.Second {
		t.Fatalf("近 lease 应收窄截止: d=%v err=%v", d, err)
	}
	// lease 比基础超时远 → 取基础超时。
	d, err = planDeadline(time.Minute, now.Add(time.Hour))
	if err != nil || time.Since(d) > -50*time.Second {
		t.Fatalf("远 lease 不应放宽上界: d=%v err=%v", d, err)
	}
}
