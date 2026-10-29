package node

// 计划写入世代（WriteEpoch）在 node 数据面的接入测试：
//   - 入站世代闸：请求携带的世代必须等于 master 当前 descriptor 的世代；
//     旧世代 in-flight 请求在 replan 后被拒，不落盘、无回执；
//   - 协议↔世代耦合：integrity-write-v3 必须携带世代，integrity-v1 不得携带；
//   - 发布前世代闸：payload 传输期间 replan 推进世代 → 拒绝发布，不留目标文件；
//   - 回执被拒（世代过期）→ 显式失败（非 201），且不重试；
//   - resume：零长度重确认，404 允许回退真实 PUT，坏 CRC 拒绝并上报 suspect；
//   - payload 进度只在实际字节前进时上报，且只对带世代的写入上报。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"atoll/pkg/types"
)

// ---- 世代感知假 master ----

type epochFakeMaster struct {
	mu            sync.Mutex
	plans         map[uint64]types.ReplicationPlan
	afterGet      func(gets int)
	receiptStatus int
	verified      []types.ObjectIntegrity
	suspects      []types.ObjectIntegrity
	progress      []types.WriteProgress
	gets          int
}

func (m *epochFakeMaster) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/files/replication":
			q := r.URL.Query()
			id, _ := strconv.ParseUint(q.Get("object_id"), 10, 64)
			m.mu.Lock()
			m.gets++
			gets := m.gets
			hook := m.afterGet
			plan, ok := m.plans[id]
			m.mu.Unlock()
			if hook != nil {
				hook(gets)
			}
			m.mu.Lock()
			plan, ok = m.plans[id]
			m.mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(plan)
		case r.Method == http.MethodPost && r.URL.Path == "/files/replicated/verified":
			var req struct {
				Object types.ObjectIntegrity `json:"object"`
			}
			json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
			m.mu.Lock()
			m.verified = append(m.verified, req.Object)
			status := m.receiptStatus
			m.mu.Unlock()
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"marked":%v}`, status == http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/files/objects/suspect":
			var req struct {
				Object types.ObjectIntegrity `json:"object"`
			}
			json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
			m.mu.Lock()
			m.suspects = append(m.suspects, req.Object)
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/files/writes/progress/begin":
			var req types.BeginWriteProgressRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(types.BeginWriteProgressResponse{Attempt: req.ExpectedAttempt + 1, AttemptToken: "wp1_fixture_attempt_token"})
		case r.Method == http.MethodPost && r.URL.Path == "/files/writes/progress":
			var req types.WriteProgress
			json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
			m.mu.Lock()
			m.progress = append(m.progress, req)
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
			w.WriteHeader(http.StatusOK)
		}
	})
}

func (m *epochFakeMaster) setPlan(id uint64, plan types.ReplicationPlan) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.plans[id] = plan
}

func (m *epochFakeMaster) snapshot() (verified, suspects []types.ObjectIntegrity, progress []types.WriteProgress, gets int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]types.ObjectIntegrity(nil), m.verified...),
		append([]types.ObjectIntegrity(nil), m.suspects...),
		append([]types.WriteProgress(nil), m.progress...), m.gets
}

func (m *epochFakeMaster) setReceiptStatus(status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.receiptStatus = status
}

// ---- fixture ----

// recoveryChunkID 返回一个落在计划写入对象 ID 区间（≥ StagingInodeBase<<8）的 ID。
func recoveryChunkID(index int) uint64 {
	return types.ChunkID(types.StagingInodeBase, index)
}

// recoveryPlan 构造一个带世代的计划写入 descriptor：integrity-write-v3 协议、
// 本节点（ID 2）在副本集合内、记录校验和。
func recoveryPlan(objID uint64, data []byte, epoch uint64) types.ReplicationPlan {
	return types.ReplicationPlan{
		Protocol:      types.WriteIntegrityProtocol,
		WriteProgress: &types.WriteProgressState{HardUntil: time.Now().Add(time.Minute)},
		Object: types.ObjectIntegrity{
			ObjectID:      objID,
			InodeID:       types.StagingInodeBase,
			Generation:    0,
			WriteEpoch:    epoch,
			Chunked:       true,
			ChunkIndex:    7,
			Size:          int64(len(data)),
			Checksum:      types.CRC32C(data),
			ChecksumKnown: true,
			Replicas:      []uint64{2},
		},
	}
}

func attachEpochMaster(t *testing.T, n *Node) *epochFakeMaster {
	t.Helper()
	m := &epochFakeMaster{plans: map[uint64]types.ReplicationPlan{}}
	srv := httptest.NewServer(m.handler())
	n.SetNodeIDForTest(2)
	n.masterURL = srv.URL
	t.Cleanup(srv.Close)
	return m
}

func putWithEpoch(t *testing.T, baseURL string, id uint64, data []byte, epoch uint64, resume bool) *http.Response {
	t.Helper()
	var body io.Reader
	if data == nil {
		body = bytes.NewReader(nil)
	} else {
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/objects/%d", baseURL, id), body)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 0 {
		req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", types.CRC32C(data)))
	}
	if epoch != 0 {
		req.Header.Set(types.WriteEpochHeader, strconv.FormatUint(epoch, 10))
	}
	if resume {
		req.Header.Set(types.WriteResumeHeader, "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func chunkObjectExists(t *testing.T, n *Node, id uint64) bool {
	t.Helper()
	_, err := os.Stat(n.objectPath(id))
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

// ---- 入站世代闸 ----

// 请求世代落后于 master 当前世代（replan 已推进）：409，不落盘、无回执。
func TestWriteEpochStaleHeaderRejected(t *testing.T) {
	data := []byte("generation payload")
	objID := recoveryChunkID(1)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 2))

	resp := putWithEpoch(t, ts.URL, objID, data, 1, false)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale epoch PUT = %d, want 409", resp.StatusCode)
	}
	if chunkObjectExists(t, n, objID) {
		t.Fatal("stale epoch write must not publish bytes")
	}
	if _, _, progress, _ := m.snapshot(); len(progress) != 0 {
		t.Fatalf("no progress expected, got %d", len(progress))
	}
}

// 无世代头打到带世代对象：拒绝（旧客户端/旧节点不得绕过世代闸）。
func TestWriteEpochMissingHeaderRejected(t *testing.T) {
	data := []byte("generation payload two")
	objID := recoveryChunkID(2)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 1))

	resp := putWithEpoch(t, ts.URL, objID, data, 0, false)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("missing epoch PUT = %d, want 409", resp.StatusCode)
	}
	if chunkObjectExists(t, n, objID) {
		t.Fatal("missing epoch write must not publish bytes")
	}
}

// 协议↔世代耦合：带世代 descriptor 走 legacy 协议 → 拒绝。
func TestWriteEpochProtocolCouplingRejectsLegacyProtocol(t *testing.T) {
	data := []byte("coupled payload")
	objID := recoveryChunkID(3)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	plan := recoveryPlan(objID, data, 1)
	plan.Protocol = types.IntegrityProtocol
	m.setPlan(objID, plan)

	resp := putWithEpoch(t, ts.URL, objID, data, 1, false)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("v1 protocol with write epoch = %d, want 409", resp.StatusCode)
	}
	if chunkObjectExists(t, n, objID) {
		t.Fatal("mismatched protocol write must not publish bytes")
	}
}

// 带世代对象必须携带世代头；世代头不得用于非计划写入对象。
func TestWriteEpochHeaderRejectedOnLegacyObject(t *testing.T) {
	data := []byte("plain legacy object")
	n, ts := newTestNode(t)
	attachEpochMaster(t, n) // legacy 对象不取 descriptor，master 不会被询问

	resp := putWithEpoch(t, ts.URL, 42, data, 1, false)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("epoch header on legacy object = %d, want 409", resp.StatusCode)
	}
	if chunkObjectExists(t, n, 42) {
		t.Fatal("legacy object must not be written with an epoch header")
	}
}

// ---- 发布前世代闸 ----

// payload 传输期间 replan 推进世代：发布被拒（409），目标文件不留残迹。
func TestWriteEpochPublishFenceBlocksReplanDuringTransfer(t *testing.T) {
	data := []byte("payload that gets replanned")
	objID := recoveryChunkID(4)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 1))

	// 第一次取 descriptor（入站闸）返回 epoch 1；之后的取 descriptor（发布闸）
	// 返回 epoch 2 —— 模拟 payload 传输期间 master 完成 replan。
	var once sync.Once
	m.mu.Lock()
	m.afterGet = func(gets int) {
		if gets >= 2 {
			once.Do(func() {
				m.setPlan(objID, recoveryPlan(objID, data, 2))
			})
		}
	}
	m.mu.Unlock()

	resp := putWithEpoch(t, ts.URL, objID, data, 1, false)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("replanned write = %d, want 409", resp.StatusCode)
	}
	if chunkObjectExists(t, n, objID) {
		t.Fatal("superseded write must not publish bytes")
	}
	if _, suspects, _, _ := m.snapshot(); len(suspects) != 0 {
		t.Fatalf("publish fence must not report suspect: %v", suspects)
	}
}

// ---- 回执被拒 ----

// master 拒收回执（世代过期/副本被改派）：PUT 显式 409 而非 201，且不重试。
func TestWriteEpochReceiptRejectionSurfaces(t *testing.T) {
	data := []byte("receipt rejection payload")
	objID := recoveryChunkID(5)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 1))
	m.setReceiptStatus(http.StatusConflict)

	resp := putWithEpoch(t, ts.URL, objID, data, 1, false)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("rejected receipt PUT = %d, want 409 (not 201)", resp.StatusCode)
	}
	if verified, _, _, _ := m.snapshot(); len(verified) != 1 {
		t.Fatalf("receipt must not be retried after a 409: %d receipts", len(verified))
	}
	if !chunkObjectExists(t, n, objID) {
		t.Fatal("bytes were stored and verified; only the receipt was refused")
	}
}

// 正常带世代写入：201 + 一条带世代的 verified 回执。
func TestWriteEpochHappyPath(t *testing.T) {
	data := []byte("happy generation payload")
	objID := recoveryChunkID(6)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 1))

	resp := putWithEpoch(t, ts.URL, objID, data, 1, false)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("generation PUT = %d, want 201", resp.StatusCode)
	}
	verified, _, progress, _ := m.snapshot()
	if len(verified) != 1 {
		t.Fatalf("verified receipts = %d, want 1", len(verified))
	}
	if verified[0].WriteEpoch != 1 {
		t.Fatalf("receipt write epoch = %d, want 1", verified[0].WriteEpoch)
	}
	if !chunkObjectExists(t, n, objID) {
		t.Fatal("object must be published")
	}
	if len(progress) == 0 {
		t.Fatal("generation write must report payload progress")
	}
	for _, p := range progress {
		if p.Epoch != 1 || p.Bytes <= 0 {
			t.Fatalf("progress epoch/bytes = %+v", p)
		}
	}
}

// ---- resume：零长度重确认 ----

// resume 命中已落盘对象：200 + 带世代回执，不重新上传 payload。
func TestWriteResumeReconfirmsStoredObject(t *testing.T) {
	data := []byte("resume payload")
	objID := recoveryChunkID(7)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 1))
	crc := types.CRC32C(data)
	if _, _, err := n.storeVerifiedObject(objID, bytes.NewReader(data), &crc, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	before, _, _, _ := m.snapshot()
	if len(before) != 0 {
		t.Fatalf("no receipts expected before resume, got %d", len(before))
	}

	resp := putWithEpoch(t, ts.URL, objID, nil, 1, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resume = %d, want 200", resp.StatusCode)
	}
	verified, _, _, _ := m.snapshot()
	if len(verified) != 1 {
		t.Fatalf("resume receipts = %d, want 1", len(verified))
	}
	if verified[0].WriteEpoch != 1 || verified[0].ObjectID != objID {
		t.Fatalf("resume receipt = %+v", verified[0])
	}
}

// 本地没有对象 → 404，客户端据此回退真实 PUT。
func TestWriteResumeMissingObjectReturns404(t *testing.T) {
	data := []byte("never stored")
	objID := recoveryChunkID(8)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 1))

	resp := putWithEpoch(t, ts.URL, objID, nil, 1, true)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("resume without stored object = %d, want 404", resp.StatusCode)
	}
	if _, verified, _, _ := m.snapshot(); len(verified) != 0 {
		t.Fatalf("missing object must not be confirmed: %v", verified)
	}
}

// 本地字节与权威元数据不符 → 409 且按 suspect 上报，绝不确认坏字节。
func TestWriteResumeRejectsCorruptStoredBytes(t *testing.T) {
	data := []byte("resume corrupt payload")
	objID := recoveryChunkID(9)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 1))
	crc := types.CRC32C(data)
	if _, _, err := n.storeVerifiedObject(objID, bytes.NewReader(data), &crc, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	// 同长度坏内容：只能靠 CRC 发现。
	if err := os.WriteFile(n.objectPath(objID), bytes.Repeat([]byte{0x5a}, len(data)), 0o644); err != nil {
		t.Fatal(err)
	}

	resp := putWithEpoch(t, ts.URL, objID, nil, 1, true)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("resume with corrupt bytes = %d, want 409", resp.StatusCode)
	}
	_, suspects, _, _ := m.snapshot()
	if len(suspects) != 1 || suspects[0].ObjectID != objID {
		t.Fatalf("corrupt stored bytes must be reported suspect: %v", suspects)
	}
	if verified, _, _, _ := m.snapshot(); len(verified) != 0 {
		t.Fatalf("corrupt bytes must not be confirmed: %v", verified)
	}
}

// 世代不匹配 / 携带 payload / 缺世代头 / 非计划写入对象：全部拒绝。
func TestWriteResumeGuards(t *testing.T) {
	data := []byte("resume guard payload")
	objID := recoveryChunkID(10)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 1))
	crc := types.CRC32C(data)
	if _, _, err := n.storeVerifiedObject(objID, bytes.NewReader(data), &crc, int64(len(data))); err != nil {
		t.Fatal(err)
	}

	t.Run("epoch mismatch", func(t *testing.T) {
		resp := putWithEpoch(t, ts.URL, objID, nil, 2, true)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("resume with wrong epoch = %d, want 409", resp.StatusCode)
		}
	})
	t.Run("carries payload", func(t *testing.T) {
		resp := putWithEpoch(t, ts.URL, objID, data, 1, true)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("resume with payload = %d, want 400", resp.StatusCode)
		}
	})
	t.Run("missing epoch", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/objects/%d", ts.URL, objID), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(types.WriteResumeHeader, "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("resume without epoch = %d, want 400", resp.StatusCode)
		}
	})
	t.Run("legacy object", func(t *testing.T) {
		resp := putWithEpoch(t, ts.URL, 43, nil, 1, true)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("resume on legacy object = %d, want 409", resp.StatusCode)
		}
	})
	if _, verified, _, _ := m.snapshot(); len(verified) != 0 {
		t.Fatalf("guarded resumes must not confirm: %v", verified)
	}
}

// ---- node→node relay 世代闸 ----

// 旧世代 relay 推送在 replan 后被目标节点拒绝。
func TestReplicateEpochStaleRejected(t *testing.T) {
	data := []byte("relay payload")
	objID := recoveryChunkID(11)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 2))

	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/replicate/%d", ts.URL, objID), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(types.WriteEpochHeader, "1")
	req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", types.CRC32C(data)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale relay = %d, want 409", resp.StatusCode)
	}
	if chunkObjectExists(t, n, objID) {
		t.Fatal("stale relay must not publish bytes")
	}
}

// 匹配世代的 relay 推送正常落盘并回执。
func TestReplicateEpochHappyPath(t *testing.T) {
	data := []byte("relay happy payload")
	objID := recoveryChunkID(12)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 1))

	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/replicate/%d", ts.URL, objID), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(types.WriteEpochHeader, "1")
	req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", types.CRC32C(data)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("matching relay = %d, want 201", resp.StatusCode)
	}
	if !chunkObjectExists(t, n, objID) {
		t.Fatal("relay payload must be published")
	}
	verified, _, _, _ := m.snapshot()
	if len(verified) != 1 || verified[0].WriteEpoch != 1 {
		t.Fatalf("relay receipt = %+v", verified)
	}
}

// ---- legacy 路径不回归 ----

// 无世代头的 legacy 写入：201，无进度上报（master 不接受无世代进度）。
func TestLegacyWriteUnchanged(t *testing.T) {
	data := []byte("legacy object")
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)

	if code := putObjectTo(t, ts.URL, 42, data, types.CRC32C(data)); code != http.StatusCreated {
		t.Fatalf("legacy PUT = %d, want 201", code)
	}
	if _, _, progress, _ := m.snapshot(); len(progress) != 0 {
		t.Fatalf("legacy write must not report progress: %v", progress)
	}
	if !chunkObjectExists(t, n, 42) {
		t.Fatal("legacy object must be published")
	}
}

// ---- 进度上报语义 ----

// 进度只在实际字节前进时上报：无空报；同世代内字节单调。
func TestWriteProgressOnlyReportsAdvance(t *testing.T) {
	data := bytes.Repeat([]byte{0x33}, 4096)
	objID := recoveryChunkID(13)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 1))

	resp := putWithEpoch(t, ts.URL, objID, data, 1, false)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("progress PUT = %d, want 201", resp.StatusCode)
	}
	_, _, progress, _ := m.snapshot()
	if len(progress) == 0 {
		t.Fatal("expected at least the final progress report")
	}
	for i, p := range progress {
		if p.Bytes <= 0 {
			t.Fatalf("progress[%d] reports no bytes: %+v", i, p)
		}
		if i > 0 && p.Bytes < progress[i-1].Bytes {
			t.Fatalf("progress went backwards: %d -> %d", progress[i-1].Bytes, p.Bytes)
		}
	}
	if last := progress[len(progress)-1]; last.Bytes != int64(len(data)) {
		t.Fatalf("final progress bytes = %d, want %d", last.Bytes, len(data))
	}
}

// 进度上报器：零世代直接禁用；无字节时不产生请求。
func TestWriteProgressReporterDisabledWithoutEpoch(t *testing.T) {
	n, _ := newTestNode(t)
	attachEpochMaster(t, n)
	if r, err := n.beginWriteProgress(t.Context(), types.ReplicationPlan{}, ""); err != nil || r != nil {
		t.Fatal("legacy write must not start a progress reporter")
	}
	r, err := n.beginWriteProgress(t.Context(), recoveryPlan(2, []byte("data"), 1), "")
	if err != nil || r == nil {
		t.Fatalf("generation write must start a progress reporter: %v", err)
	}
	// 只做一次空读：无字节 → 不上报。
	if _, err := io.CopyN(io.Discard, &progressCountingReader{src: bytes.NewReader(nil), counter: r}, 0); err != nil {
		t.Fatal(err)
	}
	r.Finish()
	if r.bytes.Load() != 0 {
		t.Fatalf("empty read must not count bytes: %d", r.bytes.Load())
	}
}

// ---- 世代推进后旧世代重放不得确认既有字节 ----

// 容量不足触发的 identical replay 路径同样要过世代闸。
func TestWriteReplayRespectsEpochFence(t *testing.T) {
	data := []byte("replay fence payload")
	objID := recoveryChunkID(14)
	// 容量恰好等于对象大小：第二次写入必然触发 capacity-exceeded 的 replay 分支。
	n := New(filepath.Join(t.TempDir(), "data"), "http://master.invalid", "127.0.0.1:9000", int64(len(data)))
	crc := types.CRC32C(data)
	if _, _, err := n.storeVerifiedObject(objID, bytes.NewReader(data), &crc, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	// 容量已满 → storeVerifiedObject 走 verifyStoredReplay 分支。
	m := attachEpochMaster(t, n)
	m.setPlan(objID, recoveryPlan(objID, data, 2))

	replayed := false
	fence := publishFence(func() error {
		replayed = true
		return fmt.Errorf("%w: epoch moved", errWriteEpochSuperseded)
	})
	if _, _, err := n.storeVerifiedObjectFenced(objID, bytes.NewReader(data), &crc, int64(len(data)), fence); err == nil {
		t.Fatal("replay must be refused when the generation moved on")
	}
	if !replayed {
		t.Fatal("replay path did not run the publish fence")
	}
}
