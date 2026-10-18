package master

// integrity_e2e_test.go —— integrity-v1 端到端集成测试（独立第三复核，只新增本文件）。
//
// 契约（与 master/meta/integrity.go、master/integrity.go、node/integrity.go 对齐）：
//   - 好数据 push/replicate/pull 后在全部副本"内容校验通过"才记 Done（verified receipt
//     事务，HTTP 200 本身永远不是 Done）；物理落盘与元数据可互相对照。
//   - 损坏的源不发送：源端 verifiedSource 重读自己的盘 CRC 不符 → 拒绝推送并上报
//     /files/objects/suspect；拉取端 storeVerifiedObject 以 master 权威 size+CRC 校验，
//     坏字节永不落盘，且 pull 校验失败上报 source suspect。
//   - 未分配节点 / 伪造 header 的 payload 必须按 master 拒绝：node 侧 /replicate 忽略
//     调用方 header，只认 master 下发的 size+CRC；master 侧 receipt 校验副本集成员资格。
//   - ChunkSuspect 去 Done 保物理：读端 suspect 报告只挪集合 + bump epoch，绝不 DELETE
//     物理对象（唯一副本也不删）。
//   - scanner 的 presence（Range 200）不能复活 Suspect：checksum-known 对象必须由节点
//     重读磁盘并通过 CRC 后的 verified receipt 才能恢复 Done。
//   - 旧 /files/replicated 与 /files/replica-targets 对 checksum-known 对象一律 426，
//     不能作为绕过 verified receipt 的恢复通道。
//   - 旧 epoch / 旧 generation / 旧 chunkID / 非副本节点的报告一律 no-op（409 或
//     marked:false），绝不污染当前版本的 Done/Suspect/epoch。
//
// 真实 bbolt + 真实 atollnode（httptest 承载），全部等待带超时；不连真集群。
// helper 一律 ie 前缀，自包含，不引用 small_publish_test.go 的 sp* 夹具（避免与其并行
// 修改冲突），也不修改它。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"atoll/master/meta"
	atollnode "atoll/node"
	"atoll/pkg/types"
)

var ieHTTP = &http.Client{Timeout: 15 * time.Second}

// ---- 环境 ----

type ieStack struct {
	t         *testing.T
	store     *meta.Store
	srv       *Server
	Master    string
	nodes     []*ieNode
	nextInode int
}

type ieNode struct {
	Base string
	Addr string // 注册进 master 的直连地址（host:port）
	node *atollnode.Node
	Info types.NodeInfo
}

func ieNewStack(t *testing.T) *ieStack {
	t.Helper()
	store, err := meta.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("meta.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	srv := NewServer(store, time.Hour)
	srv.SetCommitWait(200 * time.Millisecond)
	srv.SetHealthProbe(func(string) bool { return true })
	return &ieStack{t: t, store: store, srv: srv}
}

func (s *ieStack) startMaster() {
	s.t.Helper()
	ts := httptest.NewServer(s.srv.Handler())
	s.t.Cleanup(ts.Close)
	s.Master = ts.URL
}

func (s *ieStack) startNode() *ieNode {
	s.t.Helper()
	n := atollnode.New(filepath.Join(s.t.TempDir(), "nodedata"), s.Master, "", 1<<30)
	ts := httptest.NewServer(n.Handler())
	s.t.Cleanup(ts.Close)
	nd, err := s.store.RegisterNode(ts.Listener.Addr().String(), 1<<30)
	if err != nil {
		s.t.Fatalf("register node: %v", err)
	}
	n.SetNodeIDForTest(nd.ID)
	node := &ieNode{Base: ts.URL, Addr: nd.Addr, node: n, Info: nd}
	s.nodes = append(s.nodes, node)
	return node
}

// ---- HTTP 工具 ----

func ieDo(t *testing.T, method, rawURL string, body []byte, hdrs map[string]string) (int, []byte) {
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
	resp, err := ieHTTP.Do(req)
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

func iePostJSON(t *testing.T, rawURL string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return ieDo(t, http.MethodPost, rawURL, raw, map[string]string{"Content-Type": "application/json"})
}

func ieGetObject(t *testing.T, nd *ieNode, id uint64) (int, []byte) {
	t.Helper()
	return ieDo(t, http.MethodGet, fmt.Sprintf("%s/objects/%d", nd.Base, id), nil, nil)
}

// ieCorruptObject 直接改写节点磁盘上的物理对象（模拟位腐/篡改），返回是否命中文件。
func ieCorruptObject(t *testing.T, nd *ieNode, id uint64, payload []byte) bool {
	t.Helper()
	path := nd.node.DataDirForTest()
	p := filepath.Join(path, "objects", fmt.Sprintf("%02x", id%256), fmt.Sprintf("%d", id))
	if _, err := os.Stat(p); err != nil {
		return false
	}
	if err := os.WriteFile(p, payload, 0o644); err != nil {
		t.Fatalf("corrupt object %d on %s: %v", id, nd.Addr, err)
	}
	return true
}

func ieNodeHasObject(t *testing.T, nd *ieNode, id uint64) bool {
	t.Helper()
	p := filepath.Join(nd.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", id%256), fmt.Sprintf("%d", id))
	_, err := os.Stat(p)
	return err == nil
}

// ieWaitCond 轮询直到 cond 为真或超时。
func ieWaitCond(t *testing.T, what string, timeout time.Duration, cond func() bool) {
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

// ieWaitDone 轮询对象完整性描述，直到 Done 恰好为 want 个节点且 Suspect 为空。
func ieWaitDone(t *testing.T, s *ieStack, objectID uint64, want int) types.ObjectIntegrity {
	t.Helper()
	var out types.ObjectIntegrity
	ieWaitCond(t, fmt.Sprintf("object %d Done=%d", objectID, want), 15*time.Second, func() bool {
		d, err := s.store.ObjectIntegrity(objectID)
		if err != nil {
			return false
		}
		out = d
		return len(d.Done) == want && len(d.Suspect) == 0
	})
	return out
}

// iePublishSmall 走 /files/small 发布一个小文件（features 头必带），返回 inode。
func iePublishSmall(t *testing.T, s *ieStack, path string, body []byte, replicas int, overwrite bool) types.Inode {
	t.Helper()
	s.nextInode++
	q := fmt.Sprintf("%s/files/small?path=%s&overwrite=%t&replicas=%d&op_id=ie-op-%d",
		s.Master, path, overwrite, replicas, s.nextInode)
	status, raw := ieDo(t, http.MethodPost, q, body, map[string]string{
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

// ieVerifiedBody 构造 verified receipt 请求体（对象描述快照 + nodeID）。
func ieVerifiedBody(d types.ObjectIntegrity, nodeID uint64) map[string]any {
	return map[string]any{"object": d, "node_id": nodeID}
}

// ieIntegrityEqual 比较关心的元数据字段（epoch/Done/Suspect）是否变化。
func ieIntegrityTag(d types.ObjectIntegrity) string {
	return fmt.Sprintf("epoch=%d done=%v suspect=%v replicas=%v gen=%d",
		d.IntegrityEpoch, d.Done, d.Suspect, d.Replicas, d.Generation)
}

// ---- 1. 好数据 push/replicate：全部副本 verified 落盘 ----

func TestIntegrityE2ESmallFileReplicatesVerifiedToAllNodes(t *testing.T) {
	s := ieNewStack(t)
	s.startMaster()
	a, b, c := s.startNode(), s.startNode(), s.startNode()

	body := []byte("integrity e2e happy path payload 0123456789")
	in := iePublishSmall(t, s, "/happy.txt", body, 3, false)
	d := ieWaitDone(t, s, in.ObjID, 3)

	if !d.ChecksumKnown || d.Checksum != types.CRC32C(body) {
		t.Errorf("metadata checksum known=%v %08x, want known %08x", d.ChecksumKnown, d.Checksum, types.CRC32C(body))
	}
	if d.Size != int64(len(body)) {
		t.Errorf("metadata size = %d, want %d", d.Size, len(body))
	}
	if len(d.Replicas) != 3 {
		t.Errorf("replicas = %v, want 3 assigned nodes", d.Replicas)
	}
	// 三个节点的物理对象都必须与原始字节一致（不是仅 master 认为 Done）。
	for _, nd := range []*ieNode{a, b, c} {
		status, got := ieGetObject(t, nd, in.ObjID)
		if status != http.StatusOK || !bytes.Equal(got, body) {
			t.Errorf("node %s object: status %d content match %v", nd.Addr, status, bytes.Equal(got, body))
		}
	}
}

// ---- 2. /verify 用节点实际重读的 CRC，HTTP 可达(200 presence)本身不是 Done ----

func TestIntegrityE2EVerifyUsesNodeActualCRCNotPresence(t *testing.T) {
	s := ieNewStack(t)
	s.startMaster()
	a := s.startNode()

	body := []byte("verify must re-read the physical copy from disk")
	in := iePublishSmall(t, s, "/verify.txt", body, 1, false)
	d := ieWaitDone(t, s, in.ObjID, 1)

	// 位腐：同长度坏字节。
	corrupt := bytes.Clone(body)
	corrupt[0] ^= 0xFF
	if !ieCorruptObject(t, a, in.ObjID, corrupt) {
		t.Fatalf("primary object file not found on disk")
	}

	// 节点自校验（scanner verifyReplicaAt 打的端点）：重读磁盘 CRC 不符 → 拒绝并上报。
	status, _ := iePostJSON(t, fmt.Sprintf("%s/verify/%d", a.Base, in.ObjID), nil)
	if status != http.StatusConflict {
		t.Errorf("verify with corrupt disk: status %d, want 409", status)
	}
	var suspect types.ObjectIntegrity
	ieWaitCond(t, "suspect marked from node self-report", 5*time.Second, func() bool {
		cur, err := s.store.ObjectIntegrity(in.ObjID)
		if err != nil {
			return false
		}
		suspect = cur
		return len(cur.Suspect) == 1 && len(cur.Done) == 0
	})
	if suspect.IntegrityEpoch != d.IntegrityEpoch+1 {
		t.Errorf("epoch = %d, want %d (one bump on suspect)", suspect.IntegrityEpoch, d.IntegrityEpoch+1)
	}
	// 物理副本保留（suspect 永不 DELETE），即便内容已坏。
	if got, err := os.Stat(filepath.Join(a.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", in.ObjID%256), fmt.Sprintf("%d", in.ObjID))); err != nil || got == nil {
		t.Errorf("suspect physical copy must be preserved, stat err=%v", err)
	}

	// presence 仍在（GET 200）：再次 verify 依旧 409，epoch 不再额外 bump。
	if status, _ := ieGetObject(t, a, in.ObjID); status != http.StatusOK {
		t.Errorf("presence GET after suspect: status %d, want 200 (physical kept)", status)
	}
	if status, _ := iePostJSON(t, fmt.Sprintf("%s/verify/%d", a.Base, in.ObjID), nil); status != http.StatusConflict {
		t.Errorf("repeat verify: status %d, want 409", status)
	}
	cur, err := s.store.ObjectIntegrity(in.ObjID)
	if err != nil {
		t.Fatalf("object integrity: %v", err)
	}
	if cur.IntegrityEpoch != suspect.IntegrityEpoch {
		t.Errorf("repeat suspect bumped epoch again: %d → %d", suspect.IntegrityEpoch, cur.IntegrityEpoch)
	}
	// 长度-only presence receipt 无法复活 checksum-known 对象。
	present := map[string]any{
		"object": map[string]any{
			"object_id": cur.ObjectID, "inode_id": cur.InodeID, "generation": cur.Generation,
			"integrity_epoch": cur.IntegrityEpoch, "size": cur.Size,
			"checksum": 0, "checksum_known": false,
		},
		"node_id": a.Info.ID,
	}
	if status, _ := iePostJSON(t, s.Master+"/files/replicated/present", present); status == http.StatusOK {
		t.Errorf("presence receipt revived a checksum-known object")
	}
	if cur2, _ := s.store.ObjectIntegrity(in.ObjID); len(cur2.Done) != 0 {
		t.Errorf("presence receipt moved object to Done: %v", cur2.Done)
	}
}

// ---- 3. 损坏源不发送 + pull 校验失败上报 source suspect + 正确 repair 恢复 ----

func TestIntegrityE2ECorruptSourceNotSpreadAndRepairRestores(t *testing.T) {
	s := ieNewStack(t)
	s.startMaster()
	a, b, c := s.startNode(), s.startNode(), s.startNode()
	_ = b // b 是修复阶段唯一健康源，由 master 扫描器自行选择，测试代码不直接引用。

	body := []byte("corrupt source must never spread its bytes to any replica")
	in := iePublishSmall(t, s, "/spread.txt", body, 3, false)
	before := ieWaitDone(t, s, in.ObjID, 3)
	wantCRC := types.CRC32C(body)

	// C 丢数据（物理丢失）：显式按版本快照撤 C 的 Done（scanner/GC 对账类角色报告
	// physical suspect），让修复源集合只含健康副本。Done 槽本身不会被自动 scrub
	// （"心跳活+Done 即可信"的已知边界，见审查报告），本测试不依赖该缺口。
	cPath := filepath.Join(c.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", in.ObjID%256), fmt.Sprintf("%d", in.ObjID))
	if err := os.Remove(cPath); err != nil {
		t.Fatalf("remove C copy: %v", err)
	}
	if status, raw := iePostJSON(t, s.Master+"/files/objects/suspect", map[string]any{"object": before, "node_id": c.Info.ID}); status != http.StatusOK {
		t.Fatalf("withdraw C via physical suspect: status %d body %s", status, string(raw))
	}

	// A 位腐；C 从 A pull：坏字节必须被 master 权威 CRC 拒之门外，并且上报 A suspect。
	corrupt := bytes.Clone(body)
	corrupt[len(corrupt)-1] ^= 0xFF
	ieCorruptObject(t, a, in.ObjID, corrupt)
	pullReq := map[string]any{"inode_id": in.ObjID, "source_addr": a.Addr, "checksum": wantCRC}
	if status, _ := iePostJSON(t, fmt.Sprintf("%s/pull", c.Base), pullReq); status != http.StatusAccepted {
		t.Errorf("pull trigger: status %d, want 202", status)
	}
	ieWaitCond(t, "source A reported suspect by puller", 10*time.Second, func() bool {
		cur, err := s.store.ObjectIntegrity(in.ObjID)
		if err != nil {
			return false
		}
		return len(cur.Suspect) == 2 // A（puller 上报）+ C（显式撤 Done）
	})
	if ieNodeHasObject(t, c, in.ObjID) {
		t.Errorf("corrupt source bytes landed on the pulling node")
	}
	if status, got := ieGetObject(t, c, in.ObjID); status != http.StatusNotFound {
		t.Errorf("pulling node object: status %d body %q, want 404 (nothing stored)", status, string(got))
	}
	if !ieNodeHasObject(t, a, in.ObjID) {
		t.Errorf("suspect report must not delete the source's physical copy")
	}
	afterSuspects, _ := s.store.ObjectIntegrity(in.ObjID)
	if afterSuspects.IntegrityEpoch != before.IntegrityEpoch+2 {
		t.Errorf("epoch = %d, want before+%d (one bump per suspect report)",
			afterSuspects.IntegrityEpoch, before.IntegrityEpoch+2)
	}

	// scanner 修复：A、C 都从唯一健康源 B 重拉 → 内容恢复 → verified receipt 清 Suspect。
	// 源集合确定（B 是唯一 Done∧非 suspect），短 repairIntv 循环扫描贴近生产语义。
	sc := NewScanner(s.store, time.Hour, 10*time.Millisecond, time.Hour)
	ieWaitCond(t, "A and C repaired from healthy source B", 10*time.Second, func() bool {
		sc.RepairScanOnce()
		cur, err := s.store.ObjectIntegrity(in.ObjID)
		return err == nil && len(cur.Done) == 3 && len(cur.Suspect) == 0
	})
	// 修复必须落在物理上：A、C 重读都等于原始字节。
	for _, nd := range []*ieNode{a, c} {
		status, got := ieGetObject(t, nd, in.ObjID)
		if status != http.StatusOK || !bytes.Equal(got, body) {
			t.Errorf("node %s content after repair: status %d match %v", nd.Addr, status, bytes.Equal(got, body))
		}
	}
	// 修复不 bump epoch；再扫一轮必须幂等。
	cur, _ := s.store.ObjectIntegrity(in.ObjID)
	sc.RepairScanOnce()
	cur2, _ := s.store.ObjectIntegrity(in.ObjID)
	if ieIntegrityTag(cur) != ieIntegrityTag(cur2) {
		t.Errorf("idempotent scan changed metadata: %s → %s", ieIntegrityTag(cur), ieIntegrityTag(cur2))
	}
}

// ---- 4. ChunkSuspect 去 Done 保物理；presence 不可复活；正确 repair 后恢复 ----

// ieChunkFixture 建一个分块文件：staging + 单块（声明 CRC）+ 双方落盘 + commit。
func ieChunkFixture(t *testing.T, s *ieStack, name string, body []byte, a, b *ieNode) (fileInode types.Inode, chunkID uint64) {
	t.Helper()
	st, err := s.store.CreateStagingFile(1)
	if err != nil {
		t.Fatalf("CreateStagingFile: %v", err)
	}
	crc := types.CRC32C(body)
	ch, err := s.store.AssignChunk(st.ID, 0, int64(len(body)), []uint64{a.Info.ID, b.Info.ID}, crc, true)
	if err != nil {
		t.Fatalf("AssignChunk: %v", err)
	}
	chunkID = types.ChunkObjID(ch, st.ID)
	status, raw := ieDo(t, http.MethodPut, fmt.Sprintf("%s/objects/%d", a.Base, chunkID), body,
		map[string]string{"X-Atoll-Crc32c": fmt.Sprintf("%08x", crc)})
	if status != http.StatusCreated {
		t.Fatalf("primary chunk PUT: status %d body %s", status, string(raw))
	}
	ieWaitDone(t, s, chunkID, 2)
	fileInode, _, _, err2 := s.store.CommitStagingFile(st.ID, name, int64(len(body)))
	if err2 != nil {
		t.Fatalf("CommitStagingFile: %v", err2)
	}
	return fileInode, chunkID
}

func TestIntegrityE2EChunkSuspectKeepsPhysicalAndRepairRestores(t *testing.T) {
	s := ieNewStack(t)
	s.startMaster()
	a, b := s.startNode(), s.startNode()

	body := []byte("chunk payload that the reader will report as suspect on node B")
	in, chunkID := ieChunkFixture(t, s, "chunked.bin", body, a, b)
	before, err := s.store.ObjectIntegrity(chunkID)
	if err != nil {
		t.Fatalf("chunk integrity: %v", err)
	}

	// 读端 ChunkSuspect（完整身份绑定）：B 去 Done 入 Suspect，epoch+1，物理保留。
	report := map[string]any{
		"inode_id": in.ID, "generation": in.Generation, "chunk_index": 0,
		"object_id": chunkID, "node_id": b.Info.ID,
		"size": int64(len(body)), "checksum": types.CRC32C(body),
	}
	if status, raw := iePostJSON(t, s.Master+"/files/chunks/suspect", report); status != http.StatusOK {
		t.Fatalf("chunk suspect: status %d body %s", status, string(raw))
	}
	marked, err := s.store.ObjectIntegrity(chunkID)
	if err != nil {
		t.Fatalf("chunk integrity after suspect: %v", err)
	}
	if len(marked.Done) != 1 || marked.Done[0] != a.Info.ID || len(marked.Suspect) != 1 || marked.Suspect[0] != b.Info.ID {
		t.Errorf("after chunk suspect: done=%v suspect=%v, want B moved only", marked.Done, marked.Suspect)
	}
	if marked.IntegrityEpoch != before.IntegrityEpoch+1 {
		t.Errorf("epoch = %d, want %d", marked.IntegrityEpoch, before.IntegrityEpoch+1)
	}
	if status, got := ieGetObject(t, b, chunkID); status != http.StatusOK || !bytes.Equal(got, body) {
		t.Errorf("B physical copy after suspect: status %d match %v — suspect must keep the object",
			status, bytes.Equal(got, body))
	}

	// B 的盘随后真坏掉；scanner 修复：从 A 重拉好内容 → verified receipt 清 Suspect。
	corrupt := bytes.Clone(body)
	corrupt[2] ^= 0xFF
	ieCorruptObject(t, b, chunkID, corrupt)
	sc := NewScanner(s.store, time.Hour, time.Hour, time.Hour)
	sc.RepairScanOnce()
	ieWaitCond(t, "B chunk repaired", 10*time.Second, func() bool {
		cur, err := s.store.ObjectIntegrity(chunkID)
		return err == nil && len(cur.Done) == 2 && len(cur.Suspect) == 0
	})
	status, got := ieGetObject(t, b, chunkID)
	if status != http.StatusOK || !bytes.Equal(got, body) {
		t.Errorf("B content after repair: status %d match %v", status, bytes.Equal(got, body))
	}
	repaired, _ := s.store.ObjectIntegrity(chunkID)
	if repaired.IntegrityEpoch != marked.IntegrityEpoch {
		t.Errorf("repair must not bump epoch: %d → %d", marked.IntegrityEpoch, repaired.IntegrityEpoch)
	}
	sc.RepairScanOnce() // 幂等
	after, _ := s.store.ObjectIntegrity(chunkID)
	if ieIntegrityTag(repaired) != ieIntegrityTag(after) {
		t.Errorf("idempotent scan changed metadata: %s → %s", ieIntegrityTag(repaired), ieIntegrityTag(after))
	}
}

func TestIntegrityE2ESuspectNotRevivedByPresenceWithoutSource(t *testing.T) {
	s := ieNewStack(t)
	s.startMaster()
	a, b := s.startNode(), s.startNode()

	body := []byte("single-replica chunk: presence must not revive a suspect copy")
	st, err := s.store.CreateStagingFile(1)
	if err != nil {
		t.Fatalf("CreateStagingFile: %v", err)
	}
	crc := types.CRC32C(body)
	ch, err := s.store.AssignChunk(st.ID, 0, int64(len(body)), []uint64{b.Info.ID}, crc, true)
	if err != nil {
		t.Fatalf("AssignChunk: %v", err)
	}
	chunkID := types.ChunkObjID(ch, st.ID)
	if status, _ := ieDo(t, http.MethodPut, fmt.Sprintf("%s/objects/%d", b.Base, chunkID), body,
		map[string]string{"X-Atoll-Crc32c": fmt.Sprintf("%08x", crc)}); status != http.StatusCreated {
		t.Fatalf("chunk PUT: status %d", status)
	}
	ieWaitDone(t, s, chunkID, 1)

	// B 自报 suspect（读端路径等价）：唯一副本，无健康源。
	corrupt := bytes.Clone(body)
	corrupt[0] ^= 0x55
	ieCorruptObject(t, b, chunkID, corrupt)
	if status, _ := iePostJSON(t, fmt.Sprintf("%s/verify/%d", b.Base, chunkID), nil); status != http.StatusConflict {
		t.Errorf("verify corrupt single replica: status %d, want 409", status)
	}
	var suspect types.ObjectIntegrity
	ieWaitCond(t, "single-replica suspect", 5*time.Second, func() bool {
		cur, err := s.store.ObjectIntegrity(chunkID)
		if err != nil {
			return false
		}
		suspect = cur
		return len(cur.Suspect) == 1 && len(cur.Done) == 0
	})

	// scanner 扫描：对象 presence 在（GET 200），但无可用源 → 不得记 Done、不得删物理。
	sc := NewScanner(s.store, time.Hour, time.Hour, time.Hour)
	sc.RepairScanOnce()
	time.Sleep(200 * time.Millisecond) // 给异步 verify/receipt 留出"如果会复活"的时间窗
	cur, err2 := s.store.ObjectIntegrity(chunkID)
	if err2 != nil {
		t.Fatalf("chunk integrity: %v", err2)
	}
	if len(cur.Done) != 0 || len(cur.Suspect) != 1 || cur.Suspect[0] != b.Info.ID {
		t.Errorf("presence revived suspect: done=%v suspect=%v", cur.Done, cur.Suspect)
	}
	if cur.IntegrityEpoch != suspect.IntegrityEpoch {
		t.Errorf("scan bumped epoch on a no-source suspect: %d → %d", suspect.IntegrityEpoch, cur.IntegrityEpoch)
	}
	if !ieNodeHasObject(t, b, chunkID) {
		t.Errorf("sole suspect replica must not be DELETEd")
	}
	if status, got := ieGetObject(t, b, chunkID); status != http.StatusOK || bytes.Equal(got, body) {
		t.Errorf("physical copy status %d match %v, want 200 with corrupt content kept", status, bytes.Equal(got, body))
	}
	_ = a // 双节点集群：A 仅用于证明"无其他副本"。
}

// ---- 5. 旧端点不能绕过 verified receipt 恢复/复活 ----

func TestIntegrityE2ELegacyEndpointsCannotRestoreSuspect(t *testing.T) {
	s := ieNewStack(t)
	s.startMaster()
	a, b := s.startNode(), s.startNode()

	body := []byte("legacy endpoints must not bypass verified receipts")
	in, chunkID := ieChunkFixture(t, s, "legacy.txt", body, a, b)

	// B 被 suspect。
	report := map[string]any{
		"inode_id": in.ID, "generation": in.Generation, "chunk_index": 0,
		"object_id": chunkID, "node_id": b.Info.ID,
		"size": int64(len(body)), "checksum": types.CRC32C(body),
	}
	if status, _ := iePostJSON(t, s.Master+"/files/chunks/suspect", report); status != http.StatusOK {
		t.Fatalf("chunk suspect: status %d", status)
	}
	suspect, _ := s.store.ObjectIntegrity(chunkID)

	// 旧 /files/replicated（无 verified receipt）→ 426，不能把 B 刷回 Done。
	if status, _ := iePostJSON(t, s.Master+"/files/replicated", map[string]any{"inode_id": chunkID, "node_id": b.Info.ID}); status != http.StatusUpgradeRequired {
		t.Errorf("legacy /files/replicated: status %d, want 426", status)
	}
	// 旧 /files/replica-targets（checksum-known 对象）→ 426。
	if status, _ := ieDo(t, http.MethodGet, fmt.Sprintf("%s/files/replica-targets?inode_id=%d&node_id=%d", s.Master, chunkID, a.Info.ID), nil, nil); status != http.StatusUpgradeRequired {
		t.Errorf("legacy /files/replica-targets: status %d, want 426", status)
	}
	cur, _ := s.store.ObjectIntegrity(chunkID)
	if ieIntegrityTag(cur) != ieIntegrityTag(suspect) {
		t.Errorf("legacy endpoints mutated integrity state: %s → %s", ieIntegrityTag(suspect), ieIntegrityTag(cur))
	}

	// 旧 epoch 的 verified receipt → 409（CAS 拒绝），Suspect 保持。
	stale := map[string]any{"object": map[string]any{
		"object_id": suspect.ObjectID, "inode_id": suspect.InodeID, "generation": suspect.Generation,
		"integrity_epoch": suspect.IntegrityEpoch - 1, "chunked": true, "chunk_index": 0,
		"size": suspect.Size, "checksum": suspect.Checksum, "checksum_known": true,
	}, "node_id": b.Info.ID}
	if status, _ := iePostJSON(t, s.Master+"/files/replicated/verified", stale); status != http.StatusConflict {
		t.Errorf("stale epoch verified receipt: status %d, want 409", status)
	}
	if cur, _ := s.store.ObjectIntegrity(chunkID); len(cur.Done) != 1 {
		t.Errorf("stale receipt restored Done: %v", cur.Done)
	}

	// 当前 epoch 的恢复走节点真实 /verify：B 重读自己的盘（内容其实未坏）→ CRC 通过 →
	// 节点上报 verified receipt → Suspect 清除、Done 恢复。
	if status, raw := iePostJSON(t, fmt.Sprintf("%s/verify/%d", b.Base, chunkID), nil); status != http.StatusOK {
		t.Fatalf("node verify restore: status %d body %s", status, string(raw))
	}
	cur, _ = s.store.ObjectIntegrity(chunkID)
	if len(cur.Done) != 2 || len(cur.Suspect) != 0 {
		t.Errorf("after legitimate verified receipt: done=%v suspect=%v, want restored", cur.Done, cur.Suspect)
	}

	// 伪造"长度-only" receipt（checksum_known=false）→ 409，绝不复活。
	forged := map[string]any{"object": map[string]any{
		"object_id": suspect.ObjectID, "inode_id": suspect.InodeID, "generation": suspect.Generation,
		"integrity_epoch": suspect.IntegrityEpoch, "chunked": true, "chunk_index": 0,
		"size": suspect.Size, "checksum": 0, "checksum_known": false,
	}, "node_id": b.Info.ID}
	if status, _ := iePostJSON(t, s.Master+"/files/replicated/present", forged); status != http.StatusConflict {
		t.Errorf("forged length-only receipt: status %d, want 409", status)
	}
}

// ---- 6. 旧 generation / 旧 chunkID / 非副本节点报告 no-op ----

func TestIntegrityE2EStaleAndForeignReportsAreNoOps(t *testing.T) {
	s := ieNewStack(t)
	s.startMaster()
	a, b, d := s.startNode(), s.startNode(), s.startNode() // d = 未分配节点

	// 分块文件：A、B 为副本，D 不在副本集。
	body := []byte("stale generation and foreign node reports must be no-ops")
	in, chunkID := ieChunkFixture(t, s, "stale.bin", body, a, b)
	good, err := s.store.ObjectIntegrity(chunkID)
	if err != nil {
		t.Fatalf("chunk integrity: %v", err)
	}

	mkSuspect := func(generation uint64, index int, objectID, nodeID uint64, size int64, checksum uint32) (int, []byte) {
		return iePostJSON(t, s.Master+"/files/chunks/suspect", map[string]any{
			"inode_id": in.ID, "generation": generation, "chunk_index": index,
			"object_id": objectID, "node_id": nodeID, "size": size, "checksum": checksum,
		})
	}
	// 旧 generation、错 checksum、错 size、错 index、非副本节点、错 objectID → 全部 no-op。
	for i, tc := range []struct {
		what       string
		generation uint64
		index      int
		objectID   uint64
		nodeID     uint64
		size       int64
		checksum   uint32
	}{
		{"wrong generation", in.Generation + 7, 0, chunkID, b.Info.ID, int64(len(body)), types.CRC32C(body)},
		{"wrong checksum", in.Generation, 0, chunkID, b.Info.ID, int64(len(body)), types.CRC32C(body) + 1},
		{"wrong size", in.Generation, 0, chunkID, b.Info.ID, int64(len(body)) + 1, types.CRC32C(body)},
		{"wrong index", in.Generation, 3, chunkID, b.Info.ID, int64(len(body)), types.CRC32C(body)},
		{"foreign node", in.Generation, 0, chunkID, d.Info.ID, int64(len(body)), types.CRC32C(body)},
		{"wrong objectID", in.Generation, 0, chunkID + 999, b.Info.ID, int64(len(body)), types.CRC32C(body)},
	} {
		status, raw := mkSuspect(tc.generation, tc.index, tc.objectID, tc.nodeID, tc.size, tc.checksum)
		if status != http.StatusOK {
			t.Errorf("case %d (%s): status %d, want 200 marked:false; body %s", i, tc.what, status, string(raw))
		}
		var resp struct {
			Marked bool `json:"marked"`
		}
		json.Unmarshal(raw, &resp)
		if resp.Marked {
			t.Errorf("case %d (%s): marked=true, want false", i, tc.what)
		}
	}
	cur, _ := s.store.ObjectIntegrity(chunkID)
	if ieIntegrityTag(cur) != ieIntegrityTag(good) {
		t.Errorf("stale reports mutated state: %s → %s", ieIntegrityTag(good), ieIntegrityTag(cur))
	}

	// 非副本节点 D 的 receipts：verified 409、present 409、physical suspect no-op。
	recv := map[string]any{"object": good, "node_id": d.Info.ID}
	if status, _ := iePostJSON(t, s.Master+"/files/replicated/verified", recv); status != http.StatusConflict {
		t.Errorf("foreign verified receipt: status %d, want 409", status)
	}
	present := map[string]any{"object": map[string]any{
		"object_id": good.ObjectID, "inode_id": good.InodeID, "generation": good.Generation,
		"integrity_epoch": good.IntegrityEpoch, "chunked": true, "chunk_index": 0,
		"size": good.Size, "checksum": 0, "checksum_known": false,
	}, "node_id": d.Info.ID}
	if status, _ := iePostJSON(t, s.Master+"/files/replicated/present", present); status != http.StatusConflict {
		t.Errorf("foreign present receipt: status %d, want 409", status)
	}
	if status, raw := iePostJSON(t, s.Master+"/files/objects/suspect", recv); status != http.StatusOK {
		t.Errorf("foreign physical suspect: status %d body %s", status, string(raw))
	}
	cur, _ = s.store.ObjectIntegrity(chunkID)
	if ieIntegrityTag(cur) != ieIntegrityTag(good) {
		t.Errorf("foreign receipts mutated state: %s → %s", ieIntegrityTag(good), ieIntegrityTag(cur))
	}

	// 未分配节点 D 直接打 replicate/verify → 409，且 D 上不得出现对象。
	if status, _ := ieDo(t, http.MethodPut, fmt.Sprintf("%s/replicate/%d", d.Base, chunkID), body,
		map[string]string{"X-Atoll-Crc32c": fmt.Sprintf("%08x", types.CRC32C(body))}); status != http.StatusConflict {
		t.Errorf("unassigned node replicate: status %d, want 409", status)
	}
	if status, _ := iePostJSON(t, fmt.Sprintf("%s/verify/%d", d.Base, chunkID), nil); status != http.StatusConflict {
		t.Errorf("unassigned node verify: status %d, want 409", status)
	}
	if ieNodeHasObject(t, d, chunkID) {
		t.Errorf("unassigned node must not hold the object")
	}
}

// ---- 7. 已发布对象：不同 payload 带自身合法 CRC 头不得覆盖 ----

func TestIntegrityE2EPublishedObjectRejectsDifferentPayloadWithSelfCRC(t *testing.T) {
	s := ieNewStack(t)
	s.startMaster()
	a, b := s.startNode(), s.startNode()

	body := []byte("the published immutable object body that must stay stable")
	in := iePublishSmall(t, s, "/immutable.txt", body, 2, false)
	ieWaitDone(t, s, in.ObjID, 2)
	before, _ := s.store.ObjectIntegrity(in.ObjID)

	// 同长度不同内容 + 自身合法 CRC 头：必须被拒（master 权威 CRC/size 优先于调用方 header）。
	evil := bytes.Clone(body)
	evil[0] ^= 0xFF
	for _, tc := range []struct {
		what string
		data []byte
	}{
		{"same-length different payload", evil},
		{"different-length payload", append(bytes.Clone(body), []byte("tail")...)},
	} {
		status, _ := ieDo(t, http.MethodPut, fmt.Sprintf("%s/objects/%d", a.Base, in.ObjID), tc.data,
			map[string]string{"X-Atoll-Crc32c": fmt.Sprintf("%08x", types.CRC32C(tc.data))})
		if status == http.StatusCreated {
			t.Errorf("%s: PUT overwrote the published object (status 201)", tc.what)
		}
		status, got := ieGetObject(t, a, in.ObjID)
		if status != http.StatusOK || !bytes.Equal(got, body) {
			t.Errorf("%s: original content damaged on primary (status %d match %v)", tc.what, status, bytes.Equal(got, body))
		}
		status, got = ieGetObject(t, b, in.ObjID)
		if status != http.StatusOK || !bytes.Equal(got, body) {
			t.Errorf("%s: original content damaged on secondary (status %d match %v)", tc.what, status, bytes.Equal(got, body))
		}
	}
	after, _ := s.store.ObjectIntegrity(in.ObjID)
	if ieIntegrityTag(before) != ieIntegrityTag(after) {
		t.Errorf("metadata changed after overwrite attempts: %s → %s", ieIntegrityTag(before), ieIntegrityTag(after))
	}

	// 分块：声明 CRC 后，不同 payload 自带合法 CRC 头同样不得落盘。
	chunkBody := []byte("declared chunk content protected against self-consistent CRC plants")
	st, err := s.store.CreateStagingFile(1)
	if err != nil {
		t.Fatalf("CreateStagingFile: %v", err)
	}
	ch, err := s.store.AssignChunk(st.ID, 0, int64(len(chunkBody)), []uint64{a.Info.ID, b.Info.ID}, types.CRC32C(chunkBody), true)
	if err != nil {
		t.Fatalf("AssignChunk: %v", err)
	}
	chunkID := types.ChunkObjID(ch, st.ID)
	evilChunk := bytes.Clone(chunkBody)
	evilChunk[1] ^= 0xAA
	if status, _ := ieDo(t, http.MethodPut, fmt.Sprintf("%s/objects/%d", a.Base, chunkID), evilChunk,
		map[string]string{"X-Atoll-Crc32c": fmt.Sprintf("%08x", types.CRC32C(evilChunk))}); status == http.StatusCreated {
		t.Errorf("self-CRC plant overwrote a declared chunk")
	}
	if ieNodeHasObject(t, a, chunkID) {
		t.Errorf("planted payload exists on the node after rejection")
	}
	// 正确内容仍然可写：合法发布链路不受影响。
	if status, _ := ieDo(t, http.MethodPut, fmt.Sprintf("%s/objects/%d", a.Base, chunkID), chunkBody,
		map[string]string{"X-Atoll-Crc32c": fmt.Sprintf("%08x", types.CRC32C(chunkBody))}); status != http.StatusCreated {
		t.Errorf("legitimate chunk PUT after rejection: status %d, want 201", status)
	}
	ieWaitDone(t, s, chunkID, 2)
}
