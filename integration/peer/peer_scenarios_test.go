package peer

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/contentcrypto"
	"atoll/pkg/peerhttp"
	"atoll/pkg/types"
)

// nodeObjects walks a node's object store and returns every stored object file's
// bytes. A node that has received data has at least one non-empty file.
func nodeObjects(t *testing.T, n *peerNode) [][]byte {
	t.Helper()
	root := filepath.Join(n.node.DataDirForTest(), "objects")
	var files [][]byte
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info != nil && !info.IsDir() {
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if len(b) > 0 {
				files = append(files, b)
			}
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk %s: %v", root, err)
	}
	return files
}

// nodeObjectPath 复刻 node.objectPath 的落盘布局（dataDir/objects/<id%256 两位
// 十六进制分桶>/<id>），供测试读取指定对象 ID 的落盘字节。
func nodeObjectPath(n *peerNode, id uint64) string {
	return filepath.Join(n.node.DataDirForTest(), "objects", fmt.Sprintf("%02x", id%256), strconv.FormatUint(id, 10))
}

// nodeObjectBytes 读取节点上指定对象 ID 的落盘字节（真实 objectPath 布局）。
func nodeObjectBytes(t *testing.T, n *peerNode, id uint64) []byte {
	t.Helper()
	b, err := os.ReadFile(nodeObjectPath(n, id))
	if err != nil {
		t.Fatalf("read node object %d: %v", id, err)
	}
	return b
}

func waitNodeData(t *testing.T, n *peerNode, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(nodeObjects(t, n)) >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("node has %d object files, want >= %d", len(nodeObjects(t, n)), want)
}

// multiaddrHostPort 把 /ip4/127.0.0.1/tcp/PORT 转为 host:port，用于直连拨测。
func multiaddrHostPort(ma string) (string, bool) {
	parts := strings.Split(ma, "/")
	// ["", "ip4", "127.0.0.1", "tcp", "PORT"]
	if len(parts) >= 5 && parts[1] == "ip4" && parts[3] == "tcp" {
		return net.JoinHostPort(parts[2], parts[4]), true
	}
	return "", false
}

// findFile 在 store 中按名字找已提交（非 staging）的文件 inode。
func findFile(t *testing.T, store *meta.Store, name string) types.Inode {
	t.Helper()
	var found types.Inode
	err := store.ForEachFile(func(in types.Inode) error {
		if in.Name == name && !in.Staging {
			found = in
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ForEachFile: %v", err)
	}
	if found.ID == 0 {
		t.Fatalf("file %q not found in store", name)
	}
	return found
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// verifyAEADChunk 严格校验单个 AEAD 块：manifest（encoding/CRC/Done/Size）与
// 节点实际落盘字节一一对应，并用 master 记录的 wrapped DEK 解密证明 AEAD 确实
// 被应用（而非仅仅"找不到明文"）。
func verifyAEADChunk(t *testing.T, m *peerMaster, kek *contentcrypto.KEK, node *peerNode, chunk types.ChunkInfo, wantPlain []byte) {
	t.Helper()
	if chunk.Encoding != types.AeadRecordEncoding {
		t.Fatalf("chunk %d encoding %q != %q", chunk.Index, chunk.Encoding, types.AeadRecordEncoding)
	}
	if !chunk.ChecksumKnown || chunk.Checksum == 0 {
		t.Fatalf("chunk %d checksum not recorded (known=%v checksum=%d)", chunk.Index, chunk.ChecksumKnown, chunk.Checksum)
	}
	if len(chunk.Done) < len(chunk.Replicas) {
		t.Fatalf("chunk %d not fully done: done=%v replicas=%v", chunk.Index, chunk.Done, chunk.Replicas)
	}
	if len(chunk.Suspect) != 0 {
		t.Fatalf("chunk %d suspect: %v", chunk.Index, chunk.Suspect)
	}
	if chunk.Size <= chunk.LogicalSize {
		t.Fatalf("chunk %d stored size %d not larger than logical %d (AEAD record overhead)", chunk.Index, chunk.Size, chunk.LogicalSize)
	}

	stored := nodeObjectBytes(t, node, chunk.ID)
	if int64(len(stored)) != chunk.Size {
		t.Fatalf("chunk %d stored %d bytes, manifest size %d", chunk.Index, len(stored), chunk.Size)
	}
	if crc32.Checksum(stored, castagnoli) != chunk.Checksum {
		t.Fatalf("chunk %d stored CRC32C != manifest checksum", chunk.Index)
	}
	if bytes.Contains(stored, []byte("aead-plaintext-marker")) {
		t.Fatalf("chunk %d stored bytes contain the plaintext marker (AEAD not applied)", chunk.Index)
	}
	if chunk.LogicalSize > 0 && int64(len(wantPlain)) != chunk.LogicalSize {
		t.Fatalf("chunk %d wantPlain %d != manifest logical size %d", chunk.Index, len(wantPlain), chunk.LogicalSize)
	}

	// 解密：master 记录的 wrapped DEK 用 KEK 解开，逐记录 OpenRecord 还原明文。
	rec, err := m.store.ContentKey(chunk.ID)
	if err != nil {
		t.Fatalf("chunk %d content key: %v", chunk.Index, err)
	}
	raw, err := base64.RawStdEncoding.DecodeString(rec.WrappedDEK)
	if err != nil {
		t.Fatalf("chunk %d wrapped DEK decode: %v", chunk.Index, err)
	}
	dek, err := contentcrypto.UnwrapDEK(kek, chunk.ID, raw)
	if err != nil {
		t.Fatalf("chunk %d unwrap DEK: %v", chunk.Index, err)
	}
	if rec.Generation != chunk.ID>>8 {
		t.Fatalf("chunk %d generation %d != expected %d", chunk.Index, rec.Generation, chunk.ID>>8)
	}
	offset := 0
	for idx := 0; offset < len(stored); idx++ {
		recLen := len(stored) - offset
		if full := int(types.AeadRecordPlaintext) + types.AeadRecordOverhead; recLen > full {
			recLen = full
		}
		plain, err := contentcrypto.OpenRecord(dek, chunk.ID, rec.Generation, uint64(idx), stored[offset:offset+recLen])
		if err != nil {
			t.Fatalf("chunk %d record %d open: %v", chunk.Index, idx, err)
		}
		wantStart := idx * int(types.AeadRecordPlaintext)
		wantEnd := wantStart + int(types.AeadRecordPlaintext)
		if wantEnd > len(wantPlain) {
			wantEnd = len(wantPlain)
		}
		if !bytes.Equal(plain, wantPlain[wantStart:wantEnd]) {
			t.Fatalf("chunk %d record %d plaintext mismatch: got %d bytes want %d", chunk.Index, idx, len(plain), wantEnd-wantStart)
		}
		offset += recLen
	}
}

// TestPeerPlannedAEADMultiBlock 走真实计划写 + 内容加密（KEK）多块链路：客户端
// 分块密封、内容 CRC 读回、节点落盘的是 AEAD 密文而非明文。严格校验 manifest
// （encoding=aead、CRC、Done、Size）与节点落盘字节一一对应并解密验证。
// 不并行执行，因为会临时调整 types.ChunkSize（测试后恢复）。
func TestPeerPlannedAEADMultiBlock(t *testing.T) {
	pki := newTestPKI(t)
	kek, err := contentcrypto.NewKEKFromSecret("peer-test-key", bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatalf("NewKEKFromSecret: %v", err)
	}
	m := newPeerMasterOpts(t, pki, masterOpts{contentKEK: kek})
	m.createUser("alice")

	node := m.startNode(filepath.Join(t.TempDir(), "node"), m.nodeInvite())
	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)

	// 多块：ChunkSize=1MB，payload=1.5MB → 恰好 2 块（1MB + 0.5MB），走完整 AEAD
	// 分块链路（每块再按 64KiB 记录密封）。
	oldChunk := types.ChunkSize
	types.ChunkSize = 1 << 20
	t.Cleanup(func() { types.ChunkSize = oldChunk })

	plainMark := []byte("aead-plaintext-marker-0123456789abcdef-0xAB\x00\xff")
	payload := bytes.Repeat(plainMark, (3<<20/2)/len(plainMark)+1)
	payload = payload[:3<<20/2] // 1.5MB → 2 块
	local := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(local, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cl.PutChunked(local, "/aead.bin", 1); err != nil {
		t.Fatalf("PutChunked (AEAD): %v", err)
	}

	// 内容 CRC / 读回一致。
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := cl.Get("/aead.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("AEAD readback mismatch: got %d bytes want %d", len(got), len(payload))
	}

	// 严格 manifest ↔ 落盘密文 映射：2 块、每块 AEAD 编码、CRC/Done 与节点字节一致。
	in := findFile(t, m.store, "aead.bin")
	if !in.Chunked {
		t.Fatalf("file is not chunked")
	}
	if len(in.Chunks) != 2 {
		t.Fatalf("want 2 chunks for 1.5MB payload at 1MB chunk size, got %d", len(in.Chunks))
	}
	logicalOff := 0
	for _, chunk := range in.Chunks {
		chunkPlain := payload[logicalOff : logicalOff+int(chunk.LogicalSize)]
		verifyAEADChunk(t, m, kek, node, chunk, chunkPlain)
		logicalOff += int(chunk.LogicalSize)
	}
	if logicalOff != len(payload) {
		t.Fatalf("chunk logical sizes cover %d bytes, want %d", logicalOff, len(payload))
	}
}

// setTransferNode 在 master 落节点的 placement profile，使写转移计划能为此
// 节点规划上传/下载腿（否则 master 拒绝：节点需要有限预算）。节点的传输预算
// 在 startNodeOpts 中于 Register 前配置（必须一次）。
func (m *peerMaster) setTransferNode(pn *peerNode, zone string, upload, download uint64) {
	m.t.Helper()
	if err := m.store.SetNodePlacementProfile(meta.NodePlacementProfile{
		NodeID:                 pn.node.NodeIDForTest(),
		FailureDomains:         map[string]string{"zone": zone},
		UploadBPS:              upload,
		DownloadBPS:            download,
		MaxTransferConcurrency: 4,
	}); err != nil {
		m.t.Fatalf("placement profile: %v", err)
	}
}

// waitForLedgerReplicate 有界等待副本节点 ledger 出现源为 rootPeerID 的节点间
// /replicate/ 请求；超时返回 nil。
func waitForLedgerReplicate(l *nodeLedger, rootPeerID string, timeout time.Duration) (reqRecord, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, r := range l.snapshot() {
			if r.method == http.MethodPut && strings.HasPrefix(r.path, "/replicate/") && r.source == rootPeerID {
				return r, true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return reqRecord{}, false
}

// TestPeerNodeReplicateDirect 验证计划写 + 转移规划下节点间 replicate 走真实
// peer 数据面。客户端预算 MaxConcurrent=1 → MaxUploadTargets=1（单上传入口），
// 安全档位双副本 → 计划必须含节点复制腿：硬断言至少一条 FromNodeID!=0 的 leg，
// 且目标节点 ledger 收到源为该节点真实 PeerID 的 /replicate/。断言以落库的实际
// 布局与转移计划为据，不假定 legacy replicas 参数生效。
func TestPeerNodeReplicateDirect(t *testing.T) {
	pki := newTestPKI(t)
	m := newPeerMasterOpts(t, pki, masterOpts{transferPlanning: true})
	m.createUser("alice")

	budget := &types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 4}
	var n1Ledger, n2Ledger nodeLedger
	n1 := m.startNodeOpts(filepath.Join(t.TempDir(), "n1"), m.nodeInvite(), nodeOpts{transferBudget: budget, ledger: &n1Ledger})
	n2 := m.startNodeOpts(filepath.Join(t.TempDir(), "n2"), m.nodeInvite(), nodeOpts{transferBudget: budget, ledger: &n2Ledger})
	m.setTransferNode(n1, "a", 1<<20, 4<<20)
	m.setTransferNode(n2, "b", 1<<20, 4<<20)

	// seedLink：受控调度输入（Path="direct"、RTT=2 为注入先验，非实测）；真实
	// 路径由副本节点 ledger 的源 peer id 证实。
	seedLink := func(from, to *peerNode) {
		m.t.Helper()
		if err := m.srv.RecordTransferObservation(types.TransferObservation{
			FromNodeID: from.node.NodeIDForTest(),
			ToNodeID:   to.node.NodeIDForTest(),
			Path:       "direct",
			Available:  true,
			RTTMs:      2,
			ObservedAt: time.Now(),
		}, time.Now()); err != nil {
			m.t.Fatalf("record transfer observation: %v", err)
		}
	}
	seedLink(n1, n2)
	seedLink(n2, n1)

	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)
	// MaxConcurrent=1 把 MaxUploadTargets 压到 1：客户端只上传单一入口，第二副本
	// 必须经节点复制腿送达；安全档位提供双副本布局目标。
	if err := cl.SetTransferBudget(types.TransferBudget{UploadBPS: 1 << 20, DownloadBPS: 4 << 20, MaxConcurrent: 1}); err != nil {
		t.Fatalf("SetTransferBudget: %v", err)
	}
	if _, err := cl.SetProtection("/", types.ProtectionSecurity); err != nil {
		t.Fatalf("SetProtection: %v", err)
	}

	payload := bytes.Repeat([]byte("replicate-direct-payload-"), 1000)
	if _, err := cl.PutSmall("/rep.bin", payload, 2, false); err != nil {
		t.Fatalf("PutSmall replicas=2: %v", err)
	}

	// 实际落库布局与转移计划：断言的证据来源，不假定 legacy replicas 参数生效。
	in := findFile(t, m.store, "rep.bin")
	if len(in.Chunks) == 0 {
		t.Fatalf("committed file has no chunks: %+v", in)
	}
	chunk := in.Chunks[0]
	layout := map[uint64]bool{}
	for _, id := range chunk.Replicas {
		layout[id] = true
	}
	if !layout[n1.node.NodeIDForTest()] || !layout[n2.node.NodeIDForTest()] {
		t.Fatalf("persisted layout targets %v do not include both nodes (%d, %d)",
			chunk.Replicas, n1.node.NodeIDForTest(), n2.node.NodeIDForTest())
	}
	tp, err := m.store.WriteTransferForObject(chunk.ID)
	if err != nil {
		t.Fatalf("transfer plan for object %d: %v", chunk.ID, err)
	}
	if tp == nil {
		t.Fatalf("no persisted transfer plan for object %d; cannot derive expected data-plane evidence", chunk.ID)
	}
	t.Logf("transfer plan: upload_targets=%v legs=%v", tp.UploadTargets, tp.Legs)

	// 逐腿核对数据面：leg 的 FromNodeID==0 表示客户端上传腿（目标节点 ledger 必须有
	// 源为客户端真实 peer id 的 /objects/ PUT）；FromNodeID!=0 表示节点复制腿（目标
	// ledger 必须有源为该节点 peer id 的 /replicate/）。MaxUploadTargets=1 下节点
	// 复制腿是计划的必然产物，硬断言存在。
	byID := map[uint64]*peerNode{n1.node.NodeIDForTest(): n1, n2.node.NodeIDForTest(): n2}
	byLedger := map[uint64]*nodeLedger{n1.node.NodeIDForTest(): &n1Ledger, n2.node.NodeIDForTest(): &n2Ledger}
	nodeLegs := 0
	for _, leg := range tp.Legs {
		target := byID[leg.ToNodeID]
		targetLedger := byLedger[leg.ToNodeID]
		if target == nil || targetLedger == nil {
			t.Fatalf("transfer leg %+v references unknown node %d", leg, leg.ToNodeID)
		}
		if leg.FromNodeID == 0 {
			if !waitForLedgerObject(t, targetLedger, cs.rt.PeerID(), "/objects/", 15*time.Second) {
				t.Fatalf("client upload leg %+v: node %s ledger never recorded a client-source PUT /objects/", leg, target.nodeDataAddr())
			}
		} else {
			nodeLegs++
			source := byID[leg.FromNodeID]
			if source == nil {
				t.Fatalf("transfer leg %+v has unknown source node %d", leg, leg.FromNodeID)
			}
			rec, ok := waitForLedgerReplicate(targetLedger, source.rt.PeerID(), 30*time.Second)
			if !ok {
				t.Fatalf("node replicate leg %+v: node %s ledger never recorded /replicate/ from source peer %q; n1=%v n2=%v",
					leg, target.nodeDataAddr(), source.rt.PeerID(), n1Ledger.snapshot(), n2Ledger.snapshot())
			}
			if rec.source != source.rt.PeerID() {
				t.Fatalf("replicate request source %q != leg source peer id %q", rec.source, source.rt.PeerID())
			}
		}
	}
	if nodeLegs == 0 {
		t.Fatalf("plan has no node-to-node leg (upload_targets=%v legs=%v): MaxConcurrent=1 must cap MaxUploadTargets=1 and force a node replicate leg",
			tp.UploadTargets, tp.Legs)
	}

	// 不变式：/objects/ 只能被客户端写（节点间走 /replicate/）。
	for _, pn := range []*peerNode{n1, n2} {
		l := byLedger[pn.node.NodeIDForTest()]
		for _, r := range l.snapshot() {
			if r.method == http.MethodPut && strings.HasPrefix(r.path, "/objects/") && r.source != cs.rt.PeerID() {
				t.Fatalf("node %s /objects/ PUT from non-client source %q (expected node-side writes on /replicate/); %v",
					pn.nodeDataAddr(), r.source, l.snapshot())
			}
		}
	}
	for _, pn := range []*peerNode{n1, n2} {
		waitNodeData(t, pn, 1)
	}

	out := filepath.Join(t.TempDir(), "out.bin")
	if err := cl.Get("/rep.bin", out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("replicate readback mismatch")
	}
}

// waitForLedgerObject 有界等待 ledger 出现源为 source 的 method+path 前缀记录。
func waitForLedgerObject(t *testing.T, l *nodeLedger, source, prefix string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, r := range l.snapshot() {
			if r.method == http.MethodPut && strings.HasPrefix(r.path, prefix) && r.source == source {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// TestPeerNodeRestartSameIdentity 验证节点以同一设备/peer 身份、同一逻辑 data
// 地址重启：closeNode 覆盖 data/peer HTTPS 服务器、CloseP2P（取消并 join 节点
// heartbeat/renew 循环与 P2P publisher）与 peer runtime，peer transport 绑定
// 新端口（多地址变化），NodeID/PeerID/逻辑地址不变。复用同一客户端（已缓存旧
// transport 地址）Get 旧文件：拨旧地址失败 → 目录强刷 → 经新地址重新发现成功。
// 不用新客户端掩盖。
func TestPeerNodeRestartSameIdentity(t *testing.T) {
	pki := newTestPKI(t)
	m := newPeerMaster(t, pki)
	m.createUser("alice")

	dataDir := filepath.Join(t.TempDir(), "node")
	invite := m.nodeInvite()

	n1 := m.startNodeOpts(dataDir, invite, nodeOpts{})
	logicalAddr := n1.nodeDataAddr()
	nodeID1 := n1.node.NodeIDForTest()
	peerID1 := n1.rt.PeerID()
	transportAddrs1 := n1.rt.Addresses()
	if logicalAddr == "" || nodeID1 == 0 || peerID1 == "" || len(transportAddrs1) == 0 {
		t.Fatalf("node1 missing identity/address: addr=%q id=%d peer=%q addrs=%v", logicalAddr, nodeID1, peerID1, transportAddrs1)
	}

	// 客户端登录并写一个文件，缓存旧 transport 地址。
	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)
	payload := []byte("restart-rediscovery-payload")
	cs.path = "/restart.bin"
	if _, err := cl.PutSmall(cs.path, payload, 1, false); err != nil {
		t.Fatalf("PutSmall before restart: %v", err)
	}

	// 关闭旧实例（harness 面：data/peer server、CloseP2P、rt.Close）：旧
	// transport 多地址随之失效（客户端缓存指向死地址）。
	m.closeNode(n1)

	// 同一 dataDir、同一逻辑地址重启：复用 identity.key + peer.key（同设备/peer
	// 身份），peer transport 绑定新端口 → 新 transport 多地址。
	n2 := m.startNodeAddr(dataDir, invite, logicalAddr, nodeOpts{})
	if n2.node.NodeIDForTest() != nodeID1 {
		t.Fatalf("NodeID changed across restart: %d != %d", n2.node.NodeIDForTest(), nodeID1)
	}
	if n2.rt.PeerID() != peerID1 {
		t.Fatalf("peer identity changed across restart: %q != %q", n2.rt.PeerID(), peerID1)
	}
	if n2.nodeDataAddr() != logicalAddr {
		t.Fatalf("logical data addr changed across restart: %q != %q", n2.nodeDataAddr(), logicalAddr)
	}
	if !transportAddrsChanged(transportAddrs1, n2.rt.Addresses()) {
		t.Fatalf("peer transport multiaddr did not change across restart: %v", n2.rt.Addresses())
	}

	// 同一客户端（缓存旧 transport 地址）Get 旧文件：拨旧地址失败触发强刷，经
	// 新 transport 地址重新发现并成功。
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := cl.Get(cs.path, out); err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("restart readback mismatch")
	}
}

// transportAddrsChanged 报告两组 peer transport 多地址集合是否有差异。
func transportAddrsChanged(a, b []string) bool {
	if len(a) != len(b) {
		return true
	}
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		if !set[x] {
			return true
		}
	}
	return false
}

// TestPeerBadCertRejected 验证 peer 监听器出示非 CA 签发自签证书时的负向行为，
// 并把失败定位到证书层：
//   - 直接用真实 peer TLS（不经任何 planner）GET 节点 /healthz：外层 TLS 证书
//     校验必须拒绝（错误链含 x509/tls/certificate）——证书层证据；
//   - PutSmall 经 master 计划写必然失败：secure+peers 模式下 master 的节点健康
//     探测同样走 peer 面（server.go nodeHTTPClient），无法验证证书的节点被判
//     不在线，planner 先拒绝——这是 fail-closed 设计而非缺陷，测试把它记录为
//     预期行为（节点整体不可写，而非静默降级明文）。
func TestPeerBadCertRejected(t *testing.T) {
	pki := newTestPKI(t)
	m := newPeerMaster(t, pki)
	m.createUser("alice")

	node := m.startNodeOpts(filepath.Join(t.TempDir(), "node"), m.nodeInvite(), nodeOpts{peerCertSelfSigned: true})

	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)

	// 证书层证据：不经 planner 的真实 peer TLS 请求必须被证书校验拒绝。
	d := m.peerDirectory(res.Token, userSpaceID(res))
	ep, infra := nodeEndpoint(t, d, node.nodeDataAddr())
	httpc := m.peerPathHTTPClient(cs.rt, ep, infra, nil)
	resp, err := healthzWith(httpc, node.nodeDataAddr(), peerhttp.PathDirect, nil)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("GET /healthz over peer TLS succeeded against a self-cert node")
	}
	msg := err.Error()
	if !strings.Contains(msg, "tls") && !strings.Contains(msg, "x509") && !strings.Contains(msg, "certificate") {
		t.Fatalf("expected a TLS/certificate-layer failure, got: %v", err)
	}

	// planner 先失败是设计行为：master 经 peer 面探测节点健康，证书不可验证 →
	// 节点不在线 → 422。此处只断言"写必然失败"，不断言失败层（层证据已在上面取得）。
	if _, err := cl.PutSmall("/bad.bin", []byte("bad-cert-payload"), 1, false); err == nil {
		t.Fatalf("PutSmall succeeded against a peer listener with a self-signed cert")
	}
}

// TestPeerPlaintextRejected 验证明文 HTTP 到不了节点应用 handler：
//   - Layer A：裸 TCP 到 libp2p 端口（Noise 协商端点，不响应明文 HTTP）。
//   - Layer B：已注册客户端 runtime（授权源）建立的授权 ProtoID 流上写明文
//     HTTP，真实外层 TLS（ServeTLS）拒绝。
//
// 层证据由节点 ledger 提供：明文请求永远不出现在处理器记录里；响应前缀只是
// 旁证。任一层拨号/写失败都继续跑下一层，不得提前 return。
func TestPeerPlaintextRejected(t *testing.T) {
	pki := newTestPKI(t)
	m := newPeerMaster(t, pki)
	m.createUser("alice")

	var nLedger nodeLedger
	node := m.startNodeOpts(filepath.Join(t.TempDir(), "node"), m.nodeInvite(), nodeOpts{ledger: &nLedger})
	addrs := node.rt.Addresses()
	if len(addrs) == 0 {
		t.Fatalf("node published no peer addresses")
	}
	hostPort, ok := multiaddrHostPort(addrs[0])
	if !ok {
		t.Fatalf("unexpected peer multiaddr %q", addrs[0])
	}

	// Layer A：裸 TCP 明文 HTTP 到 libp2p 端口。
	conn, err := net.DialTimeout("tcp", hostPort, 2*time.Second)
	if err != nil {
		t.Logf("layer A: raw TCP dial refused (%v); continuing to layer B", err)
	} else {
		if _, werr := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")); werr != nil {
			t.Logf("layer A: raw TCP plaintext write refused (%v); continuing to layer B", werr)
		} else {
			buf := make([]byte, 64)
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := conn.Read(buf)
			if n > 0 && strings.HasPrefix(string(buf[:n]), "HTTP/1.1") {
				conn.Close()
				t.Fatalf("layer A: raw TCP plaintext received an application HTTP/1.1 response: %q", buf[:n])
			}
		}
		conn.Close()
	}

	// Layer B：注册过的客户端 runtime 建授权流后写明文 HTTP，真实外层 TLS 拒绝。
	cl, res := m.login("alice")
	cs := &clientSecure{c: cl, res: res}
	cs.rt = m.startClientPeer(cs)
	d := m.peerDirectory(res.Token, userSpaceID(res))
	ep, infra := nodeEndpoint(t, d, node.nodeDataAddr())

	dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dcancel()
	dres := cs.rt.Dial(dctx, ep, infra, peerhttp.PathDirect)
	if dres.Err != nil {
		t.Fatalf("registered source runtime Dial to peer failed (expected success): %v", dres.Err)
	}
	if dres.Conn == nil {
		t.Fatalf("runtime Dial returned no connection")
	}
	defer dres.Conn.Close()
	ledgerBefore := nLedger.len()
	if _, werr := dres.Conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")); werr == nil {
		buf2 := make([]byte, 256)
		_ = dres.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n2, _ := dres.Conn.Read(buf2)
		if n2 > 0 {
			got := string(buf2[:n2])
			// 明文请求的合法结局：无响应，或 Go TLS 端口的固定明文守卫
			//（"HTTP/1.0 400 … Client sent an HTTP request to an HTTPS server"）。
			if strings.HasPrefix(got, "HTTP/1.1") {
				t.Fatalf("layer B: application handler served a plaintext request over the verified peer stream: %q", got)
			}
			if !strings.Contains(got, "HTTPS server") && !strings.Contains(got, "400 Bad Request") {
				t.Fatalf("layer B: unexpected response to plaintext: %q", got)
			}
		}
	}
	// 层证据：明文请求从未到达处理器（ledger 计数不变，任何来源都不例外）。
	if delta := nLedger.len() - ledgerBefore; delta != 0 {
		t.Fatalf("layer B: plaintext request reached the node handler (%d new records): %v", delta, nLedger.snapshot()[ledgerBefore:])
	}
}
