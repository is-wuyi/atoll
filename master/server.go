// Package master 实现中心服务器：元数据管理 + 副本位置分配。
package master

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"atoll/master/meta"
	"atoll/pkg/auth"
	"atoll/pkg/contentcrypto"
	"atoll/pkg/types"
)

// Server 是 master 的 HTTP 服务。
type Server struct {
	store             *meta.Store
	nodeMaxAge        time.Duration // 节点心跳超时阈值
	scanner           *Scanner      // GC 需要调用
	backup            *MetaBackup   // 元数据备份状态查询/手动触发（可为 nil：未启用备份）
	autonomy          *Autonomy
	writePlanner      *writePlanner
	transferLinks     transferLinkStore
	security          *serverSecurity
	token             auth.Token  // 集群认证；空 = 兼容模式
	adminToken        auth.Token  // 破坏性操作（/admin/gc）专用；空 = 回退用 token
	scheme            string      // 出站访问节点的 scheme：http（默认）/https
	tlsCfg            *tls.Config // 出站 TLS 客户端配置（nil = 普通 HTTP）
	nodeTransportOnce sync.Once
	nodeTransport     *auth.Transport
	// commitWait 是 min_copies 提交时 master 侧等待从副本到齐的上限。
	// 与 nodeMaxAge 解耦（后者可能长达小时级）：这里只吸收秒级同步延迟，
	// 超时仍 409 交客户端兜底。测试可调小以免阻塞。
	commitWait time.Duration
	contentKEK *contentcrypto.KEK
	// healthProbe 探测节点实时可达性；nil = 用真实 probeHealthz（GET /healthz）。
	// 测试注入桩绕过真实网络（单测节点是假地址，无 /healthz 服务）。
	healthProbe func(addr string) bool
	// probeCache 缓存 /healthz 探测结果，避免每次块分配都同步重探每个节点——
	// 大量小文件拷贝时这份"过路费"会乘上文件数拖垮 folder 上传。短 TTL 保证幽灵
	// 节点仍能及时被发现（心跳 30s 是粗筛，这里只是秒级可达性细筛）。
	probeMu    sync.Mutex
	probeCache map[string]probeEntry
}

// probeEntry 是一次 /healthz 探测结果 + 时间戳。
type probeEntry struct {
	ok bool
	at time.Time
}

// probeCacheTTL 是探测结果的有效期。
const probeCacheTTL = 3 * time.Second

func NewServer(store *meta.Store, nodeMaxAge time.Duration) *Server {
	return &Server{store: store, nodeMaxAge: nodeMaxAge, commitWait: 20 * time.Second}
}

// SetCommitWait 覆盖 min_copies 提交的等待上限（测试用，避免 20s 阻塞）。
func (s *Server) SetCommitWait(d time.Duration) { s.commitWait = d }

// SetContentKEK enables content-key metadata and authorized DEK retrieval.
func (s *Server) SetContentKEK(kek *contentcrypto.KEK) { s.contentKEK = kek }

// SetHealthProbe 覆盖节点可达性探测（测试用，注入桩绕过真实 /healthz 网络请求）。
func (s *Server) SetHealthProbe(fn func(addr string) bool) { s.healthProbe = fn }

// SetToken 设置集群认证 token（包装 Handler 生效）。空 token = 兼容模式。
func (s *Server) SetToken(token auth.Token) { s.token = token }

// SetAdminToken 设置破坏性操作（/admin/gc）专用 token。空 = 回退用集群 token。
func (s *Server) SetAdminToken(token auth.Token) { s.adminToken = token }

// SetTLS 启用出站访问节点的 TLS（探测/回收对象走 https）。cfg 为空则不启用。
func (s *Server) SetTLS(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	s.tlsCfg = cfg
	s.scheme = "https"
}

// nodeScheme 返回访问节点的 scheme（默认 http）。
func (s *Server) nodeScheme() string {
	if s.scheme == "" {
		return "http"
	}
	return s.scheme
}

func (s *Server) nodeHTTPClient(timeout time.Duration) *http.Client {
	// token/TLS 在启动前设置；各类请求保留自己的超时，共用节点连接池。
	s.nodeTransportOnce.Do(func() {
		s.nodeTransport = auth.HTTPTransport(s.token, s.tlsCfg, nil)
	})
	if s.security != nil {
		return &http.Client{Timeout: timeout, Transport: s.secureControlTransport(s.nodeTransport.Fallback), CheckRedirect: rejectRedirect}
	}
	return &http.Client{Timeout: timeout, Transport: s.nodeTransport}
}

// adminPaths 需要 adminToken 的破坏性路径。/admin/objects 是只读清单、不在内。
var adminPaths = map[string]bool{"/admin/gc": true, "/admin/metabackup/trigger": true, "/admin/metabackup/config": true,
	"/admin/autonomy/step": true, "/admin/autonomy/profile": true, "/admin/autonomy/cancel": true}

// SetScanner 绑定扫描器，供 /admin/gc 等接口使用。
func (s *Server) SetScanner(scanner *Scanner) {
	s.scanner = scanner
}

// SetMetaBackup 绑定元数据备份器，供 /admin/metabackup 状态查询与手动触发。
func (s *Server) SetMetaBackup(b *MetaBackup) { s.backup = b }

// Handler 返回全部路由（整体经 auth 包装，healthz 豁免）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /dirs", s.handleCreateDir)
	mux.HandleFunc("GET /dirs/children", s.handleListChildren)
	mux.HandleFunc("GET /meta", s.handleLookup) // ?path=/a/b
	mux.HandleFunc("POST /writes", s.handleBeginWrite)
	mux.HandleFunc("POST /writes/chunks", s.handlePlanWriteChunk)
	mux.HandleFunc("POST /writes/chunks/recover", s.handleRecoverWriteChunk)
	mux.HandleFunc("GET /writes/transfer-nodes", s.handleWriteTransferNodes)
	mux.HandleFunc("GET /writes/status", s.handleWriteStatus)
	mux.HandleFunc("POST /nodes/transfer-observation", s.handleNodeTransferObservation)
	mux.HandleFunc("GET /nodes/transfer-peers", s.handleNodeTransferPeers)
	mux.HandleFunc("POST /writes/commit", s.handleCommitWrite)
	mux.HandleFunc("POST /writes/abort", s.handleAbortWrite)
	mux.HandleFunc("GET /protection", s.handleProtection)
	mux.HandleFunc("POST /protection", s.handleProtection)
	mux.HandleFunc("POST /files", s.handleCreateFile)
	mux.HandleFunc("POST /files/commit", s.handleCommitFile)
	mux.HandleFunc("POST /files/chunks", s.handleAssignChunk)            // 分块：分配块副本
	mux.HandleFunc("DELETE /files/staging/{id}", s.handleAbortStaging)   // 分块：放弃上传
	mux.HandleFunc("GET /files/replica-targets", s.handleReplicaTargets) // node 查询推送目标
	mux.HandleFunc("POST /files/replicated", s.handleReplicated)         // 从副本上报同步完成
	mux.HandleFunc("POST /files/corrupt", s.handleReportCorrupt)         // 读端上报副本内容损坏
	mux.HandleFunc("GET /files/replication", s.handleReplicationPlan)
	mux.HandleFunc("POST /files/replicated/verified", s.handleVerifiedReplica)
	mux.HandleFunc("POST /files/replicated/present", s.handlePresentReplica)
	mux.HandleFunc("POST /files/objects/suspect", s.handlePhysicalSuspect)
	mux.HandleFunc("POST /files/protection/progress", s.handleProtectionProgress) // 目标节点进度/失败反馈
	mux.HandleFunc("POST /files/writes/progress", s.handleWriteProgress)
	mux.HandleFunc("POST /files/chunks/suspect", s.handleChunkSuspect)
	mux.HandleFunc("POST /files/suspect", s.handleReportSuspect) // 版本校验后标记整对象副本待修
	mux.HandleFunc("POST /files/small", s.handleCreateSmall)     // 小文件单请求通道（v2-2a）
	mux.HandleFunc("POST /files/symlink", s.handleCreateSymlink) // 创建符号链接
	mux.HandleFunc("POST /entry/rename", s.handleRename)         // 同目录改名
	mux.HandleFunc("DELETE /entry", s.handleDelete)              // ?path=/a/b
	mux.HandleFunc("POST /nodes/register", s.handleNodeRegister)
	mux.HandleFunc("POST /nodes/heartbeat", s.handleNodeHeartbeat)
	mux.HandleFunc("POST /admin/gc", s.handleGC)
	// 管理后台只读 read-model（普通集群 token 即可读；破坏性操作仍走 adminToken）。
	mux.HandleFunc("GET /admin/overview", s.handleAdminOverview)
	mux.HandleFunc("GET /admin/nodes", s.handleAdminNodes)
	mux.HandleFunc("GET /admin/repairs", s.handleAdminRepairs)
	mux.HandleFunc("GET /admin/integrity", s.handleAdminIntegrity)
	mux.HandleFunc("GET /admin/autonomy", s.handleAutonomyStatus)
	mux.HandleFunc("POST /admin/autonomy/step", s.handleAutonomyStep)
	mux.HandleFunc("POST /admin/autonomy/profile", s.handleAutonomyProfile)
	mux.HandleFunc("POST /admin/autonomy/cancel", s.handleAutonomyCancel)
	mux.HandleFunc("GET /admin/metabackup", s.handleAdminMetaBackup)
	mux.HandleFunc("POST /admin/metabackup/trigger", s.handleAdminMetaBackupTrigger)
	mux.HandleFunc("POST /admin/metabackup/config", s.handleAdminMetaBackupConfig)
	if s.security != nil {
		return s.writePlanningGuard(s.securityHandler(mux))
	}
	if enabled, err := s.store.SecurityEnabled(); err != nil || enabled {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				w.WriteHeader(http.StatusOK)
				return
			}
			httpError(w, http.StatusServiceUnavailable, "security is initialized; start master in secure mode")
		})
	}
	return s.writePlanningGuard(auth.WrapTokens(mux, s.token, s.adminToken, adminPaths))
}

// ---- 目录 ----

func (s *Server) handleCreateDir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	parentPath, name := splitPath(req.Path)
	if name == "" || name == "." || name == ".." {
		httpError(w, http.StatusBadRequest, "invalid path")
		return
	}
	parent, err := s.store.ResolvePath(parentPath)
	if err != nil {
		httpError(w, http.StatusNotFound, "parent not found")
		return
	}
	dir, err := s.store.CreateDir(parent.ID, name)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, dir)
}

func (s *Server) handleListChildren(w http.ResponseWriter, r *http.Request) {
	in, err := s.store.ResolvePath(r.URL.Query().Get("path"))
	if err != nil {
		httpError(w, http.StatusNotFound, "path not found")
		return
	}
	kids, err := s.store.ListChildren(in.ID)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, kids)
}

// handleLookup 返回路径的 inode 及（对文件而言）副本所在的节点地址列表。
// 客户端拿到节点地址后直连读写，不经过 master 中转。
// legacy 文件：每个节点带 done 标记，读优先挑这些节点；心跳过期的节点不返回。
// 分块文件（Chunked=true）：nodes 恒为空，客户端按 inode.Chunks 块表自行换算。
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	in, err := s.store.ResolvePath(r.URL.Query().Get("path"))
	if err != nil {
		httpError(w, http.StatusNotFound, "path not found")
		return
	}
	// 新对象布局的显式对象引用不能被旧客户端消费（它会把 FileID 当物理地址读错对象）。
	// legacy 布局（ObjID=0）保持兼容直读。
	if !in.Chunked && in.ObjID != 0 && !hasObjectIDFeature(r) {
		httpError(w, http.StatusUpgradeRequired, "this entry requires "+types.ObjectIDFeature+" client feature")
		return
	}
	resp := struct {
		Inode types.Inode `json:"inode"`
		Nodes []nodeEntry `json:"nodes"` // 按 inode.Replicas 顺序给出节点详情
	}{Inode: in}
	if in.Chunked {
		// 分块文件：nodes 返回全部块副本节点的地址表（去重、剔除 dead），
		// 客户端用它把块表里的 node ID 解析成直连地址。
		seen := make(map[uint64]bool)
		for _, c := range in.Chunks {
			for _, id := range c.Replicas {
				if seen[id] {
					continue
				}
				seen[id] = true
				n, err := s.store.GetNode(id)
				if err != nil {
					continue
				}
				if time.Since(n.LastHeartbeat) > s.nodeMaxAge {
					continue
				}
				resp.Nodes = append(resp.Nodes, nodeEntry{NodeInfo: n, Done: types.ContainsUint64(in.DoneReplicas, id)})
			}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	for _, id := range in.Replicas {
		n, err := s.store.GetNode(id)
		if err != nil {
			continue // 节点可能已注销，跳过
		}
		if time.Since(n.LastHeartbeat) > s.nodeMaxAge {
			continue // 已判定宕机，不提供给客户端
		}
		resp.Nodes = append(resp.Nodes, nodeEntry{NodeInfo: n, Done: types.ContainsUint64(in.DoneReplicas, id)})
	}
	writeJSON(w, http.StatusOK, resp)
}

// nodeEntry 是 lookup 响应中的节点条目：节点详情 + 副本同步状态。
type nodeEntry struct {
	types.NodeInfo
	Done bool `json:"done"`
}

// handleReplicaTargets 主副本节点查询：除自己外还需要推送到哪些节点。
// ?inode_id=N&node_id=self。inode_id 可以是块对象 ID（分块模型）：
// master 反解出所属 inode 与块下标，返回该块未 Done 的副本节点。
func (s *Server) handleReplicaTargets(w http.ResponseWriter, r *http.Request) {
	inodeID, _ := strconv.ParseUint(r.URL.Query().Get("inode_id"), 10, 64)
	nodeID, _ := strconv.ParseUint(r.URL.Query().Get("node_id"), 10, 64)
	if inodeID == 0 || nodeID == 0 {
		httpError(w, http.StatusBadRequest, "inode_id and node_id required")
		return
	}
	description, err := s.store.ObjectIntegrity(inodeID)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	if description.ChecksumKnown {
		httpError(w, http.StatusUpgradeRequired, "integrity-v1 replication required")
		return
	}
	if !types.ContainsUint64(description.Replicas, nodeID) {
		httpError(w, http.StatusForbidden, "node is not an assigned replica")
		return
	}
	if description.Chunked {
		if _, err := s.store.MarkObjectPresent(description, nodeID); err != nil {
			httpErrorFromMeta(w, err)
			return
		}
	}
	var targets []types.NodeInfo
	for _, id := range description.Replicas {
		if id == nodeID || types.ContainsUint64(description.Done, id) {
			continue
		}
		n, err := s.store.GetNode(id)
		if err == nil && time.Since(n.LastHeartbeat) <= s.nodeMaxAge {
			targets = append(targets, n)
		}
	}
	writeJSON(w, http.StatusOK, targets)
}

// handleReplicated 副本落盘完成上报，把自己加入 Done 集合。
// inode_id 可以是块对象 ID（分块模型，node 上报的本来就是它存储的对象 ID）。
func (s *Server) handleReplicated(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InodeID uint64 `json:"inode_id"`
		NodeID  uint64 `json:"node_id"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.InodeID == 0 || req.NodeID == 0 {
		httpError(w, http.StatusBadRequest, "inode_id and node_id required")
		return
	}
	description, err := s.store.ObjectIntegrity(req.InodeID)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	if description.ChecksumKnown {
		httpError(w, http.StatusUpgradeRequired, "verified receipt required")
		return
	}
	if _, err := s.store.MarkObjectPresent(description, req.NodeID); err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Reports without a content identity cannot safely mutate or delete a replica.
func (s *Server) handleReportCorrupt(w http.ResponseWriter, r *http.Request) {
	httpError(w, http.StatusUpgradeRequired, "version-bound suspect report required")
}

// ---- 文件 ----

// handleCreateFile 创建文件记录并分配副本节点。
// 请求带 chunked=true（新客户端）：创建隐藏 staging inode，写完块后 commit 原子换名。
// 否则（legacy 客户端）：从活跃节点随机挑 N 个，直接挂路径（旧行为，滚动升级兼容）。
func (s *Server) handleCreateFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path      string `json:"path"`
		Replicas  int    `json:"replicas"`  // 期望副本数，<=0 时取 1
		Overwrite bool   `json:"overwrite"` // 覆盖已有文件
		Chunked   bool   `json:"chunked"`   // 分块上传模式（批次 C）
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.Replicas <= 0 {
		req.Replicas = 1
	}
	parentPath, name := splitPath(req.Path)
	if name == "" || name == "." || name == ".." {
		httpError(w, http.StatusBadRequest, "invalid path")
		return
	}
	parent, err := s.store.ResolvePath(parentPath)
	if err != nil {
		httpError(w, http.StatusNotFound, "parent not found")
		return
	}
	// 分块模式：只建 staging inode，不碰旧文件（覆盖写在 commit 时原子完成）。
	// 同名文件存在且 !overwrite 时立即拒绝，避免传完整个文件才发现冲突。
	if req.Chunked {
		if !req.Overwrite {
			if _, err := s.store.ResolvePath(req.Path); err == nil {
				httpError(w, http.StatusConflict, meta.ErrExist.Error())
				return
			}
		}
		st, err := s.store.CreateStagingFile(parent.ID)
		if err != nil {
			httpErrorFromMeta(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			Inode types.Inode      `json:"inode"`
			Nodes []types.NodeInfo `json:"nodes"`
		}{Inode: st})
		return
	}
	// legacy：先校验节点可用性，再动旧文件——否则删了旧文件才发现节点不足、
	// 返回 503，旧文件已丢且对象在回收（覆盖失败即数据丢失）。
	alive, err := s.store.ListAliveNodes(s.nodeMaxAge)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(alive) < req.Replicas {
		httpError(w, http.StatusServiceUnavailable, fmt.Sprintf("alive nodes %d < replicas %d", len(alive), req.Replicas))
		return
	}
	// 路径已存在：按 overwrite 决定拒绝还是覆盖。覆盖不在此刻删旧——只建一个 staging
	// 新版本（旧文件继续可读），待客户端把数据传到 staging 后 commit 才原子替换。
	// 此前 create 阶段就 DeleteFile + 回收旧对象，上传随后失败即旧数据永久丢失。
	if _, err := s.store.ResolvePath(req.Path); err == nil {
		if !req.Overwrite {
			httpError(w, http.StatusConflict, meta.ErrExist.Error())
			return
		}
		rand.Shuffle(len(alive), func(i, j int) { alive[i], alive[j] = alive[j], alive[i] })
		chosen := alive[:req.Replicas]
		nodeIDs := make([]uint64, len(chosen))
		for i, n := range chosen {
			nodeIDs[i] = n.ID
		}
		st, err := s.store.CreateStagingFileLegacy(parent.ID, name, nodeIDs)
		if err != nil {
			httpErrorFromMeta(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			Inode types.Inode      `json:"inode"`
			Nodes []types.NodeInfo `json:"nodes"`
		}{Inode: st, Nodes: chosen})
		return
	}
	rand.Shuffle(len(alive), func(i, j int) { alive[i], alive[j] = alive[j], alive[i] })
	chosen := alive[:req.Replicas]
	nodeIDs := make([]uint64, len(chosen))
	for i, n := range chosen {
		nodeIDs[i] = n.ID
	}
	f, err := s.store.CreateFile(parent.ID, name, nodeIDs)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	// 返回文件 inode + 节点详情，客户端直接拿去连接。
	resp := struct {
		Inode types.Inode      `json:"inode"`
		Nodes []types.NodeInfo `json:"nodes"`
	}{Inode: f, Nodes: chosen}
	writeJSON(w, http.StatusCreated, resp)
}

// pickAliveNodes 随机挑选 n 个剩余容量足够的活跃节点，不足返回错误。
// 除了心跳时间戳，还实时探测 master→节点的可达性：节点可能刚关机/退网，
// 心跳还没过期（30s 窗口）却已连不上——若把这种"幽灵节点"分配为副本，
// 那个副本永远传不上去，min_copies 永远差一个，commit 无限 409 到超时
// （27348 关机事故：块副本被指派到连不上的节点，大文件上传整体失败）。
func (s *Server) pickAliveNodes(n int, needBytes int64, exclude map[uint64]bool) ([]types.NodeInfo, error) {
	alive, err := s.store.ListAliveNodes(s.nodeMaxAge)
	if err != nil {
		return nil, err
	}
	// 过滤容量足够 + 未被排除的节点，再并行探测可达性（带短 TTL 缓存）。
	probe := s.healthProbe
	if probe == nil {
		probe = s.probeCached
	}
	var cands []types.NodeInfo
	for _, nd := range alive {
		if exclude[nd.ID] {
			continue // 调用方指名排除（如 reassign 时刚卡死的节点）
		}
		if nd.TotalBytes-nd.UsedBytes < needBytes {
			continue
		}
		cands = append(cands, nd)
	}
	// 并行探测：最坏 = 1 次超时，而非 N 次串行超时（大量小文件分配时尤其关键）。
	oks := make([]bool, len(cands))
	var wg sync.WaitGroup
	for i := range cands {
		wg.Add(1)
		go func(i int) { defer wg.Done(); oks[i] = probe(cands[i].Addr) }(i)
	}
	wg.Wait()
	var fit []types.NodeInfo
	for i, nd := range cands {
		if oks[i] {
			fit = append(fit, nd) // 心跳未过期且当前可达
		}
	}
	if len(fit) < n {
		return nil, fmt.Errorf("alive+reachable nodes with capacity %d < %d", len(fit), n)
	}
	rand.Shuffle(len(fit), func(i, j int) { fit[i], fit[j] = fit[j], fit[i] })
	return fit[:n], nil
}

// probeCached 是带短 TTL 缓存的 probeHealthz：命中缓存直接返回，避免每次块分配
// 都同步重探每个节点（大量小文件时这份开销乘以文件数会拖垮 folder 上传）。
func (s *Server) probeCached(nodeAddr string) bool {
	s.probeMu.Lock()
	if s.probeCache == nil {
		s.probeCache = make(map[string]probeEntry)
	}
	if e, ok := s.probeCache[nodeAddr]; ok && time.Since(e.at) < probeCacheTTL {
		s.probeMu.Unlock()
		return e.ok
	}
	s.probeMu.Unlock()
	ok := s.probeHealthz(nodeAddr)
	s.probeMu.Lock()
	s.probeCache[nodeAddr] = probeEntry{ok: ok, at: time.Now()}
	s.probeMu.Unlock()
	return ok
}

// probeHealthz 探测 master→节点的实时可达性（GET /healthz，2s 超时）。
// 连不上返回 false。用于副本分配前过滤幽灵节点。
func (s *Server) probeHealthz(nodeAddr string) bool {
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s://%s/healthz", s.nodeScheme(), nodeAddr), nil)
	if err != nil {
		return false
	}
	client := s.nodeHTTPClient(2 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

// handleAssignChunk 为 staging 文件分配块副本：POST /files/chunks
// {inode_id, index, size, replicas} → {nodes}。幂等；reassign=true 强制换节点。
func (s *Server) handleAssignChunk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InodeID  uint64   `json:"inode_id"`
		Index    int      `json:"index"`
		Size     int64    `json:"size"`
		Replicas int      `json:"replicas"`
		Reassign bool     `json:"reassign"`
		Checksum *uint32  `json:"checksum"`
		Exclude  []uint64 `json:"exclude"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.InodeID == 0 || req.Size <= 0 {
		httpError(w, http.StatusBadRequest, "inode_id and size required")
		return
	}
	if req.Replicas <= 0 {
		req.Replicas = 1
	}
	if current, err := s.store.GetInode(req.InodeID); err == nil && current.Staging {
		for _, ch := range current.Chunks {
			if ch.Index != req.Index {
				continue
			}
			if ch.Size != req.Size || ((ch.ChecksumKnown || ch.Checksum != 0) && req.Checksum != nil && ch.Checksum != *req.Checksum) {
				httpError(w, http.StatusConflict, "chunk contents changed; allocate a new upload")
				return
			}
			if !req.Reassign {
				nodes, err := s.store.NodeInfos(ch.Replicas)
				if err != nil {
					httpError(w, http.StatusInternalServerError, err.Error())
					return
				}
				writeJSON(w, http.StatusOK, chunkAssignResp{Chunk: ch, Nodes: nodes})
				return
			}
		}
	}
	var exclude map[uint64]bool
	if len(req.Exclude) > 0 {
		exclude = make(map[uint64]bool, len(req.Exclude))
		for _, id := range req.Exclude {
			exclude[id] = true
		}
	}
	chosen, err := s.pickAliveNodes(req.Replicas, req.Size, exclude)
	if err != nil {
		httpError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	nodeIDs := make([]uint64, len(chosen))
	for i, nd := range chosen {
		nodeIDs[i] = nd.ID
	}
	var chunk types.ChunkInfo
	var checksum uint32
	if req.Checksum != nil {
		checksum = *req.Checksum
	}
	if req.Reassign {
		chunk, err = s.store.ReassignChunk(req.InodeID, req.Index, nodeIDs, checksum, req.Checksum != nil)
	} else {
		chunk, err = s.store.AssignChunk(req.InodeID, req.Index, req.Size, nodeIDs, checksum, req.Checksum != nil)
	}
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, chunkAssignResp{Chunk: chunk, Nodes: chosen})
}

// chunkAssignResp 块分配响应。
type chunkAssignResp struct {
	Chunk types.ChunkInfo  `json:"chunk"`
	Nodes []types.NodeInfo `json:"nodes"`
}

// handleAbortStaging 放弃分块上传：删 staging 元数据 + 通知节点回收已落盘的块。
func (s *Server) handleAbortStaging(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || id == 0 {
		httpError(w, http.StatusBadRequest, "invalid inode id")
		return
	}
	in, err := s.store.GetInode(id)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	if !in.Staging {
		httpError(w, http.StatusBadRequest, meta.ErrNotStaging.Error())
		return
	}
	if err := s.store.AbortStaging(id); err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	// 分块 staging 回收各块对象；legacy staging 回收单对象。
	if in.Chunked {
		s.reclaimChunkObjects(in)
	} else if len(in.Replicas) > 0 {
		go s.notifyObjectDelete(in.ID, in.Replicas)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// reclaimChunkObjects 异步通知各节点删除 inode 全部块对象（abort/删除/覆盖替换回收用）。
// 块对象 ID 走 ChunkObjID（显式优先）——采纳式替换后不能按文件 ID 派生。
func (s *Server) reclaimChunkObjects(in types.Inode) {
	for _, c := range in.Chunks {
		go s.notifyObjectDelete(types.ChunkObjID(c, in.ID), c.Replicas)
	}
}

// reclaimReplacedObject 回收被替换/删除的旧版本内容对象：
//   - 分块旧版本：块对象逐块通知删除（现有通道）；
//   - v1 旧协议对象（ObjID==0）：立即通知删除（无登记表，无宽限载体）；
//   - 新协议对象（ObjID≠0）：此处不动作——meta 已在布局切换/删除事务里把对象登记为
//     retired，GC 在退休宽限期过后按两轮确认回收，迟到删除在宽限期内无法销毁新版本。
func (s *Server) reclaimReplacedObject(old types.Inode) {
	if old.Chunked {
		s.reclaimChunkObjects(old)
	} else if old.ObjID == 0 && len(old.Replicas) > 0 {
		go s.notifyObjectDelete(old.ID, old.Replicas)
	}
}

// handleCommitFile 数据写完后客户端 commit。
// 请求带 chunk_count > 0（新客户端）：校验块表 + 原子换名（staging → 正式文件），
// 被替换旧版本的块对象异步回收。否则（legacy）：更新大小 + 标记主副本 Done。
func (s *Server) handleCommitFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InodeID    uint64 `json:"inode_id"`
		Size       int64  `json:"size"`
		ChunkCount int    `json:"chunk_count"` // >0 = 分块提交（批次 C）
		Name       string `json:"name"`        // 分块提交的目标文件名
		MinCopies  int    `json:"min_copies"`  // >0 = commit 前每块需 ≥N 个 Done 且存活的副本（改进项3）
		Checksum   uint32 `json:"checksum"`    // legacy 整对象 CRC32C（0 = 未提供）
		OpID       string `json:"op_id"`       // v2-3a：幂等凭据（响应丢失后重试回放）
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	// v2-3a 幂等回放：commit 是最终写，响应丢失后重试必须返回原结果而非
	// ErrNotStaging 误报（审计 F3）。回放发生在一切校验之前——原结果即真相。
	if req.OpID != "" && req.ChunkCount > 0 {
		if rec, ok, err := s.store.GetOpResult(req.OpID); err == nil && ok {
			if err := s.store.EnsureDurable(); err != nil {
				httpError(w, http.StatusServiceUnavailable, err.Error())
				return
			}
			w.Header().Set("X-Atoll-Replay", "true")
			writeJSON(w, http.StatusOK, rec.Inode)
			return
		}
	}
	if req.ChunkCount > 0 {
		if req.InodeID == 0 || req.Name == "" || req.Size <= 0 {
			httpError(w, http.StatusBadRequest, "inode_id, name and size required")
			return
		}
		// chunk_count 一致性：客户端声明的块数必须与块表实际长度相符。
		// 此前 chunk_count 只用来选"走分块路径"、从不参与校验——客户端声称 9 块、
		// 表里实际 1 块也照收。连同 meta 层的下标连续性断言一起堵住块表残缺。
		if st, err := s.store.GetInode(req.InodeID); err == nil && st.Staging {
			if len(st.Chunks) != req.ChunkCount {
				httpError(w, http.StatusConflict, fmt.Sprintf(
					"chunk_count=%d != assigned chunks %d", req.ChunkCount, len(st.Chunks)))
				return
			}
		}
		// PUT and the asynchronous receipt can race. Recheck the node's content before
		// rejecting an otherwise complete upload; a probe response alone never marks Done.
		if st, err := s.store.GetInode(req.InodeID); err == nil && st.Staging {
			for _, c := range st.Chunks {
				if len(c.Replicas) == 0 || types.ContainsUint64(c.Done, c.Replicas[0]) {
					continue
				}
				n, err := s.store.GetNode(c.Replicas[0])
				if err != nil {
					continue
				}
				if time.Since(n.LastHeartbeat) > s.nodeMaxAge {
					continue // 节点已死，探测无意义
				}
				if types.ContainsUint64(c.Suspect, c.Replicas[0]) {
					continue
				}
				objectID := types.ChunkObjID(c, st.ID)
				if c.ChecksumKnown || c.Checksum != 0 {
					verifyReplicaAt(s.nodeHTTPClient(30*time.Second), s.nodeScheme(), n.Addr, objectID)
				} else if s.probeObject(n.Addr, objectID) {
					_, _ = s.store.MarkObjectPresent(types.ObjectIntegrity{ObjectID: objectID, InodeID: st.ID, Generation: st.Generation,
						Chunked: true, ChunkIndex: c.Index, Size: c.Size, IntegrityEpoch: c.IntegrityEpoch}, c.Replicas[0])
				}
			}
		}
		// min-copies 档位（改进项3）：每块需 ≥minCopies 个"Done 且节点存活"的副本才放行 commit。
		// minCopies<=0 = 现状（仅主副本 Done）。
		// master 侧短轮询等待：从副本同步通常一两秒内完成，与其让客户端每 30s 粗粒度重问、
		// 把"其实早就好了"的等待放大到几十秒，不如在这里以 200ms 细粒度等——副本一齐立即放行，
		// 客户端一次 commit 就返回。等待上限固定 commitWaitCap（与 nodeMaxAge 解耦：后者可能
		// 长达小时级；这里只想吸收秒级同步延迟），超时仍 409 由客户端兜底重试。
		if req.MinCopies > 0 {
			deadline := time.Now().Add(s.commitWait)
			for {
				st, err := s.store.GetInode(req.InodeID)
				if err != nil || !st.Staging {
					break // 非 staging（已被并发 commit 等）——交给下面 CommitStagingFile 处理
				}
				ready := s.countCommitReadyChunks(st, req.MinCopies)
				if ready >= len(st.Chunks) {
					break // 副本齐了，放行
				}
				if time.Now().After(deadline) {
					httpError(w, http.StatusConflict, fmt.Sprintf(
						"min_copies=%d not reached: %d/%d chunks ready", req.MinCopies, ready, len(st.Chunks)))
					return
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
		binding, secureCommit := secureCommitFrom(r.Context())
		var bindings []meta.SecureCommitBinding
		if secureCommit {
			bindings = append(bindings, binding)
		}
		in, old, hadOld, err := s.store.CommitStagingFile(req.InodeID, req.Name, req.Size, bindings...)
		if err != nil {
			httpErrorFromMeta(w, err)
			return
		}
		// 旧版本（含 legacy 整对象与旧分块）回收；失败由 GC 两轮确认兜底。
		if hadOld {
			s.reclaimReplacedObject(old)
		}
		// v2-3a：记录 op 结果供重试回放（仅分块提交路径；legacy commit 天然幂等安全）。
		if req.OpID != "" && !secureCommit {
			if err := s.store.PutOpResult(req.OpID, "commit", in); err != nil {
				httpErrorFromMeta(w, err)
				return
			}
		}
		writeJSON(w, http.StatusOK, in)
		return
	}
	// legacy：更新大小并标记主副本 Done。
	if req.InodeID == 0 {
		httpError(w, http.StatusBadRequest, "inode_id required")
		return
	}
	// 覆盖写走 staging：commit 时才原子替换旧文件（见 handleCreateFile legacy 分支）。
	// 非 staging 的普通新建文件仍走 UpdateFileSize（名字在 create 时已挂好）。
	if st, err := s.store.GetInode(req.InodeID); err == nil && st.Staging && !st.Chunked {
		in, old, hadOld, cerr := s.store.CommitLegacyStagingFile(req.InodeID, req.Size, req.Checksum)
		if cerr != nil {
			httpErrorFromMeta(w, cerr)
			return
		}
		// 被替换旧版本回收（分块旧版本回收其块对象，legacy 回收单对象）。
		if hadOld {
			s.reclaimReplacedObject(old)
		}
		writeJSON(w, http.StatusOK, in)
		return
	}
	if err := s.store.UpdateFileSize(req.InodeID, req.Size, req.Checksum); err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- 删除 ----

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	in, err := s.store.ResolvePath(r.URL.Query().Get("path"))
	if err != nil {
		httpError(w, http.StatusNotFound, "path not found")
		return
	}
	if in.Type == types.TypeFile || in.Type == types.TypeSymlink {
		// 先删元数据（客户端立刻看不到该文件），再异步通知各副本节点回收对象。
		// 回收失败不阻塞删除请求；残留对象由 GC 两轮确认兜底清理。
		// 符号链接无副本：notifyObjectDelete 遍历空列表为 no-op。
		// 新协议对象：delInode 已在同事务登记 retired，回收走退休宽限+GC，不立即删。
		if err := s.store.DeleteFile(in.ID); err != nil {
			httpErrorFromMeta(w, err)
			return
		}
		if in.Chunked {
			s.reclaimChunkObjects(in)
		} else if in.ObjID == 0 && len(in.Replicas) > 0 {
			go s.notifyObjectDelete(in.ID, in.Replicas)
		}
	} else {
		if err := s.store.DeleteDir(in.ID); err != nil {
			httpErrorFromMeta(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleCreateSymlink 创建符号链接：POST /files/symlink {"path":"/dir/name","target":"../x"}
// Finder 拷贝含符号链接的目录（真实项目树几乎必有）必走此路径。target 原样存储。
func (s *Server) handleCreateSymlink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path   string `json:"path"`
		Target string `json:"target"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	parentPath, name := splitPath(req.Path)
	if name == "" || name == "." || name == ".." {
		httpError(w, http.StatusBadRequest, "invalid path")
		return
	}
	if req.Target == "" || len(req.Target) > 4096 {
		httpError(w, http.StatusBadRequest, "invalid symlink target")
		return
	}
	parent, err := s.store.ResolvePath(parentPath)
	if err != nil {
		httpError(w, http.StatusNotFound, "parent not found")
		return
	}
	sl, err := s.store.CreateSymlink(parent.ID, name, req.Target)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		Inode types.Inode `json:"inode"`
	}{Inode: sl})
}

// handleCreateSmall 小文件单请求通道（v2-2a 修订）：POST /files/small?path=&replicas=&overwrite=
// body = 文件内容（≤ types.SmallFileMax）。协议三段：Prepare（事务内解析目标、分配不可复用
// 内容对象并登记 pending、op 重放/冲突判定）→ 写主副本（对象地址 = 新 ObjectID）→ Commit
// （同一事务做目标 CAS、内容指针切换、op 结果记录）。内容对象不复用：并发覆盖写各占一个
// 对象，失败/迟到的一方不影响已发布版本；旧对象经退休宽限后由 GC 回收。
// 要求 X-Atoll-Features: object-id-v1——不识别的旧客户端会得到 426 而不是读错对象。
func (s *Server) handleCreateSmall(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	remote := q.Get("path")
	overwrite := q.Get("overwrite") == "true"
	opID := q.Get("op_id")
	replicas := 1
	if n, err := strconv.Atoi(q.Get("replicas")); err == nil && n > 0 {
		replicas = n
	}
	parentPath, name := splitPath(remote)
	if name == "" || name == "." || name == ".." {
		httpError(w, http.StatusBadRequest, "invalid path")
		return
	}
	if r.ContentLength > types.SmallFileMax {
		httpError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("body %d > small limit %d", r.ContentLength, types.SmallFileMax))
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, types.SmallFileMax+1))
	if err != nil || int64(len(data)) == 0 || int64(len(data)) > types.SmallFileMax {
		httpError(w, http.StatusBadRequest, "empty or oversize body")
		return
	}
	// 特性门槛在 body 校验之后：请求级错误（400/413）与客户端版本无关；
	// 通过校验的旧客户端在这里被 426 拦截，绝不带着旧寻址语义触碰新对象。
	if !hasObjectIDFeature(r) {
		httpError(w, http.StatusUpgradeRequired, "small path requires "+types.ObjectIDFeature+" client feature")
		return
	}
	crc := types.CRC32C(data)
	fingerprint := fmt.Sprintf("%s|%d|%08x|%t|%d", remote, len(data), crc, overwrite, replicas)
	// 快路径回放：已完成的 op 直接返回原结果（无需选节点/落盘）。
	// kind+指纹双校验：同 op_id 不同请求（挪用）→ 409，绝不回放无关结果；
	// 跨 kind（同 op_id 曾用于 commit）同样拒绝。事务内的 Prepare/Commit 仍持权威判定。
	if opID != "" {
		if rec, ok, err := s.store.GetOpResult(opID); err == nil && ok {
			if rec.Kind != "small" || (rec.Fingerprint != "" && rec.Fingerprint != fingerprint) {
				httpError(w, http.StatusConflict, meta.ErrOpConflict.Error())
				return
			}
			if err := s.store.EnsureDurable(); err != nil {
				httpError(w, http.StatusServiceUnavailable, err.Error())
				return
			}
			w.Header().Set("X-Atoll-Replay", "true")
			writeJSON(w, http.StatusOK, struct {
				Inode types.Inode `json:"inode"`
			}{Inode: rec.Inode})
			return
		}
	}
	parent, err := s.store.ResolvePath(parentPath)
	if err != nil {
		httpError(w, http.StatusNotFound, "parent not found")
		return
	}

	// 选节点（与旧路径同规则：覆盖 legacy 文件且其主副本存活时沿用旧主副本）。
	existing, lookupErr := s.store.ResolvePath(remote)
	var replicaIDs []uint64
	var primary types.NodeInfo
	if lookupErr == nil && existing.Type == types.TypeFile && !existing.Chunked && len(existing.Replicas) > 0 {
		if n, err := s.store.GetNode(existing.Replicas[0]); err == nil && time.Since(n.LastHeartbeat) <= s.nodeMaxAge {
			primary = n
			replicaIDs = existing.Replicas
		}
	}
	if lookupErr == nil && existing.Type == types.TypeDir {
		httpError(w, http.StatusConflict, meta.ErrExist.Error())
		return
	}
	if primary.ID == 0 {
		alive, err := s.pickAliveNodes(replicas, int64(len(data)), nil)
		if err != nil {
			httpError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		primary = alive[0]
		replicaIDs = make([]uint64, len(alive))
		for i, nd := range alive {
			replicaIDs[i] = nd.ID
		}
	}

	obj, replay, perr := s.store.PrepareSmallFile(meta.SmallFileTarget{
		ParentID: parent.ID, Name: name, RemotePath: remote,
		Size: int64(len(data)), Checksum: crc,
		Replicas: replicaIDs, PrimaryID: primary.ID,
		Overwrite: overwrite, OpID: opID, Fingerprint: fingerprint,
		Mtime: time.Now(),
	})
	if perr != nil {
		httpErrorFromMeta(w, perr)
		return
	}
	if replay != nil {
		if err := s.store.EnsureDurable(); err != nil {
			httpError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		w.Header().Set("X-Atoll-Replay", "true")
		writeJSON(w, http.StatusOK, struct {
			Inode types.Inode `json:"inode"`
		}{Inode: replay.Inode})
		return
	}

	// 数据落主副本（节点侧 tmp+fsync+rename 原子写，CRC 头即时校验）。
	nodeClient := s.nodeHTTPClient(30 * time.Second)
	putReq, perr2 := http.NewRequest(http.MethodPut,
		fmt.Sprintf("%s://%s/objects/%d", s.nodeScheme(), primary.Addr, obj.ID), bytes.NewReader(data))
	if perr2 != nil {
		_ = s.store.AbortSmallFile(obj.ID)
		httpError(w, http.StatusInternalServerError, perr2.Error())
		return
	}
	putReq.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", crc))
	putResp, perr2 := nodeClient.Do(putReq)
	if perr2 != nil {
		_ = s.store.AbortSmallFile(obj.ID)
		httpError(w, http.StatusServiceUnavailable, fmt.Sprintf("write to node %s: %v", primary.Addr, perr2))
		return
	}
	io.Copy(io.Discard, putResp.Body)
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated && putResp.StatusCode != http.StatusOK {
		_ = s.store.AbortSmallFile(obj.ID)
		httpError(w, http.StatusServiceUnavailable, fmt.Sprintf("node %s: %d", primary.Addr, putResp.StatusCode))
		return
	}

	out, old, hadOld, wasReplay, cerr := s.store.CommitSmallFile(obj.ID)
	if cerr != nil {
		// 目标在 prepare→commit 窗口变化：CAS 拒绝，数据对象退休由 GC 回收。
		_ = s.store.AbortSmallFile(obj.ID)
		httpErrorFromMeta(w, cerr)
		return
	}
	if wasReplay {
		if err := s.store.EnsureDurable(); err != nil {
			httpError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		w.Header().Set("X-Atoll-Replay", "true")
		// 提交期回放（并发同 op 的慢者）：返回 200 与原结果，语义同 prepare 期回放。
		writeJSON(w, http.StatusOK, struct {
			Inode types.Inode `json:"inode"`
		}{Inode: out})
		return
	}
	// 被替换的旧版本：分块对象走现有回收；legacy 旧对象对象登记退休后由 GC 宽限回收。
	if hadOld {
		s.reclaimReplacedObject(old)
	}
	writeJSON(w, http.StatusCreated, struct {
		Inode types.Inode `json:"inode"`
	}{Inode: out})
}

// hasObjectIDFeature 检查客户端特性协商头：新对象寻址路径必须双向知情，
// 旧客户端（会把 FileID 当对象地址读）被明确拒绝而不是静默读错数据。
func hasObjectIDFeature(r *http.Request) bool {
	for _, f := range strings.Split(r.Header.Get(types.FeaturesHeader), ",") {
		if strings.TrimSpace(f) == types.ObjectIDFeature {
			return true
		}
	}
	return false
}

// handleRename 同目录内改名：POST /entry/rename {"path":..., "new_name":...}
func (s *Server) handleRename(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		NewName string `json:"new_name"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.NewName == "" || req.NewName == "." || req.NewName == ".." ||
		strings.Contains(req.NewName, "/") {
		httpError(w, http.StatusBadRequest, "invalid new_name")
		return
	}
	in, err := s.store.ResolvePath(req.Path)
	if err != nil {
		httpError(w, http.StatusNotFound, "path not found")
		return
	}
	if err := s.store.Rename(in.ID, req.NewName); err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// probeObject 探测节点上对象是否存在（Range 1 字节；404 = 不存在）。
// 网络/服务错误返回 false（保守：不标记 Done，让 commit 校验拒绝）。
func (s *Server) probeObject(nodeAddr string, objectID uint64) bool {
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s://%s/objects/%d", s.nodeScheme(), nodeAddr, objectID), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Range", "bytes=0-0")
	client := s.nodeHTTPClient(5 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	// 只有 200/206 才算"对象确实存在"。此前 `!= 404` 会把 401（token 不匹配）、
	// 500、503 等一律当存在——commit 前的落盘确认形同虚设，极端下主副本上没有
	// 对象也能 commit 成功。严格化后：非 200/206 一律保守判不存在，让 commit 校验拒绝。
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent
}

// countCommitReadyChunks 统计满足 minCopies 的块数（Done 且节点心跳未超时）。
// 节点已死时其 Done 不可信——min-copies 校验必须同时看存活（改进项1 同理）。
func (s *Server) countCommitReadyChunks(st types.Inode, minCopies int) int {
	aliveDone := make(map[uint64]bool)
	ready := 0
	for _, c := range st.Chunks {
		n := 0
		seen := make(map[uint64]bool)
		for _, nodeID := range c.Done {
			if seen[nodeID] || types.ContainsUint64(c.Suspect, nodeID) || !types.ContainsUint64(c.Replicas, nodeID) {
				continue
			}
			seen[nodeID] = true
			ok, has := aliveDone[nodeID]
			if !has {
				nd, err := s.store.GetNode(nodeID)
				ok = err == nil && time.Since(nd.LastHeartbeat) <= s.nodeMaxAge
				aliveDone[nodeID] = ok
			}
			if ok {
				n++
			}
		}
		if n >= minCopies {
			ready++
		}
	}
	return ready
}

// Deletion authority comes from the durable journal, not this caller's old replica snapshot.
func (s *Server) notifyObjectDelete(_ uint64, _ []uint64) {
	if s.scanner != nil {
		s.scanner.wakeRetirements()
	}
}

// ---- 节点 ----

func (s *Server) handleNodeRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Addr       string `json:"addr"` // 供客户端直连的 host:port
		TotalBytes int64  `json:"total_bytes"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.Addr == "" {
		httpError(w, http.StatusBadRequest, "addr is required")
		return
	}
	n, err := s.store.RegisterNode(req.Addr, req.TotalBytes)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, n)
}

func (s *Server) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID    uint64           `json:"node_id"`
		UsedBytes int64            `json:"used_bytes"`
		Usage     *types.NodeUsage `json:"usage,omitempty"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if err := s.store.HeartbeatWithUsage(req.NodeID, req.UsedBytes, req.Usage); err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- GC ----

func (s *Server) handleGC(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		httpError(w, http.StatusInternalServerError, "scanner not initialized")
		return
	}
	var req struct {
		Execute bool `json:"execute"`
	}
	if r.Body != nil {
		decodeJSON(w, r, &req)
	}
	reports, err := s.scanner.RunGC(req.Execute)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reports)
}

// ---- 工具 ----

// splitPath 把 "/a/b/c" 拆成 ("/a/b", "c")；非法路径（根、空段）返回错误由调用方处理。
func splitPath(p string) (parent, name string) {
	// 去掉尾部与重复斜杠。
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/", p[1:]
			}
			return p[:i], p[i+1:]
		}
	}
	return "/", p
}

// maxRequestBody 限制 master 接收的 JSON 请求体大小。元数据请求都很小（路径/ID/名字），
// 对象数据是客户端直连 node 的、不经过 master——1MiB 足够，且能挡住超大 body 打爆 master。
const maxRequestBody = 1 << 20

// decodeJSON 带大小上限地解码请求体（超限返回错误，由调用方转 400）。
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	return json.NewDecoder(r.Body).Decode(v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// httpErrorFromMeta 把元数据层错误映射到 HTTP 状态码。
func httpErrorFromMeta(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, meta.ErrNotExist):
		httpError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, meta.ErrExist), errors.Is(err, meta.ErrCommitFailed), errors.Is(err, meta.ErrOpConflict), errors.Is(err, meta.ErrProtectionConflict), errors.Is(err, meta.ErrProtectionBudget):
		httpError(w, http.StatusConflict, err.Error())
	case errors.Is(err, meta.ErrNotEmpty), errors.Is(err, meta.ErrNotDir), errors.Is(err, meta.ErrNotFile),
		errors.Is(err, meta.ErrNotStaging), errors.Is(err, meta.ErrChunkBadIndex), errors.Is(err, meta.ErrChunkBadSize),
		errors.Is(err, meta.ErrBadName):
		httpError(w, http.StatusBadRequest, err.Error())
	default:
		httpError(w, http.StatusInternalServerError, err.Error())
	}
}
