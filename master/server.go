// Package master 实现中心服务器：元数据管理 + 副本位置分配。
package master

import (
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
	"time"

	"atoll/master/meta"
	"atoll/pkg/auth"
	"atoll/pkg/types"
)

// Server 是 master 的 HTTP 服务。
type Server struct {
	store      *meta.Store
	nodeMaxAge time.Duration // 节点心跳超时阈值
	scanner    *Scanner      // GC 需要调用
	backup     *MetaBackup   // 元数据备份状态查询/手动触发（可为 nil：未启用备份）
	token      auth.Token    // 集群认证；空 = 兼容模式
	adminToken auth.Token    // 破坏性操作（/admin/gc）专用；空 = 回退用 token
	scheme     string        // 出站访问节点的 scheme：http（默认）/https
	tlsCfg     *tls.Config   // 出站 TLS 客户端配置（nil = 普通 HTTP）
}

func NewServer(store *meta.Store, nodeMaxAge time.Duration) *Server {
	return &Server{store: store, nodeMaxAge: nodeMaxAge}
}

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

// adminPaths 需要 adminToken 的破坏性路径。/admin/objects 是只读清单、不在内。
var adminPaths = map[string]bool{"/admin/gc": true, "/admin/metabackup/trigger": true, "/admin/metabackup/config": true}

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
	mux.HandleFunc("POST /files", s.handleCreateFile)
	mux.HandleFunc("POST /files/commit", s.handleCommitFile)
	mux.HandleFunc("POST /files/chunks", s.handleAssignChunk)            // 分块：分配块副本
	mux.HandleFunc("DELETE /files/staging/{id}", s.handleAbortStaging)   // 分块：放弃上传
	mux.HandleFunc("GET /files/replica-targets", s.handleReplicaTargets) // node 查询推送目标
	mux.HandleFunc("POST /files/replicated", s.handleReplicated)         // 从副本上报同步完成
	mux.HandleFunc("POST /entry/rename", s.handleRename)                 // 同目录改名
	mux.HandleFunc("DELETE /entry", s.handleDelete)                      // ?path=/a/b
	mux.HandleFunc("POST /nodes/register", s.handleNodeRegister)
	mux.HandleFunc("POST /nodes/heartbeat", s.handleNodeHeartbeat)
	mux.HandleFunc("POST /admin/gc", s.handleGC)
	// 管理后台只读 read-model（普通集群 token 即可读；破坏性操作仍走 adminToken）。
	mux.HandleFunc("GET /admin/overview", s.handleAdminOverview)
	mux.HandleFunc("GET /admin/nodes", s.handleAdminNodes)
	mux.HandleFunc("GET /admin/repairs", s.handleAdminRepairs)
	mux.HandleFunc("GET /admin/integrity", s.handleAdminIntegrity)
	mux.HandleFunc("GET /admin/metabackup", s.handleAdminMetaBackup)
	mux.HandleFunc("POST /admin/metabackup/trigger", s.handleAdminMetaBackupTrigger)
	mux.HandleFunc("POST /admin/metabackup/config", s.handleAdminMetaBackupConfig)
	return auth.WrapTokens(mux, s.token, s.adminToken, adminPaths)
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
	// 块对象 ID ≥ 2^40：反解出所属 staging inode（必为 Chunked）。
	if inodeID >= types.StagingInodeBase<<8 {
		own, index := types.ParseChunkID(inodeID)
		in, err := s.store.GetInode(own)
		if err != nil {
			httpErrorFromMeta(w, err)
			return
		}
		// 查询推送目标 = 查询者（主副本）已落盘：顺带把它标记为块 Done。
		// 主副本的 Done 由此闭环（客户端 PUT → node 落盘 → replicateToPeers
		// 查询目标 → 此处标记），不依赖单独的上报接口。
		if err := s.store.MarkChunkDone(inodeID, nodeID); err != nil && !errors.Is(err, meta.ErrChunkNotExist) {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		var targets []types.NodeInfo
		for _, c := range in.Chunks {
			if c.Index != index {
				continue
			}
			for _, id := range c.Replicas {
				if id == nodeID || types.ContainsUint64(c.Done, id) {
					continue
				}
				n, err := s.store.GetNode(id)
				if err != nil {
					continue
				}
				if time.Since(n.LastHeartbeat) > s.nodeMaxAge {
					continue
				}
				targets = append(targets, n)
			}
			break
		}
		writeJSON(w, http.StatusOK, targets)
		return
	}
	// legacy 整对象路径（原行为）。
	in, err := s.store.GetInode(inodeID)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	var targets []types.NodeInfo
	for _, id := range in.Replicas {
		if id == nodeID || types.ContainsUint64(in.DoneReplicas, id) {
			continue // 跳过自己和已完成的
		}
		n, err := s.store.GetNode(id)
		if err != nil {
			continue
		}
		if time.Since(n.LastHeartbeat) > s.nodeMaxAge {
			continue // 已判定宕机的节点不作为推送目标
		}
		targets = append(targets, n)
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
	// 块对象 ID：写入块 Done 集合（staging 与已提交的分块文件都合法）。
	if req.InodeID >= types.StagingInodeBase<<8 {
		if err := s.store.MarkChunkDone(req.InodeID, req.NodeID); err != nil {
			httpErrorFromMeta(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if err := s.store.AddReplicaDone(req.InodeID, req.NodeID); err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
	// legacy：如果路径已存在，根据 overwrite 标记决定行为。
	if old, err := s.store.ResolvePath(req.Path); err == nil {
		if !req.Overwrite {
			httpError(w, http.StatusConflict, meta.ErrExist.Error())
			return
		}
		// overwrite=true：删除旧文件元数据并异步通知副本节点回收旧对象。
		if err := s.store.DeleteFile(old.ID); err != nil {
			httpErrorFromMeta(w, err)
			return
		}
		go s.notifyObjectDelete(old.ID, old.Replicas)
	}
	alive, err := s.store.ListAliveNodes(s.nodeMaxAge)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(alive) < req.Replicas {
		httpError(w, http.StatusServiceUnavailable, fmt.Sprintf("alive nodes %d < replicas %d", len(alive), req.Replicas))
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
func (s *Server) pickAliveNodes(n int, needBytes int64) ([]types.NodeInfo, error) {
	alive, err := s.store.ListAliveNodes(s.nodeMaxAge)
	if err != nil {
		return nil, err
	}
	// 过滤容量足够的节点（块级分配的关键：不再要求单节点装下整个文件）。
	var fit []types.NodeInfo
	for _, nd := range alive {
		if nd.TotalBytes-nd.UsedBytes >= needBytes {
			fit = append(fit, nd)
		}
	}
	if len(fit) < n {
		return nil, fmt.Errorf("alive nodes with capacity %d < %d", len(fit), n)
	}
	rand.Shuffle(len(fit), func(i, j int) { fit[i], fit[j] = fit[j], fit[i] })
	return fit[:n], nil
}

// handleAssignChunk 为 staging 文件分配块副本：POST /files/chunks
// {inode_id, index, size, replicas} → {nodes}。幂等；reassign=true 强制换节点。
func (s *Server) handleAssignChunk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InodeID  uint64 `json:"inode_id"`
		Index    int    `json:"index"`
		Size     int64  `json:"size"`
		Replicas int    `json:"replicas"`
		Reassign bool   `json:"reassign"`
		Checksum uint32 `json:"checksum"` // 块内容 CRC32C（0 = 未提供）
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
	// 已分配且非 reassign → 幂等返回（不重复扣容量决策）。
	if !req.Reassign {
		if c, err := s.store.GetInode(req.InodeID); err == nil && c.Staging {
			for _, ch := range c.Chunks {
				if ch.Index == req.Index {
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
	}
	chosen, err := s.pickAliveNodes(req.Replicas, req.Size)
	if err != nil {
		httpError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	nodeIDs := make([]uint64, len(chosen))
	for i, nd := range chosen {
		nodeIDs[i] = nd.ID
	}
	var chunk types.ChunkInfo
	if req.Reassign {
		chunk, err = s.store.ReassignChunk(req.InodeID, req.Index, nodeIDs, req.Checksum)
	} else {
		chunk, err = s.store.AssignChunk(req.InodeID, req.Index, req.Size, nodeIDs, req.Checksum)
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
	s.reclaimChunkObjects(in)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// reclaimChunkObjects 异步通知各节点删除 inode 全部块对象（abort/删除回收用）。
func (s *Server) reclaimChunkObjects(in types.Inode) {
	for _, c := range in.Chunks {
		chunkID := types.ChunkID(in.ID, c.Index)
		go s.notifyObjectDelete(chunkID, c.Replicas)
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
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
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
		// 主副本 Done 兜底：客户端 PUT 成功与 node 查询推送目标（顺带标记 Done）
		// 之间有竞态窗口——commit 前对每块主副本做一次同步探测，确认落盘即标记。
		// 探测失败的块由 ErrCommitFailed 拒绝（客户端应重试或 reassign）。
		// 同时校验主副本节点存活（改进项1）：死节点上的 Done 不可信——
		// 27472 宕机期间它的块仍标记 Done，commit 若不查心跳会把数据承诺到死节点。
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
				if s.probeObject(n.Addr, types.ChunkID(req.InodeID, c.Index)) {
					_ = s.store.MarkChunkDone(types.ChunkID(req.InodeID, c.Index), c.Replicas[0])
				}
			}
		}
		// min-copies 档位（改进项3）：每块需 ≥minCopies 个"Done 且节点存活"的副本才放行 commit。
		// minCopies<=0 = 现状（仅主副本 Done）。副本没到齐 → 409，客户端轮询重试。
		if req.MinCopies > 0 {
			if st, err := s.store.GetInode(req.InodeID); err == nil && st.Staging {
				if n := s.countCommitReadyChunks(st, req.MinCopies); n < len(st.Chunks) {
					httpError(w, http.StatusConflict, fmt.Sprintf(
						"min_copies=%d not reached: %d/%d chunks ready", req.MinCopies, n, len(st.Chunks)))
					return
				}
			}
		}
		in, old, hadOld, err := s.store.CommitStagingFile(req.InodeID, req.Name, req.Size)
		if err != nil {
			httpErrorFromMeta(w, err)
			return
		}
		// 旧版本（含 legacy 整对象与旧分块）异步回收；失败由 GC 两轮确认兜底。
		if hadOld {
			if old.Chunked {
				s.reclaimChunkObjects(old)
			} else if len(old.Replicas) > 0 {
				go s.notifyObjectDelete(old.ID, old.Replicas)
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
	if in.Type == types.TypeFile {
		// 先删元数据（客户端立刻看不到该文件），再异步通知各副本节点回收对象。
		// 回收失败不阻塞删除请求；残留对象由 GC 两轮确认兜底清理。
		if err := s.store.DeleteFile(in.ID); err != nil {
			httpErrorFromMeta(w, err)
			return
		}
		if in.Chunked {
			s.reclaimChunkObjects(in)
		} else if len(in.Replicas) > 0 {
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
	client := &http.Client{Timeout: 5 * time.Second, Transport: auth.HTTPTransport(s.token, s.tlsCfg, nil)}
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
		for _, nodeID := range c.Done {
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

// notifyObjectDelete 通知持有该对象的所有节点删除本地文件。
func (s *Server) notifyObjectDelete(inodeID uint64, replicaNodeIDs []uint64) {
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: auth.HTTPTransport(s.token, s.tlsCfg, nil),
	}
	for _, id := range replicaNodeIDs {
		n, err := s.store.GetNode(id)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s://%s/objects/%d", s.nodeScheme(), n.Addr, inodeID), nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("通知节点 %d 删除对象 %d 失败: %v", id, inodeID, err)
			continue
		}
		resp.Body.Close()
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
		NodeID    uint64 `json:"node_id"`
		UsedBytes int64  `json:"used_bytes"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if err := s.store.Heartbeat(req.NodeID, req.UsedBytes); err != nil {
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
	case errors.Is(err, meta.ErrExist), errors.Is(err, meta.ErrCommitFailed):
		httpError(w, http.StatusConflict, err.Error())
	case errors.Is(err, meta.ErrNotEmpty), errors.Is(err, meta.ErrNotDir), errors.Is(err, meta.ErrNotFile),
		errors.Is(err, meta.ErrNotStaging), errors.Is(err, meta.ErrChunkBadIndex), errors.Is(err, meta.ErrChunkBadSize),
		errors.Is(err, meta.ErrBadName):
		httpError(w, http.StatusBadRequest, err.Error())
	default:
		httpError(w, http.StatusInternalServerError, err.Error())
	}
}
