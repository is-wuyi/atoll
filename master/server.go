// Package master 实现中心服务器：元数据管理 + 副本位置分配。
package master

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

// Server 是 master 的 HTTP 服务。
type Server struct {
	store      *meta.Store
	nodeMaxAge time.Duration // 节点心跳超时阈值
	scanner    *Scanner      // GC 需要调用
}

func NewServer(store *meta.Store, nodeMaxAge time.Duration) *Server {
	return &Server{store: store, nodeMaxAge: nodeMaxAge}
}

// SetScanner 绑定扫描器，供 /admin/gc 等接口使用。
func (s *Server) SetScanner(scanner *Scanner) {
	s.scanner = scanner
}

// Handler 返回全部路由。
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
	mux.HandleFunc("GET /files/replica-targets", s.handleReplicaTargets) // node 查询推送目标
	mux.HandleFunc("POST /files/replicated", s.handleReplicated)         // 从副本上报同步完成
	mux.HandleFunc("POST /entry/rename", s.handleRename)                 // 同目录改名
	mux.HandleFunc("DELETE /entry", s.handleDelete) // ?path=/a/b
	mux.HandleFunc("POST /nodes/register", s.handleNodeRegister)
	mux.HandleFunc("POST /nodes/heartbeat", s.handleNodeHeartbeat)
	mux.HandleFunc("POST /admin/gc", s.handleGC)
	return mux
}

// ---- 目录 ----

func (s *Server) handleCreateDir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
// 每个节点带 done 标记：true = 已确认同步完成，读优先挑这些节点。
// 心跳过期（判定宕机）的节点不返回，避免客户端连不可达地址。
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
	for _, id := range in.Replicas {
		n, err := s.store.GetNode(id)
		if err != nil {
			continue // 节点可能已注销，跳过
		}
		if time.Since(n.LastHeartbeat) > s.nodeMaxAge {
			continue // 已判定宕机，不提供给客户端
		}
		resp.Nodes = append(resp.Nodes, nodeEntry{NodeInfo: n, Done: contains(in.DoneReplicas, id)})
	}
	writeJSON(w, http.StatusOK, resp)
}

// nodeEntry 是 lookup 响应中的节点条目：节点详情 + 副本同步状态。
type nodeEntry struct {
	types.NodeInfo
	Done bool `json:"done"`
}

func contains(list []uint64, v uint64) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// handleReplicaTargets 主副本节点查询：除自己外还需要推送到哪些节点。
// ?inode_id=N&node_id=self
func (s *Server) handleReplicaTargets(w http.ResponseWriter, r *http.Request) {
	inodeID, _ := strconv.ParseUint(r.URL.Query().Get("inode_id"), 10, 64)
	nodeID, _ := strconv.ParseUint(r.URL.Query().Get("node_id"), 10, 64)
	if inodeID == 0 || nodeID == 0 {
		httpError(w, http.StatusBadRequest, "inode_id and node_id required")
		return
	}
	in, err := s.store.GetInode(inodeID)
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	var targets []types.NodeInfo
	for _, id := range in.Replicas {
		if id == nodeID || contains(in.DoneReplicas, id) {
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

// handleReplicated 从副本同步完成后上报，把自己加入 DoneReplicas。
func (s *Server) handleReplicated(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InodeID uint64 `json:"inode_id"`
		NodeID  uint64 `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.InodeID == 0 || req.NodeID == 0 {
		httpError(w, http.StatusBadRequest, "inode_id and node_id required")
		return
	}
	if err := s.store.AddReplicaDone(req.InodeID, req.NodeID); err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- 文件 ----

// handleCreateFile 创建文件记录并分配副本节点（阶段1：从活跃节点随机挑 N 个）。
func (s *Server) handleCreateFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path      string `json:"path"`
		Replicas  int    `json:"replicas"`  // 期望副本数，<=0 时取 1
		Overwrite bool   `json:"overwrite"` // 覆盖已有文件
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	// 如果路径已存在，根据 overwrite 标记决定行为。
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
		Inode types.Inode     `json:"inode"`
		Nodes []types.NodeInfo `json:"nodes"`
	}{Inode: f, Nodes: chosen}
	writeJSON(w, http.StatusCreated, resp)
}

// handleCommitFile 数据写完后客户端回报实际大小，master 更新元数据。
func (s *Server) handleCommitFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InodeID uint64 `json:"inode_id"`
		Size    int64  `json:"size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if err := s.store.UpdateFileSize(req.InodeID, req.Size); err != nil {
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
		// 回收失败不阻塞删除请求；残留对象由阶段 4 的对账任务兜底清理。
		if err := s.store.DeleteFile(in.ID); err != nil {
			httpErrorFromMeta(w, err)
			return
		}
		go s.notifyObjectDelete(in.ID, in.Replicas)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

// notifyObjectDelete 通知持有该对象的所有节点删除本地文件。
func (s *Server) notifyObjectDelete(inodeID uint64, replicaNodeIDs []uint64) {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, id := range replicaNodeIDs {
		n, err := s.store.GetNode(id)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("http://%s/objects/%d", n.Addr, inodeID), nil)
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
		Addr        string `json:"addr"` // 供客户端直连的 host:port
		TotalBytes  int64  `json:"total_bytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		json.NewDecoder(r.Body).Decode(&req)
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
	case errors.Is(err, meta.ErrExist):
		httpError(w, http.StatusConflict, err.Error())
	case errors.Is(err, meta.ErrNotEmpty), errors.Is(err, meta.ErrNotDir), errors.Is(err, meta.ErrNotFile):
		httpError(w, http.StatusBadRequest, err.Error())
	default:
		httpError(w, http.StatusInternalServerError, err.Error())
	}
}


