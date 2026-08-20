// Package master 实现中心服务器：元数据管理 + 副本位置分配。
package master

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"atoll/master/meta"
	"atoll/pkg/types"
)

// Server 是 master 的 HTTP 服务。
type Server struct {
	store      *meta.Store
	nodeMaxAge time.Duration // 节点心跳超时阈值
}

func NewServer(store *meta.Store, nodeMaxAge time.Duration) *Server {
	return &Server{store: store, nodeMaxAge: nodeMaxAge}
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
	mux.HandleFunc("DELETE /entry", s.handleDelete) // ?path=/a/b
	mux.HandleFunc("POST /nodes/register", s.handleNodeRegister)
	mux.HandleFunc("POST /nodes/heartbeat", s.handleNodeHeartbeat)
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
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	in, err := s.store.ResolvePath(r.URL.Query().Get("path"))
	if err != nil {
		httpError(w, http.StatusNotFound, "path not found")
		return
	}
	resp := struct {
		Inode types.Inode   `json:"inode"`
		Nodes []types.NodeInfo `json:"nodes"` // 按 inode.Replicas 顺序给出节点详情
	}{Inode: in}
	for _, id := range in.Replicas {
		n, err := s.store.GetNode(id)
		if err != nil {
			continue // 节点可能已注销，跳过
		}
		resp.Nodes = append(resp.Nodes, n)
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- 文件 ----

// handleCreateFile 创建文件记录并分配副本节点（阶段1：从活跃节点随机挑 N 个）。
func (s *Server) handleCreateFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path     string `json:"path"`
		Replicas int    `json:"replicas"` // 期望副本数，<=0 时取 1
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
		// TODO(阶段4): 通知各副本节点回收对象。当前先只删元数据。
		err = s.store.DeleteFile(in.ID)
	} else {
		err = s.store.DeleteDir(in.ID)
	}
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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


