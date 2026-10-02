package master

import (
	"net/http"

	"atoll/master/meta"
)

// handleReportSuspect 标记可疑的整对象副本。使用独立端点，以免旧 master 把新协议
// 当作无版本校验的 /files/corrupt 执行删除；旧服务返回 404 时客户端只记日志。
func (s *Server) handleReportSuspect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InodeID    uint64  `json:"inode_id"`
		NodeID     uint64  `json:"node_id"`
		Generation *uint64 `json:"generation"`
		Size       *int64  `json:"size"`
		Checksum   *uint32 `json:"checksum"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httpError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.InodeID == 0 || req.NodeID == 0 || req.Generation == nil || req.Size == nil ||
		req.Checksum == nil || *req.Size < 0 || *req.Checksum == 0 {
		httpError(w, http.StatusBadRequest, "inode_id, node_id, generation, size and recorded checksum required")
		return
	}
	changed, err := s.store.MarkLegacyReplicaSuspect(req.InodeID, req.NodeID, *req.Generation, *req.Size, *req.Checksum)
	if err != nil {
		if err == meta.ErrNotExist {
			writeJSON(w, http.StatusOK, map[string]bool{"marked": false})
			return
		}
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"marked": changed})
}
