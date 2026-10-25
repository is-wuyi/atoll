package master

import (
	"net/http"
	"time"

	"atoll/master/meta"
)

// handleProtectionProgress 接收目标节点对一次保护传输尝试的进度/失败反馈。
// secure 模式下 allowDeviceMetadata 已限定上报者必须是已认证设备且 node_id
// 与会话一致；这里再校验反馈身份并交给事务性 RecordProtectionProgress。
func (s *Server) handleProtectionProgress(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PlanID      string `json:"plan_id"`
		ObjectID    uint64 `json:"object_id"`
		NodeID      uint64 `json:"node_id"`
		Attempt     uint32 `json:"attempt"`
		BytesDone   int64  `json:"bytes_done"`
		GoodputBPS  uint64 `json:"goodput_bps"`
		FailureKind string `json:"failure_kind"`
		Message     string `json:"message"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.PlanID == "" || req.ObjectID == 0 || req.NodeID == 0 {
		httpError(w, http.StatusBadRequest, "plan_id, object_id and node_id are required")
		return
	}
	report := meta.ProtectionProgressReport{
		PlanID:      req.PlanID,
		ObjectID:    req.ObjectID,
		NodeID:      req.NodeID,
		Attempt:     req.Attempt,
		BytesDone:   req.BytesDone,
		GoodputBPS:  req.GoodputBPS,
		FailureKind: req.FailureKind,
		Message:     req.Message,
		Now:         time.Now(),
	}
	renew := meta.ProtectionRenewPolicy{}
	if s.autonomy != nil {
		renew = s.autonomy.RenewPolicy()
	}
	renewed, err := s.store.RecordProtectionProgress(report, renew)
	if err != nil {
		httpError(w, http.StatusBadRequest, "progress report rejected")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"recorded": true, "renewed": renewed})
}
