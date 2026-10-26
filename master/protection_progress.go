package master

import (
	"log"
	"net/http"
	"time"

	"atoll/internal/scheduler"
	"atoll/master/meta"
	"atoll/pkg/types"
)

func (s *Server) handleProtectionProgress(w http.ResponseWriter, r *http.Request) {
	var req types.ProtectionProgress
	if err := decodeJSON(w, r, &req); err != nil || req.PlanID == "" || req.ObjectID == 0 || req.NodeID == 0 {
		httpError(w, http.StatusBadRequest, "plan_id, object_id and node_id are required")
		return
	}
	now := time.Now()
	report := meta.ProtectionProgressReport{PlanID: req.PlanID, ObjectID: req.ObjectID, NodeID: req.NodeID, Attempt: req.Attempt, AttemptToken: req.AttemptToken, Generation: req.Generation, IntegrityEpoch: req.IntegrityEpoch, BytesDone: req.BytesDone, GoodputBPS: req.GoodputBPS, FailureKind: req.FailureKind, Message: req.Message, Now: now}
	renew := meta.ProtectionRenewPolicy{}
	if s.autonomy != nil {
		renew = s.autonomy.RenewPolicy()
	}
	result, err := s.store.RecordProtectionProgressResult(report, renew)
	if err != nil {
		httpError(w, http.StatusBadRequest, "progress report rejected")
		return
	}
	if result.Recorded && result.SourceID != 0 && (result.GoodputBPS > 0 || req.FailureKind != "") {
		path := scheduler.TransferHTTP
		if s.security != nil || s.scheme == "https" {
			path = scheduler.TransferHTTPS
		}
		// Source/target come from the authenticated attempt, never a caller-supplied link.
		if err := s.RecordTransferObservation(types.TransferObservation{FromNodeID: result.SourceID, ToNodeID: req.NodeID, Path: path, Available: req.FailureKind == "", ThroughputBPS: result.GoodputBPS, ObservedAt: now}, now); err != nil {
			log.Printf("protection transfer observation: %v", err)
		}
	}
	writeJSON(w, http.StatusOK, result)
}
