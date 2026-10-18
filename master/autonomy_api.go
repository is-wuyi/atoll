package master

import (
	"net/http"

	"atoll/master/meta"
)

func (s *Server) SetAutonomy(a *Autonomy) { s.autonomy = a }

func (s *Server) handleAutonomyStatus(w http.ResponseWriter, r *http.Request) {
	if s.autonomy == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	snapshot, err := s.store.AutonomySnapshot()
	if err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "config": s.autonomy.Config(), "last_cycle": s.autonomy.Report(), "snapshot": snapshot,
	})
}

func (s *Server) handleAutonomyStep(w http.ResponseWriter, r *http.Request) {
	if s.autonomy == nil {
		httpError(w, http.StatusConflict, "autonomy is disabled")
		return
	}
	report, err := s.autonomy.Step(r.Context())
	if err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleAutonomyProfile(w http.ResponseWriter, r *http.Request) {
	var profile meta.NodePlacementProfile
	if err := decodeJSON(w, r, &profile); err != nil {
		httpError(w, http.StatusBadRequest, "invalid placement profile")
		return
	}
	if err := s.store.SetNodePlacementProfile(profile); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.EnsureDurable(); err != nil {
		httpError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Server) handleAutonomyCancel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PlanID string `json:"plan_id"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.PlanID == "" {
		httpError(w, http.StatusBadRequest, "plan_id required")
		return
	}
	if err := s.store.CancelProtection(req.PlanID); err != nil {
		httpErrorFromMeta(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled; uncertain in-flight reservations remain held"})
}
