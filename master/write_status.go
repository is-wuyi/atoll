package master

import (
	"net/http"
	"strconv"
	"time"

	"atoll/pkg/types"
)

func (s *Server) handleWriteStatus(w http.ResponseWriter, r *http.Request) {
	actor, err := s.writeActor(r)
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	id, err := strconv.ParseUint(r.URL.Query().Get("upload_id"), 10, 64)
	if err != nil {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "write binding required")
		return
	}
	revision, err := strconv.ParseUint(r.URL.Query().Get("revision"), 10, 64)
	if err != nil {
		writePlanningError(w, http.StatusBadRequest, "invalid_write_request", "write binding required")
		return
	}
	out, err := s.store.PlannedWriteStatus(actor, types.WriteBinding{UploadID: id, PlanID: r.URL.Query().Get("plan_id"), Revision: revision}, s.nodeMaxAge, time.Now())
	if err != nil {
		writePlanningMetaError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
