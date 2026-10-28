package master

import (
	"net/http"
	"time"

	"atoll/pkg/types"
)

func (s *Server) handleWriteProgress(w http.ResponseWriter, r *http.Request) {
	var report types.WriteProgress
	if err := decodeJSON(w, r, &report); err != nil {
		httpError(w, http.StatusBadRequest, "invalid write progress")
		return
	}
	if err := s.store.RecordWriteProgress(report, time.Now()); err != nil {
		httpError(w, http.StatusConflict, "write progress rejected")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"recorded": true})
}
