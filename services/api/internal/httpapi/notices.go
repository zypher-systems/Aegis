package httpapi

import (
	"net/http"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func (s *Server) listNotices(w http.ResponseWriter, r *http.Request) {
	if s.st == nil || s.env == nil {
		writeJSON(w, http.StatusOK, []store.Notice{})
		return
	}
	n, err := s.st.ListNotices(r.Context(), s.env.Open)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if n == nil {
		n = []store.Notice{}
	}
	writeJSON(w, http.StatusOK, n)
}
