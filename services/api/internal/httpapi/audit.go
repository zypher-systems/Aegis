package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.st.ListAudit(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) audit(r *http.Request, action, resourceType, resourceID string, summary map[string]any) {
	if s.st == nil {
		return
	}
	ev := &store.AuditEvent{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Summary:      sanitizeSummary(summary),
	}
	if u := userFromCtx(r); u != nil {
		id := u.ID
		ev.ActorID = &id
		ev.ActorEmail = u.Email
	}
	_ = s.st.InsertAudit(r.Context(), ev)
}

func sanitizeSummary(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if secretKey(k) {
			continue
		}
		out[k] = v
	}
	return out
}

func secretKey(k string) bool {
	lk := strings.ToLower(k)
	switch {
	case strings.Contains(lk, "password"),
		strings.Contains(lk, "token"),
		strings.Contains(lk, "secret"),
		strings.HasSuffix(lk, "_pem"),
		lk == "key",
		lk == "cert_pem",
		lk == "key_pem":
		return true
	default:
		return false
	}
}
