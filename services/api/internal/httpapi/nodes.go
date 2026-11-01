package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/zypher-systems/aegis/services/api/internal/store"
	"github.com/zypher-systems/aegis/services/api/internal/telemetry"
)

type nodeView struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	AgentVersion  string     `json:"agent_version"`
	CertExpiresAt time.Time  `json:"cert_expires_at"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	Online        bool       `json:"online"`
	Revoked       bool       `json:"revoked"`
	RPS           float64    `json:"rps"`
	P50Ms         float64    `json:"p50_ms"`
	P99Ms         float64    `json:"p99_ms"`
	Requests      int        `json:"requests"`
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.st.ListNodes(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	stats := map[string]telemetry.NodeStats{}
	if s.telemetry != nil {
		stats = s.telemetry.NodeStats()
	}
	out := make([]nodeView, 0, len(nodes))
	now := time.Now()
	for _, n := range nodes {
		v := nodeView{
			ID: n.ID.String(), Name: n.Name, AgentVersion: n.AgentVersion,
			CertExpiresAt: n.CertExpiresAt, LastSeenAt: n.LastSeenAt, CreatedAt: n.CreatedAt,
			RevokedAt: n.RevokedAt, Revoked: n.RevokedAt != nil,
		}
		if n.RevokedAt == nil && n.LastSeenAt != nil && now.Sub(*n.LastSeenAt) < 60*time.Second {
			v.Online = true
		}
		if st, ok := stats[n.ID.String()]; ok && n.RevokedAt == nil {
			v.RPS, v.P50Ms, v.P99Ms, v.Requests = st.RPS, st.P50Ms, st.P99Ms, st.Requests
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) revokeNode(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	n, err := s.st.RevokeNode(r.Context(), id)
	if err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	if s.onRevoke != nil {
		s.onRevoke(id)
	}
	s.audit(r, "revoke", "node", id.String(), map[string]any{"name": n.Name})
	w.WriteHeader(http.StatusNoContent)
}

// renameNode changes the name shown in the dashboard and in notices.
func (s *Server) renameNode(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\r\n\t") {
		writeErr(w, http.StatusBadRequest, "name must be 1–64 characters")
		return
	}
	if err := s.st.RenameNode(r.Context(), id, name); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "rename failed")
		return
	}
	s.audit(r, "update", "node", id.String(), map[string]any{"name": name})
	writeJSON(w, http.StatusOK, map[string]string{"id": id.String(), "name": name})
}
