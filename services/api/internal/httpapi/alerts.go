package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zypher-systems/aegis/services/api/internal/alerts"
)

func (s *Server) alertsStatus(w http.ResponseWriter, _ *http.Request) {
	url := ""
	if s.alerts != nil {
		url = s.alerts.WebhookURL()
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": url != "", "hint": alerts.Hint(url)})
}

func (s *Server) putAlerts(w http.ResponseWriter, r *http.Request) {
	if s.alerts == nil {
		writeErr(w, http.StatusServiceUnavailable, "alerts unavailable")
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.alerts.SetWebhook(r.Context(), req.URL); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	url := s.alerts.WebhookURL()
	s.audit(r, "update", "settings", "alerts.webhook", map[string]any{"configured": url != "", "host": alerts.Hint(url)})
	writeJSON(w, http.StatusOK, map[string]any{"configured": url != "", "hint": alerts.Hint(url)})
}

func (s *Server) testAlerts(w http.ResponseWriter, r *http.Request) {
	if s.alerts == nil {
		writeErr(w, http.StatusServiceUnavailable, "alerts unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.alerts.Test(ctx); err != nil {
		writeErr(w, http.StatusBadGateway, "test delivery failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
