package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zypher-systems/aegis/services/api/internal/store"
	"github.com/zypher-systems/aegis/services/api/internal/telemetry"
)

func (s *Server) analyticsLive(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	var events []telemetry.Event
	if s.telemetry != nil {
		events = s.telemetry.Live(limit)
	}
	if events == nil {
		events = []telemetry.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

// analyticsRequests pages the persisted request log, newest first.
// Filters: from, to (RFC3339), host_id, country, ip, stage, outcome
// (blocked|flagged|served), rule, status (2..5), method, path, q, id; paging:
// limit (max 200) and cursor (the previous page's next).
func (s *Server) analyticsRequests(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	q := store.RequestLogQuery{
		HostID:    strings.TrimSpace(v.Get("host_id")),
		Country:   strings.TrimSpace(v.Get("country")),
		ClientIP:  strings.TrimSpace(v.Get("ip")),
		Stage:     strings.TrimSpace(v.Get("stage")),
		Outcome:   strings.TrimSpace(v.Get("outcome")),
		RuleID:    strings.TrimSpace(v.Get("rule")),
		Method:    strings.TrimSpace(v.Get("method")),
		Path:      v.Get("path"),
		Search:    strings.TrimSpace(v.Get("q")),
		RequestID: strings.TrimSpace(v.Get("id")),
		Cursor:    v.Get("cursor"),
	}
	if t, err := time.Parse(time.RFC3339, v.Get("from")); err == nil {
		q.From = t
	}
	if t, err := time.Parse(time.RFC3339, v.Get("to")); err == nil {
		q.To = t
	}
	if n, err := strconv.Atoi(v.Get("status")); err == nil {
		q.Status = n
	}
	if n, err := strconv.Atoi(v.Get("limit")); err == nil {
		q.Limit = n
	}
	page, err := s.st.ListRequestLog(r.Context(), q)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	mode := telemetry.LogAll
	if s.telemetry != nil {
		mode = s.telemetry.LogMode()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events":       page.Events,
		"next":         page.Next,
		"count":        page.Count,
		"count_capped": page.Count > store.RequestLogCountCap,
		"log_mode":     mode,
	})
}

func (s *Server) analyticsSummary(w http.ResponseWriter, _ *http.Request) {
	if s.telemetry == nil {
		writeJSON(w, http.StatusOK, telemetry.New(telemetry.Options{}).Summary())
		return
	}
	writeJSON(w, http.StatusOK, s.telemetry.Summary())
}

func (s *Server) analyticsRollups(w http.ResponseWriter, r *http.Request) {
	q := parseRollupQuery(r, time.Now().UTC())
	rows, truncated, err := s.st.ListRollups(r.Context(), q.Daily, q.From, q.To, q.HostID, q.Group)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if rows == nil {
		rows = []store.RollupRow{}
	}
	// truncated: more rows matched than one response carries, and the oldest
	// buckets (the quietest hosts for group=host) were left out.
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "period": q.Period, "from": q.From, "to": q.To, "truncated": truncated})
}

func (s *Server) analyticsGeo(w http.ResponseWriter, r *http.Request) {
	if s.st == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rows": []store.GeoRollupRow{}, "period": "hourly"})
		return
	}
	q := parseRollupQuery(r, time.Now().UTC())
	rows, err := s.st.ListGeo(r.Context(), q.Daily, q.From, q.To, q.HostID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if rows == nil {
		rows = []store.GeoRollupRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "period": q.Period, "from": q.From, "to": q.To})
}

type rollupQuery struct {
	Daily  bool
	From   time.Time
	To     time.Time
	HostID string
	Period string
	// Group is the rollups-only "group" parameter: "bucket" sums hosts away,
	// "host" sums buckets away, anything else returns the stored rows.
	Group store.RollupGroup
}

func parseRollupQuery(r *http.Request, now time.Time) rollupQuery {
	daily := r.URL.Query().Get("period") == "daily"
	from, to := now.Add(-24*time.Hour), now.Add(time.Hour)
	if daily {
		from = now.Add(-30 * 24 * time.Hour)
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}
	hostID := strings.TrimSpace(r.URL.Query().Get("host_id"))
	period := "hourly"
	if daily {
		period = "daily"
	}
	group := store.RollupRaw
	switch r.URL.Query().Get("group") {
	case string(store.RollupByBucket):
		group = store.RollupByBucket
	case string(store.RollupByHost):
		group = store.RollupByHost
	}
	return rollupQuery{Daily: daily, From: from, To: to, HostID: hostID, Period: period, Group: group}
}
