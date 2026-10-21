package httpapi

import (
	"context"
	"net/http"
	"time"
)

type depStatus struct {
	Status   string `json:"status"`
	Version  string `json:"version,omitempty"`
	Postgres bool   `json:"postgres"`
	Redis    bool   `json:"redis"`
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	st := s.depStatus(r.Context())
	st.Status = "ok"
	st.Version = s.version
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	st := s.depStatus(r.Context())
	if !st.Postgres || !st.Redis {
		st.Status = "unavailable"
		writeJSON(w, http.StatusServiceUnavailable, st)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) depStatus(ctx context.Context) depStatus {
	out := depStatus{Status: "ok"}
	if s.st != nil {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		out.Postgres = s.st.Ping(c) == nil
	}
	if s.rdb != nil {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		out.Redis = s.rdb.Ping(c).Err() == nil
	}
	return out
}
