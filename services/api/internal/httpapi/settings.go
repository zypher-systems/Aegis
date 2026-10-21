package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zypher-systems/aegis/internal/clientip"
	"github.com/zypher-systems/aegis/services/api/internal/enroll"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

// enrollTokenStatus says whether the .env bootstrap token still enrols
// anything (only until the first node) and how many generated tokens are live.
func (s *Server) enrollTokenStatus(w http.ResponseWriter, r *http.Request) {
	nodes, _ := s.st.CountNodes(r.Context())
	live, _ := s.st.ListEnrollTokens(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"bootstrap_accepted": nodes == 0,
		"nodes":              nodes,
		"live_tokens":        len(live),
	})
}

func (s *Server) listEnrollTokens(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListEnrollTokens(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// createEnrollToken mints a token shown once: default one use, one hour.
func (s *Server) createEnrollToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label      string `json:"label"`
		TTLMinutes int    `json:"ttl_minutes"`
		Uses       int    `json:"uses"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
	}
	if req.TTLMinutes <= 0 {
		req.TTLMinutes = 60
	}
	if req.TTLMinutes > 24*60 {
		writeErr(w, http.StatusBadRequest, "ttl_minutes must be at most 1440 (one day)")
		return
	}
	if req.Uses <= 0 {
		req.Uses = 1
	}
	if req.Uses > 10 {
		writeErr(w, http.StatusBadRequest, "uses must be at most 10")
		return
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		writeErr(w, http.StatusInternalServerError, "rng error")
		return
	}
	token := hex.EncodeToString(buf)
	who := ""
	if u := userFromCtx(r); u != nil {
		who = u.Email
	}
	t, err := s.st.CreateEnrollToken(r.Context(), enroll.TokenHash(token), strings.TrimSpace(req.Label), who,
		time.Now().Add(time.Duration(req.TTLMinutes)*time.Minute), req.Uses)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed")
		return
	}
	s.audit(r, "create", "enroll_token", t.ID.String(), map[string]any{"label": t.Label, "expires_at": t.ExpiresAt, "uses": t.UsesLeft})
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "meta": t})
}

func (s *Server) deleteEnrollToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteEnrollToken(r.Context(), id); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.audit(r, "delete", "enroll_token", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) dnsCloudflareStatus(w http.ResponseWriter, r *http.Request) {
	configured := false
	if s.env != nil {
		if b, err := s.st.GetSetting(r.Context(), store.SettingDNSCloudflareToken, s.env.Open); err == nil && len(b) > 0 {
			configured = true
		}
	}
	if !configured && s.certs != nil && s.certs.HasCloudflareBootstrap() {
		configured = true
	}
	writeJSON(w, http.StatusOK, map[string]bool{"configured": configured})
}

func (s *Server) putDNSCloudflare(w http.ResponseWriter, r *http.Request) {
	if s.env == nil {
		writeErr(w, http.StatusInternalServerError, "envelope unavailable")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Token == "" {
		writeErr(w, http.StatusBadRequest, "token is required")
		return
	}
	if err := s.st.SetSetting(r.Context(), store.SettingDNSCloudflareToken, []byte(req.Token), s.env.Seal); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed")
		return
	}
	s.audit(r, "update", "settings", "dns.cloudflare.api_token", map[string]any{"configured": true})
	writeJSON(w, http.StatusOK, map[string]bool{"configured": true})
}

func (s *Server) trustedProxyStatus(w http.ResponseWriter, _ *http.Request) {
	s.muTrusted.RLock()
	cidrs := append([]string(nil), s.trustedProxyCIDRs...)
	s.muTrusted.RUnlock()
	if cidrs == nil {
		cidrs = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"cidrs": cidrs})
}

func (s *Server) putTrustedProxy(w http.ResponseWriter, r *http.Request) {
	if s.env == nil {
		writeErr(w, http.StatusInternalServerError, "envelope unavailable")
		return
	}
	var req struct {
		CIDRs []string `json:"cidrs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	cidrs, err := clientip.Normalize(req.CIDRs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid cidr: "+err.Error())
		return
	}
	for _, c := range cidrs {
		if defaultRoute(c) {
			writeErr(w, http.StatusBadRequest, c+" would trust every address, so any visitor could spoof their IP; list the proxy's own range instead")
			return
		}
	}
	raw, err := json.Marshal(map[string]any{"cidrs": cidrs})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "encode failed")
		return
	}
	if err := s.st.SetSetting(r.Context(), store.SettingTrustedProxyCIDRs, raw, s.env.Seal); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed")
		return
	}
	s.setTrustedProxyCIDRs(cidrs)
	s.changed()
	s.audit(r, "update", "settings", "trusted_proxy.cidrs", map[string]any{"count": len(cidrs)})
	writeJSON(w, http.StatusOK, map[string]any{"cidrs": cidrs})
}

func (s *Server) geoipStatus(w http.ResponseWriter, _ *http.Request) {
	ready := geoIPReady(s.geoipPath)
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": ready,
		"ready":      ready,
		"path":       s.geoipPath,
	})
}

func geoIPReady(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func (s *Server) telemetryStats(w http.ResponseWriter, _ *http.Request) {
	var n int64
	if s.telemetry != nil {
		n = s.telemetry.Received()
	}
	writeJSON(w, http.StatusOK, map[string]int64{"received": n})
}
