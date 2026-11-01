package httpapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/zypher-systems/aegis/internal/wafrules"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func (s *Server) listWAFRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, wafrules.Packages())
}

func (s *Server) listWAFProfiles(w http.ResponseWriter, r *http.Request) {
	lists, err := s.st.ListWAFProfiles(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if lists == nil {
		lists = []*store.WAFProfile{}
	}
	writeJSON(w, http.StatusOK, lists)
}

func (s *Server) getWAFProfile(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, err := s.st.GetWAFProfile(r.Context(), id)
	if err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// wafRuleIDRe: one CRS rule number. Ranges and commas would be written into
// SecLang as extra directives or actions.
var wafRuleIDRe = regexp.MustCompile(`^[0-9]{6}$`)

type wafProfileRequest struct {
	Name                string               `json:"name"`
	Mode                string               `json:"mode"`
	Paranoia            int                  `json:"paranoia"`
	InboundThreshold    int                  `json:"inbound_threshold"`
	BodyLimitBytes      int                  `json:"body_limit_bytes"`
	AllowedMethods      []string             `json:"allowed_methods"`
	AllowedContentTypes []string             `json:"allowed_content_types"`
	AnyContentType      bool                 `json:"any_content_type"`
	RestrictedHeaders   []string             `json:"restricted_headers"`
	DisabledTags        []string             `json:"disabled_tags"`
	Exclusions          []store.WAFExclusion `json:"exclusions"`
}

func (s *Server) createWAFProfile(w http.ResponseWriter, r *http.Request) {
	p, msg := buildWAFProfile(r)
	if msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	created, err := s.st.CreateWAFProfile(r.Context(), p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	s.changed()
	s.audit(r, "create", "waf_profile", created.ID.String(), map[string]any{"name": created.Name, "mode": created.Mode})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) updateWAFProfile(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := s.st.GetWAFProfile(r.Context(), id); err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	p, msg := buildWAFProfile(r)
	if msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	p.ID = id
	out, err := s.st.UpdateWAFProfile(r.Context(), p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	s.changed()
	s.audit(r, "update", "waf_profile", out.ID.String(), map[string]any{"name": out.Name, "mode": out.Mode})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteWAFProfile(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	n, err := s.st.CountHostsUsingWAFProfile(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if n > 0 {
		writeErr(w, http.StatusConflict, "profile is attached to hosts")
		return
	}
	if err := s.st.DeleteWAFProfile(r.Context(), id); err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.changed()
	s.audit(r, "delete", "waf_profile", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func buildWAFProfile(r *http.Request) (*store.WAFProfile, string) {
	var req wafProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, "invalid json"
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, "name is required"
	}
	tags := wafrules.NormalizeDisabledTags(req.DisabledTags)
	if err := wafrules.ValidateDisabledTags(tags); err != nil {
		return nil, err.Error()
	}
	ex := make([]store.WAFExclusion, 0, len(req.Exclusions))
	for _, e := range req.Exclusions {
		id := strings.TrimSpace(e.RuleID)
		if id == "" {
			continue
		}
		if !wafRuleIDRe.MatchString(id) {
			return nil, "exclusion rule id must be a CRS rule number such as 942100"
		}
		if p := strings.TrimSpace(e.Path); p != "" && (!strings.HasPrefix(p, "/") || strings.ContainsAny(p, " \"'\\\n\r;")) {
			return nil, "exclusion path must start with / and contain no spaces or quotes"
		}
		target := wafrules.NormalizeTarget(e.Target)
		if err := wafrules.ValidateTarget(target); err != nil {
			return nil, err.Error()
		}
		ex = append(ex, store.WAFExclusion{RuleID: id, Path: strings.TrimSpace(e.Path), Target: target})
	}
	return &store.WAFProfile{
		Name:                strings.TrimSpace(req.Name),
		Mode:                wafrules.NormalizeMode(req.Mode),
		Paranoia:            wafrules.NormalizeParanoia(req.Paranoia),
		InboundThreshold:    wafrules.NormalizeThreshold(req.InboundThreshold),
		BodyLimitBytes:      wafrules.NormalizeBodyLimit(req.BodyLimitBytes),
		AllowedMethods:      wafrules.NormalizeMethods(req.AllowedMethods),
		AllowedContentTypes: wafrules.NormalizeContentTypes(req.AllowedContentTypes),
		AnyContentType:      req.AnyContentType,
		RestrictedHeaders:   wafrules.NormalizeHeaders(req.RestrictedHeaders),
		DisabledTags:        tags,
		Exclusions:          ex,
	}, ""
}

// wafCatalog lists CRS rules by id with their message, category and
// paranoia level, for pickers and labels.
func (s *Server) wafCatalog(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	all := wafrules.Rules()
	out := make([]wafrules.Rule, 0, len(all))
	for _, rule := range all {
		if q == "" || strings.Contains(rule.ID, q) || strings.Contains(strings.ToLower(rule.Message), q) || strings.Contains(strings.ToLower(rule.Category), q) {
			out = append(out, rule)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// wafFindings groups WAF-flagged requests by rule over a time range, with
// enough of a sample to decide on an exclusion.
func (s *Server) wafFindings(w http.ResponseWriter, r *http.Request) {
	q := parseRollupQuery(r, time.Now().UTC())
	rows, err := s.st.WAFFindings(r.Context(), q.From, q.HostID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	type finding struct {
		store.WAFFinding
		Message  string `json:"message"`
		Category string `json:"category"`
		Paranoia int    `json:"paranoia"`
	}
	out := make([]finding, 0, len(rows))
	for _, row := range rows {
		f := finding{WAFFinding: row}
		if rule, ok := wafrules.RuleByID(row.RuleID); ok {
			f.Message, f.Category, f.Paranoia = rule.Message, rule.Category, rule.Paranoia
		}
		out = append(out, f)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": out, "from": q.From})
}
