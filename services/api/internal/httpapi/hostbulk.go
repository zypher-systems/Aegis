package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

// bulkHosts applies one action to many hosts. Each host goes through the
// same store update as a single edit, so validation and the "domain taken"
// checks still apply; the config push happens once at the end.
func (s *Server) bulkHosts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs          []string `json:"ids"`
		Action       string   `json:"action"` // enable | disable | delete | set_access_list | set_waf_profile
		AccessListID *string  `json:"access_list_id"`
		WAFProfileID *string  `json:"waf_profile_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 500 {
		writeErr(w, http.StatusBadRequest, "ids must hold 1–500 host ids")
		return
	}
	var listID, profileID *uuid.UUID
	switch req.Action {
	case "enable", "disable", "delete":
	case "set_access_list":
		if req.AccessListID != nil && *req.AccessListID != "" {
			id, err := uuid.Parse(*req.AccessListID)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "invalid access_list_id")
				return
			}
			listID = &id
		}
	case "set_waf_profile":
		if req.WAFProfileID != nil && *req.WAFProfileID != "" {
			id, err := uuid.Parse(*req.WAFProfileID)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "invalid waf_profile_id")
				return
			}
			profileID = &id
		}
	default:
		writeErr(w, http.StatusBadRequest, "action must be enable, disable, delete, set_access_list or set_waf_profile")
		return
	}
	type failure struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	var done int
	var failed []failure
	for _, raw := range req.IDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			failed = append(failed, failure{raw, "invalid id"})
			continue
		}
		if req.Action == "delete" {
			if err := s.st.DeleteHost(r.Context(), id); err != nil {
				failed = append(failed, failure{raw, hostErrText(err, "delete failed")})
				continue
			}
			s.audit(r, "delete", "host", raw, map[string]any{"bulk": true})
			done++
			continue
		}
		h, err := s.st.GetHost(r.Context(), id)
		if err != nil {
			failed = append(failed, failure{raw, hostErrText(err, "load failed")})
			continue
		}
		switch req.Action {
		case "enable":
			h.Enabled = true
		case "disable":
			h.Enabled = false
		case "set_access_list":
			h.AccessListID = listID
		case "set_waf_profile":
			h.WAFProfileID = profileID
		}
		if _, err := s.st.UpdateHost(r.Context(), h); err != nil {
			failed = append(failed, failure{raw, hostErrText(err, "update failed")})
			continue
		}
		s.audit(r, "update", "host", raw, map[string]any{"bulk": req.Action, "domains": h.DomainNames})
		done++
	}
	if done > 0 {
		s.changed()
	}
	if failed == nil {
		failed = []failure{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"done": done, "failed": failed})
}

func hostErrText(err error, fallback string) string {
	if err == store.ErrNotFound {
		return "not found"
	}
	var dc *store.DomainConflictError
	if errors.As(err, &dc) {
		return dc.Error()
	}
	return fallback
}

// hostExport is the portable form of one host: no ids, and its access
// list, WAF profile and certificate named so they resolve on another
// install. It is the host JSON minus identity fields.
type hostExport = map[string]any

const hostExportFormat = 1

func (s *Server) exportHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.st.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	lists, _ := s.st.ListAccessLists(r.Context())
	profiles, _ := s.st.ListWAFProfiles(r.Context())
	certs, _ := s.st.ListCertificateMeta(r.Context())
	listName := map[uuid.UUID]string{}
	for _, l := range lists {
		listName[l.ID] = l.Name
	}
	profileName := map[uuid.UUID]string{}
	for _, p := range profiles {
		profileName[p.ID] = p.Name
	}
	certDomains := map[uuid.UUID][]string{}
	for _, c := range certs {
		certDomains[c.ID] = c.Domains
	}
	out := make([]hostExport, 0, len(hosts))
	for _, h := range hosts {
		raw, _ := json.Marshal(h)
		var m hostExport
		_ = json.Unmarshal(raw, &m)
		for _, k := range []string{"id", "created_at", "updated_at", "cert_id", "access_list_id", "waf_profile_id"} {
			delete(m, k)
		}
		if h.AccessListID != nil {
			m["access_list_name"] = listName[*h.AccessListID]
		}
		if h.WAFProfileID != nil {
			m["waf_profile_name"] = profileName[*h.WAFProfileID]
		}
		if h.CertID != nil && h.TLSMode == "custom" {
			m["cert_domains"] = certDomains[*h.CertID]
		}
		out = append(out, m)
	}
	s.audit(r, "export", "host", "", map[string]any{"count": len(out)})
	w.Header().Set("Content-Disposition", `attachment; filename="aegis-hosts-`+time.Now().UTC().Format("20060102-150405")+`.json"`)
	writeJSON(w, http.StatusOK, map[string]any{
		"aegis_hosts_export": hostExportFormat,
		"exported_at":        time.Now().UTC(),
		"hosts":              out,
	})
}

// importHosts creates hosts from an export. A host whose domain is already
// configured is skipped, or replaced when mode is "update". Named access
// lists, WAF profiles and custom certificates must already exist here;
// a host naming one that does not is reported and left out rather than
// imported unprotected.
func (s *Server) importHosts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode  string            `json:"mode"` // skip (default) | update
		Hosts []json.RawMessage `json:"hosts"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Mode == "" {
		req.Mode = "skip"
	}
	if req.Mode != "skip" && req.Mode != "update" {
		writeErr(w, http.StatusBadRequest, "mode must be skip or update")
		return
	}
	if len(req.Hosts) == 0 || len(req.Hosts) > 1000 {
		writeErr(w, http.StatusBadRequest, "hosts must hold 1–1000 entries")
		return
	}
	ctx := r.Context()
	lists, _ := s.st.ListAccessLists(ctx)
	profiles, _ := s.st.ListWAFProfiles(ctx)
	certs, _ := s.st.ListCertificateMeta(ctx)
	existing, err := s.st.ListHosts(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	listByName := map[string]uuid.UUID{}
	for _, l := range lists {
		listByName[strings.ToLower(l.Name)] = l.ID
	}
	profileByName := map[string]uuid.UUID{}
	for _, p := range profiles {
		profileByName[strings.ToLower(p.Name)] = p.ID
	}
	certByDomains := map[string]uuid.UUID{}
	for _, c := range certs {
		certByDomains[domainKey(c.Domains)] = c.ID
	}
	byDomain := map[string]*store.Host{}
	for _, h := range existing {
		for _, d := range h.DomainNames {
			byDomain[strings.ToLower(d)] = h
		}
	}

	type problem struct {
		Domains []string `json:"domains"`
		Error   string   `json:"error"`
	}
	var created, updated, skipped int
	problems := []problem{}
	changed := false
	for _, raw := range req.Hosts {
		var hr hostRequest
		if err := json.Unmarshal(raw, &hr); err != nil {
			problems = append(problems, problem{nil, "not a host object"})
			continue
		}
		var names struct {
			AccessListName *string  `json:"access_list_name"`
			WAFProfileName *string  `json:"waf_profile_name"`
			CertDomains    []string `json:"cert_domains"`
		}
		_ = json.Unmarshal(raw, &names)
		h := hr.toHost()
		h.CertID, h.AccessListID, h.WAFProfileID = nil, nil, nil
		if names.AccessListName != nil && *names.AccessListName != "" {
			id, ok := listByName[strings.ToLower(*names.AccessListName)]
			if !ok {
				problems = append(problems, problem{h.DomainNames, "access list \"" + *names.AccessListName + "\" does not exist here; create it first"})
				continue
			}
			h.AccessListID = &id
		}
		if names.WAFProfileName != nil && *names.WAFProfileName != "" {
			id, ok := profileByName[strings.ToLower(*names.WAFProfileName)]
			if !ok {
				problems = append(problems, problem{h.DomainNames, "WAF profile \"" + *names.WAFProfileName + "\" does not exist here; create it first"})
				continue
			}
			h.WAFProfileID = &id
		}
		if h.TLSMode == "custom" {
			id, ok := certByDomains[domainKey(names.CertDomains)]
			if !ok {
				problems = append(problems, problem{h.DomainNames, "its custom certificate is not uploaded here; upload it first or set tls_mode to auto"})
				continue
			}
			h.CertID = &id
		}
		if msg := validateHost(h); msg != "" {
			problems = append(problems, problem{h.DomainNames, msg})
			continue
		}
		var match *store.Host
		for _, d := range h.DomainNames {
			if e := byDomain[strings.ToLower(d)]; e != nil {
				match = e
				break
			}
		}
		if match != nil {
			if req.Mode == "skip" {
				skipped++
				continue
			}
			h.ID = match.ID
			if _, err := s.st.UpdateHost(ctx, h); err != nil {
				problems = append(problems, problem{h.DomainNames, hostErrText(err, "update failed")})
				continue
			}
			s.audit(r, "update", "host", h.ID.String(), map[string]any{"import": true, "domains": h.DomainNames})
			updated++
			changed = true
			continue
		}
		out, err := s.st.CreateHost(ctx, h)
		if err != nil {
			problems = append(problems, problem{h.DomainNames, hostErrText(err, "create failed")})
			continue
		}
		for _, d := range out.DomainNames {
			byDomain[strings.ToLower(d)] = out
		}
		s.audit(r, "create", "host", out.ID.String(), map[string]any{"import": true, "domains": out.DomainNames})
		created++
		changed = true
	}
	if changed {
		s.changed()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"created": created, "updated": updated, "skipped": skipped, "problems": problems,
	})
}

func domainKey(d []string) string {
	c := make([]string, 0, len(d))
	for _, x := range d {
		c = append(c, strings.ToLower(strings.TrimSpace(x)))
	}
	sort.Strings(c)
	return strings.Join(c, ",")
}
