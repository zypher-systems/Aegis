package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/zypher-systems/aegis/services/api/internal/certsvc"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func (s *Server) certStatus(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil {
		writeJSON(w, http.StatusOK, map[string]bool{"self_signed": true, "acme_email": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"self_signed": s.certs.SelfSigned(),
		"acme_email":  s.certs.ACMEEmailConfigured(),
	})
}

func (s *Server) listCerts(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil {
		writeJSON(w, http.StatusOK, []*store.Certificate{})
		return
	}
	list, err := s.certs.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	statuses := s.certs.RenewalStatuses()
	type certView struct {
		*store.Certificate
		Renewal *certsvc.RenewalStatus `json:"renewal,omitempty"`
	}
	out := make([]certView, 0, len(list))
	for _, c := range list {
		v := certView{Certificate: c}
		if st, ok := statuses[c.ID]; ok {
			v.Renewal = &st
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// renewCert forces an in-place renewal now.
func (s *Server) renewCert(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil {
		writeErr(w, http.StatusServiceUnavailable, "certificate service unavailable")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	c, err := s.certs.RenewNow(r.Context(), id)
	if err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusBadGateway, "renewal failed: "+err.Error())
		return
	}
	s.changed()
	s.audit(r, "renew", "certificate", id.String(), map[string]any{"domains": c.Domains})
	writeJSON(w, http.StatusOK, c)
}

// patchCert switches auto-renew.
func (s *Server) patchCert(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		AutoRenew *bool `json:"auto_renew"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AutoRenew == nil {
		writeErr(w, http.StatusBadRequest, "auto_renew is required")
		return
	}
	if err := s.st.SetCertificateAutoRenew(r.Context(), id, *req.AutoRenew); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	s.audit(r, "update", "certificate", id.String(), map[string]any{"auto_renew": *req.AutoRenew})
	c, err := s.st.GetCertificateMeta(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// certPEM downloads the certificate chain (never the key).
func (s *Server) certPEM(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	domains, _, certEnc, _, _, err := s.st.GetCertificateEnc(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	pem, err := s.env.Open(certEnc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	name := "certificate"
	if len(domains) > 0 {
		name = strings.ReplaceAll(strings.TrimPrefix(domains[0], "*."), ".", "_")
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.pem"`)
	_, _ = w.Write(pem)
}

// Settings → Certificates: the renewal window.
func (s *Server) certSettings(w http.ResponseWriter, _ *http.Request) {
	days := int(certsvc.DefaultRenewBefore.Hours() / 24)
	if s.certs != nil {
		days = int(s.certs.RenewBefore().Hours() / 24)
	}
	writeJSON(w, http.StatusOK, map[string]any{"renew_before_days": days})
}

func (s *Server) putCertSettings(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil || s.env == nil {
		writeErr(w, http.StatusServiceUnavailable, "certificate service unavailable")
		return
	}
	var req struct {
		RenewBeforeDays int `json:"renew_before_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.RenewBeforeDays < 7 || req.RenewBeforeDays > 60 {
		writeErr(w, http.StatusBadRequest, "renew_before_days must be 7–60")
		return
	}
	if err := s.st.SetSetting(r.Context(), certsvc.SettingRenewBefore, []byte(strconv.Itoa(req.RenewBeforeDays)), s.env.Seal); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed")
		return
	}
	s.certs.SetRenewBefore(time.Duration(req.RenewBeforeDays) * 24 * time.Hour)
	s.audit(r, "update", "settings", "certs.renew_before_days", map[string]any{"days": req.RenewBeforeDays})
	writeJSON(w, http.StatusOK, map[string]any{"renew_before_days": req.RenewBeforeDays})
}

type uploadCertRequest struct {
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
	ChainPEM string `json:"chain_pem"`
}

func (s *Server) uploadCert(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil {
		writeErr(w, http.StatusServiceUnavailable, "certificate service unavailable")
		return
	}
	var req uploadCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.CertPEM) == "" || strings.TrimSpace(req.KeyPEM) == "" {
		writeErr(w, http.StatusBadRequest, "cert_pem and key_pem are required")
		return
	}
	c, err := s.certs.Upload(r.Context(), []byte(req.CertPEM), []byte(req.KeyPEM), []byte(req.ChainPEM))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "create", "certificate", c.ID.String(), map[string]any{"domains": c.Domains, "issuer": c.Issuer})
	writeJSON(w, http.StatusCreated, c)
}

type issueCertRequest struct {
	Domains []string `json:"domains"`
}

func (s *Server) issueCert(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil {
		writeErr(w, http.StatusServiceUnavailable, "certificate service unavailable")
		return
	}
	var req issueCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	c, err := s.certs.Request(r.Context(), req.Domains)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "invalid domain") || strings.Contains(msg, "at least one domain") {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		writeErr(w, http.StatusBadGateway, "certificate issuance failed: "+msg)
		return
	}
	s.audit(r, "create", "certificate", c.ID.String(), map[string]any{"domains": c.Domains, "issuer": c.Issuer, "via": "issue"})
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) deleteCert(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil {
		writeErr(w, http.StatusServiceUnavailable, "certificate service unavailable")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.certs.Delete(r.Context(), id); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if strings.Contains(err.Error(), "in use") {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.changed()
	s.audit(r, "delete", "certificate", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}
