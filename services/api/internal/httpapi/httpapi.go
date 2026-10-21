// Package httpapi exposes the control-plane REST API consumed by the
// dashboard. All routes except /setup/status, /setup, and /auth/login
// require a valid session cookie.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/zypher-systems/aegis/services/api/internal/alerts"
	"github.com/zypher-systems/aegis/services/api/internal/auth"
	"github.com/zypher-systems/aegis/services/api/internal/certsvc"
	"github.com/zypher-systems/aegis/services/api/internal/crypto"
	"github.com/zypher-systems/aegis/services/api/internal/store"
	"github.com/zypher-systems/aegis/services/api/internal/telemetry"
)

const sessionCookie = "aegis_session"
const csrfCookie = "aegis_csrf"

type Server struct {
	st           *store.Store
	sm           *auth.SessionManager
	onChange     func()
	certs        *certsvc.Service
	rdb          *redis.Client
	publicOrigin string
	env          *crypto.Envelope
	telemetry    *telemetry.Service
	geoipPath    string
	version      string
	onRevoke     func(uuid.UUID)
	// metricsToken lets a scraper read /api/metrics without a session.
	metricsToken  string
	configVersion func() uint64
	apiMetrics    apiMetrics

	csControlDir      string
	csMachineID       string
	csMachinePassword string

	muTrusted         sync.RWMutex
	trustedProxyCIDRs []string

	// decisions caches the LAPI decision list for the dashboard (crowdsec.go).
	decisions decisionCache
	// In-process login counter, used when Redis is absent or erroring.
	loginLocal   *localLimiter
	loginAccount *localLimiter
	// Session ids ended by logout (mirrors revoked_sessions).
	revoked sync.Map
	alerts  *alerts.Center
}

type Deps struct {
	Store                   *store.Store
	Sessions                *auth.SessionManager
	OnChange                func()
	OnRevoke                func(uuid.UUID)
	Certs                   *certsvc.Service
	Redis                   *redis.Client
	PublicOrigin            string
	Envelope                *crypto.Envelope
	Telemetry               *telemetry.Service
	GeoIPPath               string
	TrustedProxyCIDRs       []string
	CrowdSecControlDir      string
	CrowdSecMachineID       string
	CrowdSecMachinePassword string
	Version                 string
	Alerts                  *alerts.Center
	// MetricsToken is the bearer token Prometheus presents to /api/metrics.
	MetricsToken string
	// ConfigVersion reports the configuration version pushed to nodes.
	ConfigVersion func() uint64
}

func New(d Deps) *Server {
	s := &Server{
		st: d.Store, sm: d.Sessions, onChange: d.OnChange, certs: d.Certs,
		loginLocal:   newLocalLimiter(loginAttempts, loginWindow),
		loginAccount: newLocalLimiter(accountFailures, accountWindow),
		rdb:          d.Redis, publicOrigin: d.PublicOrigin, env: d.Envelope,
		telemetry: d.Telemetry, geoipPath: d.GeoIPPath,
		version:           d.Version,
		metricsToken:      d.MetricsToken,
		configVersion:     d.ConfigVersion,
		apiMetrics:        apiMetrics{started: time.Now()},
		trustedProxyCIDRs: append([]string(nil), d.TrustedProxyCIDRs...),
		onRevoke:          d.OnRevoke,
		csControlDir:      d.CrowdSecControlDir,
		csMachineID:       d.CrowdSecMachineID,
		csMachinePassword: d.CrowdSecMachinePassword,
		alerts:            d.Alerts,
	}
	if err := s.writeFirewallControl(context.Background()); err != nil {
		log.Printf("crowdsec firewall control file: %v", err)
	}
	if s.st != nil {
		if ids, err := s.st.ListRevokedSessions(context.Background()); err == nil {
			for _, id := range ids {
				s.revoked.Store(id, struct{}{})
			}
		}
	}
	return s
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(s.securityHeaders)
	r.Use(s.csrf)
	r.Use(s.countRequests)
	r.Get("/api/healthz", s.healthz)
	r.Get("/api/readyz", s.readyz)
	r.Get("/api/metrics", s.metrics)

	r.Route("/api", func(r chi.Router) {
		r.Get("/setup/status", s.setupStatus)
		r.Post("/setup", s.setup)
		r.Post("/auth/login", s.login)
		r.Post("/auth/logout", s.logout)

		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Get("/me", s.me)
			r.Post("/me/password", s.changeMyPassword)
			r.Post("/me/sessions/revoke-all", s.revokeAllSessions)
			r.Get("/audit", s.listAudit)
			r.Get("/notices", s.listNotices)
			r.Route("/users", func(r chi.Router) {
				r.Get("/", s.listUsers)
				r.Post("/", s.createUser)
				r.Put("/{id}", s.updateUser)
				r.Delete("/{id}", s.deleteUser)
			})
			r.Get("/nodes", s.listNodes)
			r.Patch("/nodes/{id}", s.renameNode)
			r.Delete("/nodes/{id}", s.revokeNode)
			r.Get("/analytics/live", s.analyticsLive)
			r.Get("/analytics/requests", s.analyticsRequests)
			r.Get("/analytics/summary", s.analyticsSummary)
			r.Get("/analytics/rollups", s.analyticsRollups)
			r.Get("/analytics/geo", s.analyticsGeo)
			r.Get("/settings/enroll-token", s.enrollTokenStatus)
			r.Get("/settings/enroll-tokens", s.listEnrollTokens)
			r.Post("/settings/enroll-tokens", s.createEnrollToken)
			r.Delete("/settings/enroll-tokens/{id}", s.deleteEnrollToken)
			r.Get("/settings/dns-cloudflare", s.dnsCloudflareStatus)
			r.Put("/settings/dns-cloudflare", s.putDNSCloudflare)
			r.Get("/settings/crowdsec", s.crowdsecStatus)
			r.Put("/settings/crowdsec", s.putCrowdsec)
			r.Put("/settings/crowdsec/firewall", s.putCrowdsecFirewall)
			r.Get("/crowdsec/decisions", s.crowdsecDecisions)
			r.Post("/crowdsec/decisions", s.postCrowdsecDecision)
			r.Delete("/crowdsec/decisions/{id}", s.deleteCrowdsecDecision)
			r.Get("/crowdsec/alerts", s.crowdsecAlerts)
			r.Get("/settings/geoip", s.geoipStatus)
			r.Get("/settings/trusted-proxy", s.trustedProxyStatus)
			r.Put("/settings/trusted-proxy", s.putTrustedProxy)
			r.Get("/settings/alerts", s.alertsStatus)
			r.Put("/settings/alerts", s.putAlerts)
			r.Post("/settings/alerts/test", s.testAlerts)
			r.Get("/telemetry", s.telemetryStats)
			r.Route("/access-lists", func(r chi.Router) {
				r.Get("/", s.listAccessLists)
				r.Post("/", s.createAccessList)
				r.Get("/{id}", s.getAccessList)
				r.Put("/{id}", s.updateAccessList)
				r.Delete("/{id}", s.deleteAccessList)
			})
			r.Get("/waf/rules", s.listWAFRules)
			r.Get("/waf/catalog", s.wafCatalog)
			r.Get("/analytics/waf-findings", s.wafFindings)
			r.Route("/waf-profiles", func(r chi.Router) {
				r.Get("/", s.listWAFProfiles)
				r.Post("/", s.createWAFProfile)
				r.Get("/{id}", s.getWAFProfile)
				r.Put("/{id}", s.updateWAFProfile)
				r.Delete("/{id}", s.deleteWAFProfile)
			})
			r.Route("/certificates", func(r chi.Router) {
				r.Get("/", s.listCerts)
				r.Get("/status", s.certStatus)
				r.Post("/", s.uploadCert)
				r.Post("/issue", s.issueCert)
				r.Delete("/{id}", s.deleteCert)
				r.Post("/{id}/renew", s.renewCert)
				r.Patch("/{id}", s.patchCert)
				r.Get("/{id}/pem", s.certPEM)
			})
			r.Get("/settings/certificates", s.certSettings)
			r.Put("/settings/certificates", s.putCertSettings)
			r.Route("/hosts", func(r chi.Router) {
				r.Post("/bulk", s.bulkHosts)
				r.Get("/export", s.exportHosts)
				r.Post("/import", s.importHosts)
				r.Get("/", s.listHosts)
				r.Post("/", s.createHost)
				r.Get("/{id}", s.getHost)
				r.Put("/{id}", s.updateHost)
				r.Delete("/{id}", s.deleteHost)
			})
		})
	})
	return r
}

// --- setup ---

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.st.CountUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needs_setup": n == 0})
}

type setupRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	n, err := s.st.CountUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if n > 0 {
		writeErr(w, http.StatusConflict, "setup already completed")
		return
	}
	var req setupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Email = normalizeEmail(req.Email)
	if req.Email == "" || len(req.Password) < 10 {
		writeErr(w, http.StatusBadRequest, "email required and password must be at least 10 characters")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash error")
		return
	}
	// CreateFirstUser holds a lock so two setup requests cannot both win.
	u, err := s.st.CreateFirstUser(r.Context(), req.Email, req.Name, hash)
	if errors.Is(err, store.ErrSetupDone) {
		writeErr(w, http.StatusConflict, "setup already completed")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create user failed")
		return
	}
	s.setSession(w, r, u)
	writeJSON(w, http.StatusCreated, publicUser(u))
}

// --- auth ---

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !s.allowLogin(r) {
		writeErr(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}
	email := normalizeEmail(req.Email)
	if s.accountLocked(r.Context(), email) {
		writeErr(w, http.StatusTooManyRequests, "too many failed sign-ins for this account; try again in 15 minutes")
		return
	}
	u, err := s.st.UserByEmail(r.Context(), email)
	if err != nil {
		// Spend the same time as a real check so the response does not say
		// whether the email exists.
		auth.VerifyPassword(req.Password, dummyPasswordHash())
		s.accountFailed(r.Context(), email)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if !auth.VerifyPassword(req.Password, u.PasswordHash) {
		if s.accountFailed(r.Context(), email) && s.alerts != nil {
			s.alerts.Info("Repeated failed sign-ins for "+email, "10 wrong passwords in 15 minutes, last from "+s.clientIP(r)+". The account is locked for 15 minutes.")
		}
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.accountSucceeded(r.Context(), email)
	s.setSession(w, r, u)
	writeJSON(w, http.StatusOK, publicUser(u))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	// End the session server-side; clearing the cookie alone would leave a
	// copied token valid until it expired.
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if sess, ok := s.sm.Parse(c.Value); ok {
			s.revoked.Store(sess.JTI, struct{}{})
			if s.st != nil {
				_ = s.st.RevokeSession(r.Context(), sess.JTI, sess.Expires)
			}
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: "", Path: "/", MaxAge: -1,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, publicUser(u))
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, u *store.User) {
	token, expires := s.sm.Issue(u.ID.String(), u.SessionEpoch)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: requestSecure(r),
	})
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: auth.RandomToken(32), Path: "/", Expires: expires,
		HttpOnly: false, SameSite: http.SameSiteLaxMode, Secure: requestSecure(r),
	})
}

// --- hosts ---

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.st.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

type hostRequest struct {
	Kind             string               `json:"kind"`
	DomainNames      []string             `json:"domain_names"`
	UpstreamScheme   string               `json:"upstream_scheme"`
	UpstreamHost     string               `json:"upstream_host"`
	UpstreamPort     int                  `json:"upstream_port"`
	Enabled          bool                 `json:"enabled"`
	TLSMode          string               `json:"tls_mode"`
	ForceHTTPS       bool                 `json:"force_https"`
	HSTS             bool                 `json:"hsts"`
	WebsocketSupport bool                 `json:"websocket_support"`
	CertID           *string              `json:"cert_id"`
	RedirectURL      string               `json:"redirect_url"`
	RedirectCode     int                  `json:"redirect_code"`
	RequestHeaders   map[string]string    `json:"request_headers"`
	ResponseHeaders  map[string]string    `json:"response_headers"`
	AccessListID     *string              `json:"access_list_id"`
	ListenProtocol   string               `json:"listen_protocol"`
	ListenPort       int                  `json:"listen_port"`
	WAFProfileID     *string              `json:"waf_profile_id"`
	RateLimitRPS     int                  `json:"rate_limit_rps"`
	RateLimitBurst   int                  `json:"rate_limit_burst"`
	GeoAllow         []string             `json:"geo_allow"`
	GeoDeny          []string             `json:"geo_deny"`
	CrowdSecEnabled  bool                 `json:"crowdsec_enabled"`
	OIDC             store.HostOIDC       `json:"oidc"`
	Upstreams        []store.HostUpstream `json:"upstreams"`
	// UpstreamHostHeader: "" client's Host, "upstream", or a literal host.
	UpstreamHostHeader string `json:"upstream_host_header"`
	HSTSMaxAge         int    `json:"hsts_max_age"`
	HSTSSubdomains     bool   `json:"hsts_subdomains"`
	HSTSPreload        bool   `json:"hsts_preload"`
	LBPolicy           string `json:"lb_policy"`
	HealthPath         string `json:"health_path"`
	// Timeouts and limits; 0 = default.
	IdleTimeoutSeconds             int   `json:"idle_timeout_seconds"`
	UpstreamResponseTimeoutSeconds int   `json:"upstream_response_timeout_seconds"`
	MaxBodyBytes                   int64 `json:"max_body_bytes"`
}

// Bounds for per-host timeouts and body limit.
const (
	maxTimeoutSeconds = 3600
	maxBodyBytesCap   = 64 << 30 // 64 GiB
)

func (hr hostRequest) toHost() *store.Host {
	scheme := hr.UpstreamScheme
	if scheme == "" {
		scheme = "http"
	}
	mode := hr.TLSMode
	if mode == "" {
		mode = "auto"
	}
	kind := hr.Kind
	if kind == "" {
		kind = "proxy"
	}
	code := hr.RedirectCode
	if code == 0 {
		code = 301
	}
	h := &store.Host{
		Kind:             kind,
		DomainNames:      hr.DomainNames,
		UpstreamScheme:   scheme,
		UpstreamHost:     hr.UpstreamHost,
		UpstreamPort:     hr.UpstreamPort,
		Enabled:          hr.Enabled,
		TLSMode:          mode,
		ForceHTTPS:       hr.ForceHTTPS,
		HSTS:             hr.HSTS,
		WebsocketSupport: hr.WebsocketSupport,
		RedirectURL:      hr.RedirectURL,
		RedirectCode:     code,
		RequestHeaders:   hr.RequestHeaders,
		ResponseHeaders:  hr.ResponseHeaders,
		ListenProtocol:   hr.ListenProtocol,
		ListenPort:       hr.ListenPort,
		RateLimitRPS:     hr.RateLimitRPS,
		RateLimitBurst:   hr.RateLimitBurst,
		GeoAllow:         hr.GeoAllow,
		GeoDeny:          hr.GeoDeny,
		CrowdSecEnabled:  hr.CrowdSecEnabled,
		OIDC:             hr.OIDC,
		Upstreams:        hr.Upstreams,
		// Normalised here; validateHost rejects anything that is not a host.
		UpstreamHostHeader:             strings.TrimSpace(hr.UpstreamHostHeader),
		HSTSMaxAge:                     hr.HSTSMaxAge,
		HSTSSubdomains:                 hr.HSTSSubdomains,
		HSTSPreload:                    hr.HSTSPreload,
		LBPolicy:                       strings.TrimSpace(hr.LBPolicy),
		HealthPath:                     strings.TrimSpace(hr.HealthPath),
		IdleTimeoutSeconds:             hr.IdleTimeoutSeconds,
		UpstreamResponseTimeoutSeconds: hr.UpstreamResponseTimeoutSeconds,
		MaxBodyBytes:                   hr.MaxBodyBytes,
	}
	if hr.CertID != nil && *hr.CertID != "" {
		if id, err := uuid.Parse(*hr.CertID); err == nil {
			h.CertID = &id
		}
	}
	if hr.AccessListID != nil && *hr.AccessListID != "" {
		if id, err := uuid.Parse(*hr.AccessListID); err == nil {
			h.AccessListID = &id
		}
	}
	if hr.WAFProfileID != nil && *hr.WAFProfileID != "" {
		if id, err := uuid.Parse(*hr.WAFProfileID); err == nil {
			h.WAFProfileID = &id
		}
	}
	return h
}

// hostHeaderRe is a host or host:port (IPv6 in brackets); no spaces or
// control characters, so it can never smuggle another header.
var hostHeaderRe = regexp.MustCompile(`^[A-Za-z0-9.\-_:\[\]]{1,255}$`)

func validateHost(h *store.Host) string {
	if len(h.DomainNames) == 0 {
		return "domain_names is required"
	}
	for _, d := range h.DomainNames {
		if !validDomainName(strings.ToLower(strings.TrimSpace(d))) {
			return "domain name " + strings.TrimSpace(d) + " is not valid (letters, digits, hyphens and dots; *.example.com for a wildcard)"
		}
	}
	for name, value := range h.RequestHeaders {
		if msg := headerProblem(name, value); msg != "" {
			return "request " + msg
		}
	}
	for name, value := range h.ResponseHeaders {
		if msg := headerProblem(name, value); msg != "" {
			return "response " + msg
		}
	}
	if h.Kind == "proxy" || h.Kind == "stream" {
		if h.UpstreamHost != "" {
			if msg := upstreamProblem(h.UpstreamHost); msg != "" {
				return msg
			}
		}
		for _, u := range h.Upstreams {
			if msg := upstreamProblem(u.Host); msg != "" {
				return msg
			}
			if u.Port < 1 || u.Port > 65535 {
				return "upstream port must be 1–65535"
			}
			if u.Weight < 0 || u.Weight > 100 {
				return "upstream weight must be 0 (default 1) to 100"
			}
		}
		switch h.LBPolicy {
		case "", "failover", "round_robin":
		default:
			return "lb_policy must be empty, \"failover\" or \"round_robin\""
		}
		if p := h.HealthPath; p != "" && (!strings.HasPrefix(p, "/") || len(p) > 256 || strings.ContainsAny(p, " \t\r\n#")) {
			return "health_path must be a path starting with / (at most 256 characters)"
		}
		if len(h.Upstreams) == 0 && h.UpstreamHost != "" && (h.UpstreamPort < 1 || h.UpstreamPort > 65535) {
			return "upstream port must be 1–65535"
		}
	}
	if v := h.UpstreamHostHeader; v != "" && v != "upstream" && !hostHeaderRe.MatchString(v) {
		return "upstream_host_header must be empty (client's Host), \"upstream\", or a host name"
	}
	if h.HSTSMaxAge < 0 || h.HSTSMaxAge > 63072000 {
		return "hsts_max_age must be 0 (one year) to 63072000 (two years)"
	}
	if h.HSTSPreload && (h.HSTSMaxAge != 0 && h.HSTSMaxAge < 31536000 || !h.HSTSSubdomains) {
		return "HSTS preload requires includeSubDomains and a max-age of at least one year"
	}
	if h.IdleTimeoutSeconds < 0 || h.IdleTimeoutSeconds > maxTimeoutSeconds {
		return "idle_timeout_seconds must be 0 (default) to 3600"
	}
	if h.UpstreamResponseTimeoutSeconds < 0 || h.UpstreamResponseTimeoutSeconds > maxTimeoutSeconds {
		return "upstream_response_timeout_seconds must be 0 (default) to 3600"
	}
	if h.MaxBodyBytes < 0 || h.MaxBodyBytes > maxBodyBytesCap {
		return "max_body_bytes must be 0 (no limit) to 64 GiB"
	}
	if h.OIDC.Enabled {
		return "OIDC forward-auth is not supported; put Authelia or Authentik in front of the origin"
	}
	for _, u := range h.Upstreams {
		if msg := u.ValidateTLS(); msg != "" {
			return msg
		}
	}
	switch h.Kind {
	case "proxy":
		if len(h.Upstreams) == 0 && (h.UpstreamHost == "" || h.UpstreamPort == 0) {
			return "at least one upstream host and port is required for proxy hosts"
		}
	case "redirect":
		if h.RedirectURL == "" {
			return "redirect_url is required for redirect hosts"
		}
		if !validRedirectURL(h.RedirectURL) {
			return "redirect_url must be an absolute http(s) URL"
		}
		if h.RedirectCode != 301 && h.RedirectCode != 302 {
			return "redirect_code must be 301 or 302"
		}
	case "dead":
		// domain names only
	case "stream":
		if h.ListenProtocol != "tcp" && h.ListenProtocol != "udp" {
			return "listen_protocol must be tcp or udp"
		}
		if h.ListenPort < 1 || h.ListenPort > 65535 {
			return "listen_port must be 1–65535"
		}
		if h.UpstreamHost == "" || h.UpstreamPort == 0 {
			if len(h.Upstreams) == 0 {
				return "at least one upstream host and port is required for stream hosts"
			}
		}
		h.TLSMode = "none"
	default:
		return "kind must be proxy, redirect, dead, or stream"
	}
	return ""
}

func (s *Server) createHost(w http.ResponseWriter, r *http.Request) {
	var req hostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	h := req.toHost()
	if msg := validateHost(h); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if !s.bindCert(w, r, h) {
		return
	}
	if !s.requireHostFeatures(w, h) {
		return
	}
	created, err := s.st.CreateHost(r.Context(), h)
	if writeHostErr(w, err, "create failed") {
		return
	}
	s.changed()
	s.audit(r, "create", "host", created.ID.String(), map[string]any{"domains": created.DomainNames, "kind": created.Kind})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	h, err := s.st.GetHost(r.Context(), id)
	if err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req hostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	h := req.toHost()
	h.ID = id
	if msg := validateHost(h); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if !s.bindCert(w, r, h) {
		return
	}
	if !s.requireHostFeatures(w, h) {
		return
	}
	out, err := s.st.UpdateHost(r.Context(), h)
	if err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if writeHostErr(w, err, "update failed") {
		return
	}
	s.changed()
	s.audit(r, "update", "host", out.ID.String(), map[string]any{"domains": out.DomainNames, "kind": out.Kind})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteHost(r.Context(), id); err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.changed()
	s.audit(r, "delete", "host", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) bindCert(w http.ResponseWriter, r *http.Request, h *store.Host) bool {
	if h.Kind == "stream" || h.TLSMode == "none" {
		h.CertID = nil
		if h.Kind == "stream" {
			h.TLSMode = "none"
		}
		return true
	}
	switch h.TLSMode {
	case "auto":
		if s.certs == nil {
			writeErr(w, http.StatusBadGateway, "certificate service unavailable")
			return false
		}
		certID, err := s.certs.EnsureForHost(r.Context(), h.DomainNames)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "certificate issuance failed: "+err.Error())
			return false
		}
		h.CertID = &certID
	case "custom":
		if h.CertID == nil {
			writeErr(w, http.StatusBadRequest, "cert_id is required when tls_mode=custom")
			return false
		}
	default:
		h.CertID = nil
	}
	return true
}

func (s *Server) requireHostFeatures(w http.ResponseWriter, h *store.Host) bool {
	if h.OIDC.Enabled {
		writeErr(w, http.StatusBadRequest, "OIDC forward-auth is not supported; put Authelia or Authentik in front of the origin")
		return false
	}
	return true
}

func (s *Server) changed() {
	if s.onChange != nil {
		s.onChange()
	}
}

// --- helpers ---

func publicUser(u *store.User) map[string]any {
	return map[string]any{"id": u.ID, "email": u.Email, "name": u.Name, "role": u.Role}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeHostErr(w http.ResponseWriter, err error, fallback string) bool {
	if err == nil {
		return false
	}
	var pc *store.StreamPortConflictError
	if errors.As(err, &pc) {
		writeErr(w, http.StatusConflict, pc.Error())
		return true
	}
	var dc *store.DomainConflictError
	if errors.As(err, &dc) {
		writeErr(w, http.StatusConflict, dc.Error())
		return true
	}
	if errors.Is(err, store.ErrDomainTaken) {
		writeErr(w, http.StatusConflict, "domain already in use")
		return true
	}
	writeErr(w, http.StatusInternalServerError, fallback)
	return true
}

// --- auth middleware ---

type ctxKey int

const ctxUserKey ctxKey = 0

// requireAuth validates the session cookie and injects the user into ctx.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		sess, ok := s.sm.Parse(c.Value)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "invalid or expired session")
			return
		}
		if _, revoked := s.revoked.Load(sess.JTI); revoked {
			writeErr(w, http.StatusUnauthorized, "session signed out")
			return
		}
		uid, err := uuid.Parse(sess.UserID)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid session")
			return
		}
		u, err := s.st.UserByID(r.Context(), uid)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "user not found")
			return
		}
		if u.SessionEpoch != sess.Epoch {
			writeErr(w, http.StatusUnauthorized, "session revoked")
			return
		}
		// Activity keeps the session alive: hand out a fresh lease once an
		// hour so the idle limit is measured from real use.
		if time.Since(sess.IssuedAt) > time.Hour {
			http.SetCookie(w, &http.Cookie{
				Name: sessionCookie, Value: s.sm.Renew(sess), Path: "/", Expires: sess.Expires,
				HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: requestSecure(r),
			})
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUserKey, u)))
	})
}

func userFromCtx(r *http.Request) *store.User {
	if u, ok := r.Context().Value(ctxUserKey).(*store.User); ok {
		return u
	}
	return nil
}

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// dummyPasswordHash is a real argon2id hash used to equalise the timing of
// logins for unknown emails.
func dummyPasswordHash() string {
	dummyHashOnce.Do(func() { dummyHash, _ = auth.HashPassword("aegis-timing-equaliser") })
	return dummyHash
}

// revokeAllSessions bumps the caller's session epoch: every session of this
// account, on every device, ends, including the one making the call.
func (s *Server) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	me := userFromCtx(r)
	if me == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if _, err := s.st.BumpSessionEpoch(r.Context(), me.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	s.audit(r, "revoke_sessions", "user", me.ID.String(), map[string]any{"email": me.Email})
	s.logout(w, r)
}
