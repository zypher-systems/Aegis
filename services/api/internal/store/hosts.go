package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrDomainTaken = errors.New("domain already in use")

// DomainConflictError names the hostname that is already attached to another host.
type DomainConflictError struct {
	Domain string
}

func (e *DomainConflictError) Error() string {
	if e == nil || e.Domain == "" {
		return ErrDomainTaken.Error()
	}
	return e.Domain + " is already in use"
}

func (e *DomainConflictError) Unwrap() error { return ErrDomainTaken }

type Host struct {
	ID               uuid.UUID         `json:"id"`
	Kind             string            `json:"kind"` // proxy | redirect | dead | stream
	DomainNames      []string          `json:"domain_names"`
	UpstreamScheme   string            `json:"upstream_scheme"`
	UpstreamHost     string            `json:"upstream_host"`
	UpstreamPort     int               `json:"upstream_port"`
	Enabled          bool              `json:"enabled"`
	TLSMode          string            `json:"tls_mode"` // auto | custom | none
	CertID           *uuid.UUID        `json:"cert_id,omitempty"`
	ForceHTTPS       bool              `json:"force_https"`
	HSTS             bool              `json:"hsts"`
	WebsocketSupport bool              `json:"websocket_support"`
	RedirectURL      string            `json:"redirect_url"`
	RedirectCode     int               `json:"redirect_code"`
	RequestHeaders   map[string]string `json:"request_headers"`
	ResponseHeaders  map[string]string `json:"response_headers"`
	AccessListID     *uuid.UUID        `json:"access_list_id,omitempty"`
	ListenProtocol   string            `json:"listen_protocol"`
	ListenPort       int               `json:"listen_port"`
	WAFProfileID     *uuid.UUID        `json:"waf_profile_id,omitempty"`
	RateLimitRPS     int               `json:"rate_limit_rps"`
	RateLimitBurst   int               `json:"rate_limit_burst"`
	GeoAllow         []string          `json:"geo_allow"`
	GeoDeny          []string          `json:"geo_deny"`
	CrowdSecEnabled  bool              `json:"crowdsec_enabled"`
	OIDC             HostOIDC          `json:"oidc"`
	Upstreams        []HostUpstream    `json:"upstreams"`
	// UpstreamHostHeader: "" sends the client's Host, "upstream" the
	// upstream's address, anything else is sent as-is.
	UpstreamHostHeader string `json:"upstream_host_header"`
	// HSTS options, used when HSTS is on. MaxAge 0 = a year.
	HSTSMaxAge     int  `json:"hsts_max_age"`
	HSTSSubdomains bool `json:"hsts_subdomains"`
	HSTSPreload    bool `json:"hsts_preload"`
	// LBPolicy: "" or "failover" (first healthy upstream in order), or
	// "round_robin" (weighted rotation). HealthPath: HTTP path the proxy
	// probes on each upstream; "" = TCP connect.
	LBPolicy   string `json:"lb_policy"`
	HealthPath string `json:"health_path"`
	// Timeouts and limits; 0 = default (see proto Host).
	IdleTimeoutSeconds             int       `json:"idle_timeout_seconds"`
	UpstreamResponseTimeoutSeconds int       `json:"upstream_response_timeout_seconds"`
	MaxBodyBytes                   int64     `json:"max_body_bytes"`
	CreatedAt                      time.Time `json:"created_at"`
	UpdatedAt                      time.Time `json:"updated_at"`
}

// HostUpstream is one origin. Order is failover priority.
type HostUpstream struct {
	Scheme        string `json:"scheme"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	TLSCAPem      string `json:"tls_ca_pem,omitempty"`
	// Weight is this target's share under round_robin; 0 means 1.
	Weight int `json:"weight,omitempty"`
}

type HostOIDC struct {
	Enabled      bool     `json:"enabled"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Paths        []string `json:"paths"`
	CookieName   string   `json:"cookie_name"`
}

const hostCols = `id, kind, domain_names, upstream_scheme, COALESCE(upstream_host,''), upstream_port,
	enabled, tls_mode, cert_id, force_https, hsts, websocket_support,
	redirect_url, redirect_code, request_headers, response_headers,
	access_list_id, listen_protocol, listen_port,
	waf_profile_id, rate_limit_rps, rate_limit_burst,
	geo_allow, geo_deny, crowdsec_enabled, oidc, COALESCE(upstreams, '[]'::jsonb),
	upstream_host_header, idle_timeout_seconds, upstream_response_timeout_seconds, max_body_bytes,
	hsts_max_age, hsts_subdomains, hsts_preload, lb_policy, health_path,
	created_at, updated_at`

func scanHost(row pgx.Row, h *Host) error {
	var reqRaw, respRaw, oidcRaw, upsRaw []byte
	err := row.Scan(&h.ID, &h.Kind, &h.DomainNames, &h.UpstreamScheme, &h.UpstreamHost,
		&h.UpstreamPort, &h.Enabled, &h.TLSMode, &h.CertID, &h.ForceHTTPS, &h.HSTS,
		&h.WebsocketSupport, &h.RedirectURL, &h.RedirectCode, &reqRaw, &respRaw,
		&h.AccessListID, &h.ListenProtocol, &h.ListenPort,
		&h.WAFProfileID, &h.RateLimitRPS, &h.RateLimitBurst,
		&h.GeoAllow, &h.GeoDeny, &h.CrowdSecEnabled, &oidcRaw, &upsRaw,
		&h.UpstreamHostHeader, &h.IdleTimeoutSeconds, &h.UpstreamResponseTimeoutSeconds, &h.MaxBodyBytes,
		&h.HSTSMaxAge, &h.HSTSSubdomains, &h.HSTSPreload, &h.LBPolicy, &h.HealthPath,
		&h.CreatedAt, &h.UpdatedAt)
	if err != nil {
		return err
	}
	h.RequestHeaders = decodeHeaderMap(reqRaw)
	h.ResponseHeaders = decodeHeaderMap(respRaw)
	h.OIDC = decodeOIDC(oidcRaw)
	h.Upstreams = decodeUpstreams(upsRaw)
	if h.GeoAllow == nil {
		h.GeoAllow = []string{}
	}
	if h.GeoDeny == nil {
		h.GeoDeny = []string{}
	}
	syncLegacyUpstream(h)
	return nil
}

func decodeOIDC(raw []byte) HostOIDC {
	var o HostOIDC
	if len(raw) == 0 {
		return o
	}
	_ = json.Unmarshal(raw, &o)
	if o.Paths == nil {
		o.Paths = []string{}
	}
	return o
}

func encodeOIDC(o HostOIDC) []byte {
	if o.Paths == nil {
		o.Paths = []string{}
	}
	b, err := json.Marshal(o)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func decodeHeaderMap(raw []byte) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	out := map[string]string{}
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		return map[string]string{}
	}
	return out
}

func encodeHeaderMap(m map[string]string) []byte {
	if m == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func decodeUpstreams(raw []byte) []HostUpstream {
	var out []HostUpstream
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	if out == nil {
		return []HostUpstream{}
	}
	return out
}

func encodeUpstreams(u []HostUpstream) []byte {
	if u == nil {
		u = []HostUpstream{}
	}
	b, err := json.Marshal(u)
	if err != nil {
		return []byte("[]")
	}
	return b
}

func syncLegacyUpstream(h *Host) {
	if len(h.Upstreams) == 0 && h.UpstreamHost != "" {
		scheme := h.UpstreamScheme
		if scheme == "" {
			scheme = "http"
		}
		h.Upstreams = []HostUpstream{{Scheme: scheme, Host: h.UpstreamHost, Port: h.UpstreamPort}}
	}
	if len(h.Upstreams) > 0 {
		if h.Upstreams[0].Scheme != "" {
			h.UpstreamScheme = h.Upstreams[0].Scheme
		}
		h.UpstreamHost = h.Upstreams[0].Host
		h.UpstreamPort = h.Upstreams[0].Port
	}
}

func normalizeDomainNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		d := strings.ToLower(strings.TrimSpace(n))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func mapHostErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrDomainTaken
	}
	return err
}

func (s *Store) assertDomainsFree(ctx context.Context, names []string, exclude uuid.UUID) error {
	keys := normalizeDomainNames(names)
	if len(keys) == 0 {
		return nil
	}
	var taken string
	err := s.pool.QueryRow(ctx, `
		SELECT domain FROM host_domains
		WHERE domain = ANY($1) AND host_id <> $2
		LIMIT 1`, keys, exclude).Scan(&taken)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return &DomainConflictError{Domain: taken}
}

// StreamPortConflictError: another stream host already listens there.
type StreamPortConflictError struct {
	Protocol string
	Port     int
}

func (e *StreamPortConflictError) Error() string {
	return fmt.Sprintf("another stream host already listens on %s port %d", e.Protocol, e.Port)
}

func (s *Store) assertStreamPortFree(ctx context.Context, h *Host, exclude uuid.UUID) error {
	if h.Kind != "stream" || h.ListenPort == 0 {
		return nil
	}
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM hosts
		WHERE kind = 'stream' AND listen_protocol = $1 AND listen_port = $2 AND id <> $3`,
		h.ListenProtocol, h.ListenPort, exclude).Scan(&n)
	if err != nil {
		return err
	}
	if n > 0 {
		return &StreamPortConflictError{Protocol: h.ListenProtocol, Port: h.ListenPort}
	}
	return nil
}

func normalizeHostSlices(h *Host) {
	h.DomainNames = normalizeDomainNames(h.DomainNames)
	if h.GeoAllow == nil {
		h.GeoAllow = []string{}
	}
	if h.GeoDeny == nil {
		h.GeoDeny = []string{}
	}
	if h.OIDC.Paths == nil {
		h.OIDC.Paths = []string{}
	}
	syncLegacyUpstream(h)
	compact := make([]HostUpstream, 0, len(h.Upstreams))
	for _, u := range h.Upstreams {
		u.Host = strings.TrimSpace(u.Host)
		if u.Host == "" || u.Port < 1 || u.Port > 65535 {
			continue
		}
		if u.Scheme == "" {
			u.Scheme = "http"
		}
		u.TLSServerName = strings.TrimSpace(u.TLSServerName)
		u.TLSCAPem = strings.TrimSpace(u.TLSCAPem)
		if u.Scheme != "https" {
			u.TLSSkipVerify = false
			u.TLSServerName = ""
			u.TLSCAPem = ""
		}
		compact = append(compact, u)
	}
	h.Upstreams = compact
	syncLegacyUpstream(h)
	if h.Upstreams == nil {
		h.Upstreams = []HostUpstream{}
	}
}

// ValidateTLS checks origin TLS fields. Empty scheme is treated as http.
func (u HostUpstream) ValidateTLS() string {
	if u.Scheme != "https" {
		return ""
	}
	if u.TLSServerName != "" {
		if len(u.TLSServerName) > 253 || strings.ContainsAny(u.TLSServerName, " \t\r\n/") {
			return "tls_server_name must be a hostname"
		}
	}
	if strings.TrimSpace(u.TLSCAPem) == "" {
		return ""
	}
	rest := []byte(u.TLSCAPem)
	found := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "tls_ca_pem contains an invalid certificate"
		}
		found = true
	}
	if !found {
		return "tls_ca_pem must be one or more PEM certificates"
	}
	return ""
}

func (s *Store) CreateHost(ctx context.Context, h *Host) (*Host, error) {
	if h.Kind == "" {
		h.Kind = "proxy"
	}
	if h.RedirectCode == 0 {
		h.RedirectCode = 301
	}
	normalizeHostSlices(h)
	if err := s.assertDomainsFree(ctx, h.DomainNames, uuid.Nil); err != nil {
		return nil, err
	}
	if err := s.assertStreamPortFree(ctx, h, uuid.Nil); err != nil {
		return nil, err
	}
	out := &Host{}
	err := scanHost(s.pool.QueryRow(ctx, `
		INSERT INTO hosts (id, kind, domain_names, upstream_scheme, upstream_host, upstream_port,
			enabled, tls_mode, cert_id, force_https, hsts, websocket_support,
			redirect_url, redirect_code, request_headers, response_headers,
			access_list_id, listen_protocol, listen_port,
			waf_profile_id, rate_limit_rps, rate_limit_burst,
			geo_allow, geo_deny, crowdsec_enabled, oidc, upstreams, upstream_host_header,
			idle_timeout_seconds, upstream_response_timeout_seconds, max_body_bytes,
			hsts_max_age, hsts_subdomains, hsts_preload, lb_policy, health_path)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
			$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36)
		RETURNING `+hostCols,
		uuid.New(), h.Kind, h.DomainNames, h.UpstreamScheme, h.UpstreamHost, h.UpstreamPort,
		h.Enabled, h.TLSMode, h.CertID, h.ForceHTTPS, h.HSTS, h.WebsocketSupport,
		h.RedirectURL, h.RedirectCode, encodeHeaderMap(h.RequestHeaders), encodeHeaderMap(h.ResponseHeaders),
		h.AccessListID, h.ListenProtocol, h.ListenPort,
		h.WAFProfileID, h.RateLimitRPS, h.RateLimitBurst,
		h.GeoAllow, h.GeoDeny, h.CrowdSecEnabled, encodeOIDC(h.OIDC), encodeUpstreams(h.Upstreams),
		h.UpstreamHostHeader, h.IdleTimeoutSeconds, h.UpstreamResponseTimeoutSeconds, h.MaxBodyBytes,
		h.HSTSMaxAge, h.HSTSSubdomains, h.HSTSPreload, h.LBPolicy, h.HealthPath), out)
	if err != nil {
		return nil, mapHostErr(err)
	}
	return out, nil
}

func (s *Store) UpdateHost(ctx context.Context, h *Host) (*Host, error) {
	if h.Kind == "" {
		h.Kind = "proxy"
	}
	if h.RedirectCode == 0 {
		h.RedirectCode = 301
	}
	normalizeHostSlices(h)
	if err := s.assertDomainsFree(ctx, h.DomainNames, h.ID); err != nil {
		return nil, err
	}
	if err := s.assertStreamPortFree(ctx, h, h.ID); err != nil {
		return nil, err
	}
	out := &Host{}
	err := scanHost(s.pool.QueryRow(ctx, `
		UPDATE hosts SET kind=$2, domain_names=$3, upstream_scheme=$4, upstream_host=$5,
			upstream_port=$6, enabled=$7, tls_mode=$8, cert_id=$9, force_https=$10,
			hsts=$11, websocket_support=$12, redirect_url=$13, redirect_code=$14,
			request_headers=$15, response_headers=$16, access_list_id=$17,
			listen_protocol=$18, listen_port=$19,
			waf_profile_id=$20, rate_limit_rps=$21, rate_limit_burst=$22,
			geo_allow=$23, geo_deny=$24, crowdsec_enabled=$25, oidc=$26, upstreams=$27,
			upstream_host_header=$28, idle_timeout_seconds=$29, upstream_response_timeout_seconds=$30,
			max_body_bytes=$31, hsts_max_age=$32, hsts_subdomains=$33, hsts_preload=$34,
			lb_policy=$35, health_path=$36, updated_at=now()
		WHERE id=$1
		RETURNING `+hostCols,
		h.ID, h.Kind, h.DomainNames, h.UpstreamScheme, h.UpstreamHost, h.UpstreamPort,
		h.Enabled, h.TLSMode, h.CertID, h.ForceHTTPS, h.HSTS, h.WebsocketSupport,
		h.RedirectURL, h.RedirectCode, encodeHeaderMap(h.RequestHeaders), encodeHeaderMap(h.ResponseHeaders),
		h.AccessListID, h.ListenProtocol, h.ListenPort,
		h.WAFProfileID, h.RateLimitRPS, h.RateLimitBurst,
		h.GeoAllow, h.GeoDeny, h.CrowdSecEnabled, encodeOIDC(h.OIDC), encodeUpstreams(h.Upstreams),
		h.UpstreamHostHeader, h.IdleTimeoutSeconds, h.UpstreamResponseTimeoutSeconds, h.MaxBodyBytes,
		h.HSTSMaxAge, h.HSTSSubdomains, h.HSTSPreload, h.LBPolicy, h.HealthPath), out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, mapHostErr(err)
	}
	return out, nil
}

func (s *Store) DeleteHost(ctx context.Context, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, "DELETE FROM hosts WHERE id=$1", id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetHost(ctx context.Context, id uuid.UUID) (*Host, error) {
	out := &Host{}
	err := scanHost(s.pool.QueryRow(ctx,
		"SELECT "+hostCols+" FROM hosts WHERE id=$1", id), out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) CountHostsUsingCert(ctx context.Context, certID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM hosts WHERE cert_id=$1", certID).Scan(&n)
	return n, err
}

func (s *Store) CountHostsUsingAccessList(ctx context.Context, id uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM hosts WHERE access_list_id=$1", id).Scan(&n)
	return n, err
}

func (s *Store) ListHosts(ctx context.Context) ([]*Host, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+hostCols+" FROM hosts ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Host{}
	for rows.Next() {
		h := &Host{}
		if err := scanHost(rows, h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
