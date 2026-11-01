// Package config loads control-plane configuration from the environment.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zypher-systems/aegis/internal/clientip"
	"github.com/zypher-systems/aegis/internal/geoip"
)

type Config struct {
	HTTPAddr    string
	GRPCAddr    string
	EnrollAddr  string
	DatabaseURL string
	RedisAddr   string

	// SecretKey is the 32-byte master key (base64) used for AES-256-GCM
	// envelope encryption of secrets at rest (CA key, cert keys, sessions
	// HMAC). In production this should come from a secret manager.
	SecretKey []byte

	// EnrollToken is the one-time token proxy nodes present to enroll.
	EnrollToken string

	// ACME / certificate issuance.
	ACMEDirectory string
	ACMEEmail     string
	// SelfSigned, when true, issues self-signed certs instead of ACME.
	// Development/e2e only — never enable in production.
	SelfSigned bool
	// ACMESkipTLS skips verification of the ACME directory (Pebble).
	ACMESkipTLS bool
	// CloudflareToken is the env bootstrap for DNS-01. Settings token wins.
	CloudflareToken string

	// NodeCertTTL is how long issued node client certificates are valid.
	NodeCertTTL time.Duration

	// PublicOrigin is the dashboard's external URL, used for absolute links.
	PublicOrigin string

	// GeoIPMMDB is the country MMDB path (baked DB-IP Lite unless overridden).
	GeoIPMMDB string

	// TrustedProxyCIDRs is the env bootstrap. Settings wins when stored.
	TrustedProxyCIDRs []string

	// MetricsToken is the bearer token that reads /api/metrics; empty means
	// only a signed-in admin can.
	MetricsToken string

	// CrowdSecURL / CrowdSecKey seed crowdsec.lapi when the setting is empty.
	CrowdSecURL string
	CrowdSecKey string
	// CrowdSecControlDir is the shared volume the firewall bouncer watches.
	CrowdSecControlDir string
	// CrowdSecMachineID / CrowdSecMachinePassword authenticate as a LAPI
	// watcher so the dashboard can add and delete cscli decisions.
	CrowdSecMachineID       string
	CrowdSecMachinePassword string

	// Version is AEGIS_VERSION, shown in the dashboard and on nodes.
	Version string

	// RequestLog is AEGIS_REQUEST_LOG: all (default), security or off.
	RequestLog string
	// RequestLogRetention (AEGIS_REQUEST_LOG_DAYS, default 7) keeps served
	// requests; SecurityLogRetention (AEGIS_SECURITY_LOG_DAYS, default 30)
	// keeps blocked and flagged ones.
	RequestLogRetention  time.Duration
	SecurityLogRetention time.Duration
}

func days(key string, def int) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || n < 1 {
		n = def
	}
	return time.Duration(n) * 24 * time.Hour
}

func get(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func Load() (*Config, error) {
	secretB64 := os.Getenv("AEGIS_SECRET_KEY")
	if secretB64 == "" {
		return nil, fmt.Errorf("AEGIS_SECRET_KEY is required (base64-encoded 32 bytes)")
	}
	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil || len(secret) != 32 {
		return nil, fmt.Errorf("AEGIS_SECRET_KEY must be base64-encoded 32 bytes")
	}

	c := &Config{
		HTTPAddr:    get("AEGIS_HTTP_ADDR", ":8080"),
		GRPCAddr:    get("AEGIS_GRPC_ADDR", ":9443"),
		EnrollAddr:  get("AEGIS_ENROLL_ADDR", ":9444"),
		DatabaseURL: get("AEGIS_DATABASE_URL", "postgres://aegis:aegis@localhost:5432/aegis?sslmode=disable"),
		RedisAddr:   get("AEGIS_REDIS_ADDR", "localhost:6379"),
		SecretKey:   secret,
		EnrollToken: os.Getenv("AEGIS_ENROLL_TOKEN"),
		ACMEDirectory: get("AEGIS_ACME_DIRECTORY",
			"https://acme-v02.api.letsencrypt.org/directory"),
		ACMEEmail:               get("AEGIS_ACME_EMAIL", ""),
		NodeCertTTL:             90 * 24 * time.Hour,
		PublicOrigin:            get("AEGIS_PUBLIC_ORIGIN", "http://localhost:3000"),
		CloudflareToken:         get("AEGIS_CF_API_TOKEN", ""),
		GeoIPMMDB:               geoip.ResolvePath(os.Getenv("AEGIS_GEOIP_MMDB")),
		TrustedProxyCIDRs:       clientip.ParseList(os.Getenv("AEGIS_TRUSTED_PROXY_CIDRS")),
		MetricsToken:            strings.TrimSpace(os.Getenv("AEGIS_METRICS_TOKEN")),
		CrowdSecURL:             get("AEGIS_CROWDSEC_URL", ""),
		CrowdSecKey:             firstEnv("AEGIS_CROWDSEC_KEY", "CROWDSEC_BOUNCER_KEY"),
		CrowdSecControlDir:      get("AEGIS_CROWDSEC_CONTROL_DIR", ""),
		CrowdSecMachineID:       get("AEGIS_CROWDSEC_MACHINE_ID", "aegis-api"),
		CrowdSecMachinePassword: firstEnv("AEGIS_CROWDSEC_MACHINE_PASSWORD", "CROWDSEC_MACHINE_PASSWORD"),
		Version:                 get("AEGIS_VERSION", "dev"),
		RequestLog:              get("AEGIS_REQUEST_LOG", "all"),
		RequestLogRetention:     days("AEGIS_REQUEST_LOG_DAYS", 7),
		SecurityLogRetention:    days("AEGIS_SECURITY_LOG_DAYS", 30),
	}
	c.SelfSigned, _ = strconv.ParseBool(get("AEGIS_SELFSIGNED", "false"))
	c.ACMESkipTLS, _ = strconv.ParseBool(get("AEGIS_ACME_SKIP_TLS", "false"))

	if c.EnrollToken == "" && c.SelfSigned {
		// First-run local: enroll token still required so a proxy can join.
	}
	if c.EnrollToken == "" {
		return nil, fmt.Errorf("AEGIS_ENROLL_TOKEN is required")
	}
	if !c.SelfSigned && c.ACMEEmail == "" {
		return nil, fmt.Errorf("AEGIS_ACME_EMAIL is required when AEGIS_SELFSIGNED=false")
	}
	return c, nil
}
