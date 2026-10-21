// Package config loads data-plane configuration from the environment.
package config

import (
	"log"
	"os"
	"strings"

	"github.com/zypher-systems/aegis/internal/clientip"
	"github.com/zypher-systems/aegis/internal/geoip"
)

type Config struct {
	// ControlPlane is the host:port of the enrollment listener (TLS, token).
	ControlPlane string
	// NodePlane is the host:port of the mTLS node listener (config/telemetry).
	NodePlane string
	// EnrollToken is the one-time token used to obtain an mTLS identity.
	EnrollToken string
	// NodeName is the human-readable name reported to the control plane.
	NodeName string

	HTTPAddr  string
	HTTPSAddr string

	// StateDir holds the node identity (key, cert, CA) between restarts.
	StateDir string

	Version string

	RedisAddr string
	GeoIPMMDB string

	// TrustedProxyCIDRs is the env bootstrap; a snapshot overrides it.
	TrustedProxyCIDRs []string
	// AccessLog is nginx-combined output for CrowdSec (empty disables).
	AccessLog string
	// UnknownHost is "drop" (default) or "page": what a request for a name
	// no host serves gets.
	UnknownHost string
}

func get(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func Load() *Config {
	return &Config{
		ControlPlane:      get("AEGIS_CONTROL_PLANE", "localhost:9444"),
		NodePlane:         get("AEGIS_NODE_PLANE", "localhost:9443"),
		EnrollToken:       os.Getenv("AEGIS_ENROLL_TOKEN"),
		NodeName:          get("AEGIS_NODE_NAME", "aegis-proxy-1"),
		HTTPAddr:          get("AEGIS_HTTP_ADDR", ":80"),
		HTTPSAddr:         get("AEGIS_HTTPS_ADDR", ":443"),
		StateDir:          get("AEGIS_STATE_DIR", "/var/lib/aegis-proxy"),
		Version:           get("AEGIS_VERSION", "dev"),
		RedisAddr:         get("AEGIS_REDIS_ADDR", ""),
		GeoIPMMDB:         geoip.ResolvePath(os.Getenv("AEGIS_GEOIP_MMDB")),
		TrustedProxyCIDRs: clientip.ParseList(os.Getenv("AEGIS_TRUSTED_PROXY_CIDRS")),
		AccessLog:         get("AEGIS_ACCESS_LOG", ""),
		UnknownHost:       unknownHost(os.Getenv("AEGIS_UNKNOWN_HOST")),
	}
}

func unknownHost(v string) string {
	switch v := strings.ToLower(strings.TrimSpace(v)); v {
	case "", "drop":
		return "drop"
	case "page":
		return "page"
	default:
		log.Printf("proxy: AEGIS_UNKNOWN_HOST=%q is not drop or page; dropping unknown hosts", v)
		return "drop"
	}
}
