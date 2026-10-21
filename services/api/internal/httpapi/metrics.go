package httpapi

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// apiMetrics counts what this process has served since start.
type apiMetrics struct {
	mu      sync.Mutex
	started time.Time
	status  map[string]uint64 // response class -> count
}

// countRequests is middleware that tallies API responses by status class.
func (s *Server) countRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &countingWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		s.apiMetrics.mu.Lock()
		if s.apiMetrics.status == nil {
			s.apiMetrics.status = map[string]uint64{}
		}
		s.apiMetrics.status[fmt.Sprintf("%dxx", sw.status/100)]++
		s.apiMetrics.mu.Unlock()
	})
}

type countingWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (c *countingWriter) WriteHeader(code int) {
	if !c.wrote {
		c.status = code
		c.wrote = true
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	c.wrote = true
	return c.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the real writer.
func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// Certificates expiring within this long count as "expiring soon".
const metricsCertSoon = 14 * 24 * time.Hour

// metrics serves Prometheus text for the control plane. A scraper presents
// AEGIS_METRICS_TOKEN as a bearer token; without one configured, or with a
// wrong one, an admin session is required, so the endpoint never leaks
// host names to an unauthenticated caller.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if s.metricsToken != "" {
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok &&
			subtle.ConstantTimeCompare([]byte(strings.TrimSpace(tok)), []byte(s.metricsToken)) == 1 {
			s.writeMetrics(w, r)
			return
		}
	}
	s.requireAuth(http.HandlerFunc(s.writeMetrics)).ServeHTTP(w, r)
}

func (s *Server) writeMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	var b strings.Builder
	gauge := func(name, help string, rows func()) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		rows()
	}

	gauge("aegis_api_info", "Control plane build.", func() {
		fmt.Fprintf(&b, "aegis_api_info{version=%q} 1\n", s.version)
	})
	gauge("aegis_api_up_seconds", "Seconds since the control plane started.", func() {
		fmt.Fprintf(&b, "aegis_api_up_seconds %d\n", int(now.Sub(s.apiMetrics.started).Seconds()))
	})
	if s.configVersion != nil {
		gauge("aegis_api_config_version", "Version of the configuration currently pushed to nodes.", func() {
			fmt.Fprintf(&b, "aegis_api_config_version %d\n", s.configVersion())
		})
	}

	dep := s.depStatus(ctx)
	gauge("aegis_api_dependency_up", "1 when the control plane can reach the dependency.", func() {
		fmt.Fprintf(&b, "aegis_api_dependency_up{dependency=\"postgres\"} %d\n", b2i(dep.Postgres))
		fmt.Fprintf(&b, "aegis_api_dependency_up{dependency=\"redis\"} %d\n", b2i(dep.Redis))
	})

	if nodes, err := s.st.ListNodes(ctx); err == nil {
		var online, offline, revoked int
		for _, n := range nodes {
			switch {
			case n.RevokedAt != nil:
				revoked++
			case n.LastSeenAt != nil && now.Sub(*n.LastSeenAt) < 60*time.Second:
				online++
			default:
				offline++
			}
		}
		gauge("aegis_api_nodes", "Edge nodes by state (online = checked in within 60 s).", func() {
			fmt.Fprintf(&b, "aegis_api_nodes{state=\"online\"} %d\naegis_api_nodes{state=\"offline\"} %d\naegis_api_nodes{state=\"revoked\"} %d\n", online, offline, revoked)
		})
		gauge("aegis_api_node_cert_expiry_seconds", "Seconds until each active node's client certificate expires.", func() {
			for _, n := range nodes {
				if n.RevokedAt == nil {
					fmt.Fprintf(&b, "aegis_api_node_cert_expiry_seconds{node=%q} %d\n", n.Name, int64(n.CertExpiresAt.Sub(now).Seconds()))
				}
			}
		})
	}

	if hosts, err := s.st.ListHosts(ctx); err == nil {
		counts := map[string]int{}
		for _, h := range hosts {
			kind := h.Kind
			if kind == "" {
				kind = "proxy"
			}
			counts[fmt.Sprintf("%s|%t", kind, h.Enabled)]++
		}
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		gauge("aegis_api_hosts", "Configured hosts by kind and enabled state.", func() {
			for _, k := range keys {
				kind, enabled, _ := strings.Cut(k, "|")
				fmt.Fprintf(&b, "aegis_api_hosts{kind=%q,enabled=%q} %d\n", kind, enabled, counts[k])
			}
		})
	}

	if certs, err := s.st.ListCertificateMeta(ctx); err == nil {
		soon, expired := 0, 0
		gauge("aegis_api_certificate_expiry_seconds", "Seconds until each certificate expires (negative = expired).", func() {
			for _, c := range certs {
				left := c.ExpiresAt.Sub(now)
				if left <= 0 {
					expired++
				} else if left < metricsCertSoon {
					soon++
				}
				name := ""
				if len(c.Domains) > 0 {
					name = c.Domains[0]
				}
				fmt.Fprintf(&b, "aegis_api_certificate_expiry_seconds{certificate=%q,issuer=%q} %d\n", name, c.Issuer, int64(left.Seconds()))
			}
		})
		gauge("aegis_api_certificates_expiring_soon", "Certificates expiring within 14 days.", func() {
			fmt.Fprintf(&b, "aegis_api_certificates_expiring_soon %d\n", soon)
		})
		gauge("aegis_api_certificates_expired", "Certificates past their expiry.", func() {
			fmt.Fprintf(&b, "aegis_api_certificates_expired %d\n", expired)
		})
	}

	if s.env != nil {
		if notices, err := s.st.ListNotices(ctx, s.env.Open); err == nil {
			byKind := map[string]int{}
			for _, n := range notices {
				byKind[n.Kind]++
			}
			kinds := make([]string, 0, len(byKind))
			for k := range byKind {
				kinds = append(kinds, k)
			}
			sort.Strings(kinds)
			gauge("aegis_api_notices", "Open operator notices by kind.", func() {
				if len(kinds) == 0 {
					fmt.Fprintf(&b, "aegis_api_notices{kind=\"none\"} 0\n")
				}
				for _, k := range kinds {
					fmt.Fprintf(&b, "aegis_api_notices{kind=%q} %d\n", k, byKind[k])
				}
			})
		}
	}

	s.apiMetrics.mu.Lock()
	classes := make([]string, 0, len(s.apiMetrics.status))
	for k := range s.apiMetrics.status {
		classes = append(classes, k)
	}
	sort.Strings(classes)
	fmt.Fprintf(&b, "# HELP aegis_api_http_responses_total API responses since start, by status class.\n# TYPE aegis_api_http_responses_total counter\n")
	for _, k := range classes {
		fmt.Fprintf(&b, "aegis_api_http_responses_total{class=%q} %d\n", k, s.apiMetrics.status[k])
	}
	s.apiMetrics.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}

func b2i(v bool) int {
	if v {
		return 1
	}
	return 0
}
