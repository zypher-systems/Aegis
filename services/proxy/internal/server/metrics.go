package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// metrics is a small Prometheus text exporter: enough for a dashboard and
// alert rules (request and block rates per host, upstream errors, config
// version) without a client library. Labels are bounded by the number of
// hosts, so cardinality stays small.
type metrics struct {
	mu        sync.Mutex
	requests  map[string]uint64            // domain
	status    map[string]map[string]uint64 // domain → class ("2xx")
	blocked   map[string]map[string]uint64 // domain → stage
	upstream  map[string]map[string]uint64 // domain → code ("502")
	wafAction map[string]map[string]uint64 // domain → block|detect
}

func (m *metrics) bump(mm *map[string]map[string]uint64, domain, key string) {
	if *mm == nil {
		*mm = map[string]map[string]uint64{}
	}
	inner := (*mm)[domain]
	if inner == nil {
		inner = map[string]uint64{}
		(*mm)[domain] = inner
	}
	inner[key]++
}

func (m *metrics) request(domain string) {
	m.mu.Lock()
	if m.requests == nil {
		m.requests = map[string]uint64{}
	}
	m.requests[domain]++
	m.mu.Unlock()
}

// finished records a completed request from emit().
func (m *metrics) finished(domain string, status int, blockStage, wafAction string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	class := "other"
	if status >= 100 && status < 600 {
		class = fmt.Sprintf("%dxx", status/100)
	}
	m.bump(&m.status, domain, class)
	if blockStage != "" {
		m.bump(&m.blocked, domain, blockStage)
	}
	if wafAction != "" {
		m.bump(&m.wafAction, domain, wafAction)
	}
	if status == http.StatusBadGateway || status == http.StatusGatewayTimeout || status == statusClientClosed {
		m.bump(&m.upstream, domain, fmt.Sprint(status))
	}
}

func (m *metrics) write(w http.ResponseWriter, s *Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP aegis_proxy_requests_total Requests received per host.\n# TYPE aegis_proxy_requests_total counter\n")
	for _, d := range sortedKeys(m.requests) {
		fmt.Fprintf(&b, "aegis_proxy_requests_total{host=%q} %d\n", d, m.requests[d])
	}
	writeNested(&b, "aegis_proxy_responses_total", "Responses per host by status class.", "class", m.status)
	writeNested(&b, "aegis_proxy_blocked_total", "Requests stopped by a security layer, per host and layer.", "stage", m.blocked)
	writeNested(&b, "aegis_proxy_waf_matches_total", "Requests the WAF matched, per host and action.", "action", m.wafAction)
	writeNested(&b, "aegis_proxy_upstream_errors_total", "Requests that ended in 502, 504 or 499, per host.", "code", m.upstream)
	version := s.Version()
	hosts := 0
	if st := s.cur.Load(); st != nil {
		hosts = len(st.byDomain)
	}
	fmt.Fprintf(&b, "# HELP aegis_proxy_config_version Version of the applied configuration.\n# TYPE aegis_proxy_config_version gauge\naegis_proxy_config_version %d\n", version)
	fmt.Fprintf(&b, "# HELP aegis_proxy_hosts Configured host names on this node.\n# TYPE aegis_proxy_hosts gauge\naegis_proxy_hosts %d\n", hosts)
	if s.pools != nil {
		fmt.Fprintf(&b, "# HELP aegis_proxy_upstream_healthy 1 when the upstream passes health checks.\n# TYPE aegis_proxy_upstream_healthy gauge\n")
		for _, u := range s.pools.health() {
			v := 0
			if u.healthy {
				v = 1
			}
			fmt.Fprintf(&b, "aegis_proxy_upstream_healthy{host=%q,upstream=%q} %d\n", u.domain, u.addr, v)
		}
	}
	fmt.Fprintf(&b, "# HELP aegis_proxy_problems Problems this node reports to the control plane.\n# TYPE aegis_proxy_problems gauge\naegis_proxy_problems %d\n", len(s.Problems()))
	disabled := 0
	if s.disabled.Load() {
		disabled = 1
	}
	fmt.Fprintf(&b, "# HELP aegis_proxy_disabled 1 when the control plane revoked this node.\n# TYPE aegis_proxy_disabled gauge\naegis_proxy_disabled %d\n", disabled)
	_, _ = w.Write([]byte(b.String()))
}

func writeNested(b *strings.Builder, name, help, label string, mm map[string]map[string]uint64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	for _, d := range sortedKeys(mm) {
		inner := mm[d]
		for _, k := range sortedKeys(inner) {
			fmt.Fprintf(b, "%s{host=%q,%s=%q} %d\n", name, d, label, k, inner[k])
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
