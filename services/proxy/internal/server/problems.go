package server

import (
	"fmt"
	"sort"
	"strings"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

// wafProblem is a host whose WAF profile did not compile on this node.
type wafProblem struct {
	resource string // the host's first domain
	detail   string
}

// Problems is what is wrong on this node right now, for the control plane
// (ConfigService.Report): WAF profiles that failed to compile, the CrowdSec
// stream being down, a missing GeoIP database while hosts use country
// rules. Sorted, so equal states compare equal.
func (s *Server) Problems() []*aegisv1.NodeProblem {
	var out []*aegisv1.NodeProblem
	s.wafMu.Lock()
	for _, p := range s.wafProblems {
		out = append(out, &aegisv1.NodeProblem{Kind: "waf_compile", Resource: p.resource, Detail: p.detail})
	}
	s.wafMu.Unlock()
	if s.pools != nil {
		down := map[string][]upstreamHealth{}
		total := map[string]int{}
		for _, u := range s.pools.health() {
			total[u.domain]++
			if !u.healthy {
				down[u.domain] = append(down[u.domain], u)
			}
		}
		for domain, list := range down {
			var b strings.Builder
			for i, u := range list {
				if i > 0 {
					b.WriteString("; ")
				}
				fmt.Fprintf(&b, "%s (%s)", u.addr, u.lastErr)
			}
			detail := "Failing health checks: " + b.String() + ". "
			if len(list) == total[domain] {
				detail += "Every upstream is down, so visitors get 502."
			} else {
				detail += "Traffic goes to the remaining upstreams."
			}
			out = append(out, &aegisv1.NodeProblem{Kind: "upstream_down", Resource: domain, Detail: detail})
		}
	}
	if v, _ := s.csProblem.Load().(string); v != "" {
		out = append(out, &aegisv1.NodeProblem{Kind: "crowdsec_stream", Detail: v})
	}
	if s.geoLookup == nil {
		if st := s.cur.Load(); st != nil {
			for _, e := range st.byDomain {
				if len(e.host.GetGeoAllow()) > 0 || len(e.host.GetGeoDeny()) > 0 {
					out = append(out, &aegisv1.NodeProblem{Kind: "geoip_missing",
						Detail: "No country database is loaded on this node, so hosts with country rules answer 403 to every public visitor."})
					break
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Kind+"|"+out[i].Resource < out[j].Kind+"|"+out[j].Resource
	})
	return out
}

// ProblemsFingerprint changes when the problem list does.
func (s *Server) ProblemsFingerprint() string {
	var b strings.Builder
	for _, p := range s.Problems() {
		b.WriteString(p.Kind + "|" + p.Resource + "|" + p.Detail + "\n")
	}
	return b.String()
}

func firstDomain(h *aegisv1.Host) string {
	if d := h.GetDomainNames(); len(d) > 0 {
		return d[0]
	}
	return h.GetId()
}
