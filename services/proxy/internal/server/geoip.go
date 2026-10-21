package server

import (
	"net/http"
	"strings"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func (s *Server) geoWrap(h *aegisv1.Host) func(http.Handler) http.Handler {
	allow := isoSet(h.GetGeoAllow())
	deny := isoSet(h.GetGeoDeny())
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			forbid := func(detail string) {
				setBlock(r, stageGeo, detail)
				writeError(w, r, http.StatusForbidden)
			}
			ip := clientIP(r, s.trustedCIDRs())
			if ip == nil {
				forbid("client IP could not be read")
				return
			}
			// Same as CrowdSec L7: LAN/compose clients are not a country.
			// Unknown public IPs and a missing MMDB still fail closed below.
			if ip.IsPrivate() || ip.IsLoopback() {
				next.ServeHTTP(w, r)
				return
			}
			if s.geoLookup == nil {
				forbid("GeoIP database is not loaded; country rules fail closed")
				return
			}
			cc, ok := s.geoLookup(ip)
			if !ok || cc == "" {
				forbid("country unknown for this IP; country rules fail closed")
				return
			}
			cc = strings.ToUpper(cc)
			if _, blocked := deny[cc]; blocked {
				forbid("country " + cc + " is denied")
				return
			}
			if len(allow) > 0 {
				if _, ok := allow[cc]; !ok {
					forbid("country " + cc + " is not in the allowed countries")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isoSet(in []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range in {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s != "" {
			out[s] = struct{}{}
		}
	}
	return out
}

func matchCountry(iso string, allow, deny []string) bool {
	iso = strings.ToUpper(iso)
	for _, d := range deny {
		if strings.EqualFold(d, iso) {
			return false
		}
	}
	if len(allow) == 0 {
		return true
	}
	for _, a := range allow {
		if strings.EqualFold(a, iso) {
			return true
		}
	}
	return false
}
