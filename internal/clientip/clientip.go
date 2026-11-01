// Package clientip resolves the connecting client address. X-Forwarded-For is
// honoured only when the immediate hop (RemoteAddr) is in a trusted CIDR list.
// An empty list is the correct default for an internet-facing edge.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

// RemoteIP returns the immediate hop from r.RemoteAddr, or "" if r is nil.
func RemoteIP(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// LeftmostXFF returns the first X-Forwarded-For hop, or "".
func LeftmostXFF(xff string) string {
	xff = strings.TrimSpace(xff)
	if xff == "" {
		return ""
	}
	if i := strings.IndexByte(xff, ','); i >= 0 {
		return strings.TrimSpace(xff[:i])
	}
	return xff
}

// FromRequest returns the client IP. If the immediate hop is not in trusted,
// X-Forwarded-For is ignored. Otherwise X-Forwarded-For is read from the
// right: trusted proxies each append the address they received from, so the
// rightmost address that is not itself a trusted proxy is the client. Anything
// to its left was supplied by the client and cannot be believed (a visitor who
// sends "X-Forwarded-For: 1.2.3.4" through nginx arrives as "1.2.3.4, <real>").
func FromRequest(r *http.Request, trusted []string) string {
	hop := RemoteIP(r)
	if hop == "" {
		return ""
	}
	if !Contains(net.ParseIP(hop), trusted) {
		return hop
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			// A malformed entry breaks the chain of trust; stop at the hop.
			return hop
		}
		if !Contains(ip, trusted) {
			return ip.String()
		}
	}
	return hop
}

// Contains reports whether ip matches any CIDR or bare address in cidrs.
func Contains(ip net.IP, cidrs []string) bool {
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Contains(c, "/") {
			_, n, err := net.ParseCIDR(c)
			if err == nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if other := net.ParseIP(c); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}

// ParseList splits a comma-separated CIDR/IP list. Empty entries are dropped.
func ParseList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Normalize validates each entry as a CIDR or bare IP and returns trimmed copies.
func Normalize(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{}, nil
	}
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if err := Valid(c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Valid reports whether s is a CIDR or a bare IP.
func Valid(s string) error {
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return err
		}
		return nil
	}
	if net.ParseIP(s) == nil {
		return &net.ParseError{Type: "IP address", Text: s}
	}
	return nil
}
