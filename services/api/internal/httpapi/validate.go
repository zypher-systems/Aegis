package httpapi

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Input rules for hosts. Everything here is admin-supplied, so the point is
// not to stop a hostile admin but to keep a typo or a pasted value from
// becoming an outage or a hole: a host that fronts the control plane, a
// header value with a newline, a domain with a space that no node can route.

var (
	domainLabelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	headerNameRe  = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// reservedUpstreams are the stack's own service names; a proxy host pointed
// at one would publish the control plane, the database or the cache.
var reservedUpstreams = map[string]bool{
	"api": true, "aegis-api": true, "postgres": true, "redis": true, "crowdsec": true,
	"crowdsec-firewall": true, "web": true, "localhost": true,
}

// validDomainName accepts host names ("app.example.com", "intranet"), a
// leading wildcard label ("*.example.com") and IPv4 literals. Lower-case
// only; the store lower-cases before this runs.
func validDomainName(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	if ip := net.ParseIP(d); ip != nil {
		return ip.To4() != nil
	}
	if strings.HasPrefix(d, "*.") {
		d = d[2:]
		if d == "" {
			return false
		}
	}
	for _, label := range strings.Split(d, ".") {
		if !domainLabelRe.MatchString(label) {
			return false
		}
	}
	return true
}

// upstreamProblem says why host may not be an upstream target, or "".
func upstreamProblem(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return "upstream host is required"
	}
	if strings.ContainsAny(h, "/ \t\r\n") {
		return "upstream host must be a host name or IP, without a scheme or path"
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if reservedUpstreams[h] {
		return "upstream " + host + " is part of Aegis itself and cannot be published"
	}
	if ip := net.ParseIP(h); ip != nil {
		switch {
		case ip.IsLoopback():
			return "upstream " + host + " is this machine's loopback; use the app's own address"
		case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
			return "upstream " + host + " is a link-local address (cloud metadata lives there)"
		case ip.IsUnspecified(), ip.IsMulticast():
			return "upstream " + host + " is not a routable address"
		}
	}
	return ""
}

func validRedirectURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && !strings.ContainsAny(raw, " \r\n")
}

// headerProblem validates operator-set request/response headers.
func headerProblem(name, value string) string {
	if !headerNameRe.MatchString(name) {
		return "header name " + strings.TrimSpace(name) + " is not valid"
	}
	if strings.ContainsAny(value, "\r\n") || len(value) > 4096 {
		return "header " + name + " has an invalid value"
	}
	return ""
}

// normalizeEmail is how every email is stored and looked up.
func normalizeEmail(e string) string {
	return strings.ToLower(strings.TrimSpace(e))
}

// defaultRoute reports a CIDR that would trust every address.
func defaultRoute(cidr string) bool {
	_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return false
	}
	ones, _ := n.Mask.Size()
	return ones == 0
}
