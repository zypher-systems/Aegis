package server

import (
	"encoding/base64"
	"net"
	"net/http"
	"strings"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/internal/clientip"
)

func hopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade", "host":
		return true
	default:
		return false
	}
}

func clientIP(r *http.Request, trusted []string) net.IP {
	return net.ParseIP(clientIPString(r, trusted))
}

func clientIPString(r *http.Request, trusted []string) string {
	return clientip.FromRequest(r, trusted)
}

func matchCIDR(ip net.IP, cidrs []string) bool {
	return clientip.Contains(ip, cidrs)
}

// verifyBasic checks the request's Basic credentials through the guard
// (cache, lockout, bounded hashing). No header at all is simply "bad".
func verifyBasic(r *http.Request, users []*aegisv1.BasicAuthUser, ip string) authVerdict {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(h), "basic ") {
		return authBad
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[6:]))
	if err != nil {
		return authBad
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return authBad
	}
	return basicAuthGuard.verify(ip, user, pass, users)
}

// aclDenied is the cheap half of an access list: deny CIDRs only. It runs
// before the HTTPS redirect so a denied address gets nothing at all.
func aclDenied(w http.ResponseWriter, r *http.Request, acl *aegisv1.AccessList, trusted []string) bool {
	if acl == nil || len(acl.GetDenyCidrs()) == 0 {
		return false
	}
	if matchCIDR(clientIP(r, trusted), acl.GetDenyCidrs()) {
		setBlock(r, stageACL, "client IP is on the access list's deny list")
		writeError(w, r, http.StatusForbidden)
		return true
	}
	return false
}

func challengeBasic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Basic realm="aegis"`)
	writeError(w, r, http.StatusUnauthorized)
}

// applyACL enforces a compiled access list. Stream hosts pass stream=true so
// basic auth is skipped (IP rules only).
func applyACL(w http.ResponseWriter, r *http.Request, acl *aegisv1.AccessList, stream bool, trusted []string) bool {
	if acl == nil {
		return true
	}
	ip := clientIP(r, trusted)
	if matchCIDR(ip, acl.GetDenyCidrs()) {
		setBlock(r, stageACL, "client IP is on the access list's deny list")
		writeError(w, r, http.StatusForbidden)
		return false
	}
	ipConfigured := len(acl.GetAllowCidrs()) > 0
	ipOK := !ipConfigured || matchCIDR(ip, acl.GetAllowCidrs())
	users := acl.GetUsers()
	authConfigured := len(users) > 0 && !stream
	authPassed := false
	if authConfigured {
		switch verifyBasic(r, users, ip.String()) {
		case authOK:
			authPassed = true
		case authLocked:
			setBlock(r, stageACL, "too many failed logins from this IP; locked out for 10 minutes")
			writeError(w, r, http.StatusTooManyRequests)
			return false
		case authBusy:
			setBlock(r, stageACL, "login verification is saturated")
			w.Header().Set("Retry-After", "2")
			writeError(w, r, http.StatusServiceUnavailable)
			return false
		}
	}
	satisfy := acl.GetSatisfy()
	if satisfy == "" {
		satisfy = "all"
	}

	var pass bool
	if !ipConfigured && !authConfigured {
		pass = true
	} else if satisfy == "any" {
		pass = (ipConfigured && ipOK) || (authConfigured && authPassed)
		if !pass && authConfigured && !authPassed {
			setBlock(r, stageACL, basicAuthDetail(r))
			challengeBasic(w, r)
			return false
		}
	} else {
		pass = (!ipConfigured || ipOK) && (!authConfigured || authPassed)
		if authConfigured && !authPassed {
			setBlock(r, stageACL, basicAuthDetail(r))
			challengeBasic(w, r)
			return false
		}
	}
	if !pass {
		setBlock(r, stageACL, "client IP is not on the access list's allow list")
		writeError(w, r, http.StatusForbidden)
		return false
	}
	return true
}

func basicAuthDetail(r *http.Request) string {
	if r.Header.Get("Authorization") == "" {
		return "basic auth required, no credentials sent"
	}
	return "basic auth credentials rejected"
}

func applyStreamACL(acl *aegisv1.AccessList, remote net.Addr) bool {
	if acl == nil {
		return true
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		host = remote.String()
	}
	ip := net.ParseIP(host)
	if matchCIDR(ip, acl.GetDenyCidrs()) {
		return false
	}
	if len(acl.GetAllowCidrs()) > 0 && !matchCIDR(ip, acl.GetAllowCidrs()) {
		return false
	}
	return true
}
