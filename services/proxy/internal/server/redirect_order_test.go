package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/internal/passwd"
)

func forceHTTPSHost(t *testing.T, acl *aegisv1.AccessList) *Server {
	t.Helper()
	upHost, upPort := hostEcho(t)
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version:  1,
		Security: &aegisv1.SecurityConfig{TrustedProxyCidrs: []string{"10.0.0.0/8"}},
		Hosts: []*aegisv1.Host{{
			Id: "fh", DomainNames: []string{"app.example.com"}, Enabled: true,
			UpstreamScheme: "http", UpstreamHost: upHost, UpstreamPort: upPort,
			TlsMode: aegisv1.TLSMode_TLS_MODE_AUTO, ForceHttps: true, AccessList: acl,
		}},
	})
	return s
}

func plainGET(s *Server, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com:8080/private?x=1", nil)
	req.Host = "app.example.com:8080"
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	s.ServeHTTP(rr, req)
	return rr
}

func TestForceHTTPSHonoursTrustedProxySchemeAndDropsPort(t *testing.T) {
	s := forceHTTPSHost(t, nil)
	// Behind a trusted proxy that terminated TLS: no redirect loop.
	if rr := plainGET(s, "10.1.2.3:4000", map[string]string{"X-Forwarded-Proto": "https"}); rr.Code != http.StatusOK {
		t.Fatalf("trusted https hop got %d, want 200 (redirect loop)", rr.Code)
	}
	// An untrusted visitor cannot claim https.
	rr := plainGET(s, "203.0.113.5:4000", map[string]string{"X-Forwarded-Proto": "https"})
	if rr.Code != http.StatusMovedPermanently {
		t.Fatalf("untrusted visitor got %d, want 301", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "https://app.example.com/private?x=1" {
		t.Fatalf("Location %q must drop the plain-HTTP port", loc)
	}
}

func TestRedirectComesBeforeBasicAuthButAfterDeny(t *testing.T) {
	hash, err := passwd.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	s := forceHTTPSHost(t, &aegisv1.AccessList{
		Satisfy:   "all",
		Users:     []*aegisv1.BasicAuthUser{{Username: "alice", PasswordHash: hash}},
		DenyCidrs: []string{"198.51.100.0/24"},
	})
	// Plain HTTP, no credentials: send the visitor to HTTPS, never a 401
	// that would make the browser post the password in the clear.
	if rr := plainGET(s, "203.0.113.5:4000", nil); rr.Code != http.StatusMovedPermanently {
		t.Fatalf("plain HTTP on a basic-auth host got %d, want 301 before any challenge", rr.Code)
	}
	// Denied addresses do not even get the redirect.
	if rr := plainGET(s, "198.51.100.9:4000", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("denied address got %d, want 403", rr.Code)
	}
	// Over HTTPS (trusted hop says so) the challenge appears as before.
	if rr := plainGET(s, "10.1.2.3:4000", map[string]string{"X-Forwarded-Proto": "https"}); rr.Code != http.StatusUnauthorized {
		t.Fatalf("https without credentials got %d, want 401", rr.Code)
	}
}

func TestAuthGuardCachesSuccessAndLocksOutFailures(t *testing.T) {
	hash, err := passwd.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	users := []*aegisv1.BasicAuthUser{{Username: "alice", PasswordHash: hash}}
	g := newAuthGuard()
	if v := g.verify("203.0.113.1", "alice", "secret", users); v != authOK || g.hashes != 1 {
		t.Fatalf("first check: %v hashes=%d", v, g.hashes)
	}
	for i := 0; i < 20; i++ {
		if v := g.verify("203.0.113.1", "alice", "secret", users); v != authOK {
			t.Fatalf("cached check %d: %v", i, v)
		}
	}
	if g.hashes != 1 {
		t.Fatalf("a browser resending the same credentials cost %d hashes, want 1", g.hashes)
	}
	// Wrong passwords hash until the lockout, then are refused without hashing.
	for i := 0; i < authFailLimit; i++ {
		if v := g.verify("203.0.113.2", "alice", "wrong", users); v != authBad {
			t.Fatalf("failure %d: %v", i, v)
		}
	}
	before := g.hashes
	if v := g.verify("203.0.113.2", "alice", "secret", users); v != authLocked {
		t.Fatalf("after %d failures: %v, want locked (even with the right password)", authFailLimit, v)
	}
	if g.hashes != before {
		t.Fatal("a locked-out IP must not cost a hash")
	}
	// Another IP is unaffected; unknown users fail without hashing.
	if v := g.verify("203.0.113.3", "bob", "x", users); v != authBad || g.hashes != before {
		t.Fatalf("unknown user: %v hashes=%d", v, g.hashes)
	}
	if v := g.verify("203.0.113.3", "alice", "secret", users); v != authOK {
		t.Fatalf("other IP: %v", v)
	}
}
