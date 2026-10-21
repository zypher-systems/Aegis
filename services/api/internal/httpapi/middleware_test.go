package httpapi

import (
	"context"
	"crypto/hmac"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFTokenMatch(t *testing.T) {
	if hmac.Equal([]byte("a"), []byte("b")) {
		t.Fatal("mismatch should fail")
	}
	if !hmac.Equal([]byte("tok"), []byte("tok")) {
		t.Fatal("match should pass")
	}
}

func TestClientIPIgnoresXFFWhenUntrusted(t *testing.T) {
	s := New(Deps{})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "203.0.113.9:9"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := s.clientIP(req); got != "203.0.113.9" {
		t.Fatalf("got %q", got)
	}
}

func TestClientIPHonoursXFFWhenTrusted(t *testing.T) {
	s := New(Deps{TrustedProxyCIDRs: []string{"10.0.0.0/8"}})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "10.1.2.3:9"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	if got := s.clientIP(req); got != "198.51.100.7" {
		t.Fatalf("got %q", got)
	}
}

func csrfPassThrough(t *testing.T) http.Handler {
	t.Helper()
	s := New(Deps{PublicOrigin: "http://127.0.0.1:3300"})
	return s.csrf(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}

func TestOriginOKLoopbackAliases(t *testing.T) {
	s := New(Deps{PublicOrigin: "http://127.0.0.1:3300"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.Host = "localhost:18080"
	if !s.originOK("http://127.0.0.1:3300", req) {
		t.Fatal("127.0.0.1 origin should match localhost request host")
	}
	req.Host = "127.0.0.1:18080"
	if !s.originOK("http://localhost:3300", req) {
		t.Fatal("localhost origin should match 127.0.0.1 public origin")
	}
	if s.originOK("http://evil.example:3300", req) {
		t.Fatal("unrelated origin must not match")
	}
}

func TestCSRFRejectsMissingOrigin(t *testing.T) {
	h := csrfPassThrough(t)
	req := httptest.NewRequest(http.MethodPost, "/api/hosts", nil)
	req.Host = "127.0.0.1:18080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing Origin: got %d", rec.Code)
	}
}

func TestCSRFLoginLoopbackOriginSkipsToken(t *testing.T) {
	h := csrfPassThrough(t)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.Host = "localhost:18080"
	req.Header.Set("Origin", "http://127.0.0.1:3300")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login with loopback origin: got %d %s", rec.Code, rec.Body.String())
	}
}

func TestCSRFComposeDNSOriginMatchesHost(t *testing.T) {
	s := New(Deps{PublicOrigin: "http://127.0.0.1:3300"})
	h := s.csrf(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.Host = "api:8080"
	req.Header.Set("Origin", "http://api:8080")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("CI origin matching r.Host: got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLoginLimiterFallsBackToLocalCounter(t *testing.T) {
	s := New(Deps{}) // no Redis
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "203.0.113.9:9"
	for i := 0; i < loginAttempts; i++ {
		if !s.allowLogin(req) {
			t.Fatalf("attempt %d refused", i+1)
		}
	}
	if s.allowLogin(req) {
		t.Fatal("attempt past the limit must be refused even without Redis")
	}
	other := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	other.RemoteAddr = "203.0.113.10:9"
	if !s.allowLogin(other) {
		t.Fatal("another IP is unaffected")
	}
}

func TestAccountLockoutCountsFailuresAcrossAddresses(t *testing.T) {
	s := New(Deps{})
	ctx := context.Background()
	for i := 0; i < accountFailures-1; i++ {
		if s.accountFailed(ctx, "admin@corp.com") {
			t.Fatalf("locked after %d failures", i+1)
		}
	}
	if s.accountLocked(ctx, "admin@corp.com") {
		t.Fatal("not yet locked")
	}
	if !s.accountFailed(ctx, "admin@corp.com") {
		t.Fatal("the 10th failure must report the lockout")
	}
	if !s.accountLocked(ctx, "admin@corp.com") {
		t.Fatal("locked after 10 failures")
	}
	if s.accountLocked(ctx, "other@corp.com") {
		t.Fatal("other accounts unaffected")
	}
	s.accountSucceeded(ctx, "admin@corp.com")
	if s.accountLocked(ctx, "admin@corp.com") {
		t.Fatal("success clears the lock")
	}
}
