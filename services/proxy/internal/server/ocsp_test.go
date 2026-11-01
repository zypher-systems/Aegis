package server

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestOCSPSkipsCertsWithoutResponderAndServesUnstapled(t *testing.T) {
	now := time.Now()
	self := selfSigned(t, []string{"app.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	pair, err := tls.X509KeyPair(self.CertPem, self.KeyPem)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ocspTarget(&pair); err != errNoOCSP {
		t.Fatalf("self-signed single cert: %v, want errNoOCSP", err)
	}
	var o ocspStapler
	if got := o.withStaple(&pair); got != &pair {
		t.Fatal("no staple: the same certificate must be returned")
	}
	o.track(map[string]*tls.Certificate{"app.example.com": &pair})
	o.refresh(nil)
	if got := o.withStaple(&pair); got.OCSPStaple != nil {
		t.Fatal("a cert without a responder must not get a staple")
	}
	// Whole server path still serves the cert.
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: certHost("app.example.com"), Certificates: []*aegisv1.Certificate{self}})
	if servedFor(t, s, "app.example.com").Subject.CommonName != "app.example.com" {
		t.Fatal("cert not served")
	}
}

func TestHSTSValueAndTLSOnly(t *testing.T) {
	if hstsValue(&aegisv1.Host{}) != "" {
		t.Fatal("off")
	}
	if v := hstsValue(&aegisv1.Host{Hsts: true}); v != "max-age=31536000" {
		t.Fatalf("default: %q", v)
	}
	if v := hstsValue(&aegisv1.Host{Hsts: true, HstsMaxAge: 63072000, HstsIncludeSubdomains: true, HstsPreload: true}); v != "max-age=63072000; includeSubDomains; preload" {
		t.Fatalf("full: %q", v)
	}
	upHost, upPort := hostEcho(t)
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Security: &aegisv1.SecurityConfig{TrustedProxyCidrs: []string{"10.0.0.0/8"}}, Hosts: []*aegisv1.Host{{
		Id: "h", DomainNames: []string{"app.example.com"}, Enabled: true, Hsts: true,
		UpstreamScheme: "http", UpstreamHost: upHost, UpstreamPort: upPort,
	}}})
	get := func(remote string, hdr map[string]string) string {
		rr := plainGET(s, remote, hdr)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		return rr.Header().Get("Strict-Transport-Security")
	}
	if v := get("203.0.113.5:1", nil); v != "" {
		t.Fatalf("plain HTTP must not carry HSTS, got %q", v)
	}
	if v := get("10.1.2.3:1", map[string]string{"X-Forwarded-Proto": "https"}); v != "max-age=31536000" {
		t.Fatalf("https via trusted proxy: %q", v)
	}
}
