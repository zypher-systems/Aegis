package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestRateKeyBucketsIPv6BySubnet(t *testing.T) {
	if rateKey("203.0.113.5") != "203.0.113.5" {
		t.Fatal("v4 unchanged")
	}
	a, b := rateKey("2001:db8:1:2:aaaa::1"), rateKey("2001:db8:1:2:bbbb::9")
	if a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("same /64 must share a bucket: %q %q", a, b)
	}
	if rateKey("2001:db8:1:3::1") == a {
		t.Fatal("different /64 must not share")
	}
	if rateKey("::ffff:203.0.113.5") != "::ffff:203.0.113.5" && rateKey("::ffff:203.0.113.5") != "203.0.113.5" {
		t.Fatalf("v4-mapped: %q", rateKey("::ffff:203.0.113.5"))
	}
}

func TestSanitizeForwardedRewritesUntrustedChain(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	r.Header.Set("X-Forwarded-For", "127.0.0.1, 10.0.0.1, 203.0.113.5")
	r.Header.Set("CF-Connecting-IP", "127.0.0.1")
	r.Header.Set("Forwarded", "for=127.0.0.1")
	sanitizeForwarded(r, nil)
	if got := r.Header.Get("X-Forwarded-For"); got != "203.0.113.5" {
		t.Fatalf("untrusted chain kept: %q", got)
	}
	if r.Header.Get("CF-Connecting-IP") != "" || r.Header.Get("Forwarded") != "" {
		t.Fatal("other client-ip headers must be dropped from an untrusted hop")
	}
	// From a trusted proxy the chain is kept as the proxy built it.
	r = httptest.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	sanitizeForwarded(r, []string{"10.0.0.0/8"})
	if got := r.Header.Get("X-Forwarded-For"); got != "198.51.100.7, 10.0.0.1" {
		t.Fatalf("trusted chain altered: %q", got)
	}
}

func TestReadyzDisableAndMetrics(t *testing.T) {
	s := New()
	get := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		req.RemoteAddr = "127.0.0.1:9"
		s.ServeHTTP(rr, req)
		return rr
	}
	if get("/healthz").Code != 200 || get("/readyz").Code != 503 {
		t.Fatal("no config: live but not ready")
	}
	upHost, upPort := hostEcho(t)
	s.Apply(&aegisv1.ConfigUpdate{Version: 7, Hosts: []*aegisv1.Host{{
		Id: "h", DomainNames: []string{"app.example.com"}, Enabled: true,
		UpstreamScheme: "http", UpstreamHost: upHost, UpstreamPort: upPort,
	}}})
	if get("/readyz").Code != 200 {
		t.Fatal("config loaded: ready")
	}
	// Serve one request, then read the metrics.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req.Host = "app.example.com"
	s.ServeHTTP(rr, req)
	body := get("/metrics").Body.String()
	for _, want := range []string{
		`aegis_proxy_requests_total{host="app.example.com"} 1`,
		`aegis_proxy_responses_total{host="app.example.com",class="2xx"} 1`,
		"aegis_proxy_config_version 7",
		"aegis_proxy_hosts 1",
		"aegis_proxy_disabled 0",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics lack %q:\n%s", want, body)
		}
	}
	// Not for the public: from a non-loopback peer these paths route like any other.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://app.example.com/metrics", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "203.0.113.5:9"
	s.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), "aegis_proxy_requests_total") {
		t.Fatal("metrics exposed to a public visitor")
	}
	// Revoked: everything is 503 and readiness says so.
	s.Disable("test")
	if get("/readyz").Code != 503 {
		t.Fatal("disabled node must not be ready")
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req.Host = "app.example.com"
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled node served %d", rr.Code)
	}
	if !strings.Contains(get("/metrics").Body.String(), "aegis_proxy_disabled 1") {
		t.Fatal("metrics must show the disabled state")
	}
}
