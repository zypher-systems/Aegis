package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFromRequestIgnoresXFFWhenUntrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "203.0.113.9:443"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := FromRequest(req, nil); got != "203.0.113.9" {
		t.Fatalf("untrusted hop: got %q", got)
	}
	if got := FromRequest(req, []string{"10.0.0.0/8"}); got != "203.0.113.9" {
		t.Fatalf("hop outside list: got %q", got)
	}
}

func TestFromRequestHonoursXFFWhenTrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.2")
	if got := FromRequest(req, []string{"10.0.0.0/8"}); got != "198.51.100.7" {
		t.Fatalf("trusted hop: got %q", got)
	}
}

func TestFromRequestIgnoresSpoofedLeftXFF(t *testing.T) {
	// A visitor sends "X-Forwarded-For: 1.2.3.4"; nginx (NPM) appends the real
	// address it saw. The spoofed entry must not become the client IP.
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "192.168.1.10:51000" // NPM on the LAN
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.7")
	if got := FromRequest(req, []string{"192.168.1.10"}); got != "198.51.100.7" {
		t.Fatalf("spoofed XFF: got %q, want the address NPM appended", got)
	}
}

func TestFromRequestSkipsEveryTrustedHop(t *testing.T) {
	// Cloudflare → NPM → Aegis, both proxies trusted.
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "192.168.1.10:51000"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7, 173.245.48.1")
	if got := FromRequest(req, []string{"192.168.1.10", "173.245.48.0/20"}); got != "198.51.100.7" {
		t.Fatalf("got %q", got)
	}
}

func TestFromRequestMalformedEntryStopsAtHop(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, not-an-ip")
	if got := FromRequest(req, []string{"10.0.0.0/8"}); got != "10.0.0.2" {
		t.Fatalf("got %q", got)
	}
}

func TestFromRequestTrustedWithoutXFFUsesHop(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	if got := FromRequest(req, []string{"10.0.0.2"}); got != "10.0.0.2" {
		t.Fatalf("got %q", got)
	}
}

func TestParseListAndNormalize(t *testing.T) {
	got := ParseList("10.0.0.0/8, 127.0.0.1")
	if len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "127.0.0.1" {
		t.Fatalf("ParseList = %#v", got)
	}
	out, err := Normalize([]string{" 172.16.0.0/12 ", "", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("Normalize = %#v", out)
	}
	if _, err := Normalize([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected invalid CIDR")
	}
}
