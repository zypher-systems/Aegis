package httpapi

import (
	"strings"
	"testing"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func proxyHost(up string) *store.Host {
	return &store.Host{Kind: "proxy", DomainNames: []string{"app.example.com"}, UpstreamHost: up, UpstreamPort: 8080}
}

func TestValidateHostRefusesAegisItselfAndBadInput(t *testing.T) {
	for _, up := range []string{"api", "API", "postgres", "redis", "crowdsec", "localhost", "127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "http://app", "app internal"} {
		if msg := validateHost(proxyHost(up)); msg == "" {
			t.Errorf("upstream %q accepted", up)
		}
	}
	for _, up := range []string{"10.0.0.5", "app.internal", "demo", "192.168.1.20", "2001:db8::5"} {
		if msg := validateHost(proxyHost(up)); msg != "" {
			t.Errorf("upstream %q refused: %s", up, msg)
		}
	}
	h := proxyHost("10.0.0.5")
	h.Upstreams = []store.HostUpstream{{Scheme: "http", Host: "10.0.0.5", Port: 8080}, {Scheme: "http", Host: "api", Port: 8080}}
	if msg := validateHost(h); !strings.Contains(msg, "part of Aegis") {
		t.Fatalf("backup upstream pointing at the API accepted: %q", msg)
	}
	h = proxyHost("10.0.0.5")
	h.Upstreams = []store.HostUpstream{{Scheme: "http", Host: "10.0.0.5", Port: 99999}}
	if msg := validateHost(h); !strings.Contains(msg, "port") {
		t.Fatalf("port 99999 accepted: %q", msg)
	}
	for _, d := range []string{"foo bar", "a/b", "*", "*.", "-bad.example.com", "exa_mple.com"} {
		h = proxyHost("10.0.0.5")
		h.DomainNames = []string{d}
		if msg := validateHost(h); msg == "" {
			t.Errorf("domain %q accepted", d)
		}
	}
	for _, d := range []string{"app.example.com", "*.example.com", "intranet", "demo.local", "10.10.30.5"} {
		h = proxyHost("10.0.0.5")
		h.DomainNames = []string{d}
		if msg := validateHost(h); msg != "" {
			t.Errorf("domain %q refused: %s", d, msg)
		}
	}
	h = proxyHost("10.0.0.5")
	h.RequestHeaders = map[string]string{"X-Bad": "a\r\nInjected: yes"}
	if msg := validateHost(h); msg == "" {
		t.Fatal("CRLF header value accepted")
	}
	h = proxyHost("10.0.0.5")
	h.ResponseHeaders = map[string]string{"bad name": "x"}
	if msg := validateHost(h); msg == "" {
		t.Fatal("header name with a space accepted")
	}
	r := &store.Host{Kind: "redirect", DomainNames: []string{"old.example.com"}, RedirectURL: "javascript:alert(1)", RedirectCode: 301}
	if msg := validateHost(r); !strings.Contains(msg, "http(s)") {
		t.Fatalf("javascript: redirect accepted: %q", msg)
	}
	r.RedirectURL = "https://new.example.com/path?x=1"
	if msg := validateHost(r); msg != "" {
		t.Fatalf("good redirect refused: %s", msg)
	}
}

func TestDefaultRouteAndEmailNormalisation(t *testing.T) {
	if !defaultRoute("0.0.0.0/0") || !defaultRoute("::/0") || defaultRoute("10.0.0.0/8") || defaultRoute("nope") {
		t.Fatal("defaultRoute")
	}
	if normalizeEmail("  Admin@Corp.COM ") != "admin@corp.com" {
		t.Fatal("normalizeEmail")
	}
}
