package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestErrorPagesForBrowsersAndClients(t *testing.T) {
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
		Id: "d", DomainNames: []string{"deny.example.com"}, Enabled: true,
		UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
		AccessList: &aegisv1.AccessList{DenyCidrs: []string{"203.0.113.0/24"}},
	}}})
	do := func(host string, accept string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/x", nil)
		req.Host = host
		req.RemoteAddr = "203.0.113.9:1"
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		s.ServeHTTP(rr, req)
		return rr
	}
	// A browser gets HTML with the status, a neutral sentence and a request id.
	rr := do("deny.example.com", "text/html,application/xhtml+xml")
	body := rr.Body.String()
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("browser: %d %s", rr.Code, rr.Header().Get("Content-Type"))
	}
	if !strings.Contains(body, "Request blocked") || !strings.Contains(body, "Request ") || strings.Contains(body, "deny list") {
		t.Fatalf("browser page must be neutral and carry a request id:\n%s", body)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("error pages must not be cached")
	}
	// curl / an API client gets one line of text with the same id.
	rr = do("deny.example.com", "")
	if rr.Code != http.StatusForbidden || !strings.HasPrefix(rr.Body.String(), "403 Request blocked\nRequest ") {
		t.Fatalf("client: %d %q", rr.Code, rr.Body.String())
	}
	// Unknown host with AEGIS_UNKNOWN_HOST=page: 404 page (the default
	// drops it; see unknownhost_test.go).
	s = NewWithOptions(Options{UnknownHost: UnknownHostPage})
	s.Apply(&aegisv1.ConfigUpdate{Version: 1})
	if rr = do("nothing.example.com", "text/html"); rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "No such site here") {
		t.Fatalf("unknown host: %d %s", rr.Code, rr.Body.String())
	}
}

func TestOperatorErrorTemplateAndFallback(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.html")
	os.WriteFile(good, []byte(`<h1>{{.Status}} at Example Corp</h1><p>{{.RequestID}}</p>`), 0o644)
	LoadErrorPage(good)
	t.Cleanup(func() { LoadErrorPage(""); errorTemplate.Store(mustDefault()) })
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Header.Set("Accept", "text/html")
	req = attachBlockMeta(req)
	writeError(rr, req, http.StatusBadGateway)
	if !strings.Contains(rr.Body.String(), "502 at Example Corp") {
		t.Fatalf("operator template not used: %s", rr.Body.String())
	}
	// A broken template is refused and the previous one stays.
	bad := filepath.Join(dir, "bad.html")
	os.WriteFile(bad, []byte(`{{.NoSuchField}}`), 0o644)
	LoadErrorPage(bad)
	rr = httptest.NewRecorder()
	writeError(rr, req, http.StatusBadGateway)
	if !strings.Contains(rr.Body.String(), "502 at Example Corp") {
		t.Fatal("a broken template must not replace the working one")
	}
}
