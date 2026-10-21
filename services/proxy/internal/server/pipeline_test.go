package server

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestCompilePipelineWAFAndRate(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	s := New()
	s.Apply(snapshot(t, s, &aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "sec", DomainNames: []string{"sec.local"},
			UpstreamScheme: "http", UpstreamHost: host, UpstreamPort: uint32(port),
			Enabled: true, WafEnabled: true, RateLimitRps: 50, RateLimitBurst: 50,
		}},
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://sec.local/waf-probe", nil)
	req.Host = "sec.local"
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("waf status = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://sec.local/", nil)
	req.Host = "sec.local"
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("pass status = %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestDisabledStagesCompileOut(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	s := New()
	s.Apply(snapshot(t, s, &aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "plain", DomainNames: []string{"plain.local"},
			UpstreamScheme: "http", UpstreamHost: host, UpstreamPort: uint32(port),
			Enabled: true,
		}},
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://plain.local/waf-probe", nil)
	req.Host = "plain.local"
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disabled waf should compile out, status=%d", rr.Code)
	}
}
