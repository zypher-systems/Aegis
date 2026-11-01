package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/proxy/internal/telemetry"
)

// lastEvent serves one request and returns the telemetry event it produced.
func lastEvent(t *testing.T, s *Server, req *http.Request) (*httptest.ResponseRecorder, *aegisv1.TelemetryEvent) {
	t.Helper()
	s.tel = telemetry.NewEmitter()
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	evs := s.tel.Drain(10)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	return rr, evs[0]
}

func TestEventCarriesRequestDetailAndUpstream(t *testing.T) {
	seenID := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenID <- r.Header.Get("X-Request-Id")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	h, p, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(p)
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
		Id: "h", DomainNames: []string{"app.example.com"}, Enabled: true,
		UpstreamScheme: "http", UpstreamHost: h, UpstreamPort: uint32(port),
	}}})
	req := httptest.NewRequest(http.MethodPost, "http://app.example.com/search?q=shoes&page=2", strings.NewReader("a=1"))
	req.Header.Set("Referer", "https://app.example.com/")
	req.RemoteAddr = "198.51.100.7:4000"
	rr, ev := lastEvent(t, s, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if ev.GetRequestId() == "" || <-seenID != ev.GetRequestId() {
		t.Fatalf("upstream X-Request-Id must match the event id %q", ev.GetRequestId())
	}
	if want := "http://" + u.Host; ev.GetUpstream() != want {
		t.Fatalf("upstream = %q, want %q", ev.GetUpstream(), want)
	}
	if ev.GetQuery() != "q=shoes&page=2" || ev.GetReferer() != "https://app.example.com/" {
		t.Fatalf("query/referer = %q / %q", ev.GetQuery(), ev.GetReferer())
	}
	if ev.GetScheme() != "http" || ev.GetProtocol() != "HTTP/1.1" || ev.GetTlsVersion() != "" {
		t.Fatalf("scheme/protocol/tls = %q %q %q", ev.GetScheme(), ev.GetProtocol(), ev.GetTlsVersion())
	}
	if ev.GetPeerIp() != "198.51.100.7" || ev.GetBytesReceived() != 3 {
		t.Fatalf("peer/bytes = %q %d", ev.GetPeerIp(), ev.GetBytesReceived())
	}
}

func TestEventSaysWhyGeoBlocked(t *testing.T) {
	s := New()
	s.geoLookup = func(net.IP) (string, bool) { return "RU", true }
	s.Apply(snapshot(t, s, &aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
		Id: "g", DomainNames: []string{"geo.example.com"}, Enabled: true,
		UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
		GeoDeny: []string{"RU"},
	}}}))
	req := httptest.NewRequest(http.MethodGet, "http://geo.example.com/", nil)
	req.RemoteAddr = "203.0.113.5:4000"
	rr, ev := lastEvent(t, s, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status %d", rr.Code)
	}
	if ev.GetBlockStage() != stageGeo || ev.GetBlockDetail() != "country RU is denied" {
		t.Fatalf("stage/detail = %q / %q", ev.GetBlockStage(), ev.GetBlockDetail())
	}
	if ev.GetUpstream() != "" {
		t.Fatalf("a blocked request reached upstream %q", ev.GetUpstream())
	}
}

func TestEventSaysWhyACLBlocked(t *testing.T) {
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
		Id: "a", DomainNames: []string{"acl.example.com"}, Enabled: true,
		UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
		AccessList: &aegisv1.AccessList{DenyCidrs: []string{"203.0.113.0/24"}},
	}}})
	req := httptest.NewRequest(http.MethodGet, "http://acl.example.com/", nil)
	req.RemoteAddr = "203.0.113.5:4000"
	_, ev := lastEvent(t, s, req)
	if ev.GetBlockStage() != stageACL || !strings.Contains(ev.GetBlockDetail(), "deny list") {
		t.Fatalf("stage/detail = %q / %q", ev.GetBlockStage(), ev.GetBlockDetail())
	}
}

func TestWAFKeepsEveryMatchWithWhereAndValue(t *testing.T) {
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "block"}, okNext())
	req := attachBlockMeta(attachWAFResult(httptest.NewRequest(http.MethodGet, "http://x/?id=1%27%20OR%20%271%27%3D%271", nil)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
	res := wafResultFrom(req)
	if len(res.Matches) == 0 {
		t.Fatal("no rule matches kept")
	}
	m := res.Matches[0]
	if !strings.HasPrefix(m.id, "942") || m.msg == "" || m.variable != "ARGS" || m.key != "id" || !strings.Contains(m.value, "OR") {
		t.Fatalf("first match = %+v", m)
	}
	if d := blockMetaFrom(req).Detail; !strings.Contains(d, "anomaly score") || !strings.Contains(d, "threshold of 5") {
		t.Fatalf("block detail = %q", d)
	}
}

func TestTruncateUTF8KeepsWholeRunes(t *testing.T) {
	if got := truncateUTF8("héllo", 2); got != "h" {
		t.Fatalf("got %q, want %q (é is two bytes)", got, "h")
	}
	if got := truncateUTF8("abc", 10); got != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectModeDoesNotFlagCleanRequests(t *testing.T) {
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "detect"}, okNext())
	req := attachBlockMeta(attachWAFResult(httptest.NewRequest(http.MethodGet, "http://x/products?page=2", nil)))
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0")
	req.Header.Set("Accept", "text/html")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if res := wafResultFrom(req); res.Action != "" || res.RuleID != "" {
		t.Fatalf("clean request flagged: action=%q rule=%q", res.Action, res.RuleID)
	}
}

func TestDetectModeFlagsARealMatch(t *testing.T) {
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "detect"}, okNext())
	req := attachBlockMeta(attachWAFResult(httptest.NewRequest(http.MethodGet, "http://x/?id=1%27%20OR%20%271%27%3D%271", nil)))
	h.ServeHTTP(httptest.NewRecorder(), req)
	res := wafResultFrom(req)
	if res.Action != "detect" || !strings.HasPrefix(res.RuleID, "942") || len(res.Matches) == 0 {
		t.Fatalf("result = %+v", res)
	}
}
