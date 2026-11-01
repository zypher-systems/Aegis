package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"google.golang.org/protobuf/proto"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

var (
	wafTestMu    sync.Mutex
	wafTestCache = map[string]coraza.WAF{}
)

func wrapTestWAF(t *testing.T, h *aegisv1.Host, next http.Handler) http.Handler {
	t.Helper()
	if !h.GetWafEnabled() {
		h.WafEnabled = true
	}
	s := New()
	fp := wafFingerprint(h)
	wafTestMu.Lock()
	if w, ok := wafTestCache[fp]; ok {
		s.wafCache[fp] = w
	}
	wafTestMu.Unlock()
	handler := s.wafWrap(h)(next)
	wafTestMu.Lock()
	if w, ok := s.wafCache[fp]; ok {
		wafTestCache[fp] = w
	}
	wafTestMu.Unlock()
	return handler
}

func okNext() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestWAFProbeForbidden(t *testing.T) {
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "block"}, okNext())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://x/waf-probe", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("probe status = %d", rr.Code)
	}
}

func TestWAFSQLiQueryBlocked(t *testing.T) {
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "block"}, okNext())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://x/?q=union+select+1", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("sqli query status = %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestWAFSQLiBodyBlocked(t *testing.T) {
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "block"}, okNext())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://x/", strings.NewReader("q=1'+union+select+1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("sqli body status = %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestWAFDetectDoesNotInterrupt(t *testing.T) {
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "detect"}, okNext())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://x/?q=union+select+1", nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("detect status = %d", rr.Code)
	}
}

func TestWAFDisabledSQLiPackagePasses(t *testing.T) {
	h := wrapTestWAF(t, &aegisv1.Host{
		WafMode: "block", WafDisabledTags: []string{"attack-sqli"},
	}, okNext())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://x/?q=union+select+1", nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("disabled sqli status = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://x/waf-probe", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("probe must still block, status = %d", rr.Code)
	}
}

func TestWAFExclusionByIDAndPath(t *testing.T) {
	h := wrapTestWAF(t, &aegisv1.Host{
		WafMode:       "block",
		WafExclusions: []*aegisv1.WAFExclusion{{RuleId: "19901", Path: "/waf-probe"}},
	}, okNext())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://x/waf-probe", nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("excluded probe status = %d", rr.Code)
	}
}

func TestWAFInspectsWebsocketHandshake(t *testing.T) {
	var hit bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "block"}, next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://x/waf-probe", nil)
	req.Header.Set("Upgrade", "websocket")
	h.ServeHTTP(rr, req)
	if hit || rr.Code != http.StatusForbidden {
		t.Fatalf("handshake must run WAF, status=%d hit=%v", rr.Code, hit)
	}
}

func TestWAFCompileFailureKeepsLastGood(t *testing.T) {
	s := New()
	good := &aegisv1.Host{
		Id: "h1", DomainNames: []string{"waf.local"},
		Enabled: true, WafEnabled: true, WafMode: "block",
		UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
	}
	s.Apply(snapshot(t, s, &aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{good}}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://waf.local/waf-probe", nil)
	req.Host = "waf.local"
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("good compile status=%d", rr.Code)
	}

	bad := protoCloneHost(good)
	bad.WafExclusions = []*aegisv1.WAFExclusion{{
		RuleId: `941100"`, Path: `/broken"directive`,
	}}
	s.Apply(snapshot(t, s, &aegisv1.ConfigUpdate{Version: 2, Hosts: []*aegisv1.Host{bad}}))
	s.wafMu.Lock()
	slot := s.wafByHost["h1"]
	s.wafMu.Unlock()
	if slot.fp != wafFingerprint(good) {
		t.Fatalf("last-good fingerprint lost: got %q want %q", slot.fp, wafFingerprint(good))
	}
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("last-good should still block probe, status=%d", rr.Code)
	}
}

func TestWAFCompileFailureFailOpen(t *testing.T) {
	s := New()
	h := &aegisv1.Host{
		Id: "new", DomainNames: []string{"open.local"},
		Enabled: true, WafEnabled: true, WafMode: "block",
		UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
		WafExclusions: []*aegisv1.WAFExclusion{{
			RuleId: `941100"`, Path: `/broken"directive`,
		}},
	}
	s.Apply(snapshot(t, s, &aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{h}}))
	s.wafMu.Lock()
	_, kept := s.wafByHost["new"]
	s.wafMu.Unlock()
	if kept {
		t.Fatal("fail-open must not install a compiled WAF")
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://open.local/", nil)
	req.Host = "open.local"
	s.ServeHTTP(rr, req)
	if rr.Code == http.StatusServiceUnavailable {
		t.Fatalf("fail-open must not 503, status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func protoCloneHost(h *aegisv1.Host) *aegisv1.Host {
	return proto.Clone(h).(*aegisv1.Host)
}

func TestCompileWAFRejectsUnsafeExclusion(t *testing.T) {
	_, err := compileWAF(&aegisv1.Host{
		WafEnabled: true, WafMode: "block",
		WafExclusions: []*aegisv1.WAFExclusion{{
			RuleId: `941100"`, Path: `/broken"directive`,
		}},
	})
	if err == nil {
		t.Fatal("expected compile error")
	}
}

func TestWAFCleanGETPasses(t *testing.T) {
	var body string
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	})
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "block"}, next)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("clean GET status = %d", rr.Code)
	}
	body = rr.Body.String()
	if body != "ok" {
		t.Fatalf("body = %q", body)
	}
}

// A block by anomaly score is reported as the rule that scored (here a CRS
// SQL-injection rule), not the generic 949110, so an operator knows what to
// fix or exclude.
func TestWAFReportsContributingRuleNotAnomalySummary(t *testing.T) {
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "block"}, okNext())
	req := attachWAFResult(httptest.NewRequest(http.MethodGet, "http://x/?id=1%27%20OR%20%271%27%3D%271", nil))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
	res := wafResultFrom(req)
	if res == nil || res.Action != "block" {
		t.Fatalf("result = %+v", res)
	}
	if res.RuleID == "949110" || !strings.HasPrefix(res.RuleID, "942") {
		t.Fatalf("reported rule = %q, want the SQL-injection rule that scored (942xxx)", res.RuleID)
	}
}

// PostHog's cookie holds JSON with "$device_id", "$initial_…" keys; CRS 942290
// reads it as MongoDB operators. A target exclusion drops only that cookie.
const posthogCookie = "ph_phc_kMstNfAgBcB_posthog"
const posthogValue = "%7B%22distinct_id%22%3A%220199%22%2C%22%24device_id%22%3A%220199%22%2C%22%24initial_person_info%22%3A%7B%22r%22%3A%22%24direct%22%7D%7D"

func posthogReq(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.AddCookie(&http.Cookie{Name: posthogCookie, Value: posthogValue})
	return r
}

func wafStatus(t *testing.T, h *aegisv1.Host, r *http.Request) int {
	t.Helper()
	rr := httptest.NewRecorder()
	wrapTestWAF(t, h, okNext()).ServeHTTP(rr, r)
	return rr.Code
}

func TestWAFExclusionTargetsOneCookie(t *testing.T) {
	plain := &aegisv1.Host{WafMode: "block"}
	if got := wafStatus(t, plain, posthogReq("http://x/blog/")); got != http.StatusForbidden {
		t.Fatalf("PostHog cookie should trip 942290 without an exclusion, got %d", got)
	}

	for _, target := range []string{"REQUEST_COOKIES:" + posthogCookie, "REQUEST_COOKIES:/^ph_.+_posthog$/"} {
		h := &aegisv1.Host{WafMode: "block", WafExclusions: []*aegisv1.WAFExclusion{{RuleId: "942290", Target: target}}}
		if got := wafStatus(t, h, posthogReq("http://x/blog/")); got != http.StatusNoContent {
			t.Fatalf("target %q: PostHog cookie still blocked (%d)", target, got)
		}
		// The rule is still on for everything else.
		mongo := httptest.NewRequest(http.MethodGet, "http://x/api?filter=%7B%22%24ne%22%3A1%7D", nil)
		if got := wafStatus(t, h, mongo); got != http.StatusForbidden {
			t.Fatalf("target %q: 942290 must still inspect arguments, got %d", target, got)
		}
	}

	scoped := &aegisv1.Host{WafMode: "block", WafExclusions: []*aegisv1.WAFExclusion{{RuleId: "942290", Path: "/blog/", Target: "REQUEST_COOKIES:" + posthogCookie}}}
	if got := wafStatus(t, scoped, posthogReq("http://x/blog/post")); got != http.StatusNoContent {
		t.Fatalf("path-scoped target under /blog/: %d", got)
	}
	if got := wafStatus(t, scoped, posthogReq("http://x/tools/")); got != http.StatusForbidden {
		t.Fatalf("path-scoped target must not apply outside /blog/: %d", got)
	}
}

func TestCompileWAFRejectsUnsafeTarget(t *testing.T) {
	h := &aegisv1.Host{WafMode: "block", WafExclusions: []*aegisv1.WAFExclusion{{RuleId: "942290", Target: "REQUEST_COOKIES:x\"\nSecRuleEngine Off"}}}
	if _, err := compileWAF(h); err == nil {
		t.Fatal("a target that could inject SecLang must be refused")
	}
}
