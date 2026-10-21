package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func wafReq(method, target, ctype, body string, hdr map[string]string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestDefaultPolicyAllowsRESTTrafficThatCRSBlocks(t *testing.T) {
	h := &aegisv1.Host{WafMode: "block"}
	cases := []struct {
		name string
		req  *http.Request
	}{
		{"PUT json", wafReq(http.MethodPut, "http://x/api/items/3", "application/json", `{"id":3}`, nil)},
		{"PATCH json", wafReq(http.MethodPatch, "http://x/api/items/3", "application/json", `{"a":1}`, nil)},
		{"DELETE", wafReq(http.MethodDelete, "http://x/api/items/3", "", "", nil)},
		{"text/plain beacon", wafReq(http.MethodPost, "http://x/api/log", "text/plain", "hello", nil)},
		{"octet-stream", wafReq(http.MethodPost, "http://x/api/blob", "application/octet-stream", "abc", nil)},
		{"Expect header", wafReq(http.MethodPost, "http://x/api/items", "application/x-www-form-urlencoded", "a=1", map[string]string{"Expect": "100-continue"})},
		{"gzip body header", wafReq(http.MethodPost, "http://x/api/items", "application/json", `{}`, map[string]string{"Content-Encoding": "gzip"})},
	}
	for _, c := range cases {
		if code := wafStatus(t, h, c.req); code != http.StatusNoContent {
			t.Errorf("%s: %d, want pass", c.name, code)
		}
	}
	// Still refused by default: WebDAV methods and method-override headers.
	if code := wafStatus(t, h, wafReq("PROPFIND", "http://x/dav/", "", "", nil)); code != http.StatusForbidden {
		t.Errorf("PROPFIND by default: %d, want 403", code)
	}
	if code := wafStatus(t, h, wafReq(http.MethodPost, "http://x/api", "application/json", `{}`, map[string]string{"X-HTTP-Method-Override": "DELETE"})); code != http.StatusForbidden {
		t.Errorf("method override header: %d, want 403", code)
	}
}

func TestProfilePolicyIsHonoured(t *testing.T) {
	dav := &aegisv1.Host{WafMode: "block", WafAllowedMethods: append([]string{"GET", "POST", "PUT", "DELETE"}, "PROPFIND", "MKCOL")}
	if code := wafStatus(t, dav, wafReq("PROPFIND", "http://x/dav/", "", "", nil)); code != http.StatusNoContent {
		t.Fatalf("PROPFIND with WebDAV preset: %d", code)
	}
	if code := wafStatus(t, dav, wafReq(http.MethodPatch, "http://x/dav/", "application/json", `{}`, nil)); code != http.StatusForbidden {
		t.Fatalf("PATCH not in the list: %d, want 403", code)
	}
	strict := &aegisv1.Host{WafMode: "block", WafAllowedContentTypes: []string{"application/json"}}
	if code := wafStatus(t, strict, wafReq(http.MethodPost, "http://x/api", "text/plain", "x", nil)); code != http.StatusForbidden {
		t.Fatalf("text/plain against a JSON-only list: %d, want 403", code)
	}
	if code := wafStatus(t, strict, wafReq(http.MethodPost, "http://x/api", "application/json", `{}`, nil)); code != http.StatusNoContent {
		t.Fatalf("json against a JSON-only list: %d", code)
	}
	anyCT := &aegisv1.Host{WafMode: "block", WafAnyContentType: true}
	if code := wafStatus(t, anyCT, wafReq(http.MethodPost, "http://x/api", "application/x-custom-thing", "x", nil)); code != http.StatusNoContent {
		t.Fatalf("any content type: %d", code)
	}
	noExpect := &aegisv1.Host{WafMode: "block", WafRestrictedHeaders: []string{"expect", "proxy"}}
	if code := wafStatus(t, noExpect, wafReq(http.MethodPost, "http://x/api", "application/json", `{}`, map[string]string{"Expect": "100-continue"})); code != http.StatusForbidden {
		t.Fatalf("Expect with it restricted again: %d, want 403", code)
	}
	if code := wafStatus(t, noExpect, wafReq(http.MethodPost, "http://x/api", "application/json", `{}`, map[string]string{"Content-Encoding": "gzip"})); code != http.StatusNoContent {
		t.Fatalf("an explicit list only restricts what it names: %d", code)
	}
	if wafFingerprint(dav) == wafFingerprint(&aegisv1.Host{WafMode: "block"}) {
		t.Fatal("policy must be part of the compile fingerprint")
	}
}
