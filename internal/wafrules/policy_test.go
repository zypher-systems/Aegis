package wafrules

import (
	"strings"
	"testing"
)

func TestMethodPolicy(t *testing.T) {
	if got := MethodsSecLang(nil); got != "GET HEAD POST PUT PATCH DELETE OPTIONS" {
		t.Fatalf("default: %q", got)
	}
	got := NormalizeMethods([]string{"get", " propfind ", "bad method", "GET", "x"})
	if strings.Join(got, ",") != "GET,PROPFIND" {
		t.Fatalf("normalize: %v", got)
	}
}

func TestContentTypePolicy(t *testing.T) {
	d := ContentTypesSecLang(nil)
	for _, want := range []string{"|application/json|", "|text/plain|", "|application/octet-stream|", "|multipart/form-data|"} {
		if !strings.Contains(d, want) {
			t.Fatalf("default list lacks %s", want)
		}
	}
	if got := ContentTypesSecLang([]string{"Application/JSON", "nope", "text/csv"}); got != "|application/json| |text/csv|" {
		t.Fatalf("custom: %q", got)
	}
}

func TestRestrictedHeaderPolicy(t *testing.T) {
	def := RestrictedHeadersSecLang(nil)
	for _, gone := range []string{"/expect/", "/content-encoding/", "/content-range/"} {
		if strings.Contains(def, gone) {
			t.Fatalf("default still restricts %s: %q", gone, def)
		}
	}
	if !strings.Contains(def, "/x-http-method-override/") {
		t.Fatalf("method override must stay restricted: %q", def)
	}
	crs := RestrictedHeadersSecLang(CRSRestrictedHeaders)
	if !strings.Contains(crs, "/expect/") {
		t.Fatalf("an explicit list is used as given: %q", crs)
	}
	if got := NormalizeHeaders([]string{"Expect", "x custom", "PROXY", "expect"}); strings.Join(got, ",") != "expect,proxy" {
		t.Fatalf("normalize headers: %v", got)
	}
}

func TestCRSCatalogLoads(t *testing.T) {
	rules := Rules()
	if len(rules) < 150 {
		t.Fatalf("only %d rules parsed", len(rules))
	}
	r, ok := RuleByID("942100")
	if !ok || !strings.Contains(r.Message, "SQL Injection") || r.Category != "SQL injection" || r.Paranoia != 1 || r.Severity != "CRITICAL" {
		t.Fatalf("942100 = %+v (%v)", r, ok)
	}
	if r, ok := RuleByID("920420"); !ok || !strings.Contains(r.Message, "content type") {
		t.Fatalf("920420 = %+v", r)
	}
	if r, ok := RuleByID("911100"); !ok || r.Category != "Method enforcement" {
		t.Fatalf("911100 = %+v", r)
	}
	if _, ok := RuleByID("980014"); ok {
		t.Fatal("bookkeeping rule 980014 must not be in the catalog")
	}
	if RuleName("200002") != "Failed to parse request body" {
		t.Fatal("coraza's own rules must be named")
	}
	if RuleName("000000") != "" {
		t.Fatal("unknown id must give an empty name")
	}
}
