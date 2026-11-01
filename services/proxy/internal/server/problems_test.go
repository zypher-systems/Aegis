package server

import (
	"strings"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestProblemsReportWAFCompileFailureAndMissingGeoIP(t *testing.T) {
	s := New()
	s.geoLookup = nil
	if len(s.Problems()) != 0 {
		t.Fatalf("fresh node reports %+v", s.Problems())
	}
	s.Apply(snapshot(t, s, &aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{
		{
			Id: "bad", DomainNames: []string{"bad.example.com"}, Enabled: true,
			UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
			WafEnabled: true, WafMode: "block",
			// A path with a quote cannot be written into SecLang: compile fails.
			WafExclusions: []*aegisv1.WAFExclusion{{RuleId: "942100", Path: `/a"b`}},
		},
		{
			Id: "geo", DomainNames: []string{"geo.example.com"}, Enabled: true,
			UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
			GeoDeny: []string{"RU"},
		},
	}}))
	got := s.Problems()
	var kinds []string
	for _, p := range got {
		kinds = append(kinds, p.Kind+"|"+p.Resource)
	}
	if strings.Join(kinds, ",") != "geoip_missing|,waf_compile|bad.example.com" {
		t.Fatalf("problems = %v", kinds)
	}
	if !strings.Contains(got[1].Detail, "WAF is off for this host") {
		t.Fatalf("waf detail: %q", got[1].Detail)
	}
	fp := s.ProblemsFingerprint()
	// Fixing the profile clears the WAF problem; the fingerprint changes.
	s.Apply(snapshot(t, s, &aegisv1.ConfigUpdate{Version: 2, Hosts: []*aegisv1.Host{{
		Id: "bad", DomainNames: []string{"bad.example.com"}, Enabled: true,
		UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
		WafEnabled: true, WafMode: "block",
	}}}))
	if p := s.Problems(); len(p) != 0 {
		t.Fatalf("after fix: %+v", p)
	}
	if s.ProblemsFingerprint() == fp {
		t.Fatal("fingerprint must change when problems change")
	}
}
