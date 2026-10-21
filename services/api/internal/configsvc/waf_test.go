package configsvc

import (
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func TestAttachWAFProfileCopiesPolicy(t *testing.T) {
	h := &aegisv1.Host{}
	attachWAFProfile(h, &store.WAFProfile{
		Mode: "detect", Paranoia: 2, InboundThreshold: 8,
		DisabledTags: []string{"scanner"},
		Exclusions:   []store.WAFExclusion{{RuleID: "942100", Path: "/admin"}},
	})
	if !h.WafEnabled || h.WafMode != "detect" || h.WafParanoia != 2 || h.WafInboundThreshold != 8 {
		t.Fatalf("policy: %+v", h)
	}
	if len(h.WafDisabledTags) != 1 || h.WafDisabledTags[0] != "scanner" {
		t.Fatalf("tags: %v", h.WafDisabledTags)
	}
	if len(h.WafExclusions) != 1 || h.WafExclusions[0].GetRuleId() != "942100" || h.WafExclusions[0].GetPath() != "/admin" {
		t.Fatalf("exclusions: %+v", h.WafExclusions)
	}
}

func TestAttachWAFProfileNil(t *testing.T) {
	h := &aegisv1.Host{}
	attachWAFProfile(h, nil)
	if h.WafEnabled {
		t.Fatal("nil profile must not enable WAF")
	}
}
