package configsvc

import (
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestStripCutFeaturesRemovesOIDCOnly(t *testing.T) {
	h := &aegisv1.Host{
		WafEnabled:          true,
		WafMode:             "block",
		WafParanoia:         2,
		WafInboundThreshold: 5,
		WafDisabledTags:     []string{"scanner"},
		CrowdsecEnabled:     true,
		GeoAllow:            []string{"US"},
		GeoDeny:             []string{"CN"},
		OidcEnabled:         true,
		OidcIssuer:          "https://idp.example",
		OidcClientId:        "c",
		OidcClientSecret:    "s",
		OidcPaths:           []string{"/admin"},
		OidcCookieName:      "aegis",
		RateLimitRps:        10,
	}
	stripCutFeatures(h)
	if !h.WafEnabled || h.WafMode != "block" || !h.CrowdsecEnabled || len(h.GeoDeny) != 1 || h.RateLimitRps != 10 {
		t.Fatalf("security layers must stay: %+v", h)
	}
	if h.OidcEnabled || h.OidcIssuer != "" || h.OidcClientSecret != "" || h.OidcCookieName != "" || len(h.OidcPaths) != 0 {
		t.Fatalf("oidc must be stripped: %+v", h)
	}
}
