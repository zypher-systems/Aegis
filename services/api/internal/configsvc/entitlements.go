package configsvc

import aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"

// stripCutFeatures removes stages the product does not ship. OIDC
// forward-auth is cut; proto fields may linger on stored hosts.
func stripCutFeatures(h *aegisv1.Host) {
	if h == nil {
		return
	}
	h.OidcEnabled = false
	h.OidcIssuer = ""
	h.OidcClientId = ""
	h.OidcClientSecret = ""
	h.OidcPaths = nil
	h.OidcCookieName = ""
}
