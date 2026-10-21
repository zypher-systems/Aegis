package httpapi

import (
	"testing"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func TestValidateUpstreamHostHeader(t *testing.T) {
	for _, tc := range []struct {
		v  string
		ok bool
	}{
		{"", true},
		{"upstream", true},
		{"app.internal", true},
		{"app.internal:8443", true},
		{"[fd00::1]:443", true},
		{"evil.example\r\nX-Injected: 1", false},
		{"has space", false},
		{"a/b", false},
	} {
		h := &store.Host{Kind: "proxy", DomainNames: []string{"x.example"}, UpstreamScheme: "http", UpstreamHost: "10.0.0.5", UpstreamPort: 80, TLSMode: "none", UpstreamHostHeader: tc.v}
		if msg := validateHost(h); (msg == "") != tc.ok {
			t.Fatalf("%q: validateHost = %q, want ok=%v", tc.v, msg, tc.ok)
		}
	}
}
