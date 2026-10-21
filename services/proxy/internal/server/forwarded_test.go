package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

// Aegis chained behind NPM: NPM terminates TLS and forwards plain HTTP from
// the LAN with X-Forwarded-Proto / X-Forwarded-For.
func TestForwardedHeadersBehindTrustedProxy(t *testing.T) {
	type seen struct{ proto, realIP, xff string }
	got := make(chan seen, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Real-Ip"), r.Header.Get("X-Forwarded-For")}
	}))
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	h, p, _ := net.SplitHostPort(u.Host)
	n, _ := strconv.Atoi(p)

	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1,
		Hosts: []*aegisv1.Host{{Id: "c", DomainNames: []string{"app.example.com"}, Enabled: true,
			UpstreamScheme: "http", UpstreamHost: h, UpstreamPort: uint32(n)}},
		Security: &aegisv1.SecurityConfig{TrustedProxyCidrs: []string{"192.168.1.10"}},
	})
	send := func(remote string) seen {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		req.Host = "app.example.com"
		req.RemoteAddr = remote + ":51000"
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.7") // 1.2.3.4 is visitor-supplied
		s.ServeHTTP(httptest.NewRecorder(), req)
		return <-got
	}

	viaNPM := send("192.168.1.10")
	if viaNPM.proto != "https" {
		t.Fatalf("behind a trusted proxy the app must see https, got %q", viaNPM.proto)
	}
	if viaNPM.realIP != "198.51.100.7" {
		t.Fatalf("X-Real-Ip = %q, want the address NPM saw (not the spoofed 1.2.3.4 or NPM itself)", viaNPM.realIP)
	}

	direct := send("203.0.113.9") // not a trusted proxy: its headers are ignored
	if direct.proto != "http" || direct.realIP != "203.0.113.9" {
		t.Fatalf("untrusted peer must not set scheme or client IP: %+v", direct)
	}
}
