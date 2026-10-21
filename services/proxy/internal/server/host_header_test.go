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

// hostEcho is an upstream that reports the Host header it received.
func hostEcho(t *testing.T) (host string, port uint32) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Host", r.Host)
		w.Header().Set("X-Seen-Forwarded-Host", r.Header.Get("X-Forwarded-Host"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	h, p, _ := net.SplitHostPort(u.Host)
	n, _ := strconv.Atoi(p)
	return h, uint32(n)
}

func seenHost(t *testing.T, s *Server, domain string) (host, fwd string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://"+domain+"/", nil)
	req.Host = domain
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	return rr.Header().Get("X-Seen-Host"), rr.Header().Get("X-Seen-Forwarded-Host")
}

func TestUpstreamHostHeaderModes(t *testing.T) {
	upHost, upPort := hostEcho(t)
	upAuthority := net.JoinHostPort(upHost, strconv.Itoa(int(upPort)))
	cases := []struct {
		mode string
		want string
	}{
		{"", "app.example.com"},                          // default: the client's Host, like NPM
		{"upstream", upAuthority},                        // the upstream's host:port (1.7.0 behaviour)
		{"internal.example.lan", "internal.example.lan"}, // a literal
	}
	for _, tc := range cases {
		s := New()
		s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
			Id: "h-" + tc.mode, DomainNames: []string{"app.example.com"}, Enabled: true,
			UpstreamScheme: "http", UpstreamHost: upHost, UpstreamPort: upPort,
			UpstreamHostHeader: tc.mode,
		}}})
		got, fwd := seenHost(t, s, "app.example.com")
		if got != tc.want {
			t.Fatalf("mode %q: upstream saw Host %q, want %q", tc.mode, got, tc.want)
		}
		if fwd != "app.example.com" {
			t.Fatalf("mode %q: X-Forwarded-Host = %q, want the client's host", tc.mode, fwd)
		}
	}
}

func TestClientHostSurvivesFailoverToBackup(t *testing.T) {
	upHost, upPort := hostEcho(t)
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
		Id: "fo", DomainNames: []string{"app.example.com"}, Enabled: true,
		UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
		Upstreams: []*aegisv1.UpstreamTarget{
			{Scheme: "http", Host: "127.0.0.1", Port: 9}, // primary: nothing listens
			{Scheme: "http", Host: upHost, Port: upPort}, // backup
		},
	}}})
	if got, _ := seenHost(t, s, "app.example.com"); got != "app.example.com" {
		t.Fatalf("after failover the backup saw Host %q, want the client's", got)
	}
}

func TestWebSocketUpgradeKeepsClientHost(t *testing.T) {
	seen := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host
		w.WriteHeader(http.StatusBadRequest) // no real upgrade needed to observe the Host
	}))
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	h, p, _ := net.SplitHostPort(u.Host)
	n, _ := strconv.Atoi(p)
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
		Id: "ws", DomainNames: []string{"chat.example.com"}, Enabled: true, WebsocketSupport: true,
		UpstreamScheme: "http", UpstreamHost: h, UpstreamPort: uint32(n),
	}}})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://chat.example.com/socket", nil)
	req.Host = "chat.example.com"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "https://chat.example.com")
	s.ServeHTTP(rr, req)
	if got := <-seen; got != "chat.example.com" {
		t.Fatalf("WebSocket handshake reached the upstream with Host %q; origin checks compare against the client's", got)
	}
}
