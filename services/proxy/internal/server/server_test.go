package server

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/proxy/internal/configstore"
)

func TestLoopbackHealthzWithoutConfig(t *testing.T) {
	s := New()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/healthz", nil)
	req.RemoteAddr = "127.0.0.1:9"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ok\n" {
		t.Fatalf("body = %q", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "http://edge.example/healthz", nil)
	req.Host = "edge.example"
	req.RemoteAddr = "203.0.113.9:443"
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("public /healthz without config: status = %d", rr.Code)
	}
}

func TestPublicHealthzDoesNotBypassVhost(t *testing.T) {
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "h1", DomainNames: []string{"demo.local"},
			Kind: aegisv1.HostKind_HOST_KIND_DEAD, Enabled: true,
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://demo.local/healthz", nil)
	req.Host = "demo.local"
	req.RemoteAddr = "203.0.113.9:443"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestWebsocketRejectedWhenDisabled(t *testing.T) {
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "h1", DomainNames: []string{"ws.local"},
			UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
			Enabled: true, WebsocketSupport: false,
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://ws.local/", nil)
	req.Host = "ws.local"
	req.Header.Set("Upgrade", "websocket")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestNoConfigIs503UntilApply(t *testing.T) {
	s := New()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://demo.local/", nil)
	req.Host = "demo.local"
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rr.Code)
	}
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "h1", DomainNames: []string{"demo.local"},
			Kind: aegisv1.HostKind_HOST_KIND_DEAD, Enabled: true,
		}},
	})
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("after apply status = %d", rr.Code)
	}
}

func TestLastKnownGoodServesAfterReload(t *testing.T) {
	dir := t.TempDir()
	key, err := configstore.DeriveSnapshotKey([]byte("test-node-key"))
	if err != nil {
		t.Fatal(err)
	}
	s := NewWithOptions(Options{StateDir: dir, SnapshotKey: key})
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 3,
		Hosts: []*aegisv1.Host{{
			Id: "h1", DomainNames: []string{"demo.local"},
			Kind: aegisv1.HostKind_HOST_KIND_DEAD, Enabled: true,
		}},
	})
	snap, err := configstore.Load(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	s2 := New()
	s2.Apply(snap)
	if s2.Version() != 3 {
		t.Fatalf("version = %d", s2.Version())
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://demo.local/", nil)
	req.Host = "demo.local"
	s2.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHSTSOnTLS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "h1", DomainNames: []string{"hsts.local"},
			UpstreamScheme: "http", UpstreamHost: host, UpstreamPort: uint32(port),
			Enabled: true, Hsts: true, WebsocketSupport: true,
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "https://hsts.local/", nil)
	req.Host = "hsts.local"
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if got := rr.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatalf("missing HSTS, status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestApplySkipsDuplicateDomains(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("upstream"))
	}))
	t.Cleanup(up.Close)
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{
			{Id: "first", DomainNames: []string{"demo.local"}, Kind: aegisv1.HostKind_HOST_KIND_DEAD, Enabled: true},
			{
				Id: "second", DomainNames: []string{"DEMO.local"}, Enabled: true,
				UpstreamScheme: "http", UpstreamHost: host, UpstreamPort: uint32(port),
			},
		},
	})
	req := httptest.NewRequest(http.MethodGet, "http://demo.local/", nil)
	req.Host = "demo.local"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("duplicate should keep first host, status=%d body=%s", rr.Code, rr.Body.String())
	}
}
