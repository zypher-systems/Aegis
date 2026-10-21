package server

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestRedirectHost(t *testing.T) {
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "r", DomainNames: []string{"go.local"}, Enabled: true,
			Kind:        aegisv1.HostKind_HOST_KIND_REDIRECT,
			RedirectUrl: "https://example.com/x", RedirectCode: 302,
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://go.local/foo", nil)
	req.Host = "go.local"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "https://example.com/x" {
		t.Fatalf("location = %q", loc)
	}
}

func TestDeadHost(t *testing.T) {
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "d", DomainNames: []string{"gone.local"}, Enabled: true,
			Kind: aegisv1.HostKind_HOST_KIND_DEAD,
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://gone.local/", nil)
	req.Host = "gone.local"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestCustomRequestHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("X-Aegis-Test"))
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "h", DomainNames: []string{"hdr.local"}, Enabled: true,
			UpstreamScheme: "http", UpstreamHost: host, UpstreamPort: uint32(port),
			RequestHeaders: []*aegisv1.Header{{Name: "X-Aegis-Test", Value: "ok"}},
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://hdr.local/", nil)
	req.Host = "hdr.local"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Body.String() != "ok" {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestUpstreamFailover(t *testing.T) {
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "backup")
	}))
	t.Cleanup(live.Close)
	u, _ := url.Parse(live.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "h", DomainNames: []string{"fail.local"}, Enabled: true,
			UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 1,
			Upstreams: []*aegisv1.UpstreamTarget{
				{Scheme: "http", Host: "127.0.0.1", Port: 1},
				{Scheme: "http", Host: host, Port: uint32(port)},
			},
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://fail.local/", nil)
	req.Host = "fail.local"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Body.String() != "backup" {
		t.Fatalf("body = %q status=%d", rr.Body.String(), rr.Code)
	}
}

func TestUpstreamTLSSkipVerify(t *testing.T) {
	live := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(live.Close)
	host, port := tlsOrigin(t, live)

	got := proxyOnce(t, &aegisv1.Host{
		Id: "h", DomainNames: []string{"tls.local"}, Enabled: true,
		Upstreams: []*aegisv1.UpstreamTarget{{
			Scheme: "https", Host: host, Port: port, TlsSkipVerify: true,
		}},
	})
	if got != "ok" {
		t.Fatalf("skip-verify body = %q", got)
	}
}

func TestUpstreamTLSCustomCA(t *testing.T) {
	live := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(live.Close)
	host, port := tlsOrigin(t, live)
	pem := pemEncode(live.Certificate())

	got := proxyOnce(t, &aegisv1.Host{
		Id: "h", DomainNames: []string{"tls.local"}, Enabled: true,
		Upstreams: []*aegisv1.UpstreamTarget{{
			Scheme: "https", Host: host, Port: port, TlsCaPem: pem,
		}},
	})
	if got != "ok" {
		t.Fatalf("custom CA body = %q", got)
	}
}

func TestUpstreamTLSUnknownCARejected(t *testing.T) {
	live := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(live.Close)
	host, port := tlsOrigin(t, live)

	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "h", DomainNames: []string{"tls.local"}, Enabled: true,
			Upstreams: []*aegisv1.UpstreamTarget{{
				Scheme: "https", Host: host, Port: port,
			}},
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://tls.local/", nil)
	req.Host = "tls.local"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestUpstreamTLSSNIMismatch(t *testing.T) {
	live := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	t.Cleanup(live.Close)
	host, port := tlsOrigin(t, live)
	pem := pemEncode(live.Certificate())

	s := New()
	s.Apply(&aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "h", DomainNames: []string{"tls.local"}, Enabled: true,
			Upstreams: []*aegisv1.UpstreamTarget{{
				Scheme: "https", Host: host, Port: port,
				TlsCaPem: pem, TlsServerName: "not-the-cert.invalid",
			}},
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://tls.local/", nil)
	req.Host = "tls.local"
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%q", rr.Code, rr.Body.String())
	}
}

func proxyOnce(t *testing.T, h *aegisv1.Host) string {
	t.Helper()
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{h}})
	req := httptest.NewRequest(http.MethodGet, "http://"+h.DomainNames[0]+"/", nil)
	req.Host = h.DomainNames[0]
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q", rr.Code, rr.Body.String())
	}
	return rr.Body.String()
}

func tlsOrigin(t *testing.T, srv *httptest.Server) (string, uint32) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint32(port)
}

func pemEncode(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}
