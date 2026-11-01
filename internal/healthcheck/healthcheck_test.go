package healthcheck

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestURLRewritesWildcardToLoopback(t *testing.T) {
	u, err := URL(":8080", "/api/readyz")
	if err != nil {
		t.Fatal(err)
	}
	if u != "http://127.0.0.1:8080/api/readyz" {
		t.Fatalf("got %q", u)
	}
	u, err = URL("0.0.0.0:80", "healthz")
	if err != nil {
		t.Fatal(err)
	}
	if u != "http://127.0.0.1:80/healthz" {
		t.Fatalf("got %q", u)
	}
}

func TestProbeOK(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	if err := Probe(ln.Addr().String(), "/healthz"); err != nil {
		t.Fatal(err)
	}
}

func TestProbeRejectsNon200(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusServiceUnavailable)
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	if err := Probe(ln.Addr().String(), "/"); err == nil {
		t.Fatal("expected error")
	}
}
