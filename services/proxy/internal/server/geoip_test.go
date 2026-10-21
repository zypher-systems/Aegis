package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestMatchCountry(t *testing.T) {
	if !matchCountry("US", nil, nil) {
		t.Fatal("empty lists allow")
	}
	if matchCountry("CN", nil, []string{"CN"}) {
		t.Fatal("deny")
	}
	if !matchCountry("US", []string{"US", "CA"}, nil) {
		t.Fatal("allow hit")
	}
	if matchCountry("RU", []string{"US"}, nil) {
		t.Fatal("allow miss")
	}
}

func TestGeoWrapDeny(t *testing.T) {
	s := New()
	s.geoLookup = func(ip net.IP) (string, bool) { return "CN", true }
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.geoWrap(&aegisv1.Host{GeoDeny: []string{"CN"}})(next)
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "1.2.3.4:9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestGeoWrapMissingDBDenies(t *testing.T) {
	s := New()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.geoWrap(&aegisv1.Host{GeoAllow: []string{"US"}})(next)
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "1.2.3.4:9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestGeoWrapUnknownCountryDeniesAllowList(t *testing.T) {
	s := New()
	s.geoLookup = func(net.IP) (string, bool) { return "", false }
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.geoWrap(&aegisv1.Host{GeoAllow: []string{"US"}})(next)
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "1.2.3.4:9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestGeoWrapPrivateIPSkipsDeny(t *testing.T) {
	s := New()
	// Missing MMDB must not 403 RFC1918; CI curl on the compose network
	// is 172.16/12 and k6.local compiles geo deny in.
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.geoWrap(&aegisv1.Host{GeoDeny: []string{"CN"}})(next)
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "172.20.0.9:9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestGeoWrapLoopbackSkipsAllow(t *testing.T) {
	s := New()
	s.geoLookup = func(net.IP) (string, bool) { return "", false }
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.geoWrap(&aegisv1.Host{GeoAllow: []string{"US"}})(next)
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "127.0.0.1:9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestGeoWrapAllowHit(t *testing.T) {
	s := New()
	s.geoLookup = func(net.IP) (string, bool) { return "US", true }
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.geoWrap(&aegisv1.Host{GeoAllow: []string{"US"}})(next)
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "1.2.3.4:9"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
}
