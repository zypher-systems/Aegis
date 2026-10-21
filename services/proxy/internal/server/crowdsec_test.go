package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestDecisionCacheIPAndCIDR(t *testing.T) {
	c := newDecisionCache()
	c.apply([]streamDecision{
		{Type: "ban", Value: "1.2.3.4", Origin: "CAPI"},
		{Type: "ban", Value: "10.0.0.0/8", Origin: "crowdsec"},
		{Type: "captcha", Value: "8.8.8.8", Origin: "CAPI"},
	}, nil)
	if o, ok := c.banned("1.2.3.4"); !ok || o != "CAPI" {
		t.Fatalf("ip banned=%v origin=%q", ok, o)
	}
	if o, ok := c.banned("10.9.1.1"); !ok || o != "crowdsec" {
		t.Fatalf("cidr banned=%v origin=%q", ok, o)
	}
	if _, ok := c.banned("8.8.8.8"); ok {
		t.Fatal("captcha should not ban")
	}
	c.apply(nil, []streamDecision{{Value: "1.2.3.4"}})
	if _, ok := c.banned("1.2.3.4"); ok {
		t.Fatal("deleted ip still banned")
	}
}

func TestCrowdsecStreamPopulatesCache(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "k" {
			t.Fatalf("missing key")
		}
		if r.URL.Path != "/v1/decisions/stream" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.URL.Query().Get("origins") != "crowdsec" {
			t.Fatalf("origins=%q", r.URL.Query().Get("origins"))
		}
		if r.URL.Query().Get("startup") != "true" {
			t.Fatalf("startup=%q", r.URL.Query().Get("startup"))
		}
		w.Write([]byte(`{"new":[{"type":"ban","value":"203.0.113.9","origin":"crowdsec"}],"deleted":[]}`))
	}))
	t.Cleanup(ts.Close)
	c := newDecisionCache()
	if err := pullCrowdsecStream(t.Context(), ts.Client(), ts.URL, "k", true, c); err != nil {
		t.Fatal(err)
	}
	if o, ok := c.banned("203.0.113.9"); !ok || o != "crowdsec" {
		t.Fatalf("banned=%v origin=%q", ok, o)
	}
}

func TestCrowdsecWrapUsesCache(t *testing.T) {
	s := New()
	cache := newDecisionCache()
	cache.apply([]streamDecision{{Type: "ban", Value: "192.0.2.1", Origin: "crowdsec"}}, nil)
	s.csCache.Store(cache)
	s.Apply(snapshot(t, s, &aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "cs", DomainNames: []string{"cs.local"},
			Enabled: true, CrowdsecEnabled: true,
			UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
		}},
		Security: &aegisv1.SecurityConfig{
			CrowdsecLapiUrl: "http://127.0.0.1:1",
			CrowdsecLapiKey: "k",
		},
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://cs.local/", nil)
	req.Host = "cs.local"
	req.RemoteAddr = "192.0.2.1:12345"
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestCrowdsecStreamFailOpen(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errStatus(http.StatusBadGateway)
	})}
	c := newDecisionCache()
	err := pullCrowdsecStream(t.Context(), client, "http://127.0.0.1:1", "k", true, c)
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := c.banned("1.2.3.4"); ok {
		t.Fatal("empty cache should fail open")
	}
}

func TestCrowdsecSyncRestartsStream(t *testing.T) {
	n := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.URL.Query().Get("origins") != "crowdsec" {
			t.Errorf("origins=%q", r.URL.Query().Get("origins"))
		}
		w.Write([]byte(`{"new":[{"type":"ban","value":"198.51.100.7","origin":"crowdsec"}],"deleted":[]}`))
	}))
	t.Cleanup(ts.Close)
	s := New()
	s.crowdsecHTTP = ts.Client()
	s.syncCrowdsec(&aegisv1.SecurityConfig{CrowdsecLapiUrl: ts.URL, CrowdsecLapiKey: "k"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c := s.csCache.Load()
		if c != nil {
			if o, ok := c.banned("198.51.100.7"); ok && o == "crowdsec" {
				s.syncCrowdsec(nil)
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("stream never populated, pulls=%d", n)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
