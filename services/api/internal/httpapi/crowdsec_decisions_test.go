package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func lapiStub(t *testing.T, n int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	list := make([]crowdsecDecision, 0, n)
	for i := 1; i <= n; i++ {
		origin := "CAPI"
		switch {
		case i%10 == 0:
			origin = "cscli"
		case i%3 == 0:
			origin = "crowdsec"
		}
		list = append(list, crowdsecDecision{ID: int64(i), Origin: origin, Scenario: fmt.Sprintf("http:scan-%d", i), Scope: "Ip", Type: "ban", Value: fmt.Sprintf("10.0.%d.%d", i/256, i%256), Duration: "4h"})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(list)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

type pageOut struct {
	Decisions []crowdsecDecision `json:"decisions"`
	Total     int                `json:"total"`
	ByOrigin  map[string]int     `json:"by_origin"`
	Limit     int                `json:"limit"`
}

func page(t *testing.T, all []crowdsecDecision, qs string) pageOut {
	t.Helper()
	v, _ := url.ParseQuery(qs)
	raw, _ := json.Marshal(pageDecisions(all, v))
	var out pageOut
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDecisionsPagingFiltersAndCounts(t *testing.T) {
	srv, _ := lapiStub(t, 300)
	s := New(Deps{})
	all, err := s.cachedDecisions(crowdsecLAPI{URL: srv.URL, Key: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if all[0].ID != 300 || all[len(all)-1].ID != 1 {
		t.Fatalf("want newest first, got %d..%d", all[0].ID, all[len(all)-1].ID)
	}

	p := page(t, all, "")
	if len(p.Decisions) != 25 || p.Total != 300 || p.Limit != 25 {
		t.Fatalf("default page: %d of %d (limit %d)", len(p.Decisions), p.Total, p.Limit)
	}
	if p.ByOrigin["cscli"] != 30 || p.ByOrigin["crowdsec"]+p.ByOrigin["CAPI"]+p.ByOrigin["cscli"] != 300 {
		t.Fatalf("by_origin %v", p.ByOrigin)
	}
	if p := page(t, all, "limit=5000"); len(p.Decisions) != 200 || p.Limit != 200 {
		t.Fatalf("limit clamp: %d", len(p.Decisions))
	}
	if p := page(t, all, "offset=290&limit=25"); len(p.Decisions) != 10 {
		t.Fatalf("last page: %d", len(p.Decisions))
	}
	if p := page(t, all, "offset=1000"); len(p.Decisions) != 0 || p.Total != 300 {
		t.Fatalf("past end: %d / %d", len(p.Decisions), p.Total)
	}
	if p := page(t, all, "origin=CSCLI"); p.Total != 30 || p.ByOrigin["CAPI"] == 0 {
		t.Fatalf("origin filter: total %d, by_origin %v", p.Total, p.ByOrigin)
	}
	if p := page(t, all, "q=SCAN-299"); p.Total != 1 || p.Decisions[0].ID != 299 {
		t.Fatalf("q filter: %+v", p)
	}
	if p := page(t, all, "q=10.0.1.&origin=cscli"); p.Total == 0 {
		t.Fatal("q and origin combine")
	}
}

func TestDecisionsCacheSharesOneLAPIFetch(t *testing.T) {
	srv, hits := lapiStub(t, 40)
	s := New(Deps{})
	cs := crowdsecLAPI{URL: srv.URL, Key: "k"}
	for range 3 {
		if _, err := s.cachedDecisions(cs); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("three reads inside the TTL made %d LAPI calls", hits.Load())
	}
	s.invalidateDecisions()
	if _, err := s.cachedDecisions(cs); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("a ban/unban must invalidate the cache (hits %d)", hits.Load())
	}
	// A different LAPI (settings changed) is never served from the old list.
	srv2, hits2 := lapiStub(t, 5)
	got, _ := s.cachedDecisions(crowdsecLAPI{URL: srv2.URL, Key: "k"})
	if hits2.Load() != 1 || len(got) != 5 {
		t.Fatal("changed LAPI settings must refetch")
	}
}
