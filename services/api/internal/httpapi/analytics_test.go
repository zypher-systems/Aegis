package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func TestParseRollupQuery(t *testing.T) {
	now := time.Date(2026, 9, 8, 22, 0, 0, 0, time.UTC)
	r := httptest.NewRequest(http.MethodGet, "/api/analytics/rollups?period=daily&from=2026-09-01T00:00:00Z&to=2026-09-08T00:00:00Z&host_id=abc", nil)
	q := parseRollupQuery(r, now)
	if !q.Daily || q.Period != "daily" {
		t.Fatalf("daily=%v period=%s", q.Daily, q.Period)
	}
	if q.HostID != "abc" {
		t.Fatalf("host=%s", q.HostID)
	}
	if q.From.UTC().Format(time.RFC3339) != "2026-09-01T00:00:00Z" {
		t.Fatalf("from=%s", q.From)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/api/analytics/rollups", nil)
	q2 := parseRollupQuery(r2, now)
	if q2.Daily || q2.HostID != "" {
		t.Fatalf("defaults daily=%v host=%q", q2.Daily, q2.HostID)
	}
	if now.Sub(q2.From) != 24*time.Hour {
		t.Fatalf("default from window %s", now.Sub(q2.From))
	}
	if q.Group != store.RollupRaw || q2.Group != store.RollupRaw {
		t.Fatalf("no group parameter must mean stored rows, got %q and %q", q.Group, q2.Group)
	}
}

func TestParseRollupQueryGroup(t *testing.T) {
	now := time.Date(2026, 9, 8, 22, 0, 0, 0, time.UTC)
	for param, want := range map[string]store.RollupGroup{
		"bucket": store.RollupByBucket,
		"host":   store.RollupByHost,
		"":       store.RollupRaw,
		// An unknown value falls back to the stored rows rather than failing.
		"domain": store.RollupRaw,
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/analytics/rollups?group="+param, nil)
		if got := parseRollupQuery(r, now).Group; got != want {
			t.Errorf("group=%q: got %q, want %q", param, got, want)
		}
	}
}
