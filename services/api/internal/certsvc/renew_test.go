package certsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func TestRecordRenewFailureNilStore(t *testing.T) {
	s := &Service{}
	s.recordRenewFailure(context.Background(), &store.Certificate{
		ID:      uuid.New(),
		Domains: []string{"app.example.com"},
	}, errors.New("acme directory unavailable"), time.Now().Add(time.Hour))
	s.clearRenewFailure(context.Background(), uuid.New().String())
}

func TestWildcardMatchesOneLabel(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*.example.com", "app.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", "notexample.com", false},
		{"app.example.com", "app.example.com", false}, // not a wildcard
		{"*.", "x.", false},
	}
	for _, c := range cases {
		if got := WildcardMatches(c.pattern, c.name); got != c.want {
			t.Errorf("%s vs %s = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
	if covers([]string{"*.example.com"}, []string{"a.b.example.com"}) {
		t.Fatal("covers must not claim a multi-label match a browser rejects")
	}
}

func TestRenewWantedOnlyForCertsInUseOrWrongDirectory(t *testing.T) {
	s := &Service{acme: ACMEConfig{Directory: "https://prod/directory"}}
	now := time.Now()
	byID := uuid.New()
	usedByID := &store.Certificate{ID: byID, Issuer: "letsencrypt", AutoRenew: true, Directory: "https://prod/directory",
		Domains: []string{"api.example.com"}, ExpiresAt: now.Add(10 * 24 * time.Hour)}
	covering := &store.Certificate{ID: uuid.New(), Issuer: "letsencrypt", AutoRenew: true, Directory: "https://prod/directory",
		Domains: []string{"*.example.com"}, ExpiresAt: now.Add(10 * 24 * time.Hour)}
	orphan := &store.Certificate{ID: uuid.New(), Issuer: "letsencrypt", AutoRenew: true, Directory: "https://prod/directory",
		Domains: []string{"old.example.com"}, ExpiresAt: now.Add(-24 * time.Hour)}
	staging := &store.Certificate{ID: uuid.New(), Issuer: "letsencrypt", AutoRenew: true, Directory: "https://staging/directory",
		Domains: []string{"app.example.com"}, ExpiresAt: now.Add(80 * 24 * time.Hour)}
	fresh := &store.Certificate{ID: uuid.New(), Issuer: "letsencrypt", AutoRenew: true, Directory: "https://prod/directory",
		Domains: []string{"app.example.com"}, ExpiresAt: now.Add(80 * 24 * time.Hour)}
	custom := &store.Certificate{ID: uuid.New(), Issuer: "custom", Domains: []string{"app.example.com"}, ExpiresAt: now}
	paused := &store.Certificate{ID: byID, Issuer: "letsencrypt", AutoRenew: false, Directory: "https://prod/directory",
		Domains: []string{"api.example.com"}, ExpiresAt: now.Add(10 * 24 * time.Hour)}
	hosts := []*store.Host{
		{Enabled: true, TLSMode: "custom", CertID: &byID, DomainNames: []string{"api.example.com"}},
		{Enabled: true, TLSMode: "auto", DomainNames: []string{"app.example.com"}},
		{Enabled: false, TLSMode: "auto", DomainNames: []string{"old.example.com"}},
	}
	for _, c := range []struct {
		name string
		m    *store.Certificate
		want bool
	}{
		{"referenced by id, expiring", usedByID, true},
		{"covering an auto host, expiring", covering, true},
		{"orphan (only a disabled host)", orphan, false},
		{"staging cert while production is configured", staging, true},
		{"fresh production cert", fresh, false},
		{"custom upload", custom, false},
		{"auto-renew switched off", paused, false},
	} {
		if got := s.renewWanted(c.m, hosts, now); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRenewBackoffDoublesToADay(t *testing.T) {
	want := []time.Duration{time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour, 24 * time.Hour, 24 * time.Hour}
	for i, w := range want {
		if got := renewBackoff(i + 1); got != w {
			t.Fatalf("after %d failures: %s, want %s", i+1, got, w)
		}
	}
	s := &Service{}
	id := uuid.New()
	now := time.Now()
	if _, blocked := s.renewBlocked(id, now); blocked {
		t.Fatal("never failed: not blocked")
	}
	next := s.renewFailed(id, now)
	if _, blocked := s.renewBlocked(id, now.Add(30*time.Minute)); !blocked {
		t.Fatal("blocked inside the backoff window")
	}
	if _, blocked := s.renewBlocked(id, next); blocked {
		t.Fatal("free again once the window passes")
	}
	s.renewSucceeded(id)
	if _, blocked := s.renewBlocked(id, now); blocked {
		t.Fatal("success resets")
	}
}

func TestSameNamesIgnoresOrder(t *testing.T) {
	if !sameNames([]string{"a", "b"}, []string{"b", "a"}) || sameNames([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("sameNames")
	}
}
