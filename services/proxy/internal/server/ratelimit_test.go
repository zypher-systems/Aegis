package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func clockAt(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func drain(t *testing.T, l *rateLimiter, ip string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if !l.allow(context.Background(), ip) {
			t.Fatalf("request %d of burst %d refused", i+1, n)
		}
	}
}

func TestLocalBucketBurstThenRefillAtRate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newRateLimiter("h", 2, 5, nil)
	l.now = clockAt(&now)

	drain(t, l, "198.51.100.1", 5)
	if l.allow(context.Background(), "198.51.100.1") {
		t.Fatal("6th request inside the burst window must be refused")
	}
	if !l.allow(context.Background(), "198.51.100.2") {
		t.Fatal("another IP has its own bucket")
	}

	// rps is honoured: after 1s, 2 more tokens, not a full burst.
	now = now.Add(time.Second)
	drain(t, l, "198.51.100.1", 2)
	if l.allow(context.Background(), "198.51.100.1") {
		t.Fatal("refill must follow rps (2/s), not reset to burst")
	}
}

func TestLocalBucketsAreSweptAndCapped(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newRateLimiter("h", 10, 10, nil)
	l.now = clockAt(&now)
	for i := 0; i < 1000; i++ {
		l.allow(context.Background(), fmt.Sprintf("203.0.113.%d-%d", i/250, i))
	}
	if l.size() != 1000 {
		t.Fatalf("tracked %d", l.size())
	}
	// Two minutes later every bucket has refilled: the next request sweeps
	// them all (it then tracks only itself).
	now = now.Add(2 * time.Minute)
	l.allow(context.Background(), "192.0.2.1")
	if l.size() != 1 {
		t.Fatalf("idle full buckets must be dropped, still tracking %d", l.size())
	}

	// A bucket still refilling survives a sweep; its client stays limited.
	slow := newRateLimiter("h", 0.01, 3, nil) // refills one token per 100s
	slow.now = clockAt(&now)
	drain(t, slow, "192.0.2.9", 3)
	now = now.Add(2 * time.Minute) // sweep due, bucket at ~1.2 tokens
	slow.allow(context.Background(), "192.0.2.10")
	if slow.size() != 2 {
		t.Fatalf("a bucket still refilling must be kept, tracking %d", slow.size())
	}
	if !slow.allow(context.Background(), "192.0.2.9") || slow.allow(context.Background(), "192.0.2.9") {
		t.Fatal("the kept bucket must carry its state through the sweep")
	}
}

func TestLocalBucketCapBoundsMemory(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newRateLimiter("h", 1, 1, nil)
	l.now = clockAt(&now)
	l.lastSweep = now
	for i := 0; i < rateMaxBuckets+500; i++ {
		l.allow(context.Background(), fmt.Sprintf("ip-%d", i))
	}
	if l.size() > rateMaxBuckets {
		t.Fatalf("tracked %d, cap %d", l.size(), rateMaxBuckets)
	}
}

func TestLimiterSurvivesConfigPushUnlessRateChanges(t *testing.T) {
	var rl rateLimiters
	h := &aegisv1.Host{Id: "h1", Enabled: true, RateLimitRps: 1, RateLimitBurst: 2}
	a := rl.get(h, nil)
	a.allow(context.Background(), "198.51.100.7")
	a.allow(context.Background(), "198.51.100.7")
	if b := rl.get(h, nil); b != a {
		t.Fatal("same rate and burst: the limiter (and its buckets) must be kept")
	}
	if a.allow(context.Background(), "198.51.100.7") {
		t.Fatal("a config push must not hand the client a fresh burst")
	}
	h2 := &aegisv1.Host{Id: "h1", Enabled: true, RateLimitRps: 5, RateLimitBurst: 5}
	if rl.get(h2, nil) == a {
		t.Fatal("a changed rate must start a new limiter")
	}
	rl.retain(nil)
	if len(rl.byID) != 0 {
		t.Fatal("limiters for removed hosts must be dropped")
	}
}

func newMiniredis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	m := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return m, c
}

func TestRedisBucketIsSharedAtomicAndAlwaysExpires(t *testing.T) {
	m, rdb := newMiniredis(t)
	start := time.Unix(1_800_000_000, 0)
	m.SetTime(start)

	// Two edge nodes, one Redis: the burst is shared.
	nodeA := newRateLimiter("h1", 2, 4, rdb)
	nodeB := newRateLimiter("h1", 2, 4, rdb)
	drain(t, nodeA, "198.51.100.1", 2)
	drain(t, nodeB, "198.51.100.1", 2)
	if nodeA.allow(context.Background(), "198.51.100.1") || nodeB.allow(context.Background(), "198.51.100.1") {
		t.Fatal("burst of 4 is shared by all nodes")
	}
	if nodeA.size() != 0 {
		t.Fatal("with Redis up, no local buckets are kept")
	}

	// The key always carries an expiry; an IP can never be stuck blocked.
	if ttl := m.TTL("rl:h1:198.51.100.1"); ttl <= 0 || ttl > 4*time.Second {
		t.Fatalf("rate key TTL = %s, want (0, 3s]", ttl)
	}

	// Refill at rps from Redis's clock.
	m.SetTime(start.Add(time.Second))
	drain(t, nodeA, "198.51.100.1", 2)
	if nodeA.allow(context.Background(), "198.51.100.1") {
		t.Fatal("refill must follow rps")
	}
}

func TestRedisDownFallsBackToLocalBucket(t *testing.T) {
	m, rdb := newMiniredis(t)
	m.Close()
	now := time.Unix(1_800_000_000, 0)
	l := newRateLimiter("h1", 1, 2, rdb)
	l.now = clockAt(&now)
	drain(t, l, "198.51.100.3", 2)
	if l.allow(context.Background(), "198.51.100.3") {
		t.Fatal("with Redis down the node must still limit locally")
	}
}

func TestRateWrapSends429WithRetryAfter(t *testing.T) {
	s := New()
	h := &aegisv1.Host{Id: "rl", Enabled: true, RateLimitRps: 1, RateLimitBurst: 1}
	handler := s.rateWrap(h)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	do := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://rl.local/", nil)
		req.RemoteAddr = "198.51.100.50:4000"
		handler.ServeHTTP(rec, req)
		return rec
	}
	if do().Code != http.StatusNoContent {
		t.Fatal("first request passes")
	}
	rec := do()
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("second request: %d, Retry-After=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// Tests carried over from 1.7.0.

func TestRateLimitLocalBurst(t *testing.T) {
	s := New()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.rateWrap(&aegisv1.Host{Id: "h1", RateLimitRps: 1, RateLimitBurst: 1})(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "10.0.0.8:9"
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second = %d", rr.Code)
	}
}

func TestRateLimitInspectsWebsocketHandshake(t *testing.T) {
	s := New()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	h := s.rateWrap(&aegisv1.Host{Id: "ws", RateLimitRps: 1, RateLimitBurst: 1})(next)
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "10.0.0.8:9"
	req.Header.Set("Upgrade", "websocket")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusSwitchingProtocols {
		t.Fatalf("first handshake = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second handshake must be limited, status=%d", rr.Code)
	}
}
