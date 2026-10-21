package server

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

// Per-IP rate limiting is a token bucket: each client IP may burst up to
// `burst` requests and refills at `rps` per second. With Redis the bucket is
// shared by every edge node; without it (or when Redis errors) each node keeps
// its own.
const (
	// Idle buckets that have refilled completely are indistinguishable from
	// new ones, so they are dropped on a sweep to bound memory.
	rateSweepEvery = time.Minute
	// Hard cap on tracked IPs per host. Past it, new IPs are not tracked
	// (allowed) until a sweep frees room: a flood from millions of addresses
	// cannot exhaust memory, and per-IP limits cannot stop one anyway.
	rateMaxBuckets   = 100_000
	redisRateTimeout = 50 * time.Millisecond
)

// rateScript is an atomic token bucket in Redis. Clock comes from the Redis
// server (TIME) so edge nodes with skewed clocks share one timeline. The key
// always gets an expiry in the same step, so no IP can be left blocked by a
// key that never expires.
var rateScript = redis.NewScript(`
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local b = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(b[1])
local ts = tonumber(b[2])
if tokens == nil or ts == nil then
  tokens = burst
  ts = now
end
local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
tokens = math.min(burst, tokens + elapsed * rate)
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', tostring(now))
redis.call('PEXPIRE', KEYS[1], math.ceil(burst / rate * 1000) + 1000)
return allowed
`)

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is one host's limiter. It outlives config pushes while the
// host's rate and burst stay the same, so a routine config change does not
// hand every client a fresh burst.
type rateLimiter struct {
	hostID string
	rps    float64
	burst  float64
	rdb    *redis.Client
	now    func() time.Time

	mu        sync.Mutex
	buckets   map[string]*tokenBucket
	lastSweep time.Time
}

func newRateLimiter(hostID string, rps, burst float64, rdb *redis.Client) *rateLimiter {
	if burst < rps {
		burst = rps
	}
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{hostID: hostID, rps: rps, burst: burst, rdb: rdb, now: time.Now, buckets: map[string]*tokenBucket{}}
}

// allow reports whether one more request from ip may pass now.
func (l *rateLimiter) allow(ctx context.Context, ip string) bool {
	if l.rdb != nil {
		rctx, cancel := context.WithTimeout(ctx, redisRateTimeout)
		n, err := rateScript.Run(rctx, l.rdb, []string{fmt.Sprintf("rl:%s:%s", l.hostID, ip)}, l.rps, l.burst).Int()
		cancel()
		if err == nil {
			return n == 1
		}
		// Redis unreachable or erroring: fall through to this node's bucket.
	}
	return l.allowLocal(ip)
}

func (l *rateLimiter) allowLocal(ip string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) >= rateSweepEvery {
		l.sweepLocked(now)
	}
	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= rateMaxBuckets {
			return true
		}
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rps)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked drops buckets that have refilled to full since their last use.
func (l *rateLimiter) sweepLocked(now time.Time) {
	for ip, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rps >= l.burst {
			delete(l.buckets, ip)
		}
	}
	l.lastSweep = now
}

func (l *rateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// rateLimiters keeps one limiter per host across config pushes.
type rateLimiters struct {
	mu   sync.Mutex
	byID map[string]*rateLimiter
}

// get returns the host's limiter, reusing the current one when rate and
// burst are unchanged.
func (rl *rateLimiters) get(h *aegisv1.Host, rdb *redis.Client) *rateLimiter {
	rps := float64(h.GetRateLimitRps())
	burst := float64(h.GetRateLimitBurst())
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.byID == nil {
		rl.byID = map[string]*rateLimiter{}
	}
	want := newRateLimiter(h.GetId(), rps, burst, rdb)
	if cur, ok := rl.byID[h.GetId()]; ok && cur.rps == want.rps && cur.burst == want.burst && cur.rdb == rdb {
		return cur
	}
	rl.byID[h.GetId()] = want
	return want
}

// retain drops limiters for hosts that no longer rate-limit.
func (rl *rateLimiters) retain(hosts []*aegisv1.Host) {
	keep := map[string]bool{}
	for _, h := range hosts {
		if h.GetEnabled() && h.GetRateLimitRps() > 0 {
			keep[h.GetId()] = true
		}
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for id := range rl.byID {
		if !keep[id] {
			delete(rl.byID, id)
		}
	}
}

func (s *Server) rateWrap(h *aegisv1.Host) func(http.Handler) http.Handler {
	lim := s.limiters.get(h, s.rdb)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !lim.allow(r.Context(), rateKey(clientIPString(r, s.trustedCIDRs()))) {
				setBlock(r, stageRateLimit, fmt.Sprintf("over %g req/s per client IP (burst %g)", lim.rps, lim.burst))
				w.Header().Set("Retry-After", "1")
				writeError(w, r, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rateKey buckets IPv6 clients by /64: one subscriber gets one bucket, not
// 2^64 of them (which would also fill the local bucket cap in seconds).
// IPv4 and v4-mapped addresses key on the full address.
func rateKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
