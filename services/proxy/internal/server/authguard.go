package server

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/internal/passwd"
)

// Basic auth on an access list costs an argon2id hash (64 MiB, ~100 ms) per
// check, and browsers send the header on every request. authGuard keeps
// that off the hot path and out of an attacker's hands:
//   - verified credentials are remembered for authCacheTTL, so a logged-in
//     browser costs one hash, not one per asset;
//   - an IP that fails authFailLimit times in authFailWindow is refused
//     (429) for authLockout without hashing;
//   - at most authConcurrency hashes run at once; past that, callers wait
//     briefly and then get 503 rather than pinning every core.
const (
	authCacheTTL    = 5 * time.Minute
	authCacheMax    = 10_000
	authFailLimit   = 5
	authFailWindow  = 10 * time.Minute
	authLockout     = 10 * time.Minute
	authConcurrency = 4
	authWaitMax     = 2 * time.Second
)

type authGuard struct {
	mu     sync.Mutex
	cache  map[string]time.Time // credential digest → expiry
	fails  map[string]*authFail // client IP → failures
	sem    chan struct{}
	now    func() time.Time
	hashes int // argon2 runs, for tests
}

type authFail struct {
	n     int
	since time.Time
	until time.Time // locked out until (zero = not locked)
}

func newAuthGuard() *authGuard {
	return &authGuard{
		cache: map[string]time.Time{},
		fails: map[string]*authFail{},
		sem:   make(chan struct{}, authConcurrency),
		now:   time.Now,
	}
}

var basicAuthGuard = newAuthGuard()

type authVerdict int

const (
	authOK authVerdict = iota
	authBad
	authLocked // too many failures from this IP
	authBusy   // hashing capacity exhausted
)

// locked reports whether ip is currently refused.
func (g *authGuard) locked(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	f := g.fails[ip]
	return f != nil && g.now().Before(f.until)
}

// verify checks user/pass against users for a request from ip.
func (g *authGuard) verify(ip, user, pass string, users []*aegisv1.BasicAuthUser) authVerdict {
	if g.locked(ip) {
		return authLocked
	}
	var hash string
	for _, u := range users {
		if u.GetUsername() == user {
			hash = u.GetPasswordHash()
			break
		}
	}
	if hash == "" {
		g.fail(ip)
		return authBad
	}
	key := credKey(user, hash, pass)
	if g.cached(key) {
		return authOK
	}
	select {
	case g.sem <- struct{}{}:
	case <-time.After(authWaitMax):
		return authBusy
	}
	g.mu.Lock()
	g.hashes++
	g.mu.Unlock()
	ok := passwd.Verify(pass, hash)
	<-g.sem
	if !ok {
		g.fail(ip)
		return authBad
	}
	g.remember(key)
	g.clear(ip)
	return authOK
}

func credKey(user, hash, pass string) string {
	sum := sha256.Sum256([]byte(user + "\x00" + hash + "\x00" + pass))
	return hex.EncodeToString(sum[:])
}

func (g *authGuard) cached(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.cache[key]
	if !ok {
		return false
	}
	if !g.now().Before(exp) {
		delete(g.cache, key)
		return false
	}
	return true
}

func (g *authGuard) remember(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.cache) >= authCacheMax {
		now := g.now()
		for k, exp := range g.cache {
			if !now.Before(exp) {
				delete(g.cache, k)
			}
		}
		if len(g.cache) >= authCacheMax {
			return // full of live entries: skip caching, never grow unbounded
		}
	}
	g.cache[key] = g.now().Add(authCacheTTL)
}

func (g *authGuard) fail(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	f := g.fails[ip]
	if f == nil || now.Sub(f.since) > authFailWindow {
		f = &authFail{since: now}
		g.fails[ip] = f
	}
	f.n++
	if f.n >= authFailLimit {
		f.until = now.Add(authLockout)
	}
	if len(g.fails) > 100_000 { // bound memory under a distributed brute force
		for k, v := range g.fails {
			if now.Sub(v.since) > authFailWindow && !now.Before(v.until) {
				delete(g.fails, k)
			}
		}
	}
}

func (g *authGuard) clear(ip string) {
	g.mu.Lock()
	delete(g.fails, ip)
	g.mu.Unlock()
}
