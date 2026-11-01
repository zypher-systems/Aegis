package httpapi

import (
	"context"
	"crypto/hmac"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zypher-systems/aegis/internal/clientip"
)

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		if path == "/api/healthz" || path == "/api/readyz" || path == "/api/setup/status" {
			next.ServeHTTP(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		if origin == "" || !s.originOK(origin, r) {
			writeErr(w, http.StatusForbidden, "csrf: origin not allowed")
			return
		}
		// Login/setup issue the CSRF cookie; they cannot require it yet.
		if path == "/api/auth/login" || path == "/api/setup" {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(csrfCookie)
		tok := r.Header.Get("X-CSRF-Token")
		if err != nil || c.Value == "" || tok == "" || !hmac.Equal([]byte(c.Value), []byte(tok)) {
			writeErr(w, http.StatusForbidden, "csrf: token mismatch")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originOK(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	oh := hostOnly(u.Host)
	if oh == "" {
		return false
	}
	if hostsMatch(hostOnly(r.Host), oh) {
		return true
	}
	if s.publicOrigin == "" {
		return false
	}
	po, err := url.Parse(s.publicOrigin)
	if err != nil {
		return false
	}
	return hostsMatch(hostOnly(po.Host), oh)
}

func hostsMatch(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	return isLoopbackHost(a) && isLoopbackHost(b)
}

func isLoopbackHost(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func hostOnly(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.ToLower(hostport)
	}
	return strings.ToLower(h)
}

// Login attempts per client IP per window. Redis makes the count shared by
// every API replica; when Redis is missing or erroring an in-process
// counter takes over rather than letting every attempt through.
const (
	loginAttempts = 10
	loginWindow   = 10 * time.Minute
)

func (s *Server) allowLogin(r *http.Request) bool {
	ip := s.clientIP(r)
	if s.rdb != nil {
		key := "login:" + ip
		pipe := s.rdb.TxPipeline()
		incr := pipe.Incr(r.Context(), key)
		pipe.Expire(r.Context(), key, loginWindow)
		if _, err := pipe.Exec(r.Context()); err == nil {
			return incr.Val() <= loginAttempts
		}
		// fall through to the local counter
	}
	return s.loginLocal.allow(ip, time.Now())
}

// Failed sign-ins per account (any address). A distributed guess against one
// email is slowed even when each address stays under the per-IP limit.
const (
	accountFailures = 10
	accountWindow   = 15 * time.Minute
)

// accountLocked reports whether email has too many recent failures.
func (s *Server) accountLocked(ctx context.Context, email string) bool {
	if email == "" {
		return false
	}
	if s.rdb != nil {
		if n, err := s.rdb.Get(ctx, "login:acct:"+email).Int(); err == nil {
			return n >= accountFailures
		}
	}
	return s.loginAccount.count(email, time.Now()) >= accountFailures
}

// accountFailed records one failed attempt and reports whether this one
// crossed the lockout line.
func (s *Server) accountFailed(ctx context.Context, email string) bool {
	if email == "" {
		return false
	}
	if s.rdb != nil {
		pipe := s.rdb.TxPipeline()
		incr := pipe.Incr(ctx, "login:acct:"+email)
		pipe.Expire(ctx, "login:acct:"+email, accountWindow)
		if _, err := pipe.Exec(ctx); err == nil {
			return incr.Val() == accountFailures
		}
	}
	return s.loginAccount.allowAndCount(email, time.Now()) == accountFailures
}

// accountSucceeded clears the account's failure count.
func (s *Server) accountSucceeded(ctx context.Context, email string) {
	if email == "" {
		return
	}
	if s.rdb != nil {
		_ = s.rdb.Del(ctx, "login:acct:"+email).Err()
	}
	s.loginAccount.reset(email)
}

// localLimiter counts attempts per key in memory (fallback for allowLogin).
type localLimiter struct {
	mu    sync.Mutex
	seen  map[string]*window
	limit int
	span  time.Duration
}

type window struct {
	n     int
	start time.Time
}

func newLocalLimiter(limit int, span time.Duration) *localLimiter {
	return &localLimiter{seen: map[string]*window{}, limit: limit, span: span}
}

// count is the attempts in the current window without adding one.
func (l *localLimiter) count(key string, now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.seen[key]
	if w == nil || now.Sub(w.start) > l.span {
		return 0
	}
	return w.n
}

// allowAndCount adds an attempt and returns the new count.
func (l *localLimiter) allowAndCount(key string, now time.Time) int {
	l.allow(key, now)
	return l.count(key, now)
}

func (l *localLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.seen, key)
	l.mu.Unlock()
}

func (l *localLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.seen[key]
	if w == nil || now.Sub(w.start) > l.span {
		if len(l.seen) > 50_000 {
			for k, v := range l.seen {
				if now.Sub(v.start) > l.span {
					delete(l.seen, k)
				}
			}
		}
		w = &window{start: now}
		l.seen[key] = w
	}
	w.n++
	return w.n <= l.limit
}

func (s *Server) clientIP(r *http.Request) string {
	s.muTrusted.RLock()
	trusted := append([]string(nil), s.trustedProxyCIDRs...)
	s.muTrusted.RUnlock()
	return clientip.FromRequest(r, trusted)
}

func (s *Server) setTrustedProxyCIDRs(cidrs []string) {
	s.muTrusted.Lock()
	s.trustedProxyCIDRs = append([]string(nil), cidrs...)
	s.muTrusted.Unlock()
}

func requestSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
