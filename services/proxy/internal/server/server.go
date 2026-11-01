// Package server implements the data-plane HTTP(S) edge: SNI-based virtual
// host routing, atomic config swaps, ACME HTTP-01 challenge serving, and
// reverse proxying to upstreams.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/oschwald/maxminddb-golang"
	"github.com/redis/go-redis/v9"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/internal/clientip"
	"github.com/zypher-systems/aegis/services/proxy/internal/configstore"
	"github.com/zypher-systems/aegis/services/proxy/internal/telemetry"
)

// x509ParseLeaf parses and caches the leaf certificate for a keypair so SNI
// names are available without re-parsing per handshake.
func x509ParseLeaf(pair tls.Certificate) (*x509.Certificate, error) {
	if pair.Leaf != nil {
		return pair.Leaf, nil
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("empty certificate")
	}
	return x509.ParseCertificate(pair.Certificate[0])
}

// hostEntry is the immutable per-vhost runtime state.
type hostEntry struct {
	host      *aegisv1.Host
	proxy     http.Handler
	redirects bool
}

// state is the atomically-swapped routing table. It is immutable once built;
// updates replace the whole pointer.
type state struct {
	// byDomain maps lowercased domain -> entry.
	byDomain map[string]*hostEntry
	// certs maps SNI servername -> certificate.
	certs map[string]*tls.Certificate
	// wildcard entries, matched by suffix.
	wildcards []*hostEntry
	// challenges maps ACME token -> key authorization.
	challenges map[string]string
	// defaultCert served when no SNI match (may be nil).
	defaultCert *tls.Certificate
	security    *aegisv1.SecurityConfig
	version     uint64
}

// Options wires optional data-plane deps. New() uses empty options.
type Options struct {
	Redis     *redis.Client
	GeoIPMMDB string
	Telemetry *telemetry.Emitter
	NodeID    string
	// StateDir, when set, persists each applied snapshot as last-known-good.
	StateDir string
	// SnapshotKey is 32 bytes from configstore.DeriveSnapshotKey. Required
	// to persist; plaintext files are never written.
	SnapshotKey []byte
	// TrustedProxyCIDRs is the env bootstrap used until a snapshot arrives.
	TrustedProxyCIDRs []string
	// AccessLog is a nginx-combined file CrowdSec acquires. Empty disables it.
	AccessLog string
	// UnknownHost is UnknownHostDrop (also the default for "") or
	// UnknownHostPage; see unknownhost.go.
	UnknownHost string
}

// Server is the edge proxy. Config updates swap an atomic.Pointer so the hot
// path takes zero locks.
type Server struct {
	cur atomic.Pointer[state]

	transport *http.Transport
	streams   *streamManager
	pools     *upstreamHub
	rdb       *redis.Client
	geoLookup func(net.IP) (string, bool)
	tel       *telemetry.Emitter
	// One transport per distinct upstream response timeout; hosts with the
	// same timeout share connection pools.
	transportsMu sync.Mutex
	transports   map[time.Duration]*http.Transport
	stapler      ocspStapler
	// applyMu serialises Apply. The config stream is the only caller.
	applyMu sync.Mutex
	// disabled is set when the control plane revoked this node: serve 503.
	disabled atomic.Bool
	metrics  metrics
	// Self-signed certificate for unmatched SNI, minted on first use.
	placeholderOnce sync.Once
	placeholder     *tls.Certificate
	nodeID          string
	crowdsecHTTP    *http.Client
	stateDir        string
	snapshotKey     []byte
	envTrusted      []string
	accessLog       *accessLog
	// unknownHostPage answers unknown names with the placeholder cert and a
	// 404 page instead of dropping them.
	unknownHostPage bool

	csMu    sync.Mutex
	csURL   string
	csKey   string
	csStop  context.CancelFunc
	csCache atomic.Pointer[decisionCache]

	wafMu     sync.Mutex
	wafCache  map[string]coraza.WAF
	wafByHost map[string]wafSlot
	// Hosts whose WAF profile failed to compile here (guarded by wafMu).
	wafProblems map[string]wafProblem
	// Latest CrowdSec stream error, "" while healthy.
	csProblem atomic.Value

	// Per-host rate limiters survive config pushes (see ratelimit.go).
	limiters rateLimiters
}

func New() *Server { return NewWithOptions(Options{}) }

func NewWithOptions(opts Options) *Server {
	s := &Server{
		streams:         newStreamManager(),
		pools:           newUpstreamHub(),
		rdb:             opts.Redis,
		tel:             opts.Telemetry,
		nodeID:          opts.NodeID,
		stateDir:        opts.StateDir,
		snapshotKey:     append([]byte(nil), opts.SnapshotKey...),
		envTrusted:      append([]string(nil), opts.TrustedProxyCIDRs...),
		wafCache:        map[string]coraza.WAF{},
		wafByHost:       map[string]wafSlot{},
		accessLog:       newAccessLog(opts.AccessLog),
		unknownHostPage: opts.UnknownHost == UnknownHostPage,
		transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          512,
			MaxIdleConnsPerHost:   128,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: defaultUpstreamResponseTimeout,
		},
		transports: map[time.Duration]*http.Transport{},
	}
	if path := opts.GeoIPMMDB; path != "" {
		if lookup, err := openGeoIP(path); err != nil {
			log.Printf("proxy: geoip mmdb %s: %v (stage will fail closed)", path, err)
		} else {
			s.geoLookup = lookup
		}
	}
	if opts.AccessLog != "" && s.accessLog == nil {
		log.Printf("proxy: access log %s: cannot open (CrowdSec acquis disabled)", opts.AccessLog)
	} else if s.accessLog != nil {
		log.Printf("proxy: writing nginx-combined access log to %s", opts.AccessLog)
	}
	s.csCache.Store(newDecisionCache())
	return s
}

func openGeoIP(path string) (func(net.IP) (string, bool), error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return func(ip net.IP) (string, bool) {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := db.Lookup(ip, &rec); err != nil || rec.Country.ISOCode == "" {
			return "", false
		}
		return rec.Country.ISOCode, true
	}, nil
}

// Apply builds a new immutable state from a config snapshot and swaps it in.
func (s *Server) Apply(u *aegisv1.ConfigUpdate) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	hosts := u.GetHosts()
	security := u.GetSecurity()

	st := &state{
		byDomain:   map[string]*hostEntry{},
		certs:      map[string]*tls.Certificate{},
		challenges: map[string]string{},
	}

	// Certificates. Several may name the same host (a renewal next to the
	// certificate it replaces, an uploaded one next to an ACME one): the
	// newest valid one wins per name, whatever order the snapshot lists them
	// in, and an expired one is used only when nothing valid covers the name.
	now := time.Now()
	type candidate struct {
		pair *tls.Certificate
		leaf *x509.Certificate
	}
	best := map[string]candidate{}
	for _, c := range u.GetCertificates() {
		pair, err := tls.X509KeyPair(c.GetCertPem(), c.GetKeyPem())
		if err != nil {
			log.Printf("proxy: skip bad cert %s: %v", c.GetId(), err)
			continue
		}
		leaf, err := x509ParseLeaf(pair)
		if err != nil {
			continue
		}
		p := pair
		for _, name := range leaf.DNSNames {
			name = strings.ToLower(name)
			if cur, ok := best[name]; !ok || betterCert(leaf, cur.leaf, now) {
				best[name] = candidate{pair: &p, leaf: leaf}
			}
		}
	}
	for name, c := range best {
		st.certs[name] = c.pair
	}
	// A host with no certificate yet (and, with AEGIS_UNKNOWN_HOST=page, an
	// unknown SNI) gets a placeholder rather than a random customer
	// certificate that would name other hosts.
	st.defaultCert = s.placeholderCert()

	// Hosts.
	s.primeWAF(hosts)
	var streamHosts []*aegisv1.Host
	for _, h := range hosts {
		if !h.GetEnabled() {
			continue
		}
		if h.GetKind() == aegisv1.HostKind_HOST_KIND_STREAM {
			streamHosts = append(streamHosts, h)
			continue
		}
		var handler http.Handler
		if h.GetKind() == aegisv1.HostKind_HOST_KIND_PROXY || h.GetKind() == aegisv1.HostKind_HOST_KIND_UNSPECIFIED {
			handler = s.compilePipeline(h, s.buildProxy(h), security)
		}
		entry := &hostEntry{
			host:      h,
			proxy:     handler,
			redirects: h.GetForceHttps() && h.GetTlsMode() != aegisv1.TLSMode_TLS_MODE_NONE,
		}
		for _, d := range h.GetDomainNames() {
			dl := strings.ToLower(d)
			if strings.HasPrefix(dl, "*.") {
				if wildcardTaken(st.wildcards, dl) {
					log.Printf("proxy: skip duplicate wildcard %s (host %s)", dl, h.GetId())
					continue
				}
				st.wildcards = append(st.wildcards, entry)
				continue
			}
			if existing, ok := st.byDomain[dl]; ok {
				if existing.host.GetId() != h.GetId() {
					log.Printf("proxy: skip duplicate domain %s (host %s; keeping %s)", dl, h.GetId(), existing.host.GetId())
				}
				continue
			}
			st.byDomain[dl] = entry
		}
	}

	// Challenges.
	for _, ch := range u.GetChallenges() {
		st.challenges[ch.GetToken()] = ch.GetKeyAuthorization()
	}

	st.security = security
	st.version = u.GetVersion()
	s.pools.sync(hosts)
	s.limiters.retain(hosts)
	s.cur.Store(st)
	s.stapler.track(st.certs)
	s.streams.Sync(streamHosts)
	s.syncCrowdsec(st.security)
	if s.stateDir != "" {
		if err := configstore.Save(s.stateDir, u, s.snapshotKey); err != nil {
			log.Printf("proxy: persist last-known-good: %v", err)
		}
	}
	log.Printf("proxy: applied config v%d (%d hosts, %d certs, %d challenges, %d streams)",
		u.GetVersion(), len(st.byDomain)+len(st.wildcards), len(st.certs), len(st.challenges), len(streamHosts))
}

// Version is the last applied snapshot version, or 0 if none.
func (s *Server) Version() uint64 {
	if st := s.cur.Load(); st != nil {
		return st.version
	}
	return 0
}

func (s *Server) trustedCIDRs() []string {
	if st := s.cur.Load(); st != nil && st.security != nil {
		return st.security.GetTrustedProxyCidrs()
	}
	return s.envTrusted
}

// buildProxy constructs the reverse proxy handler for a host.
func (s *Server) buildProxy(h *aegisv1.Host) http.Handler {
	addrs := hostUpstreamAddrs(h)
	scheme := h.GetUpstreamScheme()
	hostport := net.JoinHostPort(h.GetUpstreamHost(), itoa(int(h.GetUpstreamPort())))
	if len(addrs) > 0 {
		scheme = addrs[0].scheme
		hostport = addrs[0].authority()
	}
	target := &url.URL{Scheme: scheme, Host: hostport}
	rp := httputil.NewSingleHostReverseProxy(target)
	hostMode := strings.TrimSpace(h.GetUpstreamHostHeader())
	rp.Transport = &failoverRT{base: s.transportFor(upstreamResponseTimeout(h)), hostID: h.GetId(), hub: s.pools, upstreamHost: hostMode == "upstream"}
	orig := rp.Director
	rp.Director = func(r *http.Request) {
		// Capture the original client-facing host before the rewrite.
		origHost := r.Host
		// The default Director already appends X-Forwarded-For once.
		orig(r)
		// Host header upstream: the client's by default (as nginx-proxy-manager
		// does), so apps keep vhost routing, absolute URLs and WebSocket
		// origin checks; "upstream" sends the upstream's host:port; any other
		// value is sent as-is.
		switch hostMode {
		case "":
			if origHost == "" {
				r.Host = target.Host
			}
		case "upstream":
			r.Host = target.Host
		default:
			r.Host = hostMode
		}
		// Behind a trusted proxy (NPM, a CDN) keep the scheme it saw, so an
		// app reached over HTTPS at the edge is not told it is on plain HTTP.
		trusted := s.trustedCIDRs()
		r.Header.Set("X-Forwarded-Proto", forwardedProto(r, trusted))
		r.Header.Set("X-Forwarded-Host", origHost)
		if clientIP := clientIPString(r, trusted); clientIP != "" {
			r.Header.Set("X-Real-Ip", clientIP)
		}
		sanitizeForwarded(r, trusted)
		// Lets an app's own logs be matched to this request in Aegis.
		if m := blockMetaFrom(r); m != nil && m.RequestID != "" && r.Header.Get("X-Request-Id") == "" {
			r.Header.Set("X-Request-Id", m.RequestID)
		}
		for _, hd := range h.GetRequestHeaders() {
			if hopByHop(hd.GetName()) {
				continue
			}
			r.Header.Set(hd.GetName(), hd.GetValue())
		}
	}
	hsts := hstsValue(h)
	rp.ModifyResponse = func(resp *http.Response) error {
		// HSTS only means anything on a TLS response; the visitor's scheme
		// is what counts, and a trusted front proxy may have terminated it.
		if hsts != "" && resp.Request != nil && forwardedProto(resp.Request, s.trustedCIDRs()) == "https" {
			resp.Header.Set("Strict-Transport-Security", hsts)
		}
		for _, hd := range h.GetResponseHeaders() {
			if hopByHop(hd.GetName()) {
				continue
			}
			resp.Header.Set(hd.GetName(), hd.GetValue())
		}
		return nil
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		code, _ := upstreamErrorStatus(r, err)
		if code != statusClientClosed {
			log.Printf("proxy: upstream error for %s %s %s: %d %v", r.Host, r.Method, r.URL.Path, code, err)
		}
		writeError(w, r, code)
	}
	return rp
}

// Defaults for per-host timeouts (0 in the config means these).
const (
	defaultIdleTimeout             = 60 * time.Second
	defaultUpstreamResponseTimeout = 60 * time.Second
	// statusClientClosed is nginx's 499: the client went away before the
	// upstream answered. Not an upstream fault, so it is not logged as one.
	statusClientClosed = 499
)

func idleTimeout(h *aegisv1.Host) time.Duration {
	if n := h.GetIdleTimeoutSeconds(); n > 0 {
		return time.Duration(n) * time.Second
	}
	return defaultIdleTimeout
}

func upstreamResponseTimeout(h *aegisv1.Host) time.Duration {
	if n := h.GetUpstreamResponseTimeoutSeconds(); n > 0 {
		return time.Duration(n) * time.Second
	}
	return defaultUpstreamResponseTimeout
}

// transportFor returns the shared transport with the given time-to-first-byte
// timeout, cloning the base for each distinct value.
func (s *Server) transportFor(d time.Duration) *http.Transport {
	if d == s.transport.ResponseHeaderTimeout {
		return s.transport
	}
	s.transportsMu.Lock()
	defer s.transportsMu.Unlock()
	if t, ok := s.transports[d]; ok {
		return t
	}
	t := s.transport.Clone()
	t.ResponseHeaderTimeout = d
	s.transports[d] = t
	return t
}

// upstreamErrorStatus maps a reverse-proxy error to what the visitor sees:
// 413 when the body cap was hit, 499 when the visitor gave up, 504 when
// the upstream was too slow, 502 for everything else.
func upstreamErrorStatus(r *http.Request, err error) (int, string) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return http.StatusRequestEntityTooLarge, "Request Entity Too Large"
	}
	if r.Context().Err() != nil {
		return statusClientClosed, "Client Closed Request"
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return http.StatusGatewayTimeout, "Gateway Timeout"
	}
	return http.StatusBadGateway, "Bad Gateway"
}

func (s *Server) compilePipeline(h *aegisv1.Host, next http.Handler, sec *aegisv1.SecurityConfig) http.Handler {
	handler := next
	if h.GetWafEnabled() {
		handler = s.wafWrap(h)(handler)
	}
	if h.GetRateLimitRps() > 0 {
		handler = s.rateWrap(h)(handler)
	}
	if len(h.GetGeoAllow()) > 0 || len(h.GetGeoDeny()) > 0 {
		handler = s.geoWrap(h)(handler)
	}
	if h.GetCrowdsecEnabled() {
		handler = s.crowdsecWrap(h, sec)(handler)
	}
	return handler
}

// ServeHTTP handles plain-HTTP requests: ACME challenges, HTTPS redirect, or
// plain proxying for tls_mode=none hosts.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if loopbackRemote(r.RemoteAddr) {
		switch r.URL.Path {
		case "/healthz": // liveness: the process answers
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok\n")
			return
		case "/readyz": // readiness: there is a config to serve and the node is not revoked
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			switch {
			case s.disabled.Load():
				http.Error(w, "revoked\n", http.StatusServiceUnavailable)
			case s.cur.Load() == nil:
				http.Error(w, "no config\n", http.StatusServiceUnavailable)
			default:
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "ready\n")
			}
			return
		case "/metrics":
			s.metrics.write(w, s)
			return
		}
	}
	if s.disabled.Load() {
		writeError(w, r, http.StatusServiceUnavailable)
		return
	}

	start := time.Now()
	r = attachWAFResult(r)
	r = attachBlockMeta(r)
	sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
	var hostID, domain string
	defer func() {
		s.emit(r, hostID, domain, sw.code, sw.n, time.Since(start))
	}()
	w = sw

	st := s.cur.Load()
	if st == nil {
		writeError(w, r, http.StatusServiceUnavailable)
		return
	}

	host := hostOnly(r.Host)
	domain = host
	entry := st.lookup(host)

	// ACME HTTP-01 challenge. A pending token is answered whatever the Host;
	// a miss on an unknown name is dropped like any other request for it.
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		if ka, ok := st.challenges[token]; ok {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, ka)
			return
		}
		if entry != nil || s.unknownHostPage {
			http.NotFound(w, r)
			return
		}
	}

	if entry == nil {
		if !s.unknownHostPage {
			dropRequest(w)
		}
		writeError(w, r, http.StatusNotFound)
		return
	}
	hostID = entry.host.GetId()
	acl := entry.host.GetAccessList()
	trusted := s.trustedCIDRs()

	// Deny-listed addresses get nothing, not even a redirect.
	if aclDenied(w, r, acl, trusted) {
		return
	}
	// Force HTTPS before anything that could ask for credentials, so basic
	// auth is never challenged over plain HTTP. A trusted front proxy's
	// scheme counts as the visitor's, so a chained setup does not loop.
	kind := entry.host.GetKind()
	if entry.redirects && kind != aegisv1.HostKind_HOST_KIND_REDIRECT && kind != aegisv1.HostKind_HOST_KIND_DEAD &&
		forwardedProto(r, trusted) != "https" {
		http.Redirect(w, r, "https://"+hostOnly(r.Host)+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	if !applyACL(w, r, acl, false, trusted) {
		return
	}

	switch kind {
	case aegisv1.HostKind_HOST_KIND_REDIRECT:
		code := int(entry.host.GetRedirectCode())
		if code != http.StatusMovedPermanently && code != http.StatusFound {
			code = http.StatusMovedPermanently
		}
		http.Redirect(w, r, entry.host.GetRedirectUrl(), code)
		return
	case aegisv1.HostKind_HOST_KIND_DEAD:
		writeError(w, r, http.StatusNotFound)
		return
	}

	if !entry.host.GetWebsocketSupport() && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		writeError(w, r, http.StatusForbidden)
		return
	}

	if v := hstsValue(entry.host); v != "" && forwardedProto(r, trusted) == "https" {
		w.Header().Set("Strict-Transport-Security", v)
	}

	if entry.proxy == nil {
		writeError(w, r, http.StatusNotFound)
		return
	}

	s.metrics.request(domain)
	// Per-host limits: body cap and idle deadline (see statusWriter).
	if max := entry.host.GetMaxBodyBytes(); max > 0 {
		if r.ContentLength > int64(max) {
			writeError(w, r, http.StatusRequestEntityTooLarge)
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, int64(max))
		}
	}
	sw.armIdle(idleTimeout(entry.host))
	defer sw.disarmIdle()
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &idleBody{ReadCloser: r.Body, sw: sw}
	}
	entry.proxy.ServeHTTP(w, r)
}

// TLSConfig returns the *tls.Config for the HTTPS listener, resolving certs
// per SNI from the current state.
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Unknown name (or no SNI, as from a bare-IP probe): close the
		// connection before the alert goes out, so the client gets nothing
		// back. This runs as soon as the ClientHello is read, ahead of ALPN,
		// HelloRetryRequest and session resumption, each of which can answer
		// before GetCertificate is asked.
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if s.unknownHostPage {
				return nil, nil
			}
			if st := s.cur.Load(); st != nil && st.lookup(strings.ToLower(hello.ServerName)) != nil {
				return nil, nil
			}
			if hello.Conn != nil {
				_ = hello.Conn.Close()
			}
			return nil, errUnknownServerName
		},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			st := s.cur.Load()
			if st == nil {
				return nil, fmt.Errorf("no config")
			}
			name := strings.ToLower(hello.ServerName)
			if cert, ok := st.certs[name]; ok {
				return s.stapler.withStaple(cert), nil
			}
			// Wildcard: one label in place of the star, as browsers check it.
			if i := strings.IndexByte(name, '.'); i > 0 {
				if cert, ok := st.certs["*"+name[i:]]; ok {
					return s.stapler.withStaple(cert), nil
				}
			}
			return st.defaultCert, nil
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}

func wildcardTaken(entries []*hostEntry, pattern string) bool {
	for _, e := range entries {
		for _, d := range e.host.GetDomainNames() {
			if strings.ToLower(d) == pattern {
				return true
			}
		}
	}
	return false
}

// lookup finds the host entry for a domain (exact then wildcard).
func (st *state) lookup(domain string) *hostEntry {
	if e, ok := st.byDomain[domain]; ok {
		return e
	}
	for _, e := range st.wildcards {
		for _, d := range e.host.GetDomainNames() {
			if wildcardMatches(strings.ToLower(d), domain) {
				return e
			}
		}
	}
	return nil
}

// wildcardMatches: "*.example.com" matches "app.example.com", not
// "a.b.example.com" or "example.com" (X.509 wildcard semantics).
func wildcardMatches(pattern, name string) bool {
	if len(pattern) < 3 || pattern[0] != '*' || pattern[1] != '.' {
		return false
	}
	suffix := pattern[1:]
	if len(name) <= len(suffix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	return !strings.Contains(name[:len(name)-len(suffix)], ".")
}

// betterCert prefers a currently valid certificate over one that is not,
// then the later expiry.
func betterCert(a, b *x509.Certificate, now time.Time) bool {
	av := !now.Before(a.NotBefore) && now.Before(a.NotAfter)
	bv := !now.Before(b.NotBefore) && now.Before(b.NotAfter)
	if av != bv {
		return av
	}
	return a.NotAfter.After(b.NotAfter)
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}

func (s *Server) emit(r *http.Request, hostID, domain string, status, bytes int, d time.Duration) {
	if r != nil {
		s.accessLog.Write(r, status, bytes, s.trustedCIDRs())
		var stage, action string
		if m := blockMetaFrom(r); m != nil {
			stage = m.Stage
		}
		if hit := wafResultFrom(r); hit != nil {
			action = hit.Action
		}
		s.metrics.finished(domain, status, stage, action)
	}
	if s.tel == nil || r == nil {
		return
	}
	path, query := "", ""
	if r.URL != nil {
		path = r.URL.Path
		query = truncateUTF8(r.URL.RawQuery, 1024)
	}
	scheme, tlsVersion := "http", ""
	if r.TLS != nil {
		scheme = "https"
		tlsVersion = tls.VersionName(r.TLS.Version)
	}
	peer := r.RemoteAddr
	if h, _, err := net.SplitHostPort(peer); err == nil {
		peer = h
	}
	var received int64
	if r.ContentLength > 0 {
		received = r.ContentLength
	}
	ev := &aegisv1.TelemetryEvent{
		TimestampUnixMs: time.Now().UnixMilli(),
		HostId:          hostID,
		Domain:          domain,
		Method:          r.Method,
		Path:            path,
		Status:          int32(status),
		DurationMs:      float64(d.Microseconds()) / 1000,
		ClientIp:        clientIPString(r, s.trustedCIDRs()),
		UserAgent:       r.UserAgent(),
		BytesSent:       int64(bytes),
		NodeId:          s.nodeID,
		Query:           query,
		Referer:         truncateUTF8(r.Referer(), 1024),
		Protocol:        r.Proto,
		Scheme:          scheme,
		TlsVersion:      tlsVersion,
		PeerIp:          peer,
		BytesReceived:   received,
	}
	if hit := wafResultFrom(r); hit != nil && hit.Action != "" {
		ev.WafAction = hit.Action
		ev.WafRuleId = hit.RuleID
		ev.WafScore = hit.Score
		for _, c := range hit.Matches {
			ev.WafMatches = append(ev.WafMatches, &aegisv1.WAFMatch{
				RuleId: c.id, Message: c.msg, Severity: int32(c.sev),
				Variable: c.variable, Key: c.key, Value: c.value,
			})
		}
	}
	if m := blockMetaFrom(r); m != nil {
		ev.BlockStage = m.Stage
		ev.BlockDetail = m.Detail
		ev.CrowdsecOrigin = m.CrowdSecOrigin
		ev.Upstream = m.Upstream
		ev.RequestId = m.RequestID
	}
	if s.geoLookup != nil {
		if ip := net.ParseIP(ev.ClientIp); ip != nil {
			if cc, ok := s.geoLookup(ip); ok {
				ev.Country = cc
			}
		}
	}
	s.tel.Emit(ev)
}

type statusWriter struct {
	http.ResponseWriter
	code int
	n    int

	// Idle deadline: every byte read from the client or written to it
	// pushes the connection's deadlines `idle` into the future, so a slow
	// but live transfer never times out while a stalled one does.
	rc    *http.ResponseController
	idle  time.Duration
	armed time.Time
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	w.touch()
	n, err := w.ResponseWriter.Write(p)
	w.n += n
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// armIdle starts the idle deadline for this request.
func (w *statusWriter) armIdle(idle time.Duration) {
	w.rc = http.NewResponseController(w.ResponseWriter)
	w.idle = idle
	w.touch()
}

// touch extends the deadlines. Re-arming is throttled to a quarter of the
// idle time (at most once a second) to keep it cheap without letting the
// deadline lapse under a steady trickle.
func (w *statusWriter) touch() {
	if w.rc == nil {
		return
	}
	now := time.Now()
	if step := min(time.Second, w.idle/4); now.Sub(w.armed) < step {
		return
	}
	w.armed = now
	dl := now.Add(w.idle)
	_ = w.rc.SetReadDeadline(dl)
	_ = w.rc.SetWriteDeadline(dl)
}

// disarmIdle clears the deadlines so they do not leak into the next
// request on a keep-alive connection.
func (w *statusWriter) disarmIdle() {
	if w.rc == nil {
		return
	}
	_ = w.rc.SetReadDeadline(time.Time{})
	_ = w.rc.SetWriteDeadline(time.Time{})
}

// idleBody extends the idle deadline as the client's body is read.
type idleBody struct {
	io.ReadCloser
	sw *statusWriter
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.sw.touch()
	}
	return n, err
}

// forwardedProto is the scheme the visitor used: the X-Forwarded-Proto a
// trusted proxy sent, else how the request reached this node.
func forwardedProto(r *http.Request, trusted []string) string {
	if clientip.Contains(net.ParseIP(clientip.RemoteIP(r)), trusted) {
		p := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]))
		if p == "https" || p == "http" {
			return p
		}
	}
	return schemeOf(r)
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func loopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func itoa(i int) string {
	if i == 0 {
		return "80"
	}
	return fmt.Sprintf("%d", i)
}

// Disable stops serving (503 for every request), closes stream listeners and
// forgets the persisted config. Called when the control plane says this
// node is revoked.
func (s *Server) Disable(reason string) {
	if s.disabled.Swap(true) {
		return
	}
	log.Printf("proxy: DISABLED: %s", reason)
	s.CloseStreams()
	if s.stateDir != "" {
		_ = configstore.Remove(s.stateDir)
	}
}

// sanitizeForwarded keeps the client-address headers honest before the
// request reaches the app. The default Director appends the hop to whatever
// X-Forwarded-For the client sent; an untrusted client could therefore plant
// "127.0.0.1, <real>" and fool an app that reads the first entry. From an
// untrusted hop the chain is rewritten to the hop alone and the other
// client-IP headers are dropped; from a trusted proxy its chain is kept.
func sanitizeForwarded(r *http.Request, trusted []string) {
	hop := clientip.RemoteIP(r)
	if hop == "" {
		return
	}
	if clientip.Contains(net.ParseIP(hop), trusted) {
		return
	}
	r.Header.Set("X-Forwarded-For", hop)
	for _, h := range []string{"Forwarded", "True-Client-IP", "CF-Connecting-IP", "X-Client-IP", "X-Cluster-Client-IP", "X-Originating-IP"} {
		r.Header.Del(h)
	}
}

// hstsValue is the Strict-Transport-Security header for a host, "" when off.
func hstsValue(h *aegisv1.Host) string {
	if !h.GetHsts() {
		return ""
	}
	maxAge := h.GetHstsMaxAge()
	if maxAge == 0 {
		maxAge = 31536000
	}
	v := fmt.Sprintf("max-age=%d", maxAge)
	if h.GetHstsIncludeSubdomains() {
		v += "; includeSubDomains"
	}
	if h.GetHstsPreload() {
		v += "; preload"
	}
	return v
}
