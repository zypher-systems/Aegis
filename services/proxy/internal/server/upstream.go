package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

const (
	upstreamProbeEvery = 5 * time.Second
	upstreamDialWait   = 2 * time.Second
	upstreamMaxTries   = 3
	// Consecutive failed probes before a target is taken out of rotation.
	upstreamFailsToDown = 2
)

var errNoUpstream = errors.New("no upstream")

type upstreamAddr struct {
	scheme     string
	host       string
	port       uint32
	skipVerify bool
	sni        string
	caPEM      string
}

func (a upstreamAddr) authority() string {
	return net.JoinHostPort(a.host, strconv.Itoa(int(a.port)))
}

func (a upstreamAddr) key() string {
	return a.scheme + "://" + a.authority()
}

func (a upstreamAddr) customTLS() bool {
	return a.scheme == "https" && (a.skipVerify || a.sni != "" || a.caPEM != "")
}

func (a upstreamAddr) tlsCacheKey() string {
	sum := sha256.Sum256([]byte(a.caPEM))
	skip := "0"
	if a.skipVerify {
		skip = "1"
	}
	return a.key() + "|" + a.sni + "|" + skip + "|" + hex.EncodeToString(sum[:8])
}

func (a upstreamAddr) tlsConfig() *tls.Config {
	if !a.customTLS() {
		return nil
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: a.skipVerify, //nolint:gosec // operator-opt-in for homelab origins
		ServerName:         a.sni,
	}
	if a.caPEM != "" && !a.skipVerify {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		rest := []byte(a.caPEM)
		ok := false
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			pool.AddCert(cert)
			ok = true
		}
		if ok {
			cfg.RootCAs = pool
		}
	}
	return cfg
}

func protoAddr(u *aegisv1.UpstreamTarget, fallbackScheme string) (upstreamAddr, bool) {
	if u.GetHost() == "" || u.GetPort() == 0 {
		return upstreamAddr{}, false
	}
	scheme := u.GetScheme()
	if scheme == "" {
		scheme = fallbackScheme
	}
	if scheme == "" {
		scheme = "http"
	}
	a := upstreamAddr{scheme: scheme, host: u.GetHost(), port: u.GetPort()}
	if scheme == "https" {
		a.skipVerify = u.GetTlsSkipVerify()
		a.sni = u.GetTlsServerName()
		a.caPEM = u.GetTlsCaPem()
	}
	return a, true
}

type liveUpstream struct {
	addr    upstreamAddr
	weight  int
	healthy bool
	fails   int
	// current is the smooth weighted round-robin accumulator.
	current int
	// lastErr is why the last probe failed, for the operator notice.
	lastErr string
}

// poolSpec is everything that shapes one host's upstream pool; a change
// to any of it rebuilds the pool.
type poolSpec struct {
	domain     string
	addrs      []upstreamAddr
	weights    []int
	roundRobin bool
	healthPath string
	// hostHeader is what the probe sends as Host: the host's own domain
	// unless the host forwards a different one.
	hostHeader string
}

func (a poolSpec) equal(b poolSpec) bool {
	if a.domain != b.domain || a.roundRobin != b.roundRobin || a.healthPath != b.healthPath ||
		a.hostHeader != b.hostHeader || len(a.addrs) != len(b.addrs) {
		return false
	}
	for i := range a.addrs {
		if a.addrs[i] != b.addrs[i] || a.weights[i] != b.weights[i] {
			return false
		}
	}
	return true
}

type upstreamPool struct {
	mu      sync.Mutex
	spec    poolSpec
	targets []*liveUpstream
	cancel  context.CancelFunc
	probeRT map[string]*http.Transport
}

// upstreamHealth is one target's state for metrics and problem reports.
type upstreamHealth struct {
	domain  string
	addr    string
	healthy bool
	fails   int
	lastErr string
}

type upstreamHub struct {
	mu     sync.Mutex
	byHost map[string]*upstreamPool
}

func newUpstreamHub() *upstreamHub {
	return &upstreamHub{byHost: map[string]*upstreamPool{}}
}

func hostUpstreamAddrs(h *aegisv1.Host) []upstreamAddr {
	var out []upstreamAddr
	for _, u := range h.GetUpstreams() {
		if a, ok := protoAddr(u, h.GetUpstreamScheme()); ok {
			out = append(out, a)
		}
	}
	if len(out) == 0 && h.GetUpstreamHost() != "" && h.GetUpstreamPort() != 0 {
		scheme := h.GetUpstreamScheme()
		if scheme == "" {
			scheme = "http"
		}
		out = append(out, upstreamAddr{scheme: scheme, host: h.GetUpstreamHost(), port: h.GetUpstreamPort()})
	}
	return out
}

// hostPoolSpec derives a host's pool spec; ok is false when it has no
// usable upstream.
func hostPoolSpec(host *aegisv1.Host) (poolSpec, bool) {
	addrs := hostUpstreamAddrs(host)
	if len(addrs) == 0 {
		return poolSpec{}, false
	}
	spec := poolSpec{
		domain:     firstDomain(host),
		addrs:      addrs,
		roundRobin: host.GetLbPolicy() == "round_robin",
		healthPath: host.GetHealthPath(),
	}
	for i := range addrs {
		w := 1
		if ups := host.GetUpstreams(); i < len(ups) && ups[i].GetWeight() > 0 {
			w = int(ups[i].GetWeight())
		}
		spec.weights = append(spec.weights, w)
	}
	switch mode := host.GetUpstreamHostHeader(); mode {
	case "":
		spec.hostHeader = spec.domain
	case "upstream":
		spec.hostHeader = "" // each target's own authority
	default:
		spec.hostHeader = mode
	}
	return spec, true
}

func (h *upstreamHub) sync(hosts []*aegisv1.Host) {
	wanted := map[string]poolSpec{}
	for _, host := range hosts {
		if !host.GetEnabled() {
			continue
		}
		if host.GetKind() == aegisv1.HostKind_HOST_KIND_STREAM {
			continue
		}
		if spec, ok := hostPoolSpec(host); ok {
			wanted[host.GetId()] = spec
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for id, p := range h.byHost {
		if _, ok := wanted[id]; !ok {
			p.cancel()
			delete(h.byHost, id)
		}
	}
	for id, spec := range wanted {
		if p, ok := h.byHost[id]; ok && p.spec.equal(spec) {
			continue
		}
		if old, ok := h.byHost[id]; ok {
			old.cancel()
		}
		ctx, cancel := context.WithCancel(context.Background())
		p := &upstreamPool{cancel: cancel, spec: spec}
		for i, a := range spec.addrs {
			p.targets = append(p.targets, &liveUpstream{addr: a, weight: spec.weights[i], healthy: true})
		}
		h.byHost[id] = p
		go p.probeLoop(ctx)
	}
}

// health lists every target's state across all pools, sorted by domain
// then address.
func (h *upstreamHub) health() []upstreamHealth {
	h.mu.Lock()
	pools := make([]*upstreamPool, 0, len(h.byHost))
	for _, p := range h.byHost {
		pools = append(pools, p)
	}
	h.mu.Unlock()
	var out []upstreamHealth
	for _, p := range pools {
		p.mu.Lock()
		for _, t := range p.targets {
			out = append(out, upstreamHealth{domain: p.spec.domain, addr: t.addr.key(), healthy: t.healthy, fails: t.fails, lastErr: t.lastErr})
		}
		p.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].domain != out[j].domain {
			return out[i].domain < out[j].domain
		}
		return out[i].addr < out[j].addr
	})
	return out
}

func (p *upstreamPool) probeLoop(ctx context.Context) {
	t := time.NewTicker(upstreamProbeEvery)
	defer t.Stop()
	p.probe()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.probe()
		}
	}
}

func (p *upstreamPool) probe() {
	p.mu.Lock()
	targets := append([]*liveUpstream(nil), p.targets...)
	spec := p.spec
	p.mu.Unlock()
	for _, t := range targets {
		var err error
		if spec.healthPath != "" {
			err = p.httpAlive(t.addr, spec)
		} else {
			err = tcpAlive(t.addr.authority())
		}
		p.mu.Lock()
		if err == nil {
			t.fails = 0
			t.healthy = true
			t.lastErr = ""
		} else {
			t.fails++
			t.lastErr = err.Error()
			if t.fails >= upstreamFailsToDown {
				t.healthy = false
			}
		}
		p.mu.Unlock()
	}
}

func tcpAlive(addr string) error {
	c, err := net.DialTimeout("tcp", addr, upstreamDialWait)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

// httpAlive GETs the health path. Any answer below 500 means the
// application is up; a 5xx, a refused connection or a slow answer does not.
func (p *upstreamPool) httpAlive(a upstreamAddr, spec poolSpec) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*upstreamDialWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.scheme+"://"+a.authority()+spec.healthPath, nil)
	if err != nil {
		return err
	}
	if spec.hostHeader != "" {
		req.Host = spec.hostHeader
	}
	req.Header.Set("User-Agent", "aegis-health/1")
	resp, err := p.probeTransport(a).RoundTrip(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("health check answered %d", resp.StatusCode)
	}
	return nil
}

// probeTransport is a small dedicated transport per TLS shape, so probes
// never compete with visitor traffic for the shared pool's connections.
func (p *upstreamPool) probeTransport(a upstreamAddr) *http.Transport {
	key := a.tlsCacheKey()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.probeRT == nil {
		p.probeRT = map[string]*http.Transport{}
	}
	if rt, ok := p.probeRT[key]; ok {
		return rt
	}
	rt := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: upstreamDialWait}).DialContext,
		TLSClientConfig:       a.tlsConfig(),
		TLSHandshakeTimeout:   upstreamDialWait,
		ResponseHeaderTimeout: 2 * upstreamDialWait,
		DisableKeepAlives:     true,
	}
	p.probeRT[key] = rt
	return rt
}

func (p *upstreamPool) markDown(a upstreamAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, t := range p.targets {
		if t.addr == a {
			t.fails++
			t.healthy = false
			if t.lastErr == "" {
				t.lastErr = "connection failed while proxying a request"
			}
			return
		}
	}
}

// order returns the targets to try, in order. Failover: healthy targets in
// configured order, then the sick ones. Round robin: the smooth weighted
// pick first (nginx's algorithm, so a 5/1 split gives A A A B A A ... not
// A A A A A B), then the other healthy targets, then the sick ones.
func (p *upstreamPool) order() []upstreamAddr {
	p.mu.Lock()
	defer p.mu.Unlock()
	var healthy, sick []upstreamAddr
	if p.spec.roundRobin {
		var pick *liveUpstream
		total := 0
		for _, t := range p.targets {
			if !t.healthy {
				continue
			}
			t.current += t.weight
			total += t.weight
			if pick == nil || t.current > pick.current {
				pick = t
			}
		}
		if pick != nil {
			pick.current -= total
			healthy = append(healthy, pick.addr)
		}
		for _, t := range p.targets {
			if t.healthy && t != pick {
				healthy = append(healthy, t.addr)
			} else if !t.healthy {
				sick = append(sick, t.addr)
			}
		}
		return append(healthy, sick...)
	}
	for _, t := range p.targets {
		if t.healthy {
			healthy = append(healthy, t.addr)
		} else {
			sick = append(sick, t.addr)
		}
	}
	return append(healthy, sick...)
}

func (h *upstreamHub) order(hostID string) []upstreamAddr {
	h.mu.Lock()
	p := h.byHost[hostID]
	h.mu.Unlock()
	if p == nil {
		return nil
	}
	return p.order()
}

func (h *upstreamHub) markDown(hostID string, a upstreamAddr) {
	h.mu.Lock()
	p := h.byHost[hostID]
	h.mu.Unlock()
	if p != nil {
		p.markDown(a)
	}
}

type failoverRT struct {
	base   *http.Transport
	hostID string
	hub    *upstreamHub
	// upstreamHost: send each target's own host:port as the Host header
	// (upstream_host_header = "upstream"). Otherwise the Host the director
	// chose (the client's, or a literal) is kept on every attempt.
	upstreamHost bool
	mu           sync.Mutex
	extra        map[string]http.RoundTripper
}

func (t *failoverRT) tripper(a upstreamAddr) http.RoundTripper {
	cfg := a.tlsConfig()
	if cfg == nil {
		return t.base
	}
	key := a.tlsCacheKey()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.extra == nil {
		t.extra = map[string]http.RoundTripper{}
	}
	if rt, ok := t.extra[key]; ok {
		return rt
	}
	nt := t.base.Clone()
	nt.TLSClientConfig = cfg
	t.extra[key] = nt
	return nt
}

// retryBodyMax is the largest request body kept in memory so a request can
// be replayed against the next upstream after a connection failure. Bigger
// bodies are sent once; if that attempt fails the visitor gets the error.
const retryBodyMax = 1 << 20

func (t *failoverRT) RoundTrip(req *http.Request) (*http.Response, error) {
	targets := t.hub.order(t.hostID)
	if len(targets) == 0 {
		resp, err := t.base.RoundTrip(req)
		if err == nil && req.URL != nil {
			setUpstream(req, req.URL.Scheme+"://"+req.URL.Host)
		}
		return resp, err
	}
	if len(targets) > upstreamMaxTries {
		targets = targets[:upstreamMaxTries]
	}
	// Replaying a request is only safe when the previous attempt never
	// reached the application: the body must be replayable (empty or
	// buffered) and the failure a connection failure.
	replayable := bufferBody(req)
	var last error
	for i, tgt := range targets {
		nr := req.Clone(req.Context())
		if nr.URL == nil {
			continue
		}
		if i > 0 && req.GetBody != nil {
			nr.Body, _ = req.GetBody()
		}
		nr.URL.Scheme = tgt.scheme
		nr.URL.Host = tgt.authority()
		if t.upstreamHost {
			nr.Host = tgt.authority()
		}
		resp, err := t.tripper(tgt).RoundTrip(nr)
		if err == nil {
			setUpstream(req, tgt.scheme+"://"+tgt.authority())
			return resp, nil
		}
		last = err
		if req.Context().Err() != nil {
			// The visitor left or our own deadline passed: not the
			// upstream's fault, and nothing to retry for.
			return nil, err
		}
		if !isConnectError(err) {
			// The upstream accepted the connection: it is up, and the
			// request may have been processed. No retry, no markDown.
			return nil, err
		}
		t.hub.markDown(t.hostID, tgt)
		if !replayable {
			return nil, err
		}
	}
	if last == nil {
		last = errNoUpstream
	}
	return nil, last
}

// bufferBody makes small bodies replayable via req.GetBody and reports
// whether the request can be sent again.
func bufferBody(req *http.Request) bool {
	if req.Body == nil || req.Body == http.NoBody {
		return true
	}
	if req.GetBody != nil {
		return true
	}
	if req.ContentLength < 0 || req.ContentLength > retryBodyMax {
		return false
	}
	buf, err := io.ReadAll(io.LimitReader(req.Body, retryBodyMax+1))
	_ = req.Body.Close()
	if err != nil || int64(len(buf)) > retryBodyMax {
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), errReader{err}))
		return false
	}
	req.Body = io.NopCloser(bytes.NewReader(buf))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf)), nil }
	return true
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	return 0, io.EOF
}

// isConnectError reports a failure to reach the upstream at all (refused,
// unreachable, DNS, dial timeout), as opposed to an error after connecting.
func isConnectError(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	var dns *net.DNSError
	return errors.As(err, &dns)
}
