// Package configsvc assembles data-plane configuration snapshots and pushes
// them to connected proxy nodes over the ConfigService gRPC stream.
package configsvc

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/api/internal/certsvc"
	"github.com/zypher-systems/aegis/services/api/internal/crypto"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

// ChallengeProvider supplies active ACME HTTP-01 challenges for snapshots.
type ChallengeProvider interface {
	Challenges() []*aegisv1.Challenge
}

type Service struct {
	aegisv1.UnimplementedConfigServiceServer
	store *store.Store
	// Node certificate renewal (EnableRenewal).
	signer      CertSigner
	nodeCertTTL time.Duration
	nodes       nodeStore
	sealer      sealer
	notifier    certsvc.Notifier
	// problems last reported by each node (Report RPC), keyed by
	// kind|resource, so a report can be diffed into raises and clears.
	problemsMu sync.Mutex
	problems   map[uuid.UUID]map[string]*aegisv1.NodeProblem
	env        *crypto.Envelope
	challenges ChallengeProvider
	envTrusted []string

	mu      sync.Mutex
	version uint64
	// subs receive a signal whenever a new snapshot is available.
	subs  map[chan struct{}]struct{}
	kicks map[uuid.UUID]context.CancelFunc
	// closing is closed on shutdown so every Watch ends at once and nodes
	// reconnect (to the restarted API) instead of holding the old process.
	closing   chan struct{}
	closeOnce sync.Once
}

func New(st *store.Store, env *crypto.Envelope, cp ChallengeProvider) *Service {
	return &Service{
		store: st, env: env, challenges: cp,
		subs:  map[chan struct{}]struct{}{},
		kicks: map[uuid.UUID]context.CancelFunc{},
		// Seeded from the clock so versions stay monotonic across API
		// restarts; a node's LastVersion from before the restart then still
		// compares meaningfully, and dashboards do not see "v0" after boot.
		version: uint64(time.Now().Unix()),
	}
}

// SetChallengeProvider wires the challenge provider after construction (the
// cert service needs the config bump callback, so creation order requires a
// setter).
// SetEnvTrustedCIDRs is the compose/CI bootstrap used when no setting is stored.
func (s *Service) SetEnvTrustedCIDRs(cidrs []string) {
	s.envTrusted = append([]string(nil), cidrs...)
}

func (s *Service) SetChallengeProvider(cp ChallengeProvider) {
	s.mu.Lock()
	s.challenges = cp
	s.mu.Unlock()
}

// Bump signals all connected nodes that a fresh snapshot is available.
// Called after any mutation (host CRUD, cert issued, challenge updated).
func (s *Service) Bump() {
	s.mu.Lock()
	s.version++
	for ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	s.mu.Unlock()
}

// Version exposes the current config version.
func (s *Service) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// Kick drops the config Watch stream for a revoked node so the cert is not
// usable until expiry.
func (s *Service) Kick(id uuid.UUID) {
	if id == uuid.Nil {
		return
	}
	s.mu.Lock()
	cancel := s.kicks[id]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Watch streams full snapshots to a node. Every emission is a complete
// snapshot, so reconnects and missed updates self-heal on the next push.
func (s *Service) Watch(req *aegisv1.WatchRequest, stream grpc.ServerStreamingServer[aegisv1.ConfigUpdate]) error {
	nodeID := nodeIDFromPeer(stream.Context())
	if s.store != nil {
		if s.store.NodeIDRevoked(nodeID) {
			return status.Error(codes.Unauthenticated, "node revoked")
		}
		_ = s.store.TouchNode(stream.Context(), nodeID)
		if v := strings.TrimSpace(req.GetAgentVersion()); v != "" {
			_ = s.store.SetNodeAgentVersion(stream.Context(), nodeID, v)
		}
	}

	watchCtx, cancel := context.WithCancel(stream.Context())
	s.mu.Lock()
	if prev := s.kicks[nodeID]; prev != nil {
		prev()
	}
	s.kicks[nodeID] = cancel
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.kicks, nodeID)
		s.mu.Unlock()
		cancel()
	}()

	notify := make(chan struct{}, 1)
	s.mu.Lock()
	s.subs[notify] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, notify)
		s.mu.Unlock()
	}()

	// Always send a snapshot immediately on connect.
	if err := s.sendSnapshot(stream); err != nil {
		return err
	}

	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.closingCh():
			return status.Error(codes.Unavailable, "control plane shutting down")
		case <-watchCtx.Done():
			if stream.Context().Err() != nil {
				return stream.Context().Err()
			}
			return status.Error(codes.Unauthenticated, "node revoked")
		case <-notify:
			if err := s.sendSnapshot(stream); err != nil {
				return err
			}
		case <-tick.C:
			if s.store != nil {
				if s.store.NodeIDRevoked(nodeID) {
					return status.Error(codes.Unauthenticated, "node revoked")
				}
				_ = s.store.TouchNode(stream.Context(), nodeID)
			}
		}
	}
}

func (s *Service) sendSnapshot(stream grpc.ServerStreamingServer[aegisv1.ConfigUpdate]) error {
	snap, err := s.BuildSnapshot(stream.Context())
	if err != nil {
		return status.Errorf(codes.Internal, "build snapshot: %v", err)
	}
	return stream.Send(snap)
}

// nodeIDFromPeer extracts the node UUID from the mTLS client cert CN.
func nodeIDFromPeer(ctx context.Context) uuid.UUID {
	if p, ok := peer.FromContext(ctx); ok {
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			for _, chain := range ti.State.VerifiedChains {
				if len(chain) > 0 {
					if id, err := uuid.Parse(chain[0].Subject.CommonName); err == nil {
						return id
					}
				}
			}
		}
	}
	return uuid.Nil
}

// BuildSnapshot assembles the complete desired config from the database.
// Certificate private keys are decrypted in-memory only for transmission over
// the mTLS channel and are never logged.
func (s *Service) BuildSnapshot(ctx context.Context) (*aegisv1.ConfigUpdate, error) {
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}

	pb := &aegisv1.ConfigUpdate{Snapshot: true}
	s.mu.Lock()
	pb.Version = s.version
	s.mu.Unlock()

	lists, err := s.store.ListAccessLists(ctx)
	if err != nil {
		return nil, err
	}
	byList := map[uuid.UUID]*store.AccessList{}
	for _, a := range lists {
		byList[a.ID] = a
	}
	wafs, err := s.store.ListWAFProfiles(ctx)
	if err != nil {
		return nil, err
	}
	byWAF := map[uuid.UUID]*store.WAFProfile{}
	for _, p := range wafs {
		byWAF[p.ID] = p
	}

	// certIDs tracks which certs to attach, keyed by id string.
	certIDs := map[string]struct{}{}
	add := func(id uuid.UUID) { certIDs[id.String()] = struct{}{} }

	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		tlsMode := aegisv1.TLSMode_TLS_MODE_AUTO
		switch h.TLSMode {
		case "custom":
			tlsMode = aegisv1.TLSMode_TLS_MODE_CUSTOM
		case "none":
			tlsMode = aegisv1.TLSMode_TLS_MODE_NONE
		}
		var certID string
		if h.CertID != nil {
			certID = h.CertID.String()
			add(*h.CertID)
		}
		pbHost := &aegisv1.Host{
			Id:                             h.ID.String(),
			DomainNames:                    h.DomainNames,
			UpstreamScheme:                 h.UpstreamScheme,
			UpstreamHost:                   h.UpstreamHost,
			UpstreamPort:                   uint32(h.UpstreamPort),
			Enabled:                        h.Enabled,
			TlsMode:                        tlsMode,
			CertId:                         certID,
			ForceHttps:                     h.ForceHTTPS,
			Hsts:                           h.HSTS,
			WebsocketSupport:               h.WebsocketSupport,
			Kind:                           hostKind(h.Kind),
			RedirectUrl:                    h.RedirectURL,
			RedirectCode:                   uint32(h.RedirectCode),
			RequestHeaders:                 headerPairs(h.RequestHeaders),
			ResponseHeaders:                headerPairs(h.ResponseHeaders),
			ListenProtocol:                 listenProto(h.ListenProtocol),
			ListenPort:                     uint32(h.ListenPort),
			RateLimitRps:                   uint32(h.RateLimitRPS),
			RateLimitBurst:                 uint32(h.RateLimitBurst),
			GeoAllow:                       h.GeoAllow,
			GeoDeny:                        h.GeoDeny,
			CrowdsecEnabled:                h.CrowdSecEnabled,
			OidcEnabled:                    h.OIDC.Enabled,
			OidcIssuer:                     h.OIDC.Issuer,
			OidcClientId:                   h.OIDC.ClientID,
			OidcClientSecret:               h.OIDC.ClientSecret,
			OidcPaths:                      h.OIDC.Paths,
			OidcCookieName:                 h.OIDC.CookieName,
			Upstreams:                      protoUpstreams(h),
			UpstreamHostHeader:             h.UpstreamHostHeader,
			HstsMaxAge:                     uint32(h.HSTSMaxAge),
			HstsIncludeSubdomains:          h.HSTSSubdomains,
			HstsPreload:                    h.HSTSPreload,
			LbPolicy:                       h.LBPolicy,
			HealthPath:                     h.HealthPath,
			IdleTimeoutSeconds:             uint32(h.IdleTimeoutSeconds),
			UpstreamResponseTimeoutSeconds: uint32(h.UpstreamResponseTimeoutSeconds),
			MaxBodyBytes:                   uint64(h.MaxBodyBytes),
		}
		if h.AccessListID != nil {
			if a := byList[*h.AccessListID]; a != nil {
				pbHost.AccessList = compileACL(a)
			}
		}
		if h.WAFProfileID != nil {
			attachWAFProfile(pbHost, byWAF[*h.WAFProfileID])
		}
		stripCutFeatures(pbHost)
		pb.Hosts = append(pb.Hosts, pbHost)
	}

	// Attach AUTO certs that cover each auto host's domains.
	metas, err := s.store.ListCertificateMeta(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if !h.Enabled || h.TLSMode != "auto" || h.Kind == "stream" {
			continue
		}
		for _, m := range metas {
			if covers(m.Domains, h.DomainNames) {
				add(m.ID)
			}
		}
	}

	// Decrypt and attach all referenced certificates.
	for idStr := range certIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			continue
		}
		_, _, certEnc, keyEnc, expiresAt, err := s.store.GetCertificateEnc(ctx, id)
		if err != nil {
			continue
		}
		certPEM, err := s.env.Open(certEnc)
		if err != nil {
			continue
		}
		keyPEM, err := s.env.Open(keyEnc)
		if err != nil {
			continue
		}
		pb.Certificates = append(pb.Certificates, &aegisv1.Certificate{
			Id:            idStr,
			CertPem:       certPEM,
			KeyPem:        keyPEM,
			ExpiresAtUnix: expiresAt.Unix(),
		})
	}

	s.mu.Lock()
	cp := s.challenges
	s.mu.Unlock()
	if cp != nil {
		pb.Challenges = cp.Challenges()
	}

	sec := &aegisv1.SecurityConfig{}
	if s.env != nil {
		if raw, err := s.store.GetSetting(ctx, store.SettingCrowdSecLAPI, s.env.Open); err == nil {
			var cs struct {
				URL string `json:"url"`
				Key string `json:"key"`
			}
			if json.Unmarshal(raw, &cs) == nil {
				sec.CrowdsecLapiUrl = cs.URL
				sec.CrowdsecLapiKey = cs.Key
			}
		}
	}
	sec.TrustedProxyCidrs = s.envTrusted
	if s.env != nil {
		if raw, err := s.store.GetSetting(ctx, store.SettingTrustedProxyCIDRs, s.env.Open); err == nil {
			var tp struct {
				CIDRs []string `json:"cidrs"`
			}
			if json.Unmarshal(raw, &tp) == nil {
				sec.TrustedProxyCidrs = tp.CIDRs
			}
		}
	}
	pb.Security = sec
	return pb, nil
}

// covers reports whether certDomains covers all hostDomains (exact or wildcard).
func covers(certDomains, hostDomains []string) bool {
	set := map[string]bool{}
	for _, d := range certDomains {
		set[d] = true
	}
	for _, hd := range hostDomains {
		if set[hd] {
			continue
		}
		matched := false
		for cd := range set {
			if certsvc.WildcardMatches(cd, hd) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func hostKind(k string) aegisv1.HostKind {
	switch k {
	case "redirect":
		return aegisv1.HostKind_HOST_KIND_REDIRECT
	case "dead":
		return aegisv1.HostKind_HOST_KIND_DEAD
	case "stream":
		return aegisv1.HostKind_HOST_KIND_STREAM
	default:
		return aegisv1.HostKind_HOST_KIND_PROXY
	}
}

func listenProto(p string) aegisv1.ListenProtocol {
	switch p {
	case "udp":
		return aegisv1.ListenProtocol_LISTEN_PROTOCOL_UDP
	case "tcp":
		return aegisv1.ListenProtocol_LISTEN_PROTOCOL_TCP
	default:
		return aegisv1.ListenProtocol_LISTEN_PROTOCOL_UNSPECIFIED
	}
}

func headerPairs(m map[string]string) []*aegisv1.Header {
	if len(m) == 0 {
		return nil
	}
	out := make([]*aegisv1.Header, 0, len(m))
	for k, v := range m {
		out = append(out, &aegisv1.Header{Name: k, Value: v})
	}
	return out
}

func compileACL(a *store.AccessList) *aegisv1.AccessList {
	users := make([]*aegisv1.BasicAuthUser, 0, len(a.Users))
	for _, u := range a.Users {
		users = append(users, &aegisv1.BasicAuthUser{Username: u.Username, PasswordHash: u.PasswordHash})
	}
	return &aegisv1.AccessList{
		Satisfy:    a.Satisfy,
		Users:      users,
		AllowCidrs: a.AllowCIDRs,
		DenyCidrs:  a.DenyCIDRs,
	}
}

func protoUpstreams(h *store.Host) []*aegisv1.UpstreamTarget {
	src := h.Upstreams
	if len(src) == 0 && h.UpstreamHost != "" {
		src = []store.HostUpstream{{Scheme: h.UpstreamScheme, Host: h.UpstreamHost, Port: h.UpstreamPort}}
	}
	if len(src) == 0 {
		return nil
	}
	out := make([]*aegisv1.UpstreamTarget, 0, len(src))
	for _, u := range src {
		out = append(out, &aegisv1.UpstreamTarget{
			Scheme:        u.Scheme,
			Host:          u.Host,
			Port:          uint32(u.Port),
			TlsSkipVerify: u.TLSSkipVerify,
			TlsServerName: u.TLSServerName,
			TlsCaPem:      u.TLSCAPem,
			Weight:        uint32(u.Weight),
		})
	}
	return out
}

// Close ends every open Watch stream with Unavailable. Nodes keep their
// last-known-good config and reconnect with backoff.
func (s *Service) Close() {
	s.closeOnce.Do(func() { close(s.closingCh()) })
}

func (s *Service) closingCh() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing == nil {
		s.closing = make(chan struct{})
	}
	return s.closing
}

// SetNotifier routes node notices (certificate expiry, offline, reported
// problems) through n instead of straight to the store.
func (s *Service) SetNotifier(n certsvc.Notifier) { s.notifier = n }
