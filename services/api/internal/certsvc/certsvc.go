// Package certsvc manages TLS certificates for proxy hosts.
//
// Paths:
//   - self-signed (AEGIS_SELFSIGNED): internal CA leaf certs for local/e2e
//   - ACME HTTP-01 via lego (Let's Encrypt by default)
//   - custom upload (PEM cert + key + optional chain)
package certsvc

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/api/internal/ca"
	"github.com/zypher-systems/aegis/services/api/internal/crypto"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

type ACMEConfig struct {
	Directory       string
	Email           string
	SkipTLS         bool
	CloudflareToken string // env bootstrap; Settings token wins
}

type Service struct {
	store      *store.Store
	env        *crypto.Envelope
	ca         *ca.CA
	selfSigned bool
	acme       ACMEConfig
	onChange   func()

	mu         sync.Mutex
	challenges []*aegisv1.Challenge

	// Renewal backoff per certificate: after a failure the next attempt
	// waits 1h, 2h, 4h … up to a day, instead of hammering Let's Encrypt's
	// failed-validation budget every hour.
	renewMu   sync.Mutex
	renewNext map[uuid.UUID]renewState

	// notifier raises and clears operator notices (and webhooks); when nil
	// notices go straight to the store.
	notifier Notifier

	// renewBefore is how long before expiry ACME certificates renew
	// (Settings → Certificates; default 30 days).
	renewBeforeMu sync.RWMutex
	renewBefore   time.Duration
}

// DefaultRenewBefore is the renewal window when none is configured.
const DefaultRenewBefore = 30 * 24 * time.Hour

// SettingRenewBefore holds the renewal window in days.
const SettingRenewBefore = "certs.renew_before_days"

// RenewBefore is the current renewal window.
func (s *Service) RenewBefore() time.Duration {
	s.renewBeforeMu.RLock()
	defer s.renewBeforeMu.RUnlock()
	if s.renewBefore <= 0 {
		return DefaultRenewBefore
	}
	return s.renewBefore
}

// SetRenewBefore applies a new window (7–60 days) in memory.
func (s *Service) SetRenewBefore(d time.Duration) {
	s.renewBeforeMu.Lock()
	s.renewBefore = d
	s.renewBeforeMu.Unlock()
}

// LoadRenewBefore reads the persisted window, if any.
func (s *Service) LoadRenewBefore(ctx context.Context) {
	if s.store == nil || s.env == nil {
		return
	}
	raw, err := s.store.GetSetting(ctx, SettingRenewBefore, s.env.Open)
	if err != nil {
		return
	}
	if n, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && n >= 7 && n <= 60 {
		s.SetRenewBefore(time.Duration(n) * 24 * time.Hour)
	}
}

// RenewNow forces an in-place renewal of one Let's Encrypt certificate and
// resets its backoff.
func (s *Service) RenewNow(ctx context.Context, id uuid.UUID) (*store.Certificate, error) {
	m, err := s.store.GetCertificateMeta(ctx, id)
	if err != nil {
		return nil, err
	}
	if m.Issuer != "letsencrypt" {
		return nil, fmt.Errorf("only Let's Encrypt certificates can be renewed; re-upload a custom certificate")
	}
	if s.selfSigned {
		return nil, fmt.Errorf("this install issues self-signed certificates (AEGIS_SELFSIGNED)")
	}
	if _, err := s.issueACME(ctx, m.Domains, m.ID); err != nil {
		next := s.renewFailed(m.ID, time.Now())
		s.recordRenewFailure(ctx, m, err, next)
		return nil, err
	}
	s.renewSucceeded(m.ID)
	s.clearRenewFailure(ctx, m.ID.String())
	return s.store.GetCertificateMeta(ctx, id)
}

// RenewalStatus is what the dashboard shows next to a certificate.
type RenewalStatus struct {
	Failing     bool      `json:"failing"`
	Fails       int       `json:"fails,omitempty"`
	NextAttempt time.Time `json:"next_attempt,omitempty"`
}

// RenewalStatuses reports the certificates whose last renewal failed.
func (s *Service) RenewalStatuses() map[uuid.UUID]RenewalStatus {
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	out := map[uuid.UUID]RenewalStatus{}
	for id, st := range s.renewNext {
		out[id] = RenewalStatus{Failing: true, Fails: st.fails, NextAttempt: st.next}
	}
	return out
}

// Notifier is what raises operator notices; alerts.Center implements it.
type Notifier interface {
	Raise(ctx context.Context, n store.Notice)
	Clear(ctx context.Context, kind, resourceID string)
}

// SetNotifier routes this service's notices through n.
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

type renewState struct {
	fails int
	next  time.Time
}

func New(st *store.Store, env *crypto.Envelope, c *ca.CA, selfSigned bool, acme ACMEConfig, onChange func()) *Service {
	return &Service{store: st, env: env, ca: c, selfSigned: selfSigned, acme: acme, onChange: onChange}
}

// Challenges implements configsvc.ChallengeProvider.
func (s *Service) Challenges() []*aegisv1.Challenge {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*aegisv1.Challenge, len(s.challenges))
	copy(out, s.challenges)
	return out
}

func (s *Service) setChallenge(token, keyAuth string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ch := range s.challenges {
		if ch.GetToken() == token {
			s.challenges[i] = &aegisv1.Challenge{Token: token, KeyAuthorization: keyAuth}
			return
		}
	}
	s.challenges = append(s.challenges, &aegisv1.Challenge{Token: token, KeyAuthorization: keyAuth})
}

func (s *Service) removeChallenge(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.challenges[:0]
	for _, ch := range s.challenges {
		if ch.GetToken() != token {
			out = append(out, ch)
		}
	}
	s.challenges = out
}

func (s *Service) bump() {
	if s.onChange != nil {
		s.onChange()
	}
}

// EnsureForHost returns a certificate covering the host's domains, minting
// one if absent. Only meaningful for tls_mode=auto hosts.
func (s *Service) EnsureForHost(ctx context.Context, domains []string) (uuid.UUID, error) {
	if len(domains) == 0 {
		return uuid.Nil, fmt.Errorf("no domains")
	}
	if s.selfSigned {
		return s.mintSelfSigned(ctx, domains)
	}
	return s.obtainACME(ctx, domains)
}

func (s *Service) List(ctx context.Context) ([]*store.Certificate, error) {
	return s.store.ListCertificateMeta(ctx)
}

// Request issues (or reuses) a certificate for the given names without a host.
// Wildcards use Cloudflare DNS-01; other names use HTTP-01 (or self-signed).
func (s *Service) Request(ctx context.Context, domains []string) (*store.Certificate, error) {
	names, err := NormalizeDomains(domains)
	if err != nil {
		return nil, err
	}
	id, err := s.EnsureForHost(ctx, names)
	if err != nil {
		return nil, err
	}
	return s.store.GetCertificateMeta(ctx, id)
}

func NormalizeDomains(in []string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range in {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" {
			continue
		}
		if !validDomain(d) {
			return nil, fmt.Errorf("invalid domain %q", raw)
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}
	return out, nil
}

func validDomain(d string) bool {
	if strings.HasPrefix(d, "*.") {
		d = d[2:]
	}
	if d == "" || strings.Contains(d, " ") || strings.Contains(d, "/") {
		return false
	}
	if !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	for _, part := range strings.Split(d, ".") {
		if part == "" || part == "*" {
			return false
		}
	}
	return true
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	n, err := s.store.CountHostsUsingCert(ctx, id)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("certificate is in use by %d host(s)", n)
	}
	return s.store.DeleteCertificate(ctx, id)
}

func (s *Service) mintSelfSigned(ctx context.Context, domains []string) (uuid.UUID, error) {
	metas, err := s.store.ListCertificateMeta(ctx)
	if err == nil {
		for _, m := range metas {
			if m.Issuer == "selfsigned" && covers(m.Domains, domains) && time.Now().Before(m.ExpiresAt) {
				return m.ID, nil
			}
		}
	}

	certPEM, keyPEM, notAfter, err := s.ca.SignLeaf(domains, 90*24*time.Hour)
	if err != nil {
		return uuid.Nil, err
	}
	return s.save(ctx, uuid.New(), domains, "selfsigned", "", certPEM, keyPEM, notAfter)
}

func (s *Service) save(ctx context.Context, id uuid.UUID, domains []string, issuer, directory string, certPEM, keyPEM []byte, notAfter time.Time) (uuid.UUID, error) {
	certEnc, err := s.env.Seal(certPEM)
	if err != nil {
		return uuid.Nil, err
	}
	keyEnc, err := s.env.Seal(keyPEM)
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.store.SaveCertificate(ctx, id, domains, issuer, directory, certEnc, keyEnc, notAfter); err != nil {
		return uuid.Nil, err
	}
	s.bump()
	return id, nil
}

// RenewLoop renews ACME certs that expire within the renewal window and
// warns about certificates nobody will renew. Custom and self-signed certs
// are not auto-renewed.
func (s *Service) RenewLoop(ctx context.Context) {
	s.LoadRenewBefore(ctx)
	if s.selfSigned {
		return
	}
	s.BackfillDirectories(ctx)
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	s.renewDue(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.renewDue(ctx)
		}
	}
}

func (s *Service) renewDue(ctx context.Context) {
	metas, err := s.store.ListCertificateMeta(ctx)
	if err != nil {
		log.Printf("certsvc: list for renew: %v", err)
		return
	}
	hosts, err := s.store.ListHosts(ctx)
	if err != nil {
		log.Printf("certsvc: list hosts for renew: %v", err)
		return
	}
	now := time.Now()
	s.warnExpiring(ctx, metas, hosts, now)
	for _, m := range metas {
		if !s.renewWanted(m, hosts, now) {
			continue
		}
		if next, ok := s.renewBlocked(m.ID, now); ok {
			log.Printf("certsvc: renew %s (%v) waits until %s after earlier failures", m.ID, m.Domains, next.Format(time.RFC3339))
			continue
		}
		log.Printf("certsvc: renewing %s (%v)", m.ID, m.Domains)
		if _, err := s.issueACME(ctx, m.Domains, m.ID); err != nil {
			next := s.renewFailed(m.ID, now)
			log.Printf("certsvc: renew %s: %v (next attempt %s)", m.ID, err, next.Format(time.RFC3339))
			s.recordRenewFailure(ctx, m, err, next)
			continue
		}
		s.renewSucceeded(m.ID)
		s.clearRenewFailure(ctx, m.ID.String())
	}
}

// renewWanted: a Let's Encrypt certificate with auto-renew on that some
// enabled host relies on, that either expires within the renewal window or
// came from a different ACME directory than the one configured now
// (staging → production).
func (s *Service) renewWanted(m *store.Certificate, hosts []*store.Host, now time.Time) bool {
	if m.Issuer != "letsencrypt" || !m.AutoRenew {
		return false
	}
	if !certInUse(m, hosts) {
		return false
	}
	if m.Directory != "" && m.Directory != s.acme.Directory {
		return true
	}
	return m.ExpiresAt.Before(now.Add(s.RenewBefore()))
}

const noticeKindCertExpiry = "cert_expiry"

// warnExpiring raises a notice for certificates nobody will renew (uploaded,
// or auto-renew off) that an enabled host uses and that expire within 14
// days, and clears it once they are replaced.
func (s *Service) warnExpiring(ctx context.Context, metas []*store.Certificate, hosts []*store.Host, now time.Time) {
	for _, m := range metas {
		id := m.ID.String()
		renewable := m.Issuer == "letsencrypt" && m.AutoRenew && !s.selfSigned
		left := m.ExpiresAt.Sub(now)
		if renewable || !certInUse(m, hosts) || left > 14*24*time.Hour {
			if s.notifier != nil {
				s.notifier.Clear(ctx, noticeKindCertExpiry, id)
			}
			continue
		}
		var title, detail string
		names := strings.Join(m.Domains, ", ")
		if left <= 0 {
			title = fmt.Sprintf("Certificate for %s has expired", names)
		} else {
			title = fmt.Sprintf("Certificate for %s expires in %d days", names, int(left.Hours()/24))
		}
		switch {
		case m.Issuer == "custom":
			detail = "It was uploaded, so Aegis cannot renew it. Upload the renewed certificate and attach it to the host."
		case m.Issuer == "letsencrypt":
			detail = "Auto-renew is off for this certificate. Turn it back on or request a new one."
		default:
			detail = "Self-signed certificates are not renewed automatically."
		}
		if s.notifier != nil {
			s.notifier.Raise(ctx, store.Notice{Kind: noticeKindCertExpiry, ResourceID: id, Title: title, Detail: detail})
		}
	}
}

// certInUse reports whether an enabled host references the certificate by
// id or, for TLS Auto hosts, is covered by its names.
func certInUse(m *store.Certificate, hosts []*store.Host) bool {
	for _, h := range hosts {
		if !h.Enabled || h.Kind == "stream" || h.TLSMode == "none" {
			continue
		}
		if h.CertID != nil && *h.CertID == m.ID {
			return true
		}
		if h.TLSMode == "auto" && covers(m.Domains, h.DomainNames) {
			return true
		}
	}
	return false
}

const renewBackoffMax = 24 * time.Hour

func (s *Service) renewBlocked(id uuid.UUID, now time.Time) (time.Time, bool) {
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	st, ok := s.renewNext[id]
	if !ok || !now.Before(st.next) {
		return time.Time{}, false
	}
	return st.next, true
}

func (s *Service) renewFailed(id uuid.UUID, now time.Time) time.Time {
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	if s.renewNext == nil {
		s.renewNext = map[uuid.UUID]renewState{}
	}
	st := s.renewNext[id]
	st.fails++
	st.next = now.Add(renewBackoff(st.fails))
	s.renewNext[id] = st
	return st.next
}

func (s *Service) renewSucceeded(id uuid.UUID) {
	s.renewMu.Lock()
	delete(s.renewNext, id)
	s.renewMu.Unlock()
}

// renewBackoff is 1h after the first failure, doubling to a day.
func renewBackoff(fails int) time.Duration {
	d := time.Hour
	for i := 1; i < fails && d < renewBackoffMax; i++ {
		d *= 2
	}
	if d > renewBackoffMax {
		d = renewBackoffMax
	}
	return d
}

const noticeKindACMERenew = "acme_renew"

func (s *Service) recordRenewFailure(ctx context.Context, m *store.Certificate, err error, nextAt time.Time) {
	if m == nil || err == nil {
		return
	}
	next := nextAt.UTC().Format(time.RFC3339)
	detail := err.Error()
	if s.store != nil {
		_ = s.store.InsertAudit(ctx, &store.AuditEvent{
			ActorEmail:   "system",
			Action:       "renew_failed",
			ResourceType: "certificate",
			ResourceID:   m.ID.String(),
			Summary: map[string]any{
				"domains":      m.Domains,
				"error":        detail,
				"next_attempt": next,
			},
		})
		n := store.Notice{
			Kind:        noticeKindACMERenew,
			ResourceID:  m.ID.String(),
			Title:       fmt.Sprintf("Certificate for %s will not renew", strings.Join(m.Domains, ", ")),
			Detail:      detail,
			NextAttempt: next,
		}
		if s.notifier != nil {
			s.notifier.Raise(ctx, n)
		} else if s.env != nil {
			_ = s.store.UpsertNotice(ctx, n, s.env.Seal, s.env.Open)
		}
	}
}

func (s *Service) clearRenewFailure(ctx context.Context, certID string) {
	if s.notifier != nil {
		s.notifier.Clear(ctx, noticeKindACMERenew, certID)
		return
	}
	if s.store == nil || s.env == nil {
		return
	}
	_ = s.store.ClearNotice(ctx, noticeKindACMERenew, certID, s.env.Seal, s.env.Open)
}

func (s *Service) HasCloudflareBootstrap() bool {
	return s.acme.CloudflareToken != ""
}

// SelfSigned reports whether issuance mints internal CA leaves instead of ACME.
func (s *Service) SelfSigned() bool {
	return s.selfSigned
}

// ACMEEmailConfigured is true when AEGIS_ACME_EMAIL is set (required to leave self-signed mode).
func (s *Service) ACMEEmailConfigured() bool {
	return strings.TrimSpace(s.acme.Email) != ""
}

// NeedsDNS01 reports whether any name requires the DNS-01 challenge
// (wildcards cannot be issued over HTTP-01).
func NeedsDNS01(domains []string) bool {
	for _, d := range domains {
		if len(d) > 2 && d[0] == '*' && d[1] == '.' {
			return true
		}
	}
	return false
}

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
			if WildcardMatches(cd, hd) {
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

// WildcardMatches reports whether pattern ("*.example.com") covers name the
// way browsers read X.509 wildcards: exactly one label in place of the star.
// "*.example.com" covers "app.example.com" but not "a.b.example.com" or
// "example.com".
func WildcardMatches(pattern, name string) bool {
	if len(pattern) < 3 || pattern[0] != '*' || pattern[1] != '.' {
		return false
	}
	suffix := pattern[1:] // ".example.com"
	if len(name) <= len(suffix) || name[len(name)-len(suffix):] != suffix {
		return false
	}
	return !strings.Contains(name[:len(name)-len(suffix)], ".")
}
