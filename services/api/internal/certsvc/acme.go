package certsvc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/google/uuid"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

type acmeAccount struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (a *acmeAccount) GetEmail() string                        { return a.email }
func (a *acmeAccount) GetPrivateKey() crypto.PrivateKey        { return a.key }
func (a *acmeAccount) GetRegistration() *registration.Resource { return a.reg }

type http01Provider struct {
	svc *Service
}

func (p *http01Provider) Present(_, token, keyAuth string) error {
	p.svc.setChallenge(token, keyAuth)
	p.svc.bump()
	// Give connected proxies a moment to apply the snapshot.
	time.Sleep(2 * time.Second)
	return nil
}

func (p *http01Provider) CleanUp(_, token, _ string) error {
	p.svc.removeChallenge(token)
	p.svc.bump()
	return nil
}

// Well-known directories, used to backfill rows from before 1.7.2.
const (
	leProduction = "https://acme-v02.api.letsencrypt.org/directory"
	leStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// obtainACME returns a certificate covering domains from the configured
// directory: an existing one with more than 30 days left, or a new issuance.
// When an existing certificate for exactly these names has to be replaced
// (expiring, or issued by another directory) it is renewed in place, so hosts
// keep their cert_id and no stale row lingers.
func (s *Service) obtainACME(ctx context.Context, domains []string) (uuid.UUID, error) {
	replace := uuid.Nil
	if metas, err := s.store.ListCertificateMeta(ctx); err == nil {
		for _, m := range metas {
			if m.Issuer != "letsencrypt" || !covers(m.Domains, domains) {
				continue
			}
			if m.Directory == s.acme.Directory && time.Now().Add(s.RenewBefore()).Before(m.ExpiresAt) {
				return m.ID, nil
			}
			if replace == uuid.Nil && sameNames(m.Domains, domains) {
				replace = m.ID
			}
		}
	}
	return s.issueACME(ctx, domains, replace)
}

// issueACME performs an issuance and saves it under id (uuid.Nil = new row).
func (s *Service) issueACME(ctx context.Context, domains []string, id uuid.UUID) (uuid.UUID, error) {
	if s.acme.Email == "" {
		return uuid.Nil, fmt.Errorf("AEGIS_ACME_EMAIL is required for ACME issuance")
	}
	// A cancelled request (browser closed, front proxy timed out) must not
	// discard a certificate Let's Encrypt has already issued and counted.
	ctx = context.WithoutCancel(ctx)

	user, err := s.acmeUser(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = s.acme.Directory
	cfg.Certificate.KeyType = certcrypto.EC256
	if s.acme.SkipTLS {
		cfg.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // pebble
			},
			Timeout: 2 * time.Minute,
		}
	}

	client, err := lego.NewClient(cfg)
	if err != nil {
		return uuid.Nil, fmt.Errorf("acme client: %w", err)
	}
	if NeedsDNS01(domains) {
		token, err := s.cloudflareToken(ctx)
		if err != nil {
			return uuid.Nil, err
		}
		cfCfg := cloudflare.NewDefaultConfig()
		cfCfg.AuthToken = token
		p, err := cloudflare.NewDNSProviderConfig(cfCfg)
		if err != nil {
			return uuid.Nil, fmt.Errorf("cloudflare dns: %w", err)
		}
		// Split-horizon: the box resolver often returns internal NS
		// (svc-ns-*.example.com) which never see the Cloudflare TXT.
		// Let's Encrypt and this precheck must use public resolvers.
		if err := client.Challenge.SetDNS01Provider(p,
			dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}),
		); err != nil {
			return uuid.Nil, err
		}
	} else if err := client.Challenge.SetHTTP01Provider(&http01Provider{svc: s}); err != nil {
		return uuid.Nil, err
	}

	if user.reg == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return uuid.Nil, fmt.Errorf("acme register: %w", err)
		}
		user.reg = reg
	}

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("acme obtain: %w", err)
	}

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	if block, _ := pem.Decode(res.Certificate); block != nil {
		if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
			notAfter = leaf.NotAfter
		}
	}

	renewed := id != uuid.Nil
	if !renewed {
		id = uuid.New()
	}
	if _, err := s.save(ctx, id, domains, "letsencrypt", s.acme.Directory, res.Certificate, res.PrivateKey, notAfter); err != nil {
		return uuid.Nil, err
	}
	verb := "issued"
	if renewed {
		verb = "renewed"
	}
	log.Printf("certsvc: %s ACME cert %s for %v (expires %s)", verb, id, domains, notAfter.Format(time.RFC3339))
	return id, nil
}

// BackfillDirectories records the issuing directory for letsencrypt rows
// from before 1.7.2, read from the certificate's issuer name.
func (s *Service) BackfillDirectories(ctx context.Context) {
	if s.store == nil || s.env == nil {
		return
	}
	metas, err := s.store.ListCertificateMeta(ctx)
	if err != nil {
		return
	}
	for _, m := range metas {
		if m.Issuer != "letsencrypt" || m.Directory != "" {
			continue
		}
		_, _, certEnc, _, _, err := s.store.GetCertificateEnc(ctx, m.ID)
		if err != nil {
			continue
		}
		certPEM, err := s.env.Open(certEnc)
		if err != nil {
			continue
		}
		dir := leProduction
		if block, _ := pem.Decode(certPEM); block != nil {
			if leaf, err := x509.ParseCertificate(block.Bytes); err == nil && strings.Contains(strings.ToUpper(leaf.Issuer.CommonName), "STAGING") {
				dir = leStaging
			}
		}
		if err := s.store.SetCertificateDirectory(ctx, m.ID, dir); err == nil {
			log.Printf("certsvc: %s (%v) recorded as issued by %s", m.ID, m.Domains, dir)
		}
	}
}

func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, d := range a {
		set[d] = true
	}
	for _, d := range b {
		if !set[d] {
			return false
		}
	}
	return true
}

func (s *Service) acmeUser(ctx context.Context) (*acmeAccount, error) {
	key, err := s.loadOrCreateAccountKey(ctx)
	if err != nil {
		return nil, err
	}
	return &acmeAccount{email: s.acme.Email, key: key}, nil
}

func (s *Service) loadOrCreateAccountKey(ctx context.Context) (crypto.PrivateKey, error) {
	raw, err := s.store.GetSetting(ctx, store.SettingACMEAccountKey, s.env.Open)
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("corrupt ACME account key")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := s.store.SetSetting(ctx, store.SettingACMEAccountKey, pemBytes, s.env.Seal); err != nil {
		return nil, err
	}
	return priv, nil
}

func (s *Service) cloudflareToken(ctx context.Context) (string, error) {
	if s.store != nil && s.env != nil {
		b, err := s.store.GetSetting(ctx, store.SettingDNSCloudflareToken, s.env.Open)
		if err == nil && len(b) > 0 {
			return string(b), nil
		}
	}
	if s.acme.CloudflareToken != "" {
		return s.acme.CloudflareToken, nil
	}
	return "", fmt.Errorf("Cloudflare API token required for wildcard ACME (Settings or AEGIS_CF_API_TOKEN)")
}
