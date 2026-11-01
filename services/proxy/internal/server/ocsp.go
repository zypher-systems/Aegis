package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ocspStapler fetches OCSP responses for the served certificates and hands
// them out with the certificate on each handshake, so browsers do not have
// to ask the CA themselves (a privacy leak and, when the CA responder is
// slow, a visible delay). Best effort: a certificate without a responder, or
// a fetch that fails, is served without a staple, exactly as before.
type ocspStapler struct {
	mu     sync.Mutex
	certs  map[[32]byte]*tls.Certificate // by leaf fingerprint: what to staple
	staple map[[32]byte]staple
	client *http.Client
	wake   chan struct{}
	once   sync.Once
}

type staple struct {
	der        []byte
	nextUpdate time.Time
	fetched    time.Time
}

const (
	ocspRefreshEvery = time.Hour
	ocspRetryAfter   = 15 * time.Minute
)

func (o *ocspStapler) init() {
	o.once.Do(func() {
		o.certs = map[[32]byte]*tls.Certificate{}
		o.staple = map[[32]byte]staple{}
		o.client = &http.Client{Timeout: 10 * time.Second}
		o.wake = make(chan struct{}, 1)
		go o.loop(context.Background())
	})
}

// track replaces the set of certificates to staple for and triggers a fetch.
func (o *ocspStapler) track(certs map[string]*tls.Certificate) {
	o.init()
	o.mu.Lock()
	next := map[[32]byte]*tls.Certificate{}
	for _, c := range certs {
		if c == nil || len(c.Certificate) == 0 {
			continue
		}
		next[sha256.Sum256(c.Certificate[0])] = c
	}
	o.certs = next
	for fp := range o.staple {
		if _, still := next[fp]; !still {
			delete(o.staple, fp)
		}
	}
	o.mu.Unlock()
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// withStaple returns cert with a fresh OCSP response attached, or cert
// itself when there is none.
func (o *ocspStapler) withStaple(cert *tls.Certificate) *tls.Certificate {
	if cert == nil || len(cert.Certificate) == 0 || o.staple == nil {
		return cert
	}
	fp := sha256.Sum256(cert.Certificate[0])
	o.mu.Lock()
	st, ok := o.staple[fp]
	o.mu.Unlock()
	if !ok || len(st.der) == 0 || time.Now().After(st.nextUpdate) {
		return cert
	}
	c := *cert
	c.OCSPStaple = st.der
	return &c
}

func (o *ocspStapler) loop(ctx context.Context) {
	t := time.NewTicker(ocspRefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-o.wake:
		case <-t.C:
		}
		o.refresh(ctx)
	}
}

func (o *ocspStapler) refresh(ctx context.Context) {
	o.mu.Lock()
	todo := map[[32]byte]*tls.Certificate{}
	now := time.Now()
	for fp, c := range o.certs {
		st, ok := o.staple[fp]
		// Refresh at the half-life, retry failures after a while.
		if !ok || now.After(st.fetched.Add(st.nextUpdate.Sub(st.fetched)/2)) || (len(st.der) == 0 && now.After(st.fetched.Add(ocspRetryAfter))) {
			todo[fp] = c
		}
	}
	o.mu.Unlock()
	for fp, c := range todo {
		der, next, err := o.fetch(ctx, c)
		o.mu.Lock()
		if err != nil {
			if _, had := o.staple[fp]; !had || len(o.staple[fp].der) == 0 {
				o.staple[fp] = staple{fetched: time.Now(), nextUpdate: time.Now().Add(ocspRetryAfter)}
			}
			o.mu.Unlock()
			if err != errNoOCSP {
				log.Printf("proxy: ocsp staple: %v", err)
			}
			continue
		}
		o.staple[fp] = staple{der: der, nextUpdate: next, fetched: time.Now()}
		o.mu.Unlock()
	}
}

type ocspErr string

func (e ocspErr) Error() string { return string(e) }

const errNoOCSP = ocspErr("certificate has no OCSP responder or no issuer in its chain")

// ocspTarget returns the leaf and issuer needed for a request, or errNoOCSP.
func ocspTarget(c *tls.Certificate) (leaf, issuer *x509.Certificate, err error) {
	if c == nil || len(c.Certificate) < 2 {
		return nil, nil, errNoOCSP
	}
	leaf, err = x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	if len(leaf.OCSPServer) == 0 {
		return nil, nil, errNoOCSP
	}
	issuer, err = x509.ParseCertificate(c.Certificate[1])
	if err != nil {
		return nil, nil, err
	}
	return leaf, issuer, nil
}

func (o *ocspStapler) fetch(ctx context.Context, c *tls.Certificate) ([]byte, time.Time, error) {
	leaf, issuer, err := ocspTarget(c)
	if err != nil {
		return nil, time.Time{}, err
	}
	reqDER, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	var last error
	for _, server := range leaf.OCSPServer {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(reqDER))
		if err != nil {
			last = err
			continue
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")
		resp, err := o.client.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		parsed, err := ocsp.ParseResponseForCert(body, leaf, issuer)
		if err != nil {
			last = err
			continue
		}
		if parsed.Status != ocsp.Good {
			last = ocspErr("responder reports status " + statusName(parsed.Status) + " for " + leaf.Subject.CommonName)
			continue
		}
		next := parsed.NextUpdate
		if next.IsZero() {
			next = time.Now().Add(24 * time.Hour)
		}
		return body, next, nil
	}
	return nil, time.Time{}, last
}

func statusName(s int) string {
	switch s {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	default:
		return "unknown"
	}
}
