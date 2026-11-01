// Package identity manages the node's mTLS identity: key generation, CSR,
// enrollment against the control plane, and persistence in the state dir.
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

const (
	keyFile  = "node_key.pem"
	certFile = "node_cert.pem"
	caFile   = "ca.pem"
	idFile   = "node_id"
)

// RenewBefore is how long before expiry a node renews its certificate.
const RenewBefore = 30 * 24 * time.Hour

type Identity struct {
	NodeID string
	CAPool *x509.CertPool
	CAPEM  []byte
	KeyPEM []byte

	stateDir string
	mu       sync.RWMutex
	cert     tls.Certificate // current client cert; Renew replaces it
	certPEM  []byte
	expires  time.Time
}

// LoadOrEnroll returns a persisted identity or performs enrollment to obtain
// one. controlPlane is the token-authenticated enrollment listener address.
// A persisted identity whose certificate has already expired cannot renew
// (the control plane rejects the handshake), so with a token it re-enrols;
// without one it is returned as-is and keeps serving its last config.
func LoadOrEnroll(ctx context.Context, stateDir, controlPlane, token, nodeName, version string) (*Identity, error) {
	if id, err := load(stateDir); err == nil {
		if !id.Expired(time.Now()) {
			return id, nil
		}
		if token == "" {
			log.Printf("identity: node certificate expired %s and AEGIS_ENROLL_TOKEN is empty; serving last config only", id.ExpiresAt().Format(time.RFC3339))
			return id, nil
		}
		log.Printf("identity: node certificate expired %s; re-enrolling", id.ExpiresAt().Format(time.RFC3339))
	}
	if token == "" {
		return nil, fmt.Errorf("no persisted identity and AEGIS_ENROLL_TOKEN is empty")
	}
	return enroll(ctx, stateDir, controlPlane, token, nodeName, version)
}

// Cert is the current client certificate.
func (id *Identity) Cert() tls.Certificate {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.cert
}

// ExpiresAt is the current certificate's NotAfter.
func (id *Identity) ExpiresAt() time.Time {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.expires
}

func (id *Identity) Expired(now time.Time) bool { return !now.Before(id.ExpiresAt()) }

// RenewDue reports whether the certificate is inside the renewal window.
func (id *Identity) RenewDue(now time.Time) bool { return now.Add(RenewBefore).After(id.ExpiresAt()) }

// TLSConfig is the client config for the node plane. New connections always
// present the current certificate, so a renewal takes effect on the next
// dial without restarting.
func (id *Identity) TLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c := id.Cert()
			return &c, nil
		},
		RootCAs:    id.CAPool,
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
	}
}

// Renew asks the control plane for a new certificate over the mTLS node
// plane, keeping the existing key, and persists it.
func (id *Identity) Renew(ctx context.Context, nodePlane, version string) error {
	priv, err := parseKey(id.KeyPEM)
	if err != nil {
		return err
	}
	csrPEM, err := csrFor(priv, id.NodeID)
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, nodePlane,
		grpc.WithTransportCredentials(credentials.NewTLS(id.TLSConfig("aegis-api"))),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("dial node plane: %w", err)
	}
	defer conn.Close()
	resp, err := aegisv1.NewConfigServiceClient(conn).Renew(dialCtx, &aegisv1.RenewRequest{
		CsrPem: csrPEM, AgentVersion: version,
	})
	if err != nil {
		return fmt.Errorf("renew rpc: %w", err)
	}
	cert, err := tls.X509KeyPair(resp.GetCertificatePem(), id.KeyPEM)
	if err != nil {
		return fmt.Errorf("renewed cert does not match key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	// Persist before switching, so a crash in between leaves the old cert on
	// disk (still valid) rather than a half-written file.
	if err := writeAtomic(filepath.Join(id.stateDir, certFile), resp.GetCertificatePem(), 0o644); err != nil {
		return fmt.Errorf("save cert: %w", err)
	}
	if ca := resp.GetCaCertificatePem(); len(ca) > 0 && string(ca) != string(id.CAPEM) {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(ca) {
			if err := writeAtomic(filepath.Join(id.stateDir, caFile), ca, 0o644); err == nil {
				id.CAPEM = ca
				id.CAPool = pool
			}
		}
	}
	id.mu.Lock()
	id.cert = cert
	id.certPEM = resp.GetCertificatePem()
	id.expires = leaf.NotAfter
	id.mu.Unlock()
	return nil
}

// RenewLoop renews the certificate when it enters the renewal window,
// retrying hourly on failure, until ctx ends.
func (id *Identity) RenewLoop(ctx context.Context, nodePlane, version string) {
	const check = 6 * time.Hour
	const retry = time.Hour
	for {
		wait := check
		if id.RenewDue(time.Now()) {
			if err := id.Renew(ctx, nodePlane, version); err != nil {
				log.Printf("identity: renew node certificate (expires %s): %v; retrying in %s", id.ExpiresAt().Format(time.RFC3339), err, retry)
				wait = retry
			} else {
				log.Printf("identity: node certificate renewed, expires %s", id.ExpiresAt().Format(time.RFC3339))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func parseKey(keyPEM []byte) (ed25519.PrivateKey, error) {
	b, _ := pem.Decode(keyPEM)
	if b == nil {
		return nil, fmt.Errorf("invalid key pem")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("node key is not ed25519")
	}
	return priv, nil
}

func csrFor(priv ed25519.PrivateKey, name string) ([]byte, error) {
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: name, Organization: []string{"Aegis Node"}},
		DNSNames: []string{name},
	}, priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func load(stateDir string) (*Identity, error) {
	keyPEM, err := os.ReadFile(filepath.Join(stateDir, keyFile))
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(filepath.Join(stateDir, certFile))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(stateDir, caFile))
	if err != nil {
		return nil, err
	}
	idBytes, err := os.ReadFile(filepath.Join(stateDir, idFile))
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid CA pem")
	}
	return &Identity{
		NodeID:   string(idBytes),
		CAPool:   pool,
		CAPEM:    caPEM,
		KeyPEM:   keyPEM,
		stateDir: stateDir,
		cert:     cert,
		certPEM:  certPEM,
		expires:  leaf.NotAfter,
	}, nil
}

func enroll(ctx context.Context, stateDir, controlPlane, token, nodeName, version string) (*Identity, error) {
	// Generate node keypair and CSR.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	csrPEM, err := csrFor(priv, nodeName)
	if err != nil {
		return nil, err
	}

	// Connect to the enrollment listener. We don't yet trust the CA, so this
	// single bootstrap call skips verification; the enrollment token
	// authenticates the exchange and the returned CA is pinned thereafter.
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, controlPlane,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // bootstrap only; CA pinned from response
			MinVersion:         tls.VersionTLS13,
		})),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("dial enrollment: %w", err)
	}
	defer conn.Close()

	resp, err := aegisv1.NewEnrollmentServiceClient(conn).Enroll(ctx, &aegisv1.EnrollRequest{
		Token:        token,
		CsrPem:       csrPEM,
		NodeName:     nodeName,
		AgentVersion: version,
	})
	if err != nil {
		return nil, fmt.Errorf("enroll rpc: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Persist identity.
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	write := func(name string, data []byte, perm os.FileMode) error {
		return os.WriteFile(filepath.Join(stateDir, name), data, perm)
	}
	if err := write(keyFile, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := write(certFile, resp.GetCertificatePem(), 0o644); err != nil {
		return nil, err
	}
	if err := write(caFile, resp.GetCaCertificatePem(), 0o644); err != nil {
		return nil, err
	}
	if err := write(idFile, []byte(resp.GetNodeId()), 0o644); err != nil {
		return nil, err
	}

	return load(stateDir)
}

// Wipe deletes the node's key, certificate, CA and id. After a revocation the
// node must not present that identity again; a restart with an enrolment
// token gets a new one.
func Wipe(stateDir string) {
	for _, f := range []string{keyFile, certFile, caFile, idFile} {
		_ = os.Remove(filepath.Join(stateDir, f))
	}
}
