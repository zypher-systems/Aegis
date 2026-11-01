// Package ca manages the control plane's internal Ed25519 root CA, which
// issues mTLS client certificates to enrolled data-plane nodes. The CA
// private key is envelope-encrypted at rest in the settings table.
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	settingsKeyCAPEM  = "internal_ca_cert_pem"
	settingsKeyKEYPEM = "internal_ca_key_pem"
)

type CA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

// PEM cert accessors.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// CertPool returns a pool containing only this CA, for verifying node certs.
func (c *CA) CertPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// RootCert returns the CA's x509 certificate, used as the signing parent for
// self-signed leaf certs minted in development mode.
func (c *CA) RootCert() *x509.Certificate { return c.cert }

// SignLeaf issues a server certificate for the given DNS names, signed by
// this CA. Returns cert PEM, key PEM, and expiry.
func (c *CA) SignLeaf(dnsNames []string, ttl time.Duration) (certPEM, keyPEM []byte, expires time.Time, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	expires = time.Now().Add(ttl)
	cn := ""
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Aegis (development CA)"}},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     expires,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// Parent is the CA; the CA's private key signs, the leaf's public key is certified.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, expires, nil
}

// LoadOrInit returns the persisted CA or generates a new self-signed root.
// get/set are the encrypted settings accessors from the store layer.
func LoadOrInit(get func(key string) ([]byte, error), set func(key string, val []byte) error) (*CA, error) {
	certPEM, err := get(settingsKeyCAPEM)
	if err == nil {
		keyPEM, kerr := get(settingsKeyKEYPEM)
		if kerr != nil {
			return nil, fmt.Errorf("ca cert present but key missing: %w", kerr)
		}
		return parse(certPEM, keyPEM)
	}

	// Generate a new Ed25519 root CA.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Aegis Internal CA", Organization: []string{"Aegis"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	out := &CA{cert: cert, key: priv}
	if err := set(settingsKeyCAPEM, out.CertPEM()); err != nil {
		return nil, err
	}
	if err := set(settingsKeyKEYPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return nil, err
	}
	return out, nil
}

func parse(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("invalid ca cert pem")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("invalid ca key pem")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca key is not ed25519")
	}
	return &CA{cert: cert, key: priv}, nil
}

// SignCSR issues a client certificate for a data-plane node from a PEM CSR.
// Returns cert PEM, serial hex, and expiry.
func (c *CA) SignCSR(csrPEM []byte, nodeID, nodeName string, ttl time.Duration) (certPEM []byte, serial string, expires time.Time, err error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil {
		err = fmt.Errorf("invalid csr pem")
		return
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return
	}
	if err = csr.CheckSignature(); err != nil {
		err = fmt.Errorf("bad csr signature: %w", err)
		return
	}
	serialInt, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}
	expires = time.Now().Add(ttl)
	tmpl := &x509.Certificate{
		SerialNumber: serialInt,
		Subject: pkix.Name{
			CommonName:   nodeID,
			Organization: []string{"Aegis Node"},
			ExtraNames:   []pkix.AttributeTypeAndValue{},
		},
		DNSNames:    []string{nodeName},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    expires,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	serial = serialInt.Text(16)
	return
}

// ServerTLSConfig builds the mTLS server config for the gRPC listener.
func (c *CA) ServerTLSConfig(serverCertPEM, serverKeyPEM []byte) (*tls.Config, error) {
	pair, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    c.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// IssueServerCert creates a server certificate for the gRPC listener itself,
// signed by this CA (so nodes can pin the CA and verify the control plane).
func (c *CA) IssueServerCert(dnsNames []string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	serialInt, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialInt,
		Subject:      pkix.Name{CommonName: "aegis-api", Organization: []string{"Aegis"}},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}
