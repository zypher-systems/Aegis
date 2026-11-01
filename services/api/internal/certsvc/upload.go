package certsvc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

// Upload stores a user-supplied PEM certificate + key (+ optional chain).
// The private key is never returned on list/get.
func (s *Service) Upload(ctx context.Context, certPEM, keyPEM, chainPEM []byte) (*store.Certificate, error) {
	leaf, key, err := parseLeafAndKey(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if err := keysMatch(leaf, key); err != nil {
		return nil, err
	}

	domains := leaf.DNSNames
	if len(domains) == 0 && leaf.Subject.CommonName != "" {
		domains = []string{leaf.Subject.CommonName}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("certificate has no DNS names")
	}

	bundle := bytes.TrimSpace(certPEM)
	if len(bytes.TrimSpace(chainPEM)) > 0 {
		bundle = append(append(bundle, '\n'), bytes.TrimSpace(chainPEM)...)
	}

	id := uuid.New()
	if _, err := s.save(ctx, id, domains, "custom", "", bundle, keyPEM, leaf.NotAfter); err != nil {
		return nil, err
	}
	return &store.Certificate{
		ID:        id,
		Domains:   domains,
		Issuer:    "custom",
		ExpiresAt: leaf.NotAfter,
	}, nil
}

func parseLeafAndKey(certPEM, keyPEM []byte) (*x509.Certificate, crypto.PrivateKey, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("cert_pem is not a PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	kblock, _ := pem.Decode(keyPEM)
	if kblock == nil {
		return nil, nil, fmt.Errorf("key_pem is not PEM")
	}
	var key crypto.PrivateKey
	switch kblock.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(kblock.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kblock.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kblock.Bytes)
	default:
		return nil, nil, fmt.Errorf("unsupported key type %q", kblock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse key: %w", err)
	}
	return leaf, key, nil
}

func keysMatch(cert *x509.Certificate, key crypto.PrivateKey) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok || k.N.Cmp(pub.N) != 0 {
			return fmt.Errorf("key does not match certificate")
		}
	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || k.X.Cmp(pub.X) != 0 || k.Y.Cmp(pub.Y) != 0 {
			return fmt.Errorf("key does not match certificate")
		}
	case ed25519.PrivateKey:
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok || !bytes.Equal(k.Public().(ed25519.PublicKey), pub) {
			return fmt.Errorf("key does not match certificate")
		}
	default:
		return fmt.Errorf("unsupported private key type")
	}
	return nil
}
