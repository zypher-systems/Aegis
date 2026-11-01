package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"
)

// placeholderCert is the certificate served when no certificate matches the
// SNI: a configured host whose certificate is not issued yet, or, with
// AEGIS_UNKNOWN_HOST=page, a name no host serves (unknown names are
// otherwise dropped). It is self-signed, names nothing real, and is
// minted once per process, so probes of the bare address learn nothing about
// the hosts behind the edge.
func (s *Server) placeholderCert() *tls.Certificate {
	s.placeholderOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Printf("proxy: placeholder cert key: %v", err)
			return
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "aegis-edge"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			log.Printf("proxy: placeholder cert: %v", err)
			return
		}
		s.placeholder = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return s.placeholder
}
