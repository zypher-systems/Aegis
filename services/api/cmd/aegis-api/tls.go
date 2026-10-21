package main

import (
	"crypto/tls"
	"fmt"
)

// Thin wrappers so the TLS settings are explicit at the call site.
const (
	tlsNoClientCert               = tls.NoClientCert
	tlsRequireAndVerifyClientCert = tls.RequireAndVerifyClientCert
)

func tlsConfigForServer(pair tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
	}
}

func tlsX509KeyPair(certPEM, keyPEM []byte) (tls.Certificate, error) {
	return tls.X509KeyPair(certPEM, keyPEM)
}

// rejectRevokedClientCerts refuses mTLS handshakes whose leaf serial is on the
// control-plane denylist. Serial encoding matches ca.SignCSR (big.Int Text 16).
func rejectRevokedClientCerts(cfg *tls.Config, revoked func(serial string) bool) {
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("no client certificate")
		}
		serial := cs.PeerCertificates[0].SerialNumber.Text(16)
		if revoked != nil && revoked(serial) {
			return fmt.Errorf("revoked client certificate")
		}
		return nil
	}
}
