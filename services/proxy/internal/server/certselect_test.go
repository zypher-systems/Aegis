package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

// selfSigned mints a certificate for names valid over [from, until].
func selfSigned(t *testing.T, names []string, from, until time.Time) *aegisv1.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: from, NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return &aegisv1.Certificate{
		Id:      serial.String(),
		CertPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPem:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

func servedFor(t *testing.T, s *Server, sni string) *x509.Certificate {
	t.Helper()
	cfg := s.TLSConfig()
	hello := &tls.ClientHelloInfo{ServerName: sni}
	if _, err := cfg.GetConfigForClient(hello); err != nil {
		t.Fatalf("%q refused: %v", sni, err)
	}
	c, err := cfg.GetCertificate(hello)
	if err != nil || c == nil {
		t.Fatalf("no cert for %q: %v", sni, err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestNewestValidCertWinsRegardlessOfOrder(t *testing.T) {
	now := time.Now()
	old := selfSigned(t, []string{"app.example.com"}, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour))
	renewed := selfSigned(t, []string{"app.example.com"}, now.Add(-time.Hour), now.Add(89*24*time.Hour))
	expired := selfSigned(t, []string{"app.example.com"}, now.Add(-100*24*time.Hour), now.Add(-time.Hour))
	for _, order := range [][]*aegisv1.Certificate{{old, renewed, expired}, {renewed, old, expired}, {expired, renewed, old}} {
		s := New()
		s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: certHost("app.example.com"), Certificates: order})
		if got := servedFor(t, s, "app.example.com"); got.NotAfter.Sub(now) < 88*24*time.Hour {
			t.Fatalf("served cert expiring %s, want the renewed one", got.NotAfter)
		}
	}
	// Only an expired cert: still served (a broken cert beats no cert).
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: certHost("app.example.com"), Certificates: []*aegisv1.Certificate{expired}})
	if got := servedFor(t, s, "app.example.com"); got.NotAfter.After(now) {
		t.Fatal("expected the expired cert as last resort")
	}
}

// certHost is an enabled host for names, so their SNI is not dropped.
func certHost(names ...string) []*aegisv1.Host {
	return []*aegisv1.Host{{Id: "h", DomainNames: names, Enabled: true, Kind: aegisv1.HostKind_HOST_KIND_DEAD}}
}

// With AEGIS_UNKNOWN_HOST=page, unknown SNI gets the placeholder (the
// default drops it; see unknownhost_test.go).
func TestWildcardCertMatchesOneLabelAndUnknownSNIGetsPlaceholder(t *testing.T) {
	now := time.Now()
	wild := selfSigned(t, []string{"*.example.com"}, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	s := NewWithOptions(Options{UnknownHost: UnknownHostPage})
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Certificates: []*aegisv1.Certificate{wild}})
	if got := servedFor(t, s, "app.example.com"); got.DNSNames[0] != "*.example.com" {
		t.Fatalf("app.example.com got %v", got.DNSNames)
	}
	for _, sni := range []string{"a.b.example.com", "example.com", "other.test", ""} {
		got := servedFor(t, s, sni)
		if got.Subject.CommonName != "aegis-edge" || len(got.DNSNames) != 0 {
			t.Fatalf("%q must get the placeholder, got CN=%q DNS=%v", sni, got.Subject.CommonName, got.DNSNames)
		}
	}
	// Same placeholder across pushes (stable for the life of the process).
	first := servedFor(t, s, "other.test").SerialNumber
	s.Apply(&aegisv1.ConfigUpdate{Version: 2, Certificates: []*aegisv1.Certificate{wild}})
	if servedFor(t, s, "other.test").SerialNumber.Cmp(first) != 0 {
		t.Fatal("placeholder must not change between pushes")
	}
}

func TestHostLookupWildcardIsOneLabel(t *testing.T) {
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
		Id: "w", DomainNames: []string{"*.Example.com"}, Enabled: true,
		UpstreamScheme: "http", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
	}}})
	st := s.cur.Load()
	if st.lookup("app.example.com") == nil {
		t.Fatal("one label under the wildcard must route")
	}
	if st.lookup("a.b.example.com") != nil || st.lookup("example.com") != nil {
		t.Fatal("multi-label and apex must not route to the wildcard host")
	}
}
