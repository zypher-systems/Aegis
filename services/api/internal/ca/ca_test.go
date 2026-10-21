package ca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

type memSettings struct {
	m   map[string][]byte
	err error
}

func (s *memSettings) get(key string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	v, ok := s.m[key]
	if !ok {
		return nil, errors.New("missing")
	}
	return v, nil
}

func (s *memSettings) set(key string, val []byte) error {
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[key] = append([]byte(nil), val...)
	return nil
}

func testCA(t *testing.T) *CA {
	t.Helper()
	s := &memSettings{m: map[string][]byte{}}
	c, err := LoadOrInit(s.get, s.set)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadOrInitPersistsAndReloads(t *testing.T) {
	s := &memSettings{m: map[string][]byte{}}
	a, err := LoadOrInit(s.get, s.set)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(a.CertPEM(), []byte("BEGIN CERTIFICATE")) {
		t.Fatal("cert pem")
	}
	b, err := LoadOrInit(s.get, s.set)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.CertPEM(), b.CertPEM()) {
		t.Fatal("reload mismatch")
	}
	if a.RootCert() == nil || a.CertPool() == nil {
		t.Fatal("accessors")
	}
}

func TestLoadOrInitKeyMissing(t *testing.T) {
	s := &memSettings{m: map[string][]byte{settingsKeyCAPEM: []byte("x")}}
	if _, err := LoadOrInit(s.get, s.set); err == nil {
		t.Fatal("expected missing key")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := parse([]byte("not pem"), []byte("not pem")); err == nil {
		t.Fatal("cert")
	}
	c := testCA(t)
	if _, err := parse(c.CertPEM(), []byte("-----BEGIN PRIVATE KEY-----\nQQ==\n-----END PRIVATE KEY-----")); err == nil {
		t.Fatal("key")
	}
}

func TestSignLeafVerifies(t *testing.T) {
	c := testCA(t)
	certPEM, keyPEM, exp, err := c.SignLeaf([]string{"demo.local", "www.demo.local"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Before(time.Now()) {
		t.Fatal("expiry")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{DNSName: "demo.local", Roots: c.CertPool()}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatal(err)
	}
}

func TestSignCSRIssueAndVerify(t *testing.T) {
	c := testCA(t)
	csrPEM, _ := mustCSR(t, "edge-1")
	certPEM, serial, exp, err := c.SignCSR(csrPEM, "node-uuid", "edge-1", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if serial == "" || exp.Before(time.Now()) {
		t.Fatalf("serial=%s exp=%s", serial, exp)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("cert pem")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "node-uuid" {
		t.Fatalf("cn=%s", leaf.Subject.CommonName)
	}
	opts := x509.VerifyOptions{Roots: c.CertPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatal(err)
	}
}

func TestSignCSRRejectsBadPEMAndSignature(t *testing.T) {
	c := testCA(t)
	if _, _, _, err := c.SignCSR([]byte("nope"), "id", "n", time.Hour); err == nil {
		t.Fatal("pem")
	}
	csrPEM, _ := mustCSR(t, "edge-1")
	block, _ := pem.Decode(csrPEM)
	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-1] ^= 0xff
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered})
	if _, _, _, err := c.SignCSR(badPEM, "id", "n", time.Hour); err == nil {
		t.Fatal("bad sig")
	}
}

func TestIssueServerCertAndTLSConfig(t *testing.T) {
	c := testCA(t)
	certPEM, keyPEM, err := c.IssueServerCert([]string{"aegis-api", "localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := c.ServerTLSConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("tls %+v", cfg)
	}
	if _, err := c.ServerTLSConfig([]byte("bad"), keyPEM); err == nil {
		t.Fatal("bad pair")
	}
}

func mustCSR(t *testing.T, name string) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: name, Organization: []string{"Aegis Node"}},
		DNSNames: []string{name},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), priv
}
