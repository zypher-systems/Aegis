package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

type testRoot struct {
	cert    *x509.Certificate
	key     ed25519.PrivateKey
	certPEM []byte
}

func newTestRoot(t *testing.T) *testRoot {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testRoot{
		cert:    cert,
		key:     priv,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (r *testRoot) signCSR(t *testing.T, csrPEM []byte, cn string) []byte {
	return r.signCSRFor(t, csrPEM, cn, time.Hour)
}

func (r *testRoot) signCSRFor(t *testing.T, csrPEM []byte, cn string, ttl time.Duration) []byte {
	t.Helper()
	b, _ := pem.Decode(csrPEM)
	if b == nil {
		t.Fatal("csr pem")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, r.cert, csr.PublicKey, r.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (r *testRoot) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "enroll"},
		DNSNames:     []string{"localhost", "aegis-api"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, r.cert, pub, r.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

type enrollHandler struct {
	aegisv1.UnimplementedEnrollmentServiceServer
	root  *testRoot
	token string
}

func (h *enrollHandler) Enroll(_ context.Context, req *aegisv1.EnrollRequest) (*aegisv1.EnrollResponse, error) {
	if req.GetToken() != h.token {
		return nil, status.Error(codes.Unauthenticated, "invalid enrollment token")
	}
	b, _ := pem.Decode(req.GetCsrPem())
	if b == nil {
		return nil, status.Error(codes.InvalidArgument, "csr")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "node-1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, h.root.cert, csr.PublicKey, h.root.key)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &aegisv1.EnrollResponse{
		NodeId:           "node-1",
		CertificatePem:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CaCertificatePem: h.root.certPEM,
	}, nil
}

func startEnroll(t *testing.T, token string) (addr string, stop func()) {
	t.Helper()
	root := newTestRoot(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{root.serverCert(t)},
		MinVersion:   tls.VersionTLS13,
	})))
	aegisv1.RegisterEnrollmentServiceServer(gs, &enrollHandler{root: root, token: token})
	go gs.Serve(lis)
	return lis.Addr().String(), func() {
		gs.Stop()
		_ = lis.Close()
	}
}

func TestLoadOrEnrollEmptyToken(t *testing.T) {
	_, err := LoadOrEnroll(context.Background(), t.TempDir(), "127.0.0.1:1", "", "edge", "dev")
	if err == nil {
		t.Fatal("expected empty token")
	}
}

func TestLoadRejectsInvalidCA(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(keyFile, "-----BEGIN PRIVATE KEY-----\nQQ==\n-----END PRIVATE KEY-----\n")
	write(certFile, "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n")
	write(caFile, "not-a-ca")
	write(idFile, "node-1")
	if _, err := load(dir); err == nil {
		t.Fatal("invalid ca")
	}
}

func TestLoadOrEnrollRoundTrip(t *testing.T) {
	addr, stop := startEnroll(t, "enroll-token")
	defer stop()
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := LoadOrEnroll(ctx, dir, addr, "enroll-token", "edge-1", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if id.NodeID != "node-1" || len(id.KeyPEM) == 0 || len(id.Cert().Certificate) == 0 {
		t.Fatalf("id=%q", id.NodeID)
	}
	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key perm %o", info.Mode().Perm())
	}
	again, err := LoadOrEnroll(ctx, dir, "127.0.0.1:1", "", "edge-1", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if again.NodeID != id.NodeID {
		t.Fatal("reload should not re-enroll")
	}
}

func TestLoadOrEnrollRejectsBadToken(t *testing.T) {
	addr, stop := startEnroll(t, "enroll-token")
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := LoadOrEnroll(ctx, t.TempDir(), addr, "wrong", "edge-1", "dev"); err == nil {
		t.Fatal("bad token")
	}
}

// renewHandler is the node-plane ConfigService: mTLS, signs Renew CSRs.
type renewHandler struct {
	aegisv1.UnimplementedConfigServiceServer
	t    *testing.T
	root *testRoot
	ttl  time.Duration
	seen chan string // CN of the client cert on each Renew
}

func (h *renewHandler) Renew(ctx context.Context, req *aegisv1.RenewRequest) (*aegisv1.RenewResponse, error) {
	p, _ := peer.FromContext(ctx)
	ti := p.AuthInfo.(credentials.TLSInfo)
	h.seen <- ti.State.VerifiedChains[0][0].Subject.CommonName
	certPEM := h.root.signCSRFor(h.t, req.GetCsrPem(), "node-1", h.ttl)
	return &aegisv1.RenewResponse{CertificatePem: certPEM, CaCertificatePem: h.root.certPEM}, nil
}

func startNodePlane(t *testing.T, root *testRoot, h *renewHandler) (addr string, stop func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{root.serverCert(t)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	})))
	aegisv1.RegisterConfigServiceServer(gs, h)
	go gs.Serve(lis)
	return lis.Addr().String(), func() { gs.Stop(); _ = lis.Close() }
}

// writeIdentity persists an identity signed by root with the given lifetime.
func writeIdentity(t *testing.T, dir string, root *testRoot, ttl time.Duration) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := csrFor(priv, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	files := map[string][]byte{
		keyFile:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		certFile: root.signCSRFor(t, csr, "node-1", ttl),
		caFile:   root.certPEM,
		idFile:   []byte("node-1"),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRenewKeepsKeyPersistsAndNewDialsUseNewCert(t *testing.T) {
	root := newTestRoot(t)
	dir := t.TempDir()
	writeIdentity(t, dir, root, 10*24*time.Hour) // inside the 30-day window
	id, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !id.RenewDue(time.Now()) || id.Expired(time.Now()) {
		t.Fatal("a 10-day cert is due for renewal and not expired")
	}
	h := &renewHandler{t: t, root: root, ttl: 90 * 24 * time.Hour, seen: make(chan string, 4)}
	addr, stop := startNodePlane(t, root, h)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	before := id.Cert().Certificate[0]
	keyBefore := append([]byte(nil), id.KeyPEM...)
	if err := id.Renew(ctx, addr, "dev"); err != nil {
		t.Fatal(err)
	}
	if string(id.KeyPEM) != string(keyBefore) {
		t.Fatal("renewal must keep the node key (the snapshot key derives from it)")
	}
	if string(id.Cert().Certificate[0]) == string(before) {
		t.Fatal("certificate did not change")
	}
	if id.RenewDue(time.Now()) {
		t.Fatalf("renewed cert expires %s, still due", id.ExpiresAt())
	}
	// Persisted: a fresh load sees the new cert.
	again, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Cert().Certificate[0]) != string(id.Cert().Certificate[0]) {
		t.Fatal("renewed cert was not written to disk")
	}
	// The next dial (a second Renew) authenticates with the new cert.
	if err := id.Renew(ctx, addr, "dev"); err != nil {
		t.Fatal(err)
	}
	<-h.seen
	if cn := <-h.seen; cn != "node-1" {
		t.Fatalf("second dial presented %q", cn)
	}
}

func TestLoadOrEnrollReenrollsWhenExpired(t *testing.T) {
	root := newTestRoot(t)
	dir := t.TempDir()
	writeIdentity(t, dir, root, -time.Hour) // already expired
	// No token: keep the identity so the last config still serves.
	id, err := LoadOrEnroll(context.Background(), dir, "127.0.0.1:1", "", "edge", "dev")
	if err != nil || !id.Expired(time.Now()) {
		t.Fatalf("expired identity without a token must load as-is: %v", err)
	}
	// With a token: re-enrol.
	addr, stop := startEnroll(t, "enroll-token")
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fresh, err := LoadOrEnroll(ctx, dir, addr, "enroll-token", "edge", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Expired(time.Now()) {
		t.Fatal("re-enrolment must yield a valid certificate")
	}
}
