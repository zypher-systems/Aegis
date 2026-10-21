package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/api/internal/ca"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func TestTokenEqual(t *testing.T) {
	if !tokenEqual("secret-token", "secret-token") {
		t.Fatal("equal tokens")
	}
	if tokenEqual("secret-token", "secret-tokeN") {
		t.Fatal("case mismatch")
	}
	if tokenEqual("short", "longer-token") {
		t.Fatal("length mismatch")
	}
	if tokenEqual("", "x") {
		t.Fatal("empty got")
	}
	if tokenEqual("x", "") {
		t.Fatal("empty want must not match")
	}
	if tokenEqual("", "") {
		t.Fatal("empty want must not match empty got")
	}
}

func TestBumpNilRedisAllows(t *testing.T) {
	s := &Service{}
	if err := s.bump(context.Background(), "enroll:ip:1.2.3.4", enrollIPLimit); err != nil {
		t.Fatal(err)
	}
}

func TestErrEnrollLimited(t *testing.T) {
	if !errors.Is(errEnrollLimited, errEnrollLimited) {
		t.Fatal("identity")
	}
}

func TestTokenRedisKeyStable(t *testing.T) {
	a := tokenRedisKey("tok")
	b := tokenRedisKey("tok")
	c := tokenRedisKey("other")
	if a != b {
		t.Fatal("not stable")
	}
	if a == c {
		t.Fatal("collision")
	}
	if len(a) < len("enroll:token:")+16 {
		t.Fatalf("key too short: %s", a)
	}
}

func TestPeerIPUnknown(t *testing.T) {
	if got := peerIP(context.Background()); got != "unknown" {
		t.Fatalf("got %q", got)
	}
}

func TestPeerIPFromAddr(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 9444},
	})
	if got := peerIP(ctx); got != "203.0.113.9" {
		t.Fatalf("got %q", got)
	}
	ctx = peer.NewContext(context.Background(), &peer.Peer{Addr: addrString("unix")})
	if got := peerIP(ctx); got != "unix" {
		t.Fatalf("got %q", got)
	}
}

type addrString string

func (a addrString) Network() string { return string(a) }
func (a addrString) String() string  { return string(a) }

type memNodes struct {
	count     int
	countErr  error
	createErr error
	updateErr error
	last      *store.Node
}

func (m *memNodes) CountNodes(context.Context) (int, error) {
	return m.count, m.countErr
}

func (m *memNodes) CreateNode(_ context.Context, name, ver, serial string, _ time.Time) (*store.Node, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	n := &store.Node{ID: uuid.New(), Name: name, AgentVersion: ver, CertSerial: serial}
	m.last = n
	m.count++
	return n, nil
}

func (m *memNodes) UpdateNodeCert(context.Context, uuid.UUID, string, time.Time) error {
	return m.updateErr
}

func testCA(t *testing.T) *ca.CA {
	t.Helper()
	m := map[string][]byte{}
	get := func(k string) ([]byte, error) {
		v, ok := m[k]
		if !ok {
			return nil, errors.New("missing")
		}
		return v, nil
	}
	set := func(k string, v []byte) error {
		m[k] = append([]byte(nil), v...)
		return nil
	}
	c, err := ca.LoadOrInit(get, set)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustCSR(t *testing.T, name string) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: name},
		DNSNames: []string{name},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestEnrollHappyPath(t *testing.T) {
	nodes := &memNodes{}
	s := New(nodes, testCA(t), func(context.Context) (string, error) { return "enroll-token", nil }, time.Hour, nil)
	resp, err := s.Enroll(context.Background(), &aegisv1.EnrollRequest{
		Token:        "enroll-token",
		CsrPem:       mustCSR(t, "edge-1"),
		NodeName:     "edge-1",
		AgentVersion: "dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetNodeId() == "" || len(resp.GetCertificatePem()) == 0 || len(resp.GetCaCertificatePem()) == 0 {
		t.Fatalf("resp=%+v", resp)
	}
	if nodes.last == nil || nodes.last.Name != "edge-1" {
		t.Fatal("node not created")
	}
}

func TestEnrollDefaultNameAndRejects(t *testing.T) {
	tok := func(context.Context) (string, error) { return "tok", nil }
	s := New(&memNodes{}, testCA(t), tok, time.Hour, nil)
	if _, err := s.Enroll(context.Background(), &aegisv1.EnrollRequest{Token: "nope", CsrPem: []byte("x")}); err == nil {
		t.Fatal("bad token")
	} else if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code=%v", status.Code(err))
	}
	s = New(&memNodes{}, testCA(t), func(context.Context) (string, error) { return "", errors.New("tok") }, time.Hour, nil)
	if _, err := s.Enroll(context.Background(), &aegisv1.EnrollRequest{Token: "tok", CsrPem: []byte("x")}); err == nil {
		t.Fatal("token func")
	}
	s = New(&memNodes{}, testCA(t), tok, time.Hour, nil)
	if _, err := s.Enroll(context.Background(), &aegisv1.EnrollRequest{Token: "tok"}); err == nil {
		t.Fatal("csr required")
	} else if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code=%v", status.Code(err))
	}
	resp, err := s.Enroll(context.Background(), &aegisv1.EnrollRequest{Token: "tok", CsrPem: mustCSR(t, "n")})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetNodeId() == "" {
		t.Fatal("default name still mints")
	}
	s = New(&memNodes{}, testCA(t), tok, time.Hour, nil)
	if _, err := s.Enroll(context.Background(), &aegisv1.EnrollRequest{Token: "tok", CsrPem: []byte("-----BEGIN CERTIFICATE REQUEST-----\nQQ==\n-----END CERTIFICATE REQUEST-----")}); err == nil {
		t.Fatal("bad csr")
	}
	s = New(&memNodes{createErr: errors.New("db")}, testCA(t), tok, time.Hour, nil)
	if _, err := s.Enroll(context.Background(), &aegisv1.EnrollRequest{Token: "tok", CsrPem: mustCSR(t, "n")}); err == nil {
		t.Fatal("create")
	}
	s = New(&memNodes{updateErr: errors.New("db")}, testCA(t), tok, time.Hour, nil)
	if _, err := s.Enroll(context.Background(), &aegisv1.EnrollRequest{Token: "tok", CsrPem: mustCSR(t, "n")}); err == nil {
		t.Fatal("update")
	}
}

type memTokens struct{ live map[string]int }

func (m *memTokens) ConsumeEnrollToken(_ context.Context, hash string) (bool, error) {
	if m.live[hash] > 0 {
		m.live[hash]--
		return true, nil
	}
	return false, nil
}

func TestBootstrapTokenOnlyEnrolsTheFirstNode(t *testing.T) {
	nodes := &memNodes{}
	svc := New(nodes, testCA(t), func(context.Context) (string, error) { return "boot", nil }, time.Hour, nil)
	svc.Tokens = &memTokens{live: map[string]int{}}
	if !svc.tokenAccepted(context.Background(), "boot") {
		t.Fatal("bootstrap token must work while no node exists")
	}
	nodes.count = 1
	if svc.tokenAccepted(context.Background(), "boot") {
		t.Fatal("bootstrap token must stop working once a node is enrolled")
	}
	// A generated token works once, from any state.
	svc.Tokens = &memTokens{live: map[string]int{TokenHash("gen-1"): 1}}
	if !svc.tokenAccepted(context.Background(), "gen-1") {
		t.Fatal("generated token refused")
	}
	if svc.tokenAccepted(context.Background(), "gen-1") {
		t.Fatal("single-use token accepted twice")
	}
	if svc.tokenAccepted(context.Background(), "") {
		t.Fatal("empty token")
	}
}
