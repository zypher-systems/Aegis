package configsvc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/api/internal/ca"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

type memNodes struct {
	nodes   map[uuid.UUID]*store.Node
	revoked map[uuid.UUID]bool
	notices map[string]store.Notice // kind|id
	updates int
}

func newMemNodes() *memNodes {
	return &memNodes{nodes: map[uuid.UUID]*store.Node{}, revoked: map[uuid.UUID]bool{}, notices: map[string]store.Notice{}}
}
func (m *memNodes) NodeIDRevoked(id uuid.UUID) bool { return m.revoked[id] }
func (m *memNodes) GetNode(_ context.Context, id uuid.UUID) (*store.Node, error) {
	n, ok := m.nodes[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return n, nil
}
func (m *memNodes) UpdateNodeCert(_ context.Context, id uuid.UUID, serial string, exp time.Time) error {
	m.nodes[id].CertSerial, m.nodes[id].CertExpiresAt = serial, exp
	m.updates++
	return nil
}
func (m *memNodes) SetNodeAgentVersion(_ context.Context, id uuid.UUID, v string) error {
	m.nodes[id].AgentVersion = v
	return nil
}
func (m *memNodes) ListNodes(context.Context) ([]*store.Node, error) {
	out := []*store.Node{}
	for _, n := range m.nodes {
		out = append(out, n)
	}
	return out, nil
}
func (m *memNodes) UpsertNotice(_ context.Context, n store.Notice, _ func([]byte) (string, error), _ func(string) ([]byte, error)) error {
	m.notices[n.Kind+"|"+n.ResourceID] = n
	return nil
}
func (m *memNodes) ClearNotice(_ context.Context, kind, id string, _ func([]byte) (string, error), _ func(string) ([]byte, error)) error {
	delete(m.notices, kind+"|"+id)
	return nil
}

type plainSealer struct{}

func (plainSealer) Seal(b []byte) (string, error) { return string(b), nil }
func (plainSealer) Open(s string) ([]byte, error) { return []byte(s), nil }

func testCA(t *testing.T) *ca.CA {
	t.Helper()
	m := map[string][]byte{}
	c, err := ca.LoadOrInit(
		func(k string) ([]byte, error) {
			v, ok := m[k]
			if !ok {
				return nil, errors.New("missing")
			}
			return v, nil
		},
		func(k string, v []byte) error { m[k] = append([]byte(nil), v...); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// peerCtx is a context as gRPC builds it for an mTLS caller whose client
// certificate has the node id as its CN.
func peerCtx(t *testing.T, c *ca.CA, nodeID uuid.UUID) (context.Context, ed25519.PrivateKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	csr := csrPEM(t, priv, "edge-1")
	certPEM, _, _, err := c.SignCSR(csr, nodeID.String(), "edge-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ti := credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, c.RootCert()}}}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: ti}), priv
}

func csrPEM(t *testing.T, priv ed25519.PrivateKey, name string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func renewService(t *testing.T) (*Service, *memNodes, *ca.CA) {
	t.Helper()
	c := testCA(t)
	s := New(nil, nil, nil)
	m := newMemNodes()
	s.nodes, s.sealer = m, plainSealer{}
	s.EnableRenewal(c, 90*24*time.Hour)
	return s, m, c
}

func TestRenewIssuesForTheCallingNodeOnly(t *testing.T) {
	s, m, c := renewService(t)
	nodeID := uuid.New()
	m.nodes[nodeID] = &store.Node{ID: nodeID, Name: "edge-1", CertExpiresAt: time.Now().Add(5 * 24 * time.Hour)}
	m.notices["node_cert|"+nodeID.String()] = store.Notice{Kind: "node_cert", ResourceID: nodeID.String()}
	ctx, priv := peerCtx(t, c, nodeID)

	// The CSR names a different node: the certificate is still issued for
	// the caller, because identity comes from the connection.
	resp, err := s.Renew(ctx, &aegisv1.RenewRequest{CsrPem: csrPEM(t, priv, "someone-else"), AgentVersion: "1.7.2"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(resp.GetCertificatePem())
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != nodeID.String() || leaf.DNSNames[0] != "edge-1" {
		t.Fatalf("issued for CN=%q DNS=%v", leaf.Subject.CommonName, leaf.DNSNames)
	}
	if time.Until(leaf.NotAfter) < 89*24*time.Hour || resp.GetExpiresAtUnix() != leaf.NotAfter.Unix() {
		t.Fatalf("lifetime %s", time.Until(leaf.NotAfter))
	}
	if m.updates != 1 || m.nodes[nodeID].AgentVersion != "1.7.2" {
		t.Fatalf("node row not updated: %+v", m.nodes[nodeID])
	}
	if _, still := m.notices["node_cert|"+nodeID.String()]; still {
		t.Fatal("renewal must clear the expiry notice")
	}
	if string(resp.GetCaCertificatePem()) != string(c.CertPEM()) {
		t.Fatal("response must carry the CA")
	}
}

func TestRenewRefusesUnknownRevokedAndAnonymous(t *testing.T) {
	s, m, c := renewService(t)
	known := uuid.New()
	m.nodes[known] = &store.Node{ID: known, Name: "edge-1"}
	_, priv := peerCtx(t, c, known)
	csr := csrPEM(t, priv, "edge-1")

	cases := []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"no peer", context.Background(), codes.Unauthenticated},
		{"unknown node", func() context.Context { c2, _ := peerCtx(t, c, uuid.New()); return c2 }(), codes.NotFound},
	}
	m.revoked[known] = true
	ctxKnown, _ := peerCtx(t, c, known)
	cases = append(cases, struct {
		name string
		ctx  context.Context
		want codes.Code
	}{"revoked", ctxKnown, codes.Unauthenticated})
	for _, tc := range cases {
		_, err := s.Renew(tc.ctx, &aegisv1.RenewRequest{CsrPem: csr})
		if status.Code(err) != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := s.Renew(ctxKnown, &aegisv1.RenewRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("empty csr on revoked: %v", err)
	}
	// Not enabled at all.
	off := New(nil, nil, nil)
	if _, err := off.Renew(ctxKnown, &aegisv1.RenewRequest{CsrPem: csr}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("disabled: %v", err)
	}
}

func TestCheckNodeCertsRaisesAndClearsNotices(t *testing.T) {
	s, m, _ := renewService(t)
	now := time.Now()
	fine := uuid.New()
	soon := uuid.New()
	dead := uuid.New()
	gone := uuid.New()
	revokedAt := now
	m.nodes[fine] = &store.Node{ID: fine, Name: "fine", CertExpiresAt: now.Add(60 * 24 * time.Hour)}
	m.nodes[soon] = &store.Node{ID: soon, Name: "soon", CertExpiresAt: now.Add(3 * 24 * time.Hour)}
	m.nodes[dead] = &store.Node{ID: dead, Name: "dead", CertExpiresAt: now.Add(-time.Hour)}
	m.nodes[gone] = &store.Node{ID: gone, Name: "gone", CertExpiresAt: now.Add(-time.Hour), RevokedAt: &revokedAt}
	m.notices["node_cert|"+fine.String()] = store.Notice{} // stale, from before a renewal

	s.CheckNodeCerts(context.Background(), now)

	if _, ok := m.notices["node_cert|"+fine.String()]; ok {
		t.Fatal("a healthy node's stale notice must be cleared")
	}
	if n, ok := m.notices["node_cert|"+soon.String()]; !ok || n.Title != "Node soon has not renewed its certificate" {
		t.Fatalf("soon: %+v", n)
	}
	if n, ok := m.notices["node_cert|"+dead.String()]; !ok || n.Title != "Node dead can no longer reach the control plane" {
		t.Fatalf("dead: %+v", n)
	}
	if _, ok := m.notices["node_cert|"+gone.String()]; ok {
		t.Fatal("revoked nodes get no notice")
	}
}

type memNotifier struct {
	raised  []store.Notice
	cleared []string
}

func (m *memNotifier) Raise(_ context.Context, n store.Notice) { m.raised = append(m.raised, n) }
func (m *memNotifier) Clear(_ context.Context, kind, id string) {
	m.cleared = append(m.cleared, kind+"|"+id)
}

func TestReportDiffsProblemsIntoRaisesAndClears(t *testing.T) {
	s, m, c := renewService(t)
	n := &memNotifier{}
	s.SetNotifier(n)
	nodeID := uuid.New()
	m.nodes[nodeID] = &store.Node{ID: nodeID, Name: "edge-1"}
	ctx, _ := peerCtx(t, c, nodeID)

	_, err := s.Report(ctx, &aegisv1.NodeReport{Problems: []*aegisv1.NodeProblem{
		{Kind: "waf_compile", Resource: "app.example.com", Detail: "bad exclusion"},
		{Kind: "crowdsec_stream", Detail: "connection refused"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(n.raised) != 2 || len(n.cleared) != 0 {
		t.Fatalf("first report: raised %d cleared %d", len(n.raised), len(n.cleared))
	}
	if n.raised[0].Kind != "node_problem" || !strings.Contains(n.raised[0].Title, "edge-1") {
		t.Fatalf("notice: %+v", n.raised[0])
	}
	// CrowdSec recovers: its notice clears, the WAF one is re-raised (the
	// notifier de-duplicates identical wording).
	if _, err := s.Report(ctx, &aegisv1.NodeReport{Problems: []*aegisv1.NodeProblem{
		{Kind: "waf_compile", Resource: "app.example.com", Detail: "bad exclusion"},
	}}); err != nil {
		t.Fatal(err)
	}
	if len(n.cleared) != 1 || n.cleared[0] != "node_problem|"+nodeID.String()+"|crowdsec_stream|" {
		t.Fatalf("cleared: %v", n.cleared)
	}
	// Everything fine: the last one clears too.
	if _, err := s.Report(ctx, &aegisv1.NodeReport{}); err != nil {
		t.Fatal(err)
	}
	if len(n.cleared) != 2 {
		t.Fatalf("cleared: %v", n.cleared)
	}
	if _, err := s.Report(context.Background(), &aegisv1.NodeReport{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous report: %v", err)
	}
}

func TestCheckNodeHealthRaisesOfflineAndClearsOnReturn(t *testing.T) {
	s, m, _ := renewService(t)
	n := &memNotifier{}
	s.SetNotifier(n)
	now := time.Now()
	recent, stale := now.Add(-30*time.Second), now.Add(-10*time.Minute)
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	m.nodes[a] = &store.Node{ID: a, Name: "fresh", LastSeenAt: &recent, CertExpiresAt: now.Add(60 * 24 * time.Hour)}
	m.nodes[b] = &store.Node{ID: b, Name: "gone", LastSeenAt: &stale, CertExpiresAt: now.Add(60 * 24 * time.Hour)}
	m.nodes[c] = &store.Node{ID: c, Name: "never", CertExpiresAt: now.Add(60 * 24 * time.Hour)}
	s.CheckNodeHealth(context.Background(), now)
	if len(n.raised) != 1 || n.raised[0].ResourceID != b.String() || n.raised[0].Title != "Node gone is offline" {
		t.Fatalf("raised: %+v", n.raised)
	}
	if len(n.cleared) != 1 || n.cleared[0] != "node_offline|"+a.String() {
		t.Fatalf("cleared: %v", n.cleared)
	}
}
