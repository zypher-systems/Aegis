package configsvc

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

// CertSigner issues node client certificates (the internal CA).
type CertSigner interface {
	SignCSR(csrPEM []byte, nodeID, nodeName string, ttl time.Duration) (certPEM []byte, serial string, expires time.Time, err error)
	CertPEM() []byte
}

// nodeStore is what renewal needs from the store; *store.Store satisfies it.
type nodeStore interface {
	NodeIDRevoked(id uuid.UUID) bool
	GetNode(ctx context.Context, id uuid.UUID) (*store.Node, error)
	UpdateNodeCert(ctx context.Context, id uuid.UUID, serial string, expiresAt time.Time) error
	SetNodeAgentVersion(ctx context.Context, id uuid.UUID, version string) error
	ListNodes(ctx context.Context) ([]*store.Node, error)
	UpsertNotice(ctx context.Context, n store.Notice, seal func([]byte) (string, error), open func(string) ([]byte, error)) error
	ClearNotice(ctx context.Context, kind, resourceID string, seal func([]byte) (string, error), open func(string) ([]byte, error)) error
}

type sealer interface {
	Seal([]byte) (string, error)
	Open(string) ([]byte, error)
}

// Node certificates that expire within this long raise an operator notice,
// since a node that has not renewed by then is not going to on its own.
const nodeCertWarnWithin = 14 * 24 * time.Hour

const noticeKindNodeCert = "node_cert"

// EnableRenewal lets nodes renew their client certificate over the mTLS
// stream (the Renew RPC) with certificates of the given lifetime.
func (s *Service) EnableRenewal(signer CertSigner, ttl time.Duration) {
	s.signer = signer
	s.nodeCertTTL = ttl
	if s.store != nil && s.nodes == nil {
		s.nodes = s.store
	}
	if s.env != nil && s.sealer == nil {
		s.sealer = s.env
	}
}

// Renew re-issues the calling node's certificate. The caller is identified by
// the client certificate on the connection, never by a field in the request.
func (s *Service) Renew(ctx context.Context, req *aegisv1.RenewRequest) (*aegisv1.RenewResponse, error) {
	if s.signer == nil || s.nodes == nil {
		return nil, status.Error(codes.Unimplemented, "renewal is not enabled")
	}
	nodeID := nodeIDFromPeer(ctx)
	if nodeID == uuid.Nil {
		return nil, status.Error(codes.Unauthenticated, "no node identity on this connection")
	}
	if s.nodes.NodeIDRevoked(nodeID) {
		return nil, status.Error(codes.Unauthenticated, "node revoked")
	}
	if len(req.GetCsrPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr_pem is required")
	}
	node, err := s.nodes.GetNode(ctx, nodeID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "unknown node")
	}
	certPEM, serial, expires, err := s.signer.SignCSR(req.GetCsrPem(), nodeID.String(), node.Name, s.nodeCertTTL)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign csr: %v", err)
	}
	if err := s.nodes.UpdateNodeCert(ctx, nodeID, serial, expires); err != nil {
		return nil, status.Error(codes.Internal, "record cert")
	}
	if v := req.GetAgentVersion(); v != "" {
		_ = s.nodes.SetNodeAgentVersion(ctx, nodeID, v)
	}
	log.Printf("configsvc: node %s (%s) renewed its certificate, expires %s", node.Name, nodeID, expires.Format(time.RFC3339))
	s.clearNotice(ctx, noticeKindNodeCert, nodeID.String())
	return &aegisv1.RenewResponse{
		CertificatePem:   certPEM,
		CaCertificatePem: s.signer.CertPEM(),
		ExpiresAtUnix:    expires.Unix(),
	}, nil
}

// raiseNotice and clearNotice go through the notifier when one is set
// (webhooks), else straight to the store.
func (s *Service) raiseNotice(ctx context.Context, n store.Notice) {
	if s.notifier != nil {
		s.notifier.Raise(ctx, n)
		return
	}
	if s.nodes != nil && s.sealer != nil {
		_ = s.nodes.UpsertNotice(ctx, n, s.sealer.Seal, s.sealer.Open)
	}
}

func (s *Service) clearNotice(ctx context.Context, kind, id string) {
	if s.notifier != nil {
		s.notifier.Clear(ctx, kind, id)
		return
	}
	if s.nodes != nil && s.sealer != nil {
		_ = s.nodes.ClearNotice(ctx, kind, id, s.sealer.Seal, s.sealer.Open)
	}
}

const (
	noticeKindNodeOffline = "node_offline"
	noticeKindNodeProblem = "node_problem"
	// A node checks in every 20 s on its config stream; this long without
	// one means it is down or cut off.
	nodeOfflineAfter = 2 * time.Minute
)

// CheckNodeHealth raises notices for nodes that have gone quiet and clears
// them when they check in again. Nodes that never checked in are skipped
// (they are still enrolling).
func (s *Service) CheckNodeHealth(ctx context.Context, now time.Time) {
	if s.nodes == nil {
		return
	}
	nodes, err := s.nodes.ListNodes(ctx)
	if err != nil {
		return
	}
	for _, n := range nodes {
		if n.RevokedAt != nil || n.LastSeenAt == nil {
			continue
		}
		since := now.Sub(*n.LastSeenAt)
		if since < nodeOfflineAfter {
			s.clearNotice(ctx, noticeKindNodeOffline, n.ID.String())
			continue
		}
		s.raiseNotice(ctx, store.Notice{
			Kind: noticeKindNodeOffline, ResourceID: n.ID.String(),
			Title:  fmt.Sprintf("Node %s is offline", n.Name),
			Detail: fmt.Sprintf("Last seen %s (%s ago). It keeps serving its last config while unreachable.", n.LastSeenAt.UTC().Format(time.RFC3339), since.Truncate(time.Minute)),
			At:     now.UTC().Format(time.RFC3339),
		})
	}
}

// Report receives a node's current problem list and turns the difference
// from the last report into raised and resolved notices.
func (s *Service) Report(ctx context.Context, req *aegisv1.NodeReport) (*aegisv1.ReportAck, error) {
	nodeID := nodeIDFromPeer(ctx)
	if nodeID == uuid.Nil {
		return nil, status.Error(codes.Unauthenticated, "no node identity on this connection")
	}
	name := nodeID.String()[:8]
	if s.nodes != nil {
		if s.nodes.NodeIDRevoked(nodeID) {
			return nil, status.Error(codes.Unauthenticated, "node revoked")
		}
		if n, err := s.nodes.GetNode(ctx, nodeID); err == nil {
			name = n.Name
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	next := map[string]*aegisv1.NodeProblem{}
	for _, p := range req.GetProblems() {
		if p.GetKind() == "" {
			continue
		}
		next[p.GetKind()+"|"+p.GetResource()] = p
	}
	s.problemsMu.Lock()
	if s.problems == nil {
		s.problems = map[uuid.UUID]map[string]*aegisv1.NodeProblem{}
	}
	prev := s.problems[nodeID]
	s.problems[nodeID] = next
	s.problemsMu.Unlock()

	for key, p := range next {
		s.raiseNotice(ctx, store.Notice{
			Kind: noticeKindNodeProblem, ResourceID: nodeID.String() + "|" + key,
			Title: problemTitle(name, p), Detail: p.GetDetail(), At: now,
		})
	}
	for key := range prev {
		if _, still := next[key]; !still {
			s.clearNotice(ctx, noticeKindNodeProblem, nodeID.String()+"|"+key)
		}
	}
	return &aegisv1.ReportAck{}, nil
}

func problemTitle(node string, p *aegisv1.NodeProblem) string {
	switch p.GetKind() {
	case "waf_compile":
		return fmt.Sprintf("WAF is not running as configured on %s (node %s)", p.GetResource(), node)
	case "crowdsec_stream":
		return fmt.Sprintf("Node %s cannot reach CrowdSec", node)
	case "geoip_missing":
		return fmt.Sprintf("Node %s has no GeoIP database; country rules block everyone", node)
	case "upstream_down":
		return fmt.Sprintf("Upstream down for %s (node %s)", p.GetResource(), node)
	default:
		if p.GetResource() != "" {
			return fmt.Sprintf("Node %s: %s on %s", node, p.GetKind(), p.GetResource())
		}
		return fmt.Sprintf("Node %s: %s", node, p.GetKind())
	}
}

// CheckNodeCerts raises a notice for every active node whose certificate is
// about to expire or has expired, and clears it once renewed. Nodes renew
// themselves from 30 days out, so a notice means the node is not talking to
// the control plane.
func (s *Service) CheckNodeCerts(ctx context.Context, now time.Time) {
	if s.nodes == nil {
		return
	}
	nodes, err := s.nodes.ListNodes(ctx)
	if err != nil {
		return
	}
	for _, n := range nodes {
		if n.RevokedAt != nil {
			continue
		}
		left := n.CertExpiresAt.Sub(now)
		if left > nodeCertWarnWithin {
			s.clearNotice(ctx, noticeKindNodeCert, n.ID.String())
			continue
		}
		var title, detail string
		if left <= 0 {
			title = fmt.Sprintf("Node %s can no longer reach the control plane", n.Name)
			detail = fmt.Sprintf("Its certificate expired %s. It keeps serving its last config but receives no updates. "+
				"Generate an enrolment token in Settings → Edge and restart it with AEGIS_ENROLL_TOKEN set to that token (its stored config is kept).", n.CertExpiresAt.Format("2006-01-02"))
		} else {
			days := int(left.Hours() / 24)
			title = fmt.Sprintf("Node %s has not renewed its certificate", n.Name)
			detail = fmt.Sprintf("It expires in %d day%s (%s). Nodes renew from 30 days out; this one is offline, "+
				"older than 1.7.2, or cannot reach the control plane.", days, plural(days), n.CertExpiresAt.Format("2006-01-02"))
		}
		s.raiseNotice(ctx, store.Notice{
			Kind: noticeKindNodeCert, ResourceID: n.ID.String(), Title: title, Detail: detail,
			At: now.UTC().Format(time.RFC3339),
		})
	}
}

// NodeHealthLoop checks node liveness every minute and certificate expiry
// hourly until ctx ends.
func (s *Service) NodeHealthLoop(ctx context.Context) {
	s.CheckNodeCerts(ctx, time.Now())
	minute := time.NewTicker(time.Minute)
	hour := time.NewTicker(time.Hour)
	defer minute.Stop()
	defer hour.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-minute.C:
			s.CheckNodeHealth(ctx, time.Now())
		case <-hour.C:
			s.CheckNodeCerts(ctx, time.Now())
		}
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
