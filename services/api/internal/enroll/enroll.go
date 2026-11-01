// Package enroll implements the EnrollmentService: turns a one-time token +
// CSR into an mTLS client identity for a data-plane node.
package enroll

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/api/internal/ca"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

const (
	enrollIPLimit    = 10
	enrollTokenLimit = 5
	enrollWindow     = 10 * time.Minute
)

var errEnrollLimited = errors.New("enrollment rate limited")

// TokenFunc returns the bootstrap token (a legacy rotated value in settings,
// else the env token). It only enrols the first node; after that only
// generated tokens (TokenStore) are accepted.
type TokenFunc func(ctx context.Context) (string, error)

// TokenStore spends generated enrolment tokens; *store.Store implements it.
type TokenStore interface {
	ConsumeEnrollToken(ctx context.Context, hash string) (bool, error)
}

// TokenHash is how generated tokens are stored and looked up.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NodeStore is the enrollment persistence the service needs. *store.Store implements it.
type NodeStore interface {
	CountNodes(ctx context.Context) (int, error)
	CreateNode(ctx context.Context, name, agentVersion, certSerial string, certExpiresAt time.Time) (*store.Node, error)
	UpdateNodeCert(ctx context.Context, id uuid.UUID, serial string, expiresAt time.Time) error
}

type Service struct {
	aegisv1.UnimplementedEnrollmentServiceServer
	store       NodeStore
	ca          *ca.CA
	token       TokenFunc
	nodeCertTTL time.Duration
	rdb         *redis.Client
	// OnEnrolled runs after a node is issued its certificate (audit, alert).
	OnEnrolled func(ctx context.Context, id uuid.UUID, name, ip, version string)
	// Tokens holds generated single-use tokens; nil means bootstrap only.
	Tokens TokenStore
}

func New(st NodeStore, c *ca.CA, token TokenFunc, nodeCertTTL time.Duration, rdb *redis.Client) *Service {
	return &Service{store: st, ca: c, token: token, nodeCertTTL: nodeCertTTL, rdb: rdb}
}

func tokenEqual(got, want string) bool {
	if want == "" {
		return false
	}
	g := sha256.Sum256([]byte(got))
	w := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}

func tokenRedisKey(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return "enroll:token:" + hex.EncodeToString(sum[:])
}

func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func (s *Service) bump(ctx context.Context, key string, limit int) error {
	if s.rdb == nil {
		return nil
	}
	n, err := s.rdb.Incr(ctx, key).Result()
	if err != nil {
		return err
	}
	if n == 1 {
		s.rdb.Expire(ctx, key, enrollWindow)
	}
	if n > int64(limit) {
		return errEnrollLimited
	}
	return nil
}

func (s *Service) Enroll(ctx context.Context, req *aegisv1.EnrollRequest) (*aegisv1.EnrollResponse, error) {
	if err := s.bump(ctx, "enroll:ip:"+peerIP(ctx), enrollIPLimit); err != nil {
		if errors.Is(err, errEnrollLimited) {
			return nil, status.Error(codes.ResourceExhausted, "too many enrollment attempts")
		}
		return nil, status.Error(codes.Unavailable, "enrollment temporarily unavailable")
	}

	if !s.tokenAccepted(ctx, req.GetToken()) {
		return nil, status.Error(codes.Unauthenticated, "invalid enrollment token")
	}
	if len(req.GetCsrPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr_pem is required")
	}
	name := req.GetNodeName()
	if name == "" {
		name = "node"
	}

	if err := s.bump(ctx, tokenRedisKey(req.GetToken()), enrollTokenLimit); err != nil {
		if errors.Is(err, errEnrollLimited) {
			return nil, status.Error(codes.ResourceExhausted, "too many enrollments")
		}
		return nil, status.Error(codes.Unavailable, "enrollment temporarily unavailable")
	}

	node, err := s.store.CreateNode(ctx, name, req.GetAgentVersion(), "", time.Now())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create node: %v", err)
	}

	certPEM, serial, expires, err := s.ca.SignCSR(req.GetCsrPem(), node.ID.String(), name, s.nodeCertTTL)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign csr: %v", err)
	}

	if err := s.store.UpdateNodeCert(ctx, node.ID, serial, expires); err != nil {
		return nil, status.Errorf(codes.Internal, "record cert: %v", err)
	}
	log.Printf("enroll: node %s (%s) enrolled from %s, agent %s", name, node.ID, peerIP(ctx), req.GetAgentVersion())
	if s.OnEnrolled != nil {
		s.OnEnrolled(ctx, node.ID, name, peerIP(ctx), req.GetAgentVersion())
	}

	return &aegisv1.EnrollResponse{
		NodeId:           node.ID.String(),
		CertificatePem:   certPEM,
		CaCertificatePem: s.ca.CertPEM(),
	}, nil
}

// tokenAccepted: a generated token that is live and unspent, or, while no
// node is enrolled yet, the bootstrap token. Once one node exists the
// bootstrap value in .env stops working, so a leaked .env cannot enrol a
// rogue node that would receive every certificate key.
func (s *Service) tokenAccepted(ctx context.Context, token string) bool {
	if token == "" {
		return false
	}
	if s.Tokens != nil {
		if ok, err := s.Tokens.ConsumeEnrollToken(ctx, TokenHash(token)); err == nil && ok {
			return true
		}
	}
	n, err := s.store.CountNodes(ctx)
	if err != nil || n > 0 {
		return false
	}
	want, err := s.token(ctx)
	return err == nil && tokenEqual(token, want)
}
