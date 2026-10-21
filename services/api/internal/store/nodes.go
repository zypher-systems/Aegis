package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Node struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	AgentVersion  string     `json:"agent_version"`
	CertSerial    string     `json:"-"`
	CertExpiresAt time.Time  `json:"cert_expires_at"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

const nodeCols = `id, name, agent_version, cert_serial, cert_expires_at, last_seen_at, revoked_at, created_at`

func (s *Store) CreateNode(ctx context.Context, name, agentVersion, certSerial string, certExpiresAt time.Time) (*Node, error) {
	n := &Node{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO nodes (id, name, agent_version, cert_serial, cert_expires_at)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING `+nodeCols,
		uuid.New(), name, agentVersion, certSerial, certExpiresAt).
		Scan(&n.ID, &n.Name, &n.AgentVersion, &n.CertSerial, &n.CertExpiresAt, &n.LastSeenAt, &n.RevokedAt, &n.CreatedAt)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func (s *Store) TouchNode(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, "UPDATE nodes SET last_seen_at=now() WHERE id=$1 AND revoked_at IS NULL", id)
	return err
}

// SetNodeAgentVersion records the version a node reports on each Watch
// connect. Enrollment stores it only once, which goes stale on upgrade.
func (s *Store) SetNodeAgentVersion(ctx context.Context, id uuid.UUID, version string) error {
	if id == uuid.Nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, "UPDATE nodes SET agent_version=$2 WHERE id=$1 AND revoked_at IS NULL", id, version)
	return err
}

// UpdateNodeCert records the issued client-cert serial and expiry.
func (s *Store) UpdateNodeCert(ctx context.Context, id uuid.UUID, serial string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE nodes SET cert_serial=$2, cert_expires_at=$3 WHERE id=$1 AND revoked_at IS NULL",
		id, serial, expiresAt)
	return err
}

// CountNodes returns enrolled nodes that still occupy a licence slot.
// RenameNode changes a node's display name.
func (s *Store) RenameNode(ctx context.Context, id uuid.UUID, name string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE nodes SET name=$2 WHERE id=$1`, id, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CountNodes(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM nodes WHERE revoked_at IS NULL").Scan(&n)
	return n, err
}

func (s *Store) ListNodes(ctx context.Context) ([]*Node, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+nodeCols+`
		FROM nodes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Node{}
	for rows.Next() {
		n := &Node{}
		if err := rows.Scan(&n.ID, &n.Name, &n.AgentVersion, &n.CertSerial, &n.CertExpiresAt, &n.LastSeenAt, &n.RevokedAt, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) GetNode(ctx context.Context, id uuid.UUID) (*Node, error) {
	n := &Node{}
	err := s.pool.QueryRow(ctx, `SELECT `+nodeCols+` FROM nodes WHERE id=$1`, id).
		Scan(&n.ID, &n.Name, &n.AgentVersion, &n.CertSerial, &n.CertExpiresAt, &n.LastSeenAt, &n.RevokedAt, &n.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return n, nil
}

// RevokeNode marks a node revoked and keeps its cert serial on the denylist.
// Idempotent: a second call returns the already-revoked row.
func (s *Store) RevokeNode(ctx context.Context, id uuid.UUID) (*Node, error) {
	n := &Node{}
	err := s.pool.QueryRow(ctx, `
		UPDATE nodes SET revoked_at = COALESCE(revoked_at, now())
		WHERE id=$1
		RETURNING `+nodeCols, id).
		Scan(&n.ID, &n.Name, &n.AgentVersion, &n.CertSerial, &n.CertExpiresAt, &n.LastSeenAt, &n.RevokedAt, &n.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.rememberRevoked(n.ID, n.CertSerial)
	return n, nil
}

func (s *Store) hydrateRevocations(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT id, cert_serial FROM nodes WHERE revoked_at IS NOT NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var serial string
		if err := rows.Scan(&id, &serial); err != nil {
			return err
		}
		s.rememberRevoked(id, serial)
	}
	return rows.Err()
}

func (s *Store) rememberRevoked(id uuid.UUID, serial string) {
	if s == nil {
		return
	}
	s.revMu.Lock()
	defer s.revMu.Unlock()
	if s.revokedIDs == nil {
		s.revokedIDs = map[uuid.UUID]struct{}{}
	}
	if s.revokedSerials == nil {
		s.revokedSerials = map[string]struct{}{}
	}
	if id != uuid.Nil {
		s.revokedIDs[id] = struct{}{}
	}
	if serial != "" {
		s.revokedSerials[serial] = struct{}{}
	}
}

// SerialRevoked reports whether a client-cert serial is on the denylist.
// Handshake path: in-memory, no DB round-trip.
func (s *Store) SerialRevoked(serial string) bool {
	if s == nil || serial == "" {
		return false
	}
	s.revMu.RLock()
	defer s.revMu.RUnlock()
	_, ok := s.revokedSerials[serial]
	return ok
}

// NodeIDRevoked reports whether a node UUID is revoked.
func (s *Store) NodeIDRevoked(id uuid.UUID) bool {
	if s == nil || id == uuid.Nil {
		return false
	}
	s.revMu.RLock()
	defer s.revMu.RUnlock()
	_, ok := s.revokedIDs[id]
	return ok
}
