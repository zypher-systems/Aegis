package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// EnrollToken is a generated enrolment credential (the token itself is never
// stored, only its hash).
type EnrollToken struct {
	ID        uuid.UUID `json:"id"`
	Label     string    `json:"label"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UsesLeft  int       `json:"uses_left"`
}

func (s *Store) CreateEnrollToken(ctx context.Context, hash, label, createdBy string, expires time.Time, uses int) (*EnrollToken, error) {
	t := &EnrollToken{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO enroll_tokens (id, token_hash, label, created_by, expires_at, uses_left)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, label, created_by, created_at, expires_at, uses_left`,
		uuid.New(), hash, label, createdBy, expires, uses).
		Scan(&t.ID, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.UsesLeft)
	return t, err
}

// ConsumeEnrollToken spends one use of a live token. Atomic: two nodes
// presenting a single-use token at once cannot both succeed.
func (s *Store) ConsumeEnrollToken(ctx context.Context, hash string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE enroll_tokens SET uses_left = uses_left - 1
		WHERE token_hash = $1 AND expires_at > now() AND uses_left > 0`, hash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ListEnrollTokens returns tokens that can still enrol something.
func (s *Store) ListEnrollTokens(ctx context.Context) ([]EnrollToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, label, created_by, created_at, expires_at, uses_left FROM enroll_tokens
		WHERE expires_at > now() AND uses_left > 0 ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnrollToken{}
	for rows.Next() {
		var t EnrollToken
		if err := rows.Scan(&t.ID, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.UsesLeft); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteEnrollToken(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM enroll_tokens WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// PruneEnrollTokens drops spent and expired tokens.
func (s *Store) PruneEnrollTokens(ctx context.Context, now time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM enroll_tokens WHERE expires_at < $1 OR uses_left <= 0`, now.Add(-24*time.Hour))
	return err
}
