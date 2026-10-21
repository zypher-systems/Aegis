package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// RevokeSession records a session id as ended (logout).
func (s *Store) RevokeSession(ctx context.Context, jti string, expiresAt time.Time) error {
	if s == nil || s.pool == nil || jti == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO revoked_sessions (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING`, jti, expiresAt)
	return err
}

// ListRevokedSessions returns the ids of revoked sessions that have not yet
// expired on their own (loaded into memory at boot).
func (s *Store) ListRevokedSessions(ctx context.Context) ([]string, error) {
	if s == nil || s.pool == nil {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT jti FROM revoked_sessions WHERE expires_at > now()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// PruneRevokedSessions drops rows whose session has expired anyway.
func (s *Store) PruneRevokedSessions(ctx context.Context, now time.Time) error {
	if s == nil || s.pool == nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM revoked_sessions WHERE expires_at < $1`, now)
	return err
}

// BumpSessionEpoch ends every session of a user ("sign out everywhere").
func (s *Store) BumpSessionEpoch(ctx context.Context, id uuid.UUID) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		UPDATE users SET session_epoch = session_epoch + 1, updated_at = now()
		WHERE id = $1
		RETURNING `+userCols, id))
}
