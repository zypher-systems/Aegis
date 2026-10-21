package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrLastAdmin  = errors.New("cannot delete the last admin")
	ErrEmailTaken = errors.New("email already in use")
)

type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	SessionEpoch int       `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

const userCols = `id, email, name, password_hash, role, session_epoch, created_at, updated_at`

func scanUser(row pgx.Row) (*User, error) {
	u := &User{}
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Role, &u.SessionEpoch, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func mapUserErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrEmailTaken
	}
	return err
}

func (s *Store) CreateUser(ctx context.Context, email, name, passwordHash, role string) (*User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `
		INSERT INTO users (id, email, name, password_hash, role)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+userCols,
		uuid.New(), email, name, passwordHash, role))
	if err != nil {
		return nil, mapUserErr(err)
	}
	return u, nil
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE lower(email) = lower($1)`, email))
}

// ErrSetupDone: the first admin already exists.
var ErrSetupDone = errors.New("setup already completed")

// CreateFirstUser creates the initial admin, holding a transaction-scoped
// advisory lock so concurrent first-run requests cannot both succeed.
func (s *Store) CreateFirstUser(ctx context.Context, email, name, passwordHash string) (*User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7241)`); err != nil {
		return nil, err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, ErrSetupDone
	}
	u, err := scanUser(tx.QueryRow(ctx, `
		INSERT INTO users (id, email, name, password_hash, role)
		VALUES ($1, $2, $3, $4, 'admin')
		RETURNING `+userCols, uuid.New(), email, name, passwordHash))
	if err != nil {
		return nil, mapUserErr(err)
	}
	return u, tx.Commit(ctx)
}

func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if out == nil {
		out = []*User{}
	}
	return out, rows.Err()
}

func (s *Store) UpdateUser(ctx context.Context, id uuid.UUID, email, name string) (*User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `
		UPDATE users SET email = $2, name = $3, updated_at = now()
		WHERE id = $1
		RETURNING `+userCols, id, email, name))
	if err != nil {
		return nil, mapUserErr(err)
	}
	return u, nil
}

func (s *Store) SetPassword(ctx context.Context, id uuid.UUID, passwordHash string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		UPDATE users SET password_hash = $2, session_epoch = session_epoch + 1, updated_at = now()
		WHERE id = $1
		RETURNING `+userCols, id, passwordHash))
}

// DeleteUser refuses to remove the last admin. The count and the delete run
// under one lock so two concurrent deletes cannot leave zero users (which
// would reopen first-run setup to anyone who can reach the API).
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7241)`); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if denyLastAdmin(n) != nil {
		return ErrLastAdmin
	}
	tag, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// CountUsers is used by the first-run setup check and last-admin guard.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n)
	return n, err
}

func denyLastAdmin(userCount int) error {
	if userCount <= 1 {
		return ErrLastAdmin
	}
	return nil
}
