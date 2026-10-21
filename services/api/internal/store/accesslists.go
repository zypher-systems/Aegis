package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AccessListUser struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type AccessList struct {
	ID         uuid.UUID        `json:"id"`
	Name       string           `json:"name"`
	Satisfy    string           `json:"satisfy"` // any | all
	Users      []AccessListUser `json:"users"`
	AllowCIDRs []string         `json:"allow_cidrs"`
	DenyCIDRs  []string         `json:"deny_cidrs"`
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

const accessListCols = `id, name, satisfy, users, allow_cidrs, deny_cidrs, created_at, updated_at`

func scanAccessList(row pgx.Row, a *AccessList) error {
	var usersRaw []byte
	err := row.Scan(&a.ID, &a.Name, &a.Satisfy, &usersRaw, &a.AllowCIDRs, &a.DenyCIDRs, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return err
	}
	if a.AllowCIDRs == nil {
		a.AllowCIDRs = []string{}
	}
	if a.DenyCIDRs == nil {
		a.DenyCIDRs = []string{}
	}
	a.Users = []AccessListUser{}
	if len(usersRaw) > 0 {
		_ = json.Unmarshal(usersRaw, &a.Users)
	}
	return nil
}

func encodeUsers(users []AccessListUser) []byte {
	if users == nil {
		users = []AccessListUser{}
	}
	b, err := json.Marshal(users)
	if err != nil {
		return []byte("[]")
	}
	return b
}

func (s *Store) CreateAccessList(ctx context.Context, a *AccessList) (*AccessList, error) {
	if a.Satisfy == "" {
		a.Satisfy = "all"
	}
	out := &AccessList{}
	err := scanAccessList(s.pool.QueryRow(ctx, `
		INSERT INTO access_lists (id, name, satisfy, users, allow_cidrs, deny_cidrs)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING `+accessListCols,
		uuid.New(), a.Name, a.Satisfy, encodeUsers(a.Users), a.AllowCIDRs, a.DenyCIDRs), out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) UpdateAccessList(ctx context.Context, a *AccessList) (*AccessList, error) {
	if a.Satisfy == "" {
		a.Satisfy = "all"
	}
	out := &AccessList{}
	err := scanAccessList(s.pool.QueryRow(ctx, `
		UPDATE access_lists SET name=$2, satisfy=$3, users=$4, allow_cidrs=$5, deny_cidrs=$6, updated_at=now()
		WHERE id=$1
		RETURNING `+accessListCols,
		a.ID, a.Name, a.Satisfy, encodeUsers(a.Users), a.AllowCIDRs, a.DenyCIDRs), out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) DeleteAccessList(ctx context.Context, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, "DELETE FROM access_lists WHERE id=$1", id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetAccessList(ctx context.Context, id uuid.UUID) (*AccessList, error) {
	out := &AccessList{}
	err := scanAccessList(s.pool.QueryRow(ctx,
		"SELECT "+accessListCols+" FROM access_lists WHERE id=$1", id), out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) ListAccessLists(ctx context.Context) ([]*AccessList, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+accessListCols+" FROM access_lists ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AccessList{}
	for rows.Next() {
		a := &AccessList{}
		if err := scanAccessList(rows, a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
