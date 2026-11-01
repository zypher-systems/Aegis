package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Certificate struct {
	ID        uuid.UUID `json:"id"`
	Domains   []string  `json:"domains"`
	Issuer    string    `json:"issuer"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	// Directory is the ACME directory URL that issued a letsencrypt cert;
	// empty for custom and self-signed certs.
	Directory string `json:"acme_directory,omitempty"`
	// AutoRenew: renew this Let's Encrypt certificate before it expires.
	AutoRenew bool `json:"auto_renew"`
}

// SetCertificateAutoRenew switches renewal for one certificate.
func (s *Store) SetCertificateAutoRenew(ctx context.Context, id uuid.UUID, on bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE certificates SET auto_renew=$2 WHERE id=$1`, id, on)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveCertificate stores envelope-encrypted PEM material. Saving under an
// existing id replaces that certificate in place (renewal).
func (s *Store) SaveCertificate(ctx context.Context, id uuid.UUID, domains []string, issuer, directory string, certPEMEnc, keyPEMEnc string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO certificates (id, domains, issuer, acme_directory, cert_pem_enc, key_pem_enc, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (id) DO UPDATE SET domains=$2, issuer=$3, acme_directory=$4, cert_pem_enc=$5, key_pem_enc=$6, expires_at=$7`,
		id, domains, issuer, directory, certPEMEnc, keyPEMEnc, expiresAt)
	return err
}

// SetCertificateDirectory records the issuing directory of an existing row
// (backfill for certificates issued before 1.7.2).
func (s *Store) SetCertificateDirectory(ctx context.Context, id uuid.UUID, directory string) error {
	_, err := s.pool.Exec(ctx, `UPDATE certificates SET acme_directory=$2 WHERE id=$1`, id, directory)
	return err
}

// CertificateMaterial is the decrypted PEM pair, used when assembling the
// data-plane config snapshot.
type CertificateMaterial struct {
	Certificate
	CertPEM []byte
	KeyPEM  []byte
}

func (s *Store) GetCertificateEnc(ctx context.Context, id uuid.UUID) (domains []string, issuer, certEnc, keyEnc string, expiresAt time.Time, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT domains, issuer, cert_pem_enc, key_pem_enc, expires_at
		FROM certificates WHERE id=$1`, id).
		Scan(&domains, &issuer, &certEnc, &keyEnc, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return
}

func (s *Store) GetCertificateMeta(ctx context.Context, id uuid.UUID) (*Certificate, error) {
	c := &Certificate{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, domains, issuer, expires_at, created_at, acme_directory, auto_renew
		FROM certificates WHERE id=$1`, id).
		Scan(&c.ID, &c.Domains, &c.Issuer, &c.ExpiresAt, &c.CreatedAt, &c.Directory, &c.AutoRenew)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ListCertificateMeta returns metadata for all certificates (no key material).
func (s *Store) ListCertificateMeta(ctx context.Context) ([]*Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, domains, issuer, expires_at, created_at, acme_directory, auto_renew
		FROM certificates ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Certificate{}
	for rows.Next() {
		c := &Certificate{}
		if err := rows.Scan(&c.ID, &c.Domains, &c.Issuer, &c.ExpiresAt, &c.CreatedAt, &c.Directory, &c.AutoRenew); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteCertificate(ctx context.Context, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, "DELETE FROM certificates WHERE id=$1", id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
