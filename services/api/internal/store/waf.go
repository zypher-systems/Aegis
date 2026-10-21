package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type WAFExclusion struct {
	RuleID string `json:"rule_id"`
	Path   string `json:"path,omitempty"`
	// Target narrows the exclusion to one input (REQUEST_COOKIES:name, …).
	Target string `json:"target,omitempty"`
}

type WAFProfile struct {
	ID               uuid.UUID `json:"id"`
	Name             string    `json:"name"`
	Mode             string    `json:"mode"`
	Paranoia         int       `json:"paranoia"`
	InboundThreshold int       `json:"inbound_threshold"`
	// BodyLimitBytes: how much of a request body the WAF inspects; the rest
	// is forwarded uninspected. 0 = default (1 MiB).
	BodyLimitBytes int `json:"body_limit_bytes"`
	// Protocol policy; see wafrules/policy.go for the defaults.
	AllowedMethods      []string       `json:"allowed_methods"`
	AllowedContentTypes []string       `json:"allowed_content_types"` // empty = default list
	AnyContentType      bool           `json:"any_content_type"`
	RestrictedHeaders   []string       `json:"restricted_headers"`
	DisabledTags        []string       `json:"disabled_tags"`
	Exclusions          []WAFExclusion `json:"exclusions"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

const wafCols = `id, name, mode, paranoia, inbound_threshold, body_limit_bytes,
	allowed_methods, allowed_content_types, any_content_type, restricted_headers,
	disabled_tags, exclusions, created_at, updated_at`

func scanWAF(row pgx.Row, p *WAFProfile) error {
	var raw []byte
	err := row.Scan(
		&p.ID, &p.Name, &p.Mode, &p.Paranoia, &p.InboundThreshold, &p.BodyLimitBytes,
		&p.AllowedMethods, &p.AllowedContentTypes, &p.AnyContentType, &p.RestrictedHeaders,
		&p.DisabledTags, &raw, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return err
	}
	if p.DisabledTags == nil {
		p.DisabledTags = []string{}
	}
	if p.AllowedMethods == nil {
		p.AllowedMethods = []string{}
	}
	if p.AllowedContentTypes == nil {
		p.AllowedContentTypes = []string{}
	}
	if p.RestrictedHeaders == nil {
		p.RestrictedHeaders = []string{}
	}
	if len(raw) == 0 || string(raw) == "null" {
		p.Exclusions = []WAFExclusion{}
	} else if err := json.Unmarshal(raw, &p.Exclusions); err != nil {
		return err
	}
	if p.Exclusions == nil {
		p.Exclusions = []WAFExclusion{}
	}
	return nil
}

func exclusionsJSON(ex []WAFExclusion) ([]byte, error) {
	if ex == nil {
		ex = []WAFExclusion{}
	}
	return json.Marshal(ex)
}

func (s *Store) CreateWAFProfile(ctx context.Context, p *WAFProfile) (*WAFProfile, error) {
	if p.DisabledTags == nil {
		p.DisabledTags = []string{}
	}
	raw, err := exclusionsJSON(p.Exclusions)
	if err != nil {
		return nil, err
	}
	out := &WAFProfile{}
	err = scanWAF(s.pool.QueryRow(ctx, `
		INSERT INTO waf_profiles (id, name, mode, paranoia, inbound_threshold, body_limit_bytes,
			allowed_methods, allowed_content_types, any_content_type, restricted_headers, disabled_tags, exclusions)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING `+wafCols,
		uuid.New(), p.Name, p.Mode, p.Paranoia, p.InboundThreshold, p.BodyLimitBytes,
		nn(p.AllowedMethods), nn(p.AllowedContentTypes), p.AnyContentType, nn(p.RestrictedHeaders), p.DisabledTags, raw), out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) UpdateWAFProfile(ctx context.Context, p *WAFProfile) (*WAFProfile, error) {
	if p.DisabledTags == nil {
		p.DisabledTags = []string{}
	}
	raw, err := exclusionsJSON(p.Exclusions)
	if err != nil {
		return nil, err
	}
	out := &WAFProfile{}
	err = scanWAF(s.pool.QueryRow(ctx, `
		UPDATE waf_profiles SET name=$2, mode=$3, paranoia=$4, inbound_threshold=$5,
			body_limit_bytes=$6, allowed_methods=$7, allowed_content_types=$8, any_content_type=$9,
			restricted_headers=$10, disabled_tags=$11, exclusions=$12, updated_at=now()
		WHERE id=$1
		RETURNING `+wafCols,
		p.ID, p.Name, p.Mode, p.Paranoia, p.InboundThreshold, p.BodyLimitBytes,
		nn(p.AllowedMethods), nn(p.AllowedContentTypes), p.AnyContentType, nn(p.RestrictedHeaders), p.DisabledTags, raw), out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) DeleteWAFProfile(ctx context.Context, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, "DELETE FROM waf_profiles WHERE id=$1", id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetWAFProfile(ctx context.Context, id uuid.UUID) (*WAFProfile, error) {
	out := &WAFProfile{}
	err := scanWAF(s.pool.QueryRow(ctx,
		"SELECT "+wafCols+" FROM waf_profiles WHERE id=$1", id), out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) ListWAFProfiles(ctx context.Context) ([]*WAFProfile, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+wafCols+" FROM waf_profiles ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*WAFProfile{}
	for rows.Next() {
		p := &WAFProfile{}
		if err := scanWAF(rows, p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) CountHostsUsingWAFProfile(ctx context.Context, id uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM hosts WHERE waf_profile_id=$1", id).Scan(&n)
	return n, err
}

// nn makes a nil slice an empty one for NOT NULL text[] columns.
func nn(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
