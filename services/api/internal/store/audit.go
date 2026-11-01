package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type AuditEvent struct {
	ID           uuid.UUID      `json:"id"`
	At           time.Time      `json:"at"`
	ActorID      *uuid.UUID     `json:"actor_id,omitempty"`
	ActorEmail   string         `json:"actor_email"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Summary      map[string]any `json:"summary"`
}

func (s *Store) InsertAudit(ctx context.Context, ev *AuditEvent) error {
	if ev.ID == uuid.Nil {
		ev.ID = uuid.New()
	}
	if ev.Summary == nil {
		ev.Summary = map[string]any{}
	}
	raw, err := json.Marshal(ev.Summary)
	if err != nil {
		return err
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO audit_events (id, actor_id, actor_email, action, resource_type, resource_id, summary)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING at`,
		ev.ID, ev.ActorID, ev.ActorEmail, ev.Action, ev.ResourceType, ev.ResourceID, raw,
	).Scan(&ev.At)
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]*AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, at, actor_id, actor_email, action, resource_type, resource_id, summary
		FROM audit_events
		ORDER BY at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AuditEvent{}
	for rows.Next() {
		ev := &AuditEvent{}
		var raw []byte
		if err := rows.Scan(&ev.ID, &ev.At, &ev.ActorID, &ev.ActorEmail, &ev.Action, &ev.ResourceType, &ev.ResourceID, &raw); err != nil {
			return nil, err
		}
		ev.Summary = map[string]any{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &ev.Summary)
		}
		out = append(out, ev)
	}
	if out == nil {
		out = []*AuditEvent{}
	}
	return out, rows.Err()
}

// PruneAudit deletes audit_events older than AuditRetention.
func (s *Store) PruneAudit(ctx context.Context, now time.Time) error {
	if s == nil || s.pool == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM audit_events WHERE at < $1`, now.Add(-AuditRetention))
	return err
}
