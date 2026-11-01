package store

import (
	"context"
	"encoding/json"
	"time"
)

const SettingNotices = "operator.notices"

// Notice is a persistent operator banner (ACME renewal failure, etc).
type Notice struct {
	Kind        string `json:"kind"`
	ResourceID  string `json:"resource_id"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	NextAttempt string `json:"next_attempt,omitempty"`
	At          string `json:"at"`
}

func MergeNotice(existing []Notice, n Notice) []Notice {
	out := dropNotice(existing, n.Kind, n.ResourceID)
	return append(out, n)
}

func dropNotice(existing []Notice, kind, resourceID string) []Notice {
	out := make([]Notice, 0, len(existing))
	for _, e := range existing {
		if e.Kind == kind && e.ResourceID == resourceID {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (s *Store) ListNotices(ctx context.Context, open func(string) ([]byte, error)) ([]Notice, error) {
	if s == nil {
		return []Notice{}, nil
	}
	raw, err := s.GetSetting(ctx, SettingNotices, open)
	if err == ErrNotFound {
		return []Notice{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Notice{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return []Notice{}, nil
	}
	if out == nil {
		out = []Notice{}
	}
	return out, nil
}

func (s *Store) UpsertNotice(ctx context.Context, n Notice, seal func([]byte) (string, error), open func(string) ([]byte, error)) error {
	if s == nil {
		return nil
	}
	if n.At == "" {
		n.At = time.Now().UTC().Format(time.RFC3339)
	}
	cur, err := s.ListNotices(ctx, open)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(MergeNotice(cur, n))
	if err != nil {
		return err
	}
	return s.SetSetting(ctx, SettingNotices, raw, seal)
}

func (s *Store) ClearNotice(ctx context.Context, kind, resourceID string, seal func([]byte) (string, error), open func(string) ([]byte, error)) error {
	if s == nil {
		return nil
	}
	cur, err := s.ListNotices(ctx, open)
	if err != nil {
		return err
	}
	next := dropNotice(cur, kind, resourceID)
	if len(next) == len(cur) {
		return nil
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return s.SetSetting(ctx, SettingNotices, raw, seal)
}
