package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

const (
	SettingEnrollToken        = "enroll_token"
	SettingACMEAccountKey     = "acme_account_key"
	SettingDNSCloudflareToken = "dns.cloudflare.api_token"
	SettingCrowdSecLAPI       = "crowdsec.lapi"
	SettingCrowdSecFirewall   = "crowdsec.firewall"
	SettingTrustedProxyCIDRs  = "trusted_proxy.cidrs"
)

// GetSetting returns the decrypted value for key, or ErrNotFound.
func (s *Store) GetSetting(ctx context.Context, key string, open func(string) ([]byte, error)) ([]byte, error) {
	var enc string
	err := s.pool.QueryRow(ctx, "SELECT value_enc FROM settings WHERE key=$1", key).Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return open(enc)
}

// SetSetting encrypts and upserts a setting.
func (s *Store) SetSetting(ctx context.Context, key string, plaintext []byte, seal func([]byte) (string, error)) error {
	enc, err := seal(plaintext)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO settings (key, value_enc, updated_at) VALUES ($1,$2,now())
		ON CONFLICT (key) DO UPDATE SET value_enc=$2, updated_at=now()`, key, enc)
	return err
}

// SeedCrowdSecLAPI writes url+key when the setting is missing or incomplete.
func (s *Store) SeedCrowdSecLAPI(ctx context.Context, url, key string, seal func([]byte) (string, error), open func(string) ([]byte, error)) (bool, error) {
	if s == nil || url == "" || key == "" {
		return false, nil
	}
	if raw, err := s.GetSetting(ctx, SettingCrowdSecLAPI, open); err == nil {
		var cs struct {
			URL string `json:"url"`
			Key string `json:"key"`
		}
		if json.Unmarshal(raw, &cs) == nil && cs.URL != "" && cs.Key != "" {
			return false, nil
		}
	}
	raw, err := json.Marshal(map[string]string{"url": url, "key": key})
	if err != nil {
		return false, err
	}
	return true, s.SetSetting(ctx, SettingCrowdSecLAPI, raw, seal)
}

// CrowdSecFirewallEnabled is the host nftables switch. Missing setting is on
// (1.3.0 shipped with the firewall container running).
func (s *Store) CrowdSecFirewallEnabled(ctx context.Context, open func(string) ([]byte, error)) bool {
	if s == nil {
		return true
	}
	raw, err := s.GetSetting(ctx, SettingCrowdSecFirewall, open)
	if err != nil {
		return true
	}
	var v struct {
		Enabled *bool `json:"enabled"`
	}
	if json.Unmarshal(raw, &v) != nil || v.Enabled == nil {
		return true
	}
	return *v.Enabled
}

// SeedCrowdSecFirewall writes the default when the key is absent.
func (s *Store) SeedCrowdSecFirewall(ctx context.Context, enabled bool, seal func([]byte) (string, error), open func(string) ([]byte, error)) error {
	if s == nil {
		return nil
	}
	if _, err := s.GetSetting(ctx, SettingCrowdSecFirewall, open); err == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]bool{"enabled": enabled})
	if err != nil {
		return err
	}
	return s.SetSetting(ctx, SettingCrowdSecFirewall, raw, seal)
}
