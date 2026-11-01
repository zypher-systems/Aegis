package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

const firewallFlagName = "firewall.enabled"

func (s *Server) firewallEnabled(ctx context.Context) bool {
	if s.st == nil || s.env == nil {
		return true
	}
	return s.st.CrowdSecFirewallEnabled(ctx, s.env.Open)
}

// writeFirewallControl writes the flag the host firewall bouncer watches.
// The bouncer runs while the operator wants it on.
func (s *Server) writeFirewallControl(ctx context.Context) error {
	if s.csControlDir == "" {
		return nil
	}
	return writeFirewallFlag(s.csControlDir, s.firewallEnabled(ctx))
}

func writeFirewallFlag(dir string, enabled bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	v := "0\n"
	if enabled {
		v = "1\n"
	}
	tmp := filepath.Join(dir, "."+firewallFlagName+".tmp")
	dest := filepath.Join(dir, firewallFlagName)
	if err := os.WriteFile(tmp, []byte(v), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

func (s *Server) putCrowdsecFirewall(w http.ResponseWriter, r *http.Request) {
	if s.env == nil {
		writeErr(w, http.StatusInternalServerError, "envelope unavailable")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	raw, err := json.Marshal(map[string]bool{"enabled": req.Enabled})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "encode failed")
		return
	}
	if err := s.st.SetSetting(r.Context(), store.SettingCrowdSecFirewall, raw, s.env.Seal); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed")
		return
	}
	if s.csControlDir != "" {
		if err := writeFirewallFlag(s.csControlDir, req.Enabled); err != nil {
			writeErr(w, http.StatusInternalServerError, "control file: "+err.Error())
			return
		}
	}
	s.audit(r, "update", "settings", "crowdsec.firewall", map[string]any{"enabled": req.Enabled})
	writeJSON(w, http.StatusOK, map[string]any{
		"firewall_enabled": req.Enabled,
		"firewall_control": s.csControlDir != "",
	})
}
