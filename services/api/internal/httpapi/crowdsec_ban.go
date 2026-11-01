package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

var banDurations = map[string]string{
	"4h":  "4h",
	"24h": "24h",
	"7d":  "168h",
	"30d": "720h",
}

func (s *Server) postCrowdsecDecision(w http.ResponseWriter, r *http.Request) {
	if s.csMachineID == "" || s.csMachinePassword == "" {
		writeErr(w, http.StatusServiceUnavailable, "CrowdSec machine credentials are not set (CROWDSEC_MACHINE_PASSWORD)")
		return
	}
	cs, ok := s.loadCrowdsecLAPI(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "CrowdSec LAPI is not configured")
		return
	}
	var req struct {
		IP       string `json:"ip"`
		Duration string `json:"duration"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	scope, value, err := parseBanTarget(req.IP)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	dur, ok := banDurations[strings.TrimSpace(req.Duration)]
	if !ok {
		writeErr(w, http.StatusBadRequest, "duration must be 4h, 24h, 7d, or 30d")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "manual ban from Aegis"
	}
	if err := crowdsecAddBan(cs.URL, s.csMachineID, s.csMachinePassword, scope, value, dur, reason); err != nil {
		writeErr(w, http.StatusBadGateway, "crowdsec lapi: "+err.Error())
		return
	}
	fwOn := s.firewallEnabled(r.Context())
	out := map[string]any{
		"ok":               true,
		"scope":            scope,
		"value":            value,
		"duration":         dur,
		"firewall_enabled": fwOn,
	}
	if !fwOn {
		out["warning"] = "Decision saved. The host firewall is off, so it will not drop packets until you turn it on in Settings."
	}
	s.invalidateDecisions()
	s.audit(r, "create", "crowdsec.decision", value, map[string]any{
		"scope": scope, "duration": dur, "origin": "cscli",
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteCrowdsecDecision(w http.ResponseWriter, r *http.Request) {
	if s.csMachineID == "" || s.csMachinePassword == "" {
		writeErr(w, http.StatusServiceUnavailable, "CrowdSec machine credentials are not set (CROWDSEC_MACHINE_PASSWORD)")
		return
	}
	cs, ok := s.loadCrowdsecLAPI(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "CrowdSec LAPI is not configured")
		return
	}
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid decision id")
		return
	}
	if err := crowdsecDeleteDecision(cs.URL, s.csMachineID, s.csMachinePassword, id); err != nil {
		writeErr(w, http.StatusBadGateway, "crowdsec lapi: "+err.Error())
		return
	}
	s.invalidateDecisions()
	s.audit(r, "delete", "crowdsec.decision", id, map[string]any{"id": id})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

func parseBanTarget(raw string) (scope, value string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("ip or CIDR is required")
	}
	if strings.Contains(raw, "/") {
		ip, ipnet, e := net.ParseCIDR(raw)
		if e != nil {
			return "", "", fmt.Errorf("invalid CIDR")
		}
		if forbiddenBanIP(ip) {
			return "", "", fmt.Errorf("private, loopback, and link-local ranges cannot be banned")
		}
		ones, bits := ipnet.Mask.Size()
		if ones == 0 || ones > bits {
			return "", "", fmt.Errorf("CIDR is too broad")
		}
		return "Range", ipnet.String(), nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", "", fmt.Errorf("invalid IP")
	}
	if forbiddenBanIP(ip) {
		return "", "", fmt.Errorf("private, loopback, and link-local addresses cannot be banned")
	}
	return "Ip", ip.String(), nil
}

func forbiddenBanIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func crowdsecAddBan(base, machineID, password, scope, value, duration, reason string) error {
	token, err := crowdsecWatcherLogin(base, machineID, password)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	src := map[string]string{"scope": scope, "value": value}
	if scope == "Ip" {
		src["ip"] = value
	} else {
		src["range"] = value
	}
	alert := map[string]any{
		"capacity": 0,
		"decisions": []map[string]any{{
			"duration": duration,
			"origin":   "cscli",
			"scenario": reason,
			"scope":    scope,
			"type":     "ban",
			"value":    value,
		}},
		"events":           []any{},
		"events_count":     1,
		"leakspeed":        "0",
		"message":          reason,
		"scenario":         "manual/ban",
		"scenario_hash":    "",
		"scenario_version": "",
		"simulated":        false,
		"source":           src,
		"start_at":         now,
		"stop_at":          now,
	}
	body, err := json.Marshal([]any{alert})
	if err != nil {
		return err
	}
	u := strings.TrimRight(base, "/") + "/v1/alerts"
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return crowdsecDo(req, http.StatusCreated)
}

func crowdsecDeleteDecision(base, machineID, password, id string) error {
	token, err := crowdsecWatcherLogin(base, machineID, password)
	if err != nil {
		return err
	}
	u := strings.TrimRight(base, "/") + "/v1/decisions/" + id
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return crowdsecDo(req, http.StatusOK)
}

func crowdsecWatcherLogin(base, machineID, password string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"machine_id": machineID,
		"password":   password,
	})
	if err != nil {
		return "", err
	}
	u := strings.TrimRight(base, "/") + "/v1/watchers/login"
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("watcher login: %s", lapiErr(resp.StatusCode, raw))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("watcher login: empty token")
	}
	return out.Token, nil
}

func crowdsecDo(req *http.Request, want int) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != want && resp.StatusCode >= 300 {
		return fmt.Errorf("%s", lapiErr(resp.StatusCode, raw))
	}
	if resp.StatusCode != want {
		return fmt.Errorf("status %s", http.StatusText(resp.StatusCode))
	}
	return nil
}

func lapiErr(code int, raw []byte) string {
	var m struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(raw, &m) == nil {
		if m.Message != "" {
			return m.Message
		}
		if m.Error != "" {
			return m.Error
		}
	}
	if len(raw) > 0 && len(raw) < 300 {
		return strings.TrimSpace(string(raw))
	}
	return http.StatusText(code)
}
