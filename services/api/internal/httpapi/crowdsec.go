package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

type crowdsecLAPI struct {
	URL string `json:"url"`
	Key string `json:"key"`
}

type crowdsecDecision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
}

type crowdsecAlert struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	Scenario  string `json:"scenario"`
	Message   string `json:"message"`
	SourceIP  string `json:"source_ip"`
	Decisions int    `json:"decisions"`
}

func (s *Server) loadCrowdsecLAPI(r *http.Request) (crowdsecLAPI, bool) {
	var cs crowdsecLAPI
	if s.env == nil {
		return cs, false
	}
	b, err := s.st.GetSetting(r.Context(), store.SettingCrowdSecLAPI, s.env.Open)
	if err != nil {
		return cs, false
	}
	if json.Unmarshal(b, &cs) != nil {
		return cs, false
	}
	return cs, cs.URL != "" && cs.Key != ""
}

func (s *Server) crowdsecStatus(w http.ResponseWriter, r *http.Request) {
	fwOn := s.firewallEnabled(r.Context())
	out := map[string]any{
		"configured":       false,
		"url":              "",
		"in_stack":         true,
		"lapi_ok":          false,
		"firewall_enabled": fwOn,
		"firewall_control": s.csControlDir != "",
		"can_ban":          s.csMachineID != "" && s.csMachinePassword != "",
	}
	cs, ok := s.loadCrowdsecLAPI(r)
	if ok {
		out["configured"] = true
		out["url"] = cs.URL
		if err := pingCrowdsec(cs); err == nil {
			out["lapi_ok"] = true
		} else {
			out["error"] = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putCrowdsec(w http.ResponseWriter, r *http.Request) {
	if s.env == nil {
		writeErr(w, http.StatusInternalServerError, "envelope unavailable")
		return
	}
	var req struct {
		URL string `json:"url"`
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.URL == "" {
		writeErr(w, http.StatusBadRequest, "url is required")
		return
	}
	existingKey := ""
	if b, err := s.st.GetSetting(r.Context(), store.SettingCrowdSecLAPI, s.env.Open); err == nil {
		var cs crowdsecLAPI
		if json.Unmarshal(b, &cs) == nil {
			existingKey = cs.Key
		}
	}
	key := req.Key
	if key == "" {
		key = existingKey
	}
	raw, err := json.Marshal(crowdsecLAPI{URL: req.URL, Key: key})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "encode failed")
		return
	}
	if err := s.st.SetSetting(r.Context(), store.SettingCrowdSecLAPI, raw, s.env.Seal); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed")
		return
	}
	s.changed()
	s.audit(r, "update", "settings", "crowdsec.lapi", map[string]any{"url": req.URL, "configured": key != ""})
	writeJSON(w, http.StatusOK, map[string]any{"configured": key != "", "url": req.URL, "in_stack": true})
}

// decisionsCacheTTL bounds how often dashboard polls reach LAPI: every viewer
// refreshing every 10s shares one fetch of the full list.
const decisionsCacheTTL = 10 * time.Second

type decisionCache struct {
	mu      sync.Mutex
	source  string // LAPI URL+key the list came from
	at      time.Time
	list    []crowdsecDecision
	fetches int // LAPI round trips, for tests
}

func (s *Server) decisionCache() *decisionCache { return &s.decisions }

// invalidateDecisions drops the cached list so the next read reflects a ban
// or unban immediately. Call after a successful POST/DELETE decision.
func (s *Server) invalidateDecisions() {
	c := s.decisionCache()
	c.mu.Lock()
	c.list, c.at, c.source = nil, time.Time{}, ""
	c.mu.Unlock()
}

// cachedDecisions returns the full LAPI list, newest first, from a cache
// that is at most decisionsCacheTTL old.
func (s *Server) cachedDecisions(cs crowdsecLAPI) ([]crowdsecDecision, error) {
	c := s.decisionCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	src := cs.URL + "\x00" + cs.Key
	if c.list != nil && c.source == src && time.Since(c.at) < decisionsCacheTTL {
		return c.list, nil
	}
	list, err := fetchCrowdsecDecisions(cs)
	c.fetches++
	if err != nil {
		return nil, err
	}
	// LAPI ids grow with creation, so id desc is newest first; stable for ties.
	sort.SliceStable(list, func(i, j int) bool { return list[i].ID > list[j].ID })
	c.list, c.at, c.source = list, time.Now(), src
	return list, nil
}

const (
	decisionsDefaultLimit = 25
	decisionsMaxLimit     = 200
)

// crowdsecDecisions pages active decisions server-side:
// ?limit (default 25, max 200) &offset &q (substring of value, scenario or
// origin) &origin (exact, case-insensitive). by_origin counts ignore the
// origin filter so the dashboard can show every chip with its count.
func (s *Server) crowdsecDecisions(w http.ResponseWriter, r *http.Request) {
	cs, ok := s.loadCrowdsecLAPI(r)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"decisions": []crowdsecDecision{}, "total": 0, "by_origin": map[string]int{}, "configured": false,
		})
		return
	}
	all, err := s.cachedDecisions(cs)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "crowdsec lapi: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pageDecisions(all, r.URL.Query()))
}

func pageDecisions(all []crowdsecDecision, qv url.Values) map[string]any {
	limit := decisionsDefaultLimit
	if n, err := strconv.Atoi(qv.Get("limit")); err == nil && n > 0 {
		limit = min(n, decisionsMaxLimit)
	}
	offset := 0
	if n, err := strconv.Atoi(qv.Get("offset")); err == nil && n > 0 {
		offset = n
	}
	q := strings.ToLower(strings.TrimSpace(qv.Get("q")))
	origin := strings.TrimSpace(qv.Get("origin"))

	byOrigin := map[string]int{}
	matched := make([]crowdsecDecision, 0, len(all))
	for _, d := range all {
		if q != "" && !strings.Contains(strings.ToLower(d.Value), q) &&
			!strings.Contains(strings.ToLower(d.Scenario), q) &&
			!strings.Contains(strings.ToLower(d.Origin), q) {
			continue
		}
		byOrigin[d.Origin]++
		if origin != "" && !strings.EqualFold(d.Origin, origin) {
			continue
		}
		matched = append(matched, d)
	}
	page := []crowdsecDecision{}
	if offset < len(matched) {
		page = matched[offset:min(offset+limit, len(matched))]
	}
	return map[string]any{
		"decisions":  page,
		"total":      len(matched),
		"by_origin":  byOrigin,
		"limit":      limit,
		"offset":     offset,
		"configured": true,
	}
}

func (s *Server) crowdsecAlerts(w http.ResponseWriter, r *http.Request) {
	// Bouncer keys cannot list LAPI alerts. Surface recent L7 CrowdSec blocks
	// from the live ring so the dashboard still has a "what just happened" list.
	recent := []telemetryCrowdsecBlock{}
	if s.telemetry != nil {
		for _, e := range s.telemetry.Live(100) {
			if e.BlockStage != "crowdsec" {
				continue
			}
			recent = append(recent, telemetryCrowdsecBlock{
				TimestampMs: e.TimestampMs,
				Domain:      e.Domain,
				ClientIP:    e.ClientIP,
				Path:        e.Path,
				Origin:      e.CrowdSecOrigin,
				Status:      e.Status,
			})
			if len(recent) >= 40 {
				break
			}
		}
	}
	if recent == nil {
		recent = []telemetryCrowdsecBlock{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": recent, "source": "telemetry"})
}

type telemetryCrowdsecBlock struct {
	TimestampMs int64  `json:"timestamp_unix_ms"`
	Domain      string `json:"domain"`
	ClientIP    string `json:"client_ip"`
	Path        string `json:"path"`
	Origin      string `json:"origin"`
	Status      int32  `json:"status"`
}

func pingCrowdsec(cs crowdsecLAPI) error {
	u := strings.TrimRight(cs.URL, "/") + "/v1/decisions/stream"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", cs.Key)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return errStatus(resp.StatusCode)
	}
	return nil
}

func fetchCrowdsecDecisions(cs crowdsecLAPI) ([]crowdsecDecision, error) {
	u := strings.TrimRight(cs.URL, "/") + "/v1/decisions"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", cs.Key)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, errStatus(resp.StatusCode)
	}
	if len(body) == 0 || string(body) == "null" {
		return []crowdsecDecision{}, nil
	}
	var list []crowdsecDecision
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	return list, nil
}

type errStatus int

func (e errStatus) Error() string { return "status " + http.StatusText(int(e)) }
