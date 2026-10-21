package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

type streamDecision struct {
	Duration string `json:"duration"`
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

type streamResponse struct {
	New     []streamDecision `json:"new"`
	Deleted []streamDecision `json:"deleted"`
}

func (s *Server) crowdsecWrap(_ *aegisv1.Host, _ *aegisv1.SecurityConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cache := s.csCache.Load()
			if cache == nil {
				next.ServeHTTP(w, r)
				return
			}
			ip := clientIPString(r, s.trustedCIDRs())
			if parsed := net.ParseIP(ip); parsed != nil && (parsed.IsPrivate() || parsed.IsLoopback()) {
				next.ServeHTTP(w, r)
				return
			}
			origin, banned := cache.banned(ip)
			if !banned {
				next.ServeHTTP(w, r)
				return
			}
			detail := "client IP has an active CrowdSec ban"
			if origin != "" {
				detail += " (origin " + origin + ")"
			}
			setBlock(r, stageCrowdSec, detail)
			setCrowdsecOrigin(r, origin)
			writeError(w, r, http.StatusForbidden)
		})
	}
}

func (s *Server) syncCrowdsec(sec *aegisv1.SecurityConfig) {
	url := ""
	key := ""
	if sec != nil {
		url = strings.TrimRight(sec.GetCrowdsecLapiUrl(), "/")
		key = sec.GetCrowdsecLapiKey()
	}
	s.csMu.Lock()
	defer s.csMu.Unlock()
	if url == s.csURL && key == s.csKey {
		if url == "" || key == "" {
			return
		}
		if s.csStop != nil {
			return
		}
	}
	if s.csStop != nil {
		s.csStop()
		s.csStop = nil
	}
	s.csURL, s.csKey = url, key
	if url == "" || key == "" {
		s.csCache.Store(newDecisionCache())
		return
	}
	// Keep the live cache until the new stream has a first payload. Swapping
	// an empty map here is a fail-open window on every Apply.
	cache := newDecisionCache()
	ctx, cancel := context.WithCancel(context.Background())
	s.csStop = cancel
	client := s.crowdsecHTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	go s.crowdsecStream(ctx, client, url, key, cache)
}

func (s *Server) crowdsecStream(ctx context.Context, client *http.Client, base, key string, cache *decisionCache) {
	startup := true
	backoff := time.Second
	installed := false
	for {
		if ctx.Err() != nil {
			return
		}
		err := pullCrowdsecStream(ctx, client, base, key, startup, cache)
		if err == nil {
			s.csProblem.Store("")
			if !installed {
				s.csCache.Store(cache)
				installed = true
			}
			startup = false
			backoff = time.Second
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		log.Printf("proxy: crowdsec stream fail-open: %v", err)
		if installed {
			s.csProblem.Store("The decision stream is failing; this node keeps enforcing the bans it already knows. " + compileErr(err))
		} else {
			s.csProblem.Store("The decision stream has never succeeded on this node, so no CrowdSec bans are enforced here. " + compileErr(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// l7CrowdsecOrigins is local log scenarios only. CAPI / lists / cscli are
// enforced by the host firewall bouncer (separate API key + stream cursor).
const l7CrowdsecOrigins = "crowdsec"

func pullCrowdsecStream(ctx context.Context, client *http.Client, base, key string, startup bool, cache *decisionCache) error {
	u, err := url.Parse(strings.TrimRight(base, "/") + "/v1/decisions/stream")
	if err != nil {
		return err
	}
	q := u.Query()
	if startup {
		q.Set("startup", "true")
	}
	q.Set("origins", l7CrowdsecOrigins)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", key)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return errStatus(resp.StatusCode)
	}
	if len(body) == 0 || string(body) == "null" {
		return nil
	}
	var out streamResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}
	cache.apply(out.New, out.Deleted)
	return nil
}

type errStatus int

func (e errStatus) Error() string { return "crowdsec status " + http.StatusText(int(e)) }
