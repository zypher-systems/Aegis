// Package alerts turns operator notices into outbound webhook calls, so a
// certificate that will not renew or a node that went dark reaches someone
// who is not looking at the dashboard.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zypher-systems/aegis/services/api/internal/crypto"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

// SettingWebhook is the settings key holding the webhook URL (sealed).
const SettingWebhook = "alerts.webhook_url"

// Center persists notices and posts a webhook when one is raised or
// resolved. Unchanged notices (the same title and detail re-raised by a
// periodic check) do not post again.
type Center struct {
	st  *store.Store
	env *crypto.Envelope

	mu  sync.RWMutex
	url string
	// mem holds notices when there is no store (tests).
	mem []store.Notice

	client *http.Client
	// sync posts inline instead of in a goroutine (tests).
	sync bool
	wg   sync.WaitGroup
}

// Event is the webhook body. `text` and `content` carry the same one-line
// summary so Slack and Discord incoming webhooks render it unchanged;
// everything else is for systems that want structure.
type Event struct {
	Source     string `json:"source"`
	Status     string `json:"status"` // raised | resolved | test
	Kind       string `json:"kind"`
	ResourceID string `json:"resource_id"`
	Title      string `json:"title"`
	Detail     string `json:"detail,omitempty"`
	At         string `json:"at"`
	Text       string `json:"text"`
	Content    string `json:"content"`
}

func New(st *store.Store, env *crypto.Envelope) *Center {
	c := &Center{st: st, env: env, client: &http.Client{Timeout: 10 * time.Second}}
	if st != nil && env != nil {
		if raw, err := st.GetSetting(context.Background(), SettingWebhook, env.Open); err == nil {
			c.url = strings.TrimSpace(string(raw))
		}
	}
	return c
}

// WebhookURL is the configured destination ("" = alerts off).
func (c *Center) WebhookURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.url
}

// SetWebhook validates, persists and applies the destination. Empty turns
// alerts off.
func (c *Center) SetWebhook(ctx context.Context, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("webhook must be an http(s) URL")
		}
	}
	if c.st != nil && c.env != nil {
		if err := c.st.SetSetting(ctx, SettingWebhook, []byte(raw), c.env.Seal); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.url = raw
	c.mu.Unlock()
	return nil
}

// Test posts a test event synchronously and reports the delivery result.
func (c *Center) Test(ctx context.Context) error {
	dest := c.WebhookURL()
	if dest == "" {
		return fmt.Errorf("no webhook configured")
	}
	return c.deliver(ctx, dest, c.event("test", store.Notice{
		Kind: "test", ResourceID: "settings", Title: "Aegis alerts are working",
		Detail: "This is a test from Settings → Alerts.",
	}))
}

// Info posts a one-off event (nothing to resolve later), e.g. a node enrolled.
func (c *Center) Info(title, detail string) {
	c.post(c.event("info", store.Notice{Kind: "info", Title: title, Detail: detail, At: time.Now().UTC().Format(time.RFC3339)}))
}

// Raise records a notice and posts it if it is new or its wording changed.
func (c *Center) Raise(ctx context.Context, n store.Notice) {
	if n.At == "" {
		n.At = time.Now().UTC().Format(time.RFC3339)
	}
	existing := c.find(ctx, n.Kind, n.ResourceID)
	if err := c.upsert(ctx, n); err != nil {
		log.Printf("alerts: save notice %s/%s: %v", n.Kind, n.ResourceID, err)
	}
	if existing != nil && existing.Title == n.Title && existing.Detail == n.Detail {
		return
	}
	c.post(c.event("raised", n))
}

// Clear removes a notice and, if it existed, posts that it is resolved.
func (c *Center) Clear(ctx context.Context, kind, resourceID string) {
	existing := c.find(ctx, kind, resourceID)
	if existing == nil {
		return
	}
	if err := c.remove(ctx, kind, resourceID); err != nil {
		log.Printf("alerts: clear notice %s/%s: %v", kind, resourceID, err)
	}
	n := *existing
	n.At = time.Now().UTC().Format(time.RFC3339)
	c.post(c.event("resolved", n))
}

// List returns the open notices.
func (c *Center) List(ctx context.Context) []store.Notice {
	if c.st == nil || c.env == nil {
		c.mu.RLock()
		defer c.mu.RUnlock()
		return append([]store.Notice{}, c.mem...)
	}
	out, err := c.st.ListNotices(ctx, c.env.Open)
	if err != nil {
		return []store.Notice{}
	}
	return out
}

func (c *Center) find(ctx context.Context, kind, id string) *store.Notice {
	for _, n := range c.List(ctx) {
		if n.Kind == kind && n.ResourceID == id {
			n := n
			return &n
		}
	}
	return nil
}

func (c *Center) upsert(ctx context.Context, n store.Notice) error {
	if c.st == nil || c.env == nil {
		c.mu.Lock()
		c.mem = store.MergeNotice(c.mem, n)
		c.mu.Unlock()
		return nil
	}
	return c.st.UpsertNotice(ctx, n, c.env.Seal, c.env.Open)
}

func (c *Center) remove(ctx context.Context, kind, id string) error {
	if c.st == nil || c.env == nil {
		c.mu.Lock()
		kept := c.mem[:0]
		for _, n := range c.mem {
			if !(n.Kind == kind && n.ResourceID == id) {
				kept = append(kept, n)
			}
		}
		c.mem = kept
		c.mu.Unlock()
		return nil
	}
	return c.st.ClearNotice(ctx, kind, id, c.env.Seal, c.env.Open)
}

func (c *Center) event(status string, n store.Notice) Event {
	line := "[Aegis] " + n.Title
	switch status {
	case "resolved":
		line = "[Aegis] Resolved: " + n.Title
	case "test":
		line = "[Aegis] Test: " + n.Title
	case "info":
		line = "[Aegis] " + n.Title
	}
	if n.Detail != "" {
		line += " — " + n.Detail
	}
	return Event{
		Source: "aegis", Status: status, Kind: n.Kind, ResourceID: n.ResourceID,
		Title: n.Title, Detail: n.Detail, At: n.At, Text: line, Content: line,
	}
}

// post delivers in the background with two retries; the caller never waits
// on the network.
func (c *Center) post(ev Event) {
	dest := c.WebhookURL()
	if dest == "" {
		return
	}
	send := func() {
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err = c.deliver(ctx, dest, ev)
			cancel()
			if err == nil {
				return
			}
			if attempt < 2 {
				time.Sleep(time.Duration(attempt+1) * 5 * time.Second)
			}
		}
		log.Printf("alerts: webhook %s: %v (gave up after 3 attempts)", redact(dest), err)
	}
	if c.sync {
		send()
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		send()
	}()
}

func (c *Center) deliver(ctx context.Context, dest string, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aegis-alerts/1")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook answered %s", resp.Status)
	}
	return nil
}

// Wait blocks until queued deliveries finish (shutdown).
func (c *Center) Wait() { c.wg.Wait() }

// redact hides the path of a webhook URL, which usually carries a secret.
func redact(dest string) string {
	u, err := url.Parse(dest)
	if err != nil {
		return "webhook"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// Hint is what the dashboard shows for a configured webhook.
func Hint(dest string) string {
	if dest == "" {
		return ""
	}
	return redact(dest)
}
