package alerts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/zypher-systems/aegis/services/api/internal/store"
)

func webhook(t *testing.T) (*httptest.Server, func() []Event) {
	t.Helper()
	var mu sync.Mutex
	var got []Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			t.Errorf("bad body: %v", err)
		}
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []Event { mu.Lock(); defer mu.Unlock(); return append([]Event(nil), got...) }
}

func TestRaisePostsOncePerChangeAndClearPostsResolved(t *testing.T) {
	srv, got := webhook(t)
	c := New(nil, nil)
	c.sync = true
	if err := c.SetWebhook(context.Background(), srv.URL+"/hook/secret"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	n := store.Notice{Kind: "acme_renew", ResourceID: "c1", Title: "ACME renewal failed", Detail: "dns timeout"}
	c.Raise(ctx, n)
	c.Raise(ctx, n) // hourly re-check, same wording: silent
	c.Raise(ctx, n)
	if evs := got(); len(evs) != 1 || evs[0].Status != "raised" || evs[0].Text != "[Aegis] ACME renewal failed — dns timeout" {
		t.Fatalf("events after 3 identical raises: %+v", evs)
	}
	n.Detail = "rate limited"
	c.Raise(ctx, n) // wording changed: post again
	if evs := got(); len(evs) != 2 || evs[1].Detail != "rate limited" {
		t.Fatalf("changed detail not posted: %+v", evs)
	}
	if l := c.List(ctx); len(l) != 1 || l[0].Detail != "rate limited" {
		t.Fatalf("stored notice: %+v", l)
	}
	c.Clear(ctx, "acme_renew", "c1")
	c.Clear(ctx, "acme_renew", "c1") // already gone: silent
	evs := got()
	if len(evs) != 3 || evs[2].Status != "resolved" || evs[2].Content != "[Aegis] Resolved: ACME renewal failed — rate limited" {
		t.Fatalf("resolved event: %+v", evs)
	}
	if len(c.List(ctx)) != 0 {
		t.Fatal("notice still listed after Clear")
	}
}

func TestNoWebhookMeansNoticesOnly(t *testing.T) {
	c := New(nil, nil)
	c.sync = true
	c.Raise(context.Background(), store.Notice{Kind: "k", ResourceID: "r", Title: "t"})
	if len(c.List(context.Background())) != 1 {
		t.Fatal("notice must still be recorded without a webhook")
	}
	if err := c.Test(context.Background()); err == nil {
		t.Fatal("Test with no webhook must report it")
	}
}

func TestSetWebhookValidatesAndTestDelivers(t *testing.T) {
	c := New(nil, nil)
	for _, bad := range []string{"ftp://x/y", "not a url", "https://"} {
		if err := c.SetWebhook(context.Background(), bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	srv, got := webhook(t)
	if err := c.SetWebhook(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := c.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if evs := got(); len(evs) != 1 || evs[0].Status != "test" {
		t.Fatalf("test event: %+v", evs)
	}
	if err := c.SetWebhook(context.Background(), ""); err != nil || c.WebhookURL() != "" {
		t.Fatal("empty must turn alerts off")
	}
	if Hint(srv.URL+"/services/T000/B000/xyz") != srv.URL+"/…" {
		t.Fatalf("hint leaks the path: %q", Hint(srv.URL+"/services/T000/B000/xyz"))
	}
}

func TestFailingWebhookDoesNotBlockRaise(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	t.Cleanup(down.Close)
	c := New(nil, nil)
	_ = c.SetWebhook(context.Background(), down.URL)
	// Asynchronous: Raise returns immediately even though delivery will fail.
	c.Raise(context.Background(), store.Notice{Kind: "k", ResourceID: "r", Title: "t"})
	if len(c.List(context.Background())) != 1 {
		t.Fatal("notice recorded regardless of delivery")
	}
	// Do not wait for the retries (15 s); the goroutine is independent.
}
