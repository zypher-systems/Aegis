package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseBanTarget(t *testing.T) {
	scope, value, err := parseBanTarget("203.0.113.9")
	if err != nil || scope != "Ip" || value != "203.0.113.9" {
		t.Fatalf("ip: scope=%s value=%s err=%v", scope, value, err)
	}
	scope, value, err = parseBanTarget("203.0.113.0/24")
	if err != nil || scope != "Range" || value != "203.0.113.0/24" {
		t.Fatalf("cidr: scope=%s value=%s err=%v", scope, value, err)
	}
	for _, bad := range []string{"", "nope", "10.0.0.1", "127.0.0.1", "192.168.1.0/24", "::1", "0.0.0.0"} {
		if _, _, err := parseBanTarget(bad); err == nil {
			t.Fatalf("expected reject %q", bad)
		}
	}
}

func TestWriteFirewallFlag(t *testing.T) {
	dir := t.TempDir()
	if err := writeFirewallFlag(dir, true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, firewallFlagName))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "1\n" {
		t.Fatalf("got %q", b)
	}
	if err := writeFirewallFlag(dir, false); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(filepath.Join(dir, firewallFlagName))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "0\n" {
		t.Fatalf("got %q", b)
	}
}

func TestCrowdsecAddBan(t *testing.T) {
	var posted []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/watchers/login":
			w.Write([]byte(`{"token":"t"}`))
		case "/v1/alerts":
			posted, _ = io.ReadAll(r.Body)
			if r.Header.Get("Authorization") != "Bearer t" {
				t.Errorf("auth=%s", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`["1"]`))
		default:
			t.Errorf("path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	if err := crowdsecAddBan(ts.URL, "aegis-api", "pw", "Ip", "203.0.113.9", "4h", "scanner"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(posted, []byte(`"origin":"cscli"`)) || !bytes.Contains(posted, []byte(`"203.0.113.9"`)) {
		t.Fatalf("payload %s", posted)
	}
}

func TestCrowdsecDeleteDecision(t *testing.T) {
	deleted := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/watchers/login":
			w.Write([]byte(`{"token":"t"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/decisions/42":
			deleted = true
			w.Write([]byte(`{"nbDeleted":"1"}`))
		default:
			t.Errorf("path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	if err := crowdsecDeleteDecision(ts.URL, "aegis-api", "pw", "42"); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("delete not called")
	}
}
