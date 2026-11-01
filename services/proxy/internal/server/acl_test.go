package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/internal/passwd"
)

func TestACLDenyCIDR(t *testing.T) {
	acl := &aegisv1.AccessList{DenyCidrs: []string{"127.0.0.1/32"}}
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "127.0.0.1:9"
	rr := httptest.NewRecorder()
	if applyACL(rr, req, acl, false, nil) {
		t.Fatal("expected deny")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestACLBasicAuth(t *testing.T) {
	hash, err := passwd.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	acl := &aegisv1.AccessList{
		Satisfy: "all",
		Users:   []*aegisv1.BasicAuthUser{{Username: "alice", PasswordHash: hash}},
	}
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "10.0.0.2:9"
	rr := httptest.NewRecorder()
	if applyACL(rr, req, acl, false, nil) {
		t.Fatal("expected 401")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req2.RemoteAddr = "10.0.0.2:9"
	req2.SetBasicAuth("alice", "secret")
	rr2 := httptest.NewRecorder()
	if !applyACL(rr2, req2, acl, false, nil) {
		t.Fatalf("expected allow, status=%d", rr2.Code)
	}
}

func TestHopByHop(t *testing.T) {
	if !hopByHop("Connection") || hopByHop("X-Custom") {
		t.Fatal("hop-by-hop classification")
	}
}

func TestACLIgnoresSpoofedXFF(t *testing.T) {
	acl := &aegisv1.AccessList{DenyCidrs: []string{"203.0.113.9/32"}}
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "198.51.100.1:9"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	rr := httptest.NewRecorder()
	if !applyACL(rr, req, acl, false, nil) {
		t.Fatal("untrusted XFF must not trigger deny")
	}
}

func TestACLHonoursXFFFromTrustedHop(t *testing.T) {
	acl := &aegisv1.AccessList{DenyCidrs: []string{"203.0.113.9/32"}}
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.RemoteAddr = "10.0.0.2:9"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	rr := httptest.NewRecorder()
	if applyACL(rr, req, acl, false, []string{"10.0.0.0/8"}) {
		t.Fatal("trusted hop should honour XFF deny")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}
