package auth

import (
	"testing"
	"time"
)

func TestSessionEpoch(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret-key-32-bytes-long!!"), time.Hour)
	tok, _ := sm.Issue("user-1", 0)
	id, ep, ok := sm.Validate(tok)
	if !ok || id != "user-1" || ep != 0 {
		t.Fatalf("epoch 0: id=%q ep=%d ok=%v", id, ep, ok)
	}

	tok1, _ := sm.Issue("user-1", 1)
	id, ep, ok = sm.Validate(tok1)
	if !ok || id != "user-1" || ep != 1 {
		t.Fatalf("epoch 1: id=%q ep=%d ok=%v", id, ep, ok)
	}

	// Old cookie still validates as epoch 0; requireAuth compares to DB.
	id, ep, ok = sm.Validate(tok)
	if !ok || ep != 0 {
		t.Fatalf("old token should still decode as epoch 0, got ep=%d ok=%v", ep, ok)
	}
}

func TestSessionRejectsTamperAndExpiry(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret-key-32-bytes-long!!"), -time.Hour)
	tok, _ := sm.Issue("user-1", 0)
	if _, _, ok := sm.Validate(tok); ok {
		t.Fatal("expired token should fail")
	}
	sm2 := NewSessionManager([]byte("test-secret-key-32-bytes-long!!"), time.Hour)
	good, _ := sm2.Issue("user-1", 3)
	if _, _, ok := sm2.Validate(good + "x"); ok {
		t.Fatal("tampered token should fail")
	}
}

func TestSessionKeyIsDerivedNotMaster(t *testing.T) {
	master := []byte("test-secret-key-32-bytes-long!!!")
	k := SessionKey(master)
	if len(k) != 32 || string(k) == string(master) {
		t.Fatalf("session key must be a distinct 32-byte derivation, got %d bytes", len(k))
	}
	if string(SessionKey(master)) != string(k) {
		t.Fatal("derivation must be deterministic so sessions survive restarts")
	}
	other := SessionKey([]byte("another-secret-key-32-bytes-lng!"))
	if string(other) == string(k) {
		t.Fatal("different master keys must give different session keys")
	}
}

func TestSessionIdleLimitAndRenewal(t *testing.T) {
	sm := NewSessionManager([]byte("test-secret-key-32-bytes-long!!"), 7*24*time.Hour)
	base := time.Unix(1_800_000_000, 0)
	now := base
	sm.now = func() time.Time { return now }
	tok, exp := sm.Issue("user-1", 2)
	s, ok := sm.Parse(tok)
	if !ok || s.JTI == "" || !s.Expires.Equal(exp) || s.Epoch != 2 {
		t.Fatalf("parse: %+v %v", s, ok)
	}
	// Unused for longer than the idle limit: gone, even though far from expiry.
	now = base.Add(SessionIdle + time.Minute)
	if _, ok := sm.Parse(tok); ok {
		t.Fatal("idle session must not validate")
	}
	// Renewed just before the idle limit: same session, new lease.
	now = base.Add(SessionIdle - time.Minute)
	renewed := sm.Renew(s)
	now = base.Add(2*SessionIdle - 2*time.Minute)
	r, ok := sm.Parse(renewed)
	if !ok || r.JTI != s.JTI || !r.Expires.Equal(s.Expires) {
		t.Fatalf("renewed: %+v %v", r, ok)
	}
	// But never past the absolute expiry.
	now = exp.Add(time.Second)
	if _, ok := sm.Parse(sm.Renew(r)); ok {
		t.Fatal("renewal must not extend past the absolute expiry")
	}
	// Two logins get different session ids.
	now = base
	a, _ := sm.Issue("user-1", 2)
	b, _ := sm.Issue("user-1", 2)
	sa, _ := sm.Parse(a)
	sb, _ := sm.Parse(b)
	if sa.JTI == sb.JTI {
		t.Fatal("session ids must be unique")
	}
}
