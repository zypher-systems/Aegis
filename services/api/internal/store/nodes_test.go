package store

import (
	"testing"

	"github.com/google/uuid"
)

func TestSerialRevokedCache(t *testing.T) {
	s := &Store{}
	id := uuid.New()
	s.rememberRevoked(id, "abc")
	if !s.SerialRevoked("abc") {
		t.Fatal("serial should be revoked")
	}
	if s.SerialRevoked("def") {
		t.Fatal("other serial should not be revoked")
	}
	if !s.NodeIDRevoked(id) {
		t.Fatal("id should be revoked")
	}
	if s.NodeIDRevoked(uuid.New()) {
		t.Fatal("other id should not be revoked")
	}
}

func TestRetentionWindows(t *testing.T) {
	if HourlyRetention.Hours() != 14*24 {
		t.Fatalf("hourly=%v", HourlyRetention)
	}
	if DailyRetention.Hours() != 90*24 {
		t.Fatalf("daily=%v", DailyRetention)
	}
	if AuditRetention.Hours() != 90*24 {
		t.Fatalf("audit=%v", AuditRetention)
	}
}
