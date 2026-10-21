package store

import "testing"

func TestDenyLastAdmin(t *testing.T) {
	if err := denyLastAdmin(1); err != ErrLastAdmin {
		t.Fatalf("count=1: want ErrLastAdmin, got %v", err)
	}
	if err := denyLastAdmin(0); err != ErrLastAdmin {
		t.Fatalf("count=0: want ErrLastAdmin, got %v", err)
	}
	if err := denyLastAdmin(2); err != nil {
		t.Fatalf("count=2: want nil, got %v", err)
	}
}
