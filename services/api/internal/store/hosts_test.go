package store

import (
	"errors"
	"testing"
)

func TestNormalizeDomainNames(t *testing.T) {
	got := normalizeDomainNames([]string{" Demo.LOCAL ", "demo.local", "", "other.local"})
	if len(got) != 2 || got[0] != "demo.local" || got[1] != "other.local" {
		t.Fatalf("got %#v", got)
	}
}

func TestDomainConflictError(t *testing.T) {
	err := &DomainConflictError{Domain: "demo.local"}
	if err.Error() != "demo.local is already in use" {
		t.Fatalf("error = %q", err.Error())
	}
	if !errors.Is(err, ErrDomainTaken) {
		t.Fatal("should unwrap to ErrDomainTaken")
	}
	if mapHostErr(errors.New("nope")) == ErrDomainTaken {
		t.Fatal("unrelated error mapped")
	}
}
