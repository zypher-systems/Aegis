package crypto

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewEnvelopeRejectsWrongKeyLength(t *testing.T) {
	if _, err := NewEnvelope(nil); err == nil {
		t.Fatal("nil key")
	}
	if _, err := NewEnvelope(make([]byte, 16)); err == nil {
		t.Fatal("16-byte key")
	}
	if _, err := NewEnvelope(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	e, err := NewEnvelope(bytes.Repeat([]byte{0xab}, 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("ca-private-key-bytes")
	sealed, err := e.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if sealed == "" || strings.Contains(sealed, "ca-private") {
		t.Fatalf("plaintext leaked: %q", sealed)
	}
	got, err := e.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q", got)
	}
	again, err := e.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if again == sealed {
		t.Fatal("nonces should differ")
	}
}

func TestOpenTamperAndGarbage(t *testing.T) {
	e, err := NewEnvelope(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := e.Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := e.Open(tampered); err == nil {
		t.Fatal("tamper")
	}
	if _, err := e.Open("%%%not-b64"); err == nil {
		t.Fatal("bad b64")
	}
	if _, err := e.Open(base64.StdEncoding.EncodeToString([]byte("x"))); err == nil {
		t.Fatal("too short")
	}
	other, err := NewEnvelope(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("wrong key")
	}
}
