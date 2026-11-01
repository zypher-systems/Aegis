package configstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := DeriveSnapshotKey([]byte("-----BEGIN PRIVATE KEY-----\ntest-node-key\n-----END PRIVATE KEY-----"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDeriveSnapshotKeyStable(t *testing.T) {
	pem := []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")
	a, err := DeriveSnapshotKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveSnapshotKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) || len(a) != 32 {
		t.Fatalf("len=%d equal=%v", len(a), bytes.Equal(a, b))
	}
	c, err := DeriveSnapshotKey([]byte("other"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("different PEM produced the same key")
	}
	if _, err := DeriveSnapshotKey(nil); err == nil {
		t.Fatal("empty key")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	in := &aegisv1.ConfigUpdate{
		Version:  7,
		Snapshot: true,
		Hosts: []*aegisv1.Host{{
			Id:          "h1",
			DomainNames: []string{"demo.local"},
			Enabled:     true,
		}},
		Security: &aegisv1.SecurityConfig{
			TrustedProxyCidrs: []string{"10.0.0.0/8"},
		},
	}
	if err := Save(dir, in, key); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o", info.Mode().Perm())
	}
	out, err := Load(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if out.GetVersion() != 7 || len(out.GetHosts()) != 1 || out.GetHosts()[0].GetId() != "h1" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if got := out.GetSecurity().GetTrustedProxyCidrs(); len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("cidrs = %#v", got)
	}
}

func TestSaveHidesPEM(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	in := &aegisv1.ConfigUpdate{
		Version: 1,
		Certificates: []*aegisv1.Certificate{{
			Id:      "c1",
			CertPem: []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"),
			KeyPem:  []byte("-----BEGIN PRIVATE KEY-----\nMIIESECRET\n-----END PRIVATE KEY-----"),
		}},
	}
	if err := Save(dir, in, key); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(raw, []byte("MIIESECRET")) {
		t.Fatal("plaintext PEM leaked into last_config.pb")
	}
	if !bytes.HasPrefix(raw, []byte(magic)) {
		t.Fatal("missing envelope magic")
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(t.TempDir(), testKey(t))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadPlaintextRefused(t *testing.T) {
	dir := t.TempDir()
	plain, err := proto.Marshal(&aegisv1.ConfigUpdate{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileName), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, testKey(t)); err == nil {
		t.Fatal("expected refuse")
	}
}

func TestLoadWrongKey(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, &aegisv1.ConfigUpdate{Version: 1}, testKey(t)); err != nil {
		t.Fatal(err)
	}
	other, err := DeriveSnapshotKey([]byte("other-node"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, other); err == nil {
		t.Fatal("expected decrypt failure")
	}
}

func TestSaveReplaces(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	if err := Save(dir, &aegisv1.ConfigUpdate{Version: 1}, key); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, &aegisv1.ConfigUpdate{Version: 2}, key); err != nil {
		t.Fatal(err)
	}
	out, err := Load(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if out.GetVersion() != 2 {
		t.Fatalf("version = %d", out.GetVersion())
	}
}
