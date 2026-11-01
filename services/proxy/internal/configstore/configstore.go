// Package configstore persists the last-known-good config snapshot so a
// proxy restart during a control-plane outage can keep serving.
package configstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

const (
	fileName = "last_config.pb"
	tmpName  = "last_config.pb.tmp"
	magic    = "AEGIS1\n"
)

// DeriveSnapshotKey returns a 32-byte AES key from the node's private key PEM.
func DeriveSnapshotKey(keyPEM []byte) ([]byte, error) {
	if len(bytes.TrimSpace(keyPEM)) == 0 {
		return nil, fmt.Errorf("empty node key")
	}
	r := hkdf.New(sha256.New, keyPEM, []byte("aegis-proxy"), []byte("last-config-v1"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func envelopeSeal(key, plaintext []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("snapshot key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func envelopeOpen(key []byte, encoded string) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("snapshot key must be 32 bytes")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return aead.Open(nil, raw[:ns], raw[ns:], nil)
}

// Save atomically writes an AES-256-GCM envelope of u to stateDir/last_config.pb
// (mode 0600). key is 32 bytes from DeriveSnapshotKey. The envelope is the
// same family as the control plane (nonce || ciphertext, base64).
func Save(stateDir string, u *aegisv1.ConfigUpdate, key []byte) error {
	if stateDir == "" || u == nil {
		return nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	plain, err := proto.Marshal(u)
	if err != nil {
		return err
	}
	sealed, err := envelopeSeal(key, plain)
	if err != nil {
		return err
	}
	payload := append([]byte(magic), sealed...)
	tmp := filepath.Join(stateDir, tmpName)
	final := filepath.Join(stateDir, fileName)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(payload); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Load decrypts the last persisted snapshot. Returns os.ErrNotExist when
// missing. Plaintext (pre-1.4.1) files are refused.
func Load(stateDir string, key []byte) (*aegisv1.ConfigUpdate, error) {
	if stateDir == "" {
		return nil, fmt.Errorf("empty state dir")
	}
	data, err := os.ReadFile(filepath.Join(stateDir, fileName))
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(data, []byte(magic)) {
		return nil, fmt.Errorf("plaintext or unknown last-known-good; refusing")
	}
	plain, err := envelopeOpen(key, string(data[len(magic):]))
	if err != nil {
		return nil, fmt.Errorf("decrypt last-known-good: %w", err)
	}
	u := &aegisv1.ConfigUpdate{}
	if err := proto.Unmarshal(plain, u); err != nil {
		return nil, err
	}
	return u, nil
}

// Remove deletes the persisted snapshot (a revoked node must not keep it).
func Remove(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, fileName))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(filepath.Join(stateDir, tmpName))
	return nil
}
