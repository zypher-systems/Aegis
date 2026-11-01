// Package crypto provides AES-256-GCM envelope encryption for secrets at
// rest (CA private key, certificate private keys, ACME account key).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Envelope encrypts and decrypts small secret blobs with a 32-byte key.
type Envelope struct {
	aead cipher.AEAD
}

func NewEnvelope(key []byte) (*Envelope, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("envelope key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Envelope{aead: aead}, nil
}

// Seal encrypts plaintext and returns base64(nonce || ciphertext).
func (e *Envelope) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := e.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open decrypts a value produced by Seal.
func (e *Envelope) Open(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	ns := e.aead.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return e.aead.Open(nil, raw[:ns], raw[ns:], nil)
}
