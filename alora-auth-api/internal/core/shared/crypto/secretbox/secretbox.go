// Package secretbox seals the secrets App Central must be able to read back —
// an SSO connection's client secret — so the database only ever holds
// ciphertext. AES-256-GCM with a fresh random nonce per seal; the caller's
// associated data (the connection id) is bound into the tag, so a ciphertext
// copied onto another connection's row does not open.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// ErrNoKey is returned when no key is configured: nothing can be sealed or opened.
var ErrNoKey = errors.New("secretbox: no key configured")

// Box holds one key and the id stored beside everything it seals, so a later
// rotation can tell which key a ciphertext needs.
type Box struct {
	aead  cipher.AEAD
	keyID string
}

// New builds a box for a 32-byte key. A nil key yields a box that refuses every
// operation with ErrNoKey, so a deployment without SSO still starts.
func New(key []byte, keyID string) (*Box, error) {
	if key == nil {
		return &Box{keyID: keyID}, nil
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secretbox: key must be 32 bytes, got %d", len(key))
	}
	if keyID == "" {
		return nil, errors.New("secretbox: key id is required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead, keyID: keyID}, nil
}

// Enabled reports whether a key is configured.
func (b *Box) Enabled() bool { return b.aead != nil }

// KeyID is the id to store beside a ciphertext this box sealed.
func (b *Box) KeyID() string { return b.keyID }

// Seal encrypts plaintext bound to aad. The result is nonce || ciphertext+tag.
func (b *Box) Seal(plaintext, aad []byte) ([]byte, error) {
	if b.aead == nil {
		return nil, ErrNoKey
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open decrypts what Seal produced under keyID with the same aad. Any mismatch —
// another key, another aad, a flipped bit — is an error, never garbage.
func (b *Box) Open(keyID string, sealed, aad []byte) ([]byte, error) {
	if b.aead == nil {
		return nil, ErrNoKey
	}
	if keyID != b.keyID {
		return nil, fmt.Errorf("secretbox: sealed with key %q, but the configured key is %q", keyID, b.keyID)
	}
	n := b.aead.NonceSize()
	if len(sealed) < n+b.aead.Overhead() {
		return nil, errors.New("secretbox: ciphertext too short")
	}
	out, err := b.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, errors.New("secretbox: ciphertext does not open under this key and associated data")
	}
	return out, nil
}
