// Package tokens generates opaque high-entropy tokens and their at-rest hashes.
// Encoding is deliberate and must not be conflated (SPEC §8 global-risk #2):
//   - refresh + invite tokens: hex   (matches the Node implementation)
//   - auth codes / reset tokens / OAuth state+nonce: base64url (unpadded)
//   - at-rest: sha256 → LOWERCASE hex of the raw token STRING's UTF-8 bytes
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

const tokenBytes = 32 // 256 bits of entropy

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRefreshToken returns a 32-byte random token, hex-encoded (64 chars).
func GenerateRefreshToken() (string, error) {
	b, err := randomBytes(tokenBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateOpaque returns a 32-byte random token, base64url unpadded — for auth
// codes, reset tokens, and OAuth state/nonce.
func GenerateOpaque() (string, error) {
	b, err := randomBytes(tokenBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the lowercase-hex sha256 of the raw token string (at-rest form).
// High-entropy tokens don't need a salt; exact-match lookups rely on this being stable.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateInviteToken returns a hex raw invite token (sent in the email) and its
// at-rest hash (stored). Only the hash is ever persisted.
func GenerateInviteToken() (raw, hash string, err error) {
	raw, err = GenerateRefreshToken() // hex — matches Node generateInviteToken
	if err != nil {
		return "", "", err
	}
	return raw, HashToken(raw), nil
}

// EqualHash compares two at-rest hashes in constant time, so a comparison against
// a stored secret's hash leaks nothing about how many leading characters matched.
func EqualHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
