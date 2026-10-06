// Package pkce implements RFC 7636 PKCE S256: verifying a client's proof when
// App Central is the authorization server, and making one when it is the client
// of Google or an SSO provider.
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// VerifyS256 reports whether base64url(sha256(verifier)) equals the stored
// challenge, compared in constant time. Empty inputs fail closed. S256 is the
// only supported method (the only one this server ever issues).
func VerifyS256(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// ChallengeS256 is base64url(sha256(verifier)): what a client sends up front.
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewVerifier returns a fresh 43-character verifier (32 random bytes, base64url),
// the minimum length RFC 7636 allows and the full entropy it asks for.
func NewVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
