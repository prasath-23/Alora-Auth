// Package pkce implements RFC 7636 PKCE S256 verification.
package pkce

import (
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
