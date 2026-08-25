package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyS256(t *testing.T) {
	// RFC 7636 appendix B style verifier.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if !VerifyS256(verifier, challenge) {
		t.Error("valid verifier/challenge pair was rejected")
	}
	if VerifyS256(verifier, "wrong-challenge") {
		t.Error("wrong challenge accepted")
	}
	if VerifyS256("wrong-verifier", challenge) {
		t.Error("wrong verifier accepted")
	}
	if VerifyS256("", challenge) {
		t.Error("empty verifier accepted")
	}
	if VerifyS256(verifier, "") {
		t.Error("empty challenge accepted")
	}
}
