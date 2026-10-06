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

// The client half must produce exactly what the server half accepts, and a
// fresh verifier every time.
func TestNewVerifierAndChallengeRoundTrip(t *testing.T) {
	v1, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	v2, _ := NewVerifier()
	if len(v1) != 43 || v1 == v2 {
		t.Fatalf("verifiers %q and %q: want 43 characters and distinct", v1, v2)
	}
	if !VerifyS256(v1, ChallengeS256(v1)) {
		t.Error("a verifier does not satisfy its own challenge")
	}
	if VerifyS256(v2, ChallengeS256(v1)) {
		t.Error("another verifier satisfied the challenge")
	}
	// RFC 7636 appendix B.
	if got := ChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("ChallengeS256(RFC 7636 B) = %q", got)
	}
}
