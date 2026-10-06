package tokens

import (
	"encoding/hex"
	"regexp"
	"testing"
)

func TestGenerateRefreshTokenIsHex(t *testing.T) {
	tok, err := GenerateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 { // 32 bytes → 64 hex chars
		t.Errorf("len = %d, want 64", len(tok))
	}
	if _, err := hex.DecodeString(tok); err != nil {
		t.Errorf("not hex: %v", err)
	}
}

func TestHashTokenDeterministicLowercaseHex(t *testing.T) {
	// Known SHA-256 of "abc".
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := HashToken("abc"); got != want {
		t.Errorf("HashToken(abc) = %s, want %s", got, want)
	}
	if HashToken("abc") != HashToken("abc") {
		t.Error("not deterministic")
	}
}

func TestGenerateOpaqueIsBase64URL(t *testing.T) {
	tok, err := GenerateOpaque()
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`[^A-Za-z0-9_-]`).MatchString(tok) {
		t.Errorf("not base64url (has +/=/other): %s", tok)
	}
}

func TestGenerateInviteTokenHashMatches(t *testing.T) {
	raw, hash, err := GenerateInviteToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 64 {
		t.Errorf("invite raw len = %d, want 64 (hex)", len(raw))
	}
	if HashToken(raw) != hash {
		t.Error("returned hash does not match HashToken(raw)")
	}
}
