package password

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	const pw = "correct horse battery staple"
	h, err := Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("unexpected PHC params: %s", h)
	}
	if !Verify(pw, h) {
		t.Error("valid password rejected")
	}
	if Verify("wrong password", h) {
		t.Error("wrong password accepted")
	}
}

func TestTooLong(t *testing.T) {
	long := strings.Repeat("a", MaxPasswordLength+1)
	if _, err := Hash(long); err != ErrPasswordTooLong {
		t.Errorf("got %v, want ErrPasswordTooLong", err)
	}
	// Exactly at the limit is allowed.
	if _, err := Hash(strings.Repeat("a", MaxPasswordLength)); err != nil {
		t.Errorf("boundary length rejected: %v", err)
	}
}

func TestVerifyMalformedHashIsFalse(t *testing.T) {
	if Verify("anything", "not-a-valid-phc-string") {
		t.Error("malformed hash must verify as false, never error out")
	}
}

func TestDummyHashStableAndInert(t *testing.T) {
	d := DummyHash()
	if d == "" {
		t.Fatal("empty dummy hash")
	}
	if DummyHash() != d {
		t.Error("dummy hash not stable across calls")
	}
	if Verify("anything", d) {
		t.Error("dummy hash unexpectedly matched a password")
	}
}

// Regression test for the codex+agy review fix: Verify must reject over-length
// input BEFORE hashing (DoS guard), returning false without touching argon2.
func TestVerifyRejectsOverLength(t *testing.T) {
	h, err := Hash("short")
	if err != nil {
		t.Fatal(err)
	}
	if Verify(strings.Repeat("a", MaxPasswordLength+1), h) {
		t.Error("over-length password must not verify")
	}
}
