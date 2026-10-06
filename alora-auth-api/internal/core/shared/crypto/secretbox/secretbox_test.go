package secretbox

import (
	"bytes"
	"errors"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestSealOpenRoundTrip(t *testing.T) {
	box, err := New(key(1), "k1")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal([]byte("client-secret"), []byte("conn-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("client-secret")) {
		t.Fatal("SECURITY: the plaintext is visible in the ciphertext")
	}
	got, err := box.Open("k1", sealed, []byte("conn-1"))
	if err != nil || string(got) != "client-secret" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	// A fresh nonce per seal: the same secret never seals to the same bytes.
	again, _ := box.Seal([]byte("client-secret"), []byte("conn-1"))
	if bytes.Equal(sealed, again) {
		t.Error("two seals of the same plaintext are identical: the nonce is not fresh")
	}
}

// A ciphertext moved to another connection's row, opened with another key, or
// tampered with must not open.
func TestOpenRefusesEverythingElse(t *testing.T) {
	box, _ := New(key(1), "k1")
	sealed, _ := box.Seal([]byte("s3cret"), []byte("conn-1"))

	if _, err := box.Open("k1", sealed, []byte("conn-2")); err == nil {
		t.Error("SECURITY: a ciphertext opened under another connection's id")
	}
	other, _ := New(key(2), "k1")
	if _, err := other.Open("k1", sealed, []byte("conn-1")); err == nil {
		t.Error("SECURITY: a ciphertext opened under another key")
	}
	if _, err := box.Open("k2", sealed, []byte("conn-1")); err == nil {
		t.Error("a ciphertext stamped with another key id was opened")
	}
	flipped := append([]byte{}, sealed...)
	flipped[len(flipped)-1] ^= 1
	if _, err := box.Open("k1", flipped, []byte("conn-1")); err == nil {
		t.Error("SECURITY: a tampered ciphertext opened")
	}
	if _, err := box.Open("k1", sealed[:5], []byte("conn-1")); err == nil {
		t.Error("a truncated ciphertext opened")
	}
}

func TestNewValidatesKey(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := New(make([]byte, n), "k1"); err == nil {
			t.Errorf("a %d-byte key was accepted", n)
		}
	}
	if _, err := New(key(1), ""); err == nil {
		t.Error("a key without an id was accepted")
	}
}

// With no key configured the box exists but refuses to do anything, so a
// deployment without SSO starts and fails loudly only if SSO is used.
func TestNoKeyRefusesEverything(t *testing.T) {
	box, err := New(nil, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if box.Enabled() {
		t.Error("a box with no key reports itself enabled")
	}
	if _, err := box.Seal([]byte("x"), nil); !errors.Is(err, ErrNoKey) {
		t.Errorf("Seal without a key: %v, want ErrNoKey", err)
	}
	if _, err := box.Open("k1", []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), nil); !errors.Is(err, ErrNoKey) {
		t.Errorf("Open without a key: %v, want ErrNoKey", err)
	}
}
