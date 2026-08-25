// Package password wraps argon2id hashing with the project's exact parameters
// and the anti-enumeration primitives the login path relies on.
package password

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"unicode/utf16"

	"github.com/alexedwards/argon2id"
)

// MaxPasswordLength is counted in UTF-16 code units to match the Node
// implementation's String.length semantics exactly (parity).
const MaxPasswordLength = 512

// ErrPasswordTooLong is returned by Hash for over-length input.
var ErrPasswordTooLong = errors.New("password: too long")

// argon2id parameters — MUST match MIGRATION_SPEC §2 byte-for-byte.
var params = &argon2id.Params{
	Memory:      19456, // KiB (~19 MiB)
	Iterations:  2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// Hash returns a PHC-encoded argon2id hash of plaintext.
func Hash(plaintext string) (string, error) {
	if utf16Len(plaintext) > MaxPasswordLength {
		return "", ErrPasswordTooLong
	}
	return argon2id.CreateHash(plaintext, params)
}

// Verify reports whether plaintext matches the PHC hash. It swallows all errors
// (malformed hash, etc.) → false, so a bad stored hash can never surface as a 500.
//
// Over-length input is rejected BEFORE the expensive argon2 call: an over-length
// password can never match (Hash rejects them at creation), and this closes a DoS
// where an unauthenticated login submits a huge password to force costly hashing
// (codex + agy review consensus).
func Verify(plaintext, hash string) (ok bool) {
	if utf16Len(plaintext) > MaxPasswordLength {
		return false
	}
	// golang.org/x/crypto/argon2 PANICS (does not error) on some malformed stored
	// hashes — e.g. t=0, p=0, or an empty key segment. This function's bool-only
	// signature promises totality, so a corrupt row must degrade to "no match"
	// rather than crash the request goroutine.
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	match, err := argon2id.ComparePasswordAndHash(plaintext, hash)
	if err != nil {
		return false
	}
	return match
}

func utf16Len(s string) int {
	return len(utf16.Encode([]rune(s)))
}

var (
	dummyMu   sync.Mutex
	dummyHash string
)

// DummyHash returns a stable argon2id hash used to equalize timing on the
// unknown-user login path (anti-enumeration): the service always runs a Verify,
// against the real hash if the user exists or against this dummy if not, so the
// two paths are indistinguishable by timing. Computed once, lazily.
// It caches ONLY on success (a sync.Once would latch a failed/panicked attempt
// as the permanent empty value, silently reopening the enumeration oracle with
// no error anywhere).
func DummyHash() string {
	dummyMu.Lock()
	defer dummyMu.Unlock()
	if dummyHash != "" {
		return dummyHash
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "" // caller still performs a Verify; it returns false either way
	}
	h, err := argon2id.CreateHash(hex.EncodeToString(b), params)
	if err != nil {
		return ""
	}
	dummyHash = h
	return dummyHash
}

// Warm precomputes the dummy hash so the FIRST unknown-user login does not pay
// the argon2 cost inline (which would make first-use timing distinguishable from
// a real verify). main must call this once at startup (codex review).
func Warm() { _ = DummyHash() }
