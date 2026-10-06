package middlewares

import (
	"encoding/base64"
	"testing"
)

// The budget key a Basic credential claims is read from untrusted input before
// anything authenticates it: it never panics, and it is never longer than a
// client id can be — so a caller cannot grow the limiter's memory with keys.
func FuzzBasicClientID(f *testing.F) {
	for _, s := range []string{"", "Basic", "Basic !!!", "Basic " + base64.StdEncoding.EncodeToString([]byte("id:secret")),
		"basic " + base64.StdEncoding.EncodeToString([]byte("a%zz:b")), "Bearer x", "Basic " + base64.StdEncoding.EncodeToString([]byte("%00:x"))} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		if id := BasicClientID(header); len(id) > 64 {
			t.Fatalf("BasicClientID gave a %d-byte key", len(id))
		}
	})
}
