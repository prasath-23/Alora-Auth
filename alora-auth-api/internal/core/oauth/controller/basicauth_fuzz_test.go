package controller

import (
	"encoding/base64"
	"testing"

	"github.com/alora/auth/internal/core/shared"
)

// client_secret_basic is decoded from untrusted input before anything is
// looked up: it never panics, and a credential it accepts has a non-empty id
// and secret the database can store.
func FuzzBasicAuth(f *testing.F) {
	enc := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, s := range []string{"", "Basic", enc("id:secret"), enc("id%3Aa:b%3Ac"), enc(":secret"), enc("id:"),
		enc("a\x00b:c"), enc("\xff:c"), enc("a%zz:b"), enc("a%00:b"), "Bearer x", "basic  " + enc("x:y")[6:]} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		id, secret, ok := basicAuth(header)
		if !ok {
			return
		}
		if id == "" || secret == "" || !shared.Storable(id) || !shared.Storable(secret) {
			t.Fatalf("basicAuth(%q) accepted id %q and secret %q", header, id, secret)
		}
	})
}
