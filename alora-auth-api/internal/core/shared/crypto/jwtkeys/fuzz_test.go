package jwtkeys

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// initFuzz installs a fresh signing key for a fuzz run.
func initFuzz(f *testing.F) {
	f.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		f.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		f.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	if err := Init(string(privPEM), string(pubPEM), "kid-fuzz", "https://auth.test"); err != nil {
		f.Fatal(err)
	}
}

// decodedSegments is a token's three segments decoded, or nil when any fails:
// what the signature actually covers.
func decodedSegments(tok string) [][]byte {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([][]byte, 0, 3)
	for _, p := range parts {
		b, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return nil
		}
		out = append(out, b)
	}
	return out
}

// No string verifies unless this issuer signed exactly its content for the
// audience: not arbitrary input, and no alteration of a real token. (Changing
// only the unused low bits of a segment's last character decodes to the same
// bytes, so the same signed content — that alone may still verify.)
func FuzzVerifyAccessRefusesEverythingItDidNotSign(f *testing.F) {
	initFuzz(f)
	tok, err := SignAccess("user-1", map[string]any{"tenant_id": "t-1", "sid": "s-1"}, time.Hour, "app-central")
	if err != nil {
		f.Fatal(err)
	}
	other, err := SignAccess("user-1", map[string]any{"tenant_id": "t-1", "sid": "s-1"}, time.Hour, "product:CRM")
	if err != nil {
		f.Fatal(err)
	}
	original := decodedSegments(tok)
	f.Add("", 0, byte('A'))
	f.Add("garbage", 1, byte('.'))
	f.Add(other, len(tok)-1, byte('x'))
	f.Add(tok[:len(tok)-5], 10, byte('='))
	f.Add(strings.Replace(tok, ".", "..", 1), 3, byte(0))
	f.Fuzz(func(t *testing.T, s string, pos int, b byte) {
		if s != tok {
			if _, err := VerifyAccess(s, "app-central"); err == nil {
				if seg := decodedSegments(s); seg == nil || !sameSegments(seg, original) {
					t.Fatalf("SECURITY: %q verified", s)
				}
			}
		}
		if pos < 0 {
			pos = -pos
		}
		i := pos % len(tok)
		if tok[i] == b {
			return
		}
		m := []byte(tok)
		m[i] = b
		if _, err := VerifyAccess(string(m), "app-central"); err == nil {
			if seg := decodedSegments(string(m)); seg == nil || !sameSegments(seg, original) {
				t.Fatalf("SECURITY: changing byte %d of a token to %q leaves it verifying", i, b)
			}
		}
	})
}

func sameSegments(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
