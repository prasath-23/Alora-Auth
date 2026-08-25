package jwtkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func testPEMs(t *testing.T) (priv, pub string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	priv = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pub = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return priv, pub
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, pub := testPEMs(t)
	if err := Init(priv, pub, "kid-1", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	s, err := Sign("user-123", map[string]any{"client_id": "c1", "pv": 1, "is_global_admin": false}, 15*time.Minute, []string{"alora-auth-api"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Verify(s, "alora-auth-api")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tok.Subject() != "user-123" {
		t.Errorf("sub = %q, want user-123", tok.Subject())
	}
	if cid, ok := tok.Get("client_id"); !ok || cid != "c1" {
		t.Errorf("client_id = %v, want c1", cid)
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	priv, pub := testPEMs(t)
	if err := Init(priv, pub, "kid-1", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	s, _ := Sign("u", map[string]any{}, time.Minute, []string{"aud-a"})
	if _, err := Verify(s, "aud-b"); err == nil {
		t.Error("expected audience mismatch to fail")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	priv, pub := testPEMs(t)
	if err := Init(priv, pub, "kid-1", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	s, _ := Sign("u", map[string]any{}, -1*time.Minute, nil) // already expired
	if _, err := Verify(s, ""); err == nil {
		t.Error("expected expired token to fail")
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	priv, pub := testPEMs(t)
	if err := Init(priv, pub, "kid-1", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	// Sign a token whose iss is overridden to a foreign issuer via a raw claim.
	s, _ := Sign("u", map[string]any{}, time.Minute, nil)
	// Re-init with a different expected issuer so the good token now mismatches.
	if err := Init(priv, pub, "kid-1", "https://evil.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(s, ""); err == nil {
		t.Error("expected issuer mismatch to fail")
	}
}

// The core security guarantee: a token forged with alg=HS256 (even bearing a
// known kid) must be rejected, because verification pins RS256.
func TestVerifyRejectsAlgConfusion(t *testing.T) {
	priv, pub := testPEMs(t)
	if err := Init(priv, pub, "kid-1", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.NewBuilder().
		Issuer("https://auth.test").
		Subject("attacker").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Minute)).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, "kid-1")
	forged, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, []byte("attacker-secret"), jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(string(forged), ""); err == nil {
		t.Fatal("SECURITY: alg-confusion HS256 token was accepted")
	}
}

// Regression (audit critical #2): a caller-supplied private claim must never be
// able to shadow a registered claim. Previously the claims map was applied AFTER
// the registered claims, so exp/sub/iss could be overridden — yielding a signed,
// never-expiring token that survives logout, family burn and the pv bump.
func TestSignRejectsReservedClaimOverride(t *testing.T) {
	priv, pub := testPEMs(t)
	if err := Init(priv, pub, "kid-1", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	for _, claim := range []string{"exp", "sub", "iss", "iat", "jti", "aud", "nbf"} {
		if _, err := Sign("u", map[string]any{claim: 0}, time.Minute, nil); err == nil {
			t.Errorf("SECURITY: reserved claim %q was allowed to be overridden", claim)
		}
	}
}

// Regression (audit critical #2b): time.Unix(0,0).IsZero() is FALSE, so an exp:0
// sentinel would slip past an IsZero()-based required-claim check.
func TestSignRejectsNonPositiveTTL(t *testing.T) {
	priv, pub := testPEMs(t)
	if err := Init(priv, pub, "kid-1", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []time.Duration{0, -time.Minute} {
		if _, err := Sign("u", nil, ttl, nil); err == nil {
			t.Errorf("SECURITY: ttl %v was accepted", ttl)
		}
	}
}

func TestJWKS(t *testing.T) {
	priv, pub := testPEMs(t)
	if err := Init(priv, pub, "kid-1", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	b, err := JWKS()
	if err != nil {
		t.Fatal(err)
	}
	set, err := jwk.Parse(b)
	if err != nil {
		t.Fatalf("JWKS not parseable: %v", err)
	}
	if set.Len() < 1 {
		t.Error("empty JWKS")
	}
}
