package jwtkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
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
	return pemPair(t, key)
}

func initTest(t *testing.T) (priv, pub string) {
	t.Helper()
	priv, pub = testPEMs(t)
	if err := Init(priv, pub, "kid-1", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// forge signs claims with the active key but a caller-chosen header, for the
// cases the real signer refuses to produce.
func forge(t *testing.T, typ, kid string, exp time.Time, aud []string) string {
	t.Helper()
	b := jwt.NewBuilder().Issuer("https://auth.test").Subject("u").IssuedAt(time.Now()).Expiration(exp)
	if aud != nil {
		b = b.Audience(aud)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	if kid != "" {
		_ = hdrs.Set(jws.KeyIDKey, kid)
	}
	if typ != "" {
		_ = hdrs.Set(jws.TypeKey, typ)
	}
	mu.RLock()
	priv := keys[activeKid].priv
	mu.RUnlock()
	s, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(s)
}

func header(t *testing.T, token string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestSignVerifyRoundTrip(t *testing.T) {
	initTest(t)
	s, err := SignAccess("user-123", map[string]any{"tenant_id": "c1", "pv": 1}, 15*time.Minute, "product:crm")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := VerifyAccess(s, "product:crm")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tok.Subject() != "user-123" {
		t.Errorf("sub = %q, want user-123", tok.Subject())
	}
	if cid, ok := tok.Get("tenant_id"); !ok || cid != "c1" {
		t.Errorf("tenant_id = %v, want c1", cid)
	}
	if aud := tok.Audience(); len(aud) != 1 || aud[0] != "product:crm" {
		t.Errorf("aud = %v, want exactly [product:crm]", aud)
	}
	if h := header(t, s); h["typ"] != "at+jwt" || h["kid"] != "kid-1" || h["alg"] != "RS256" {
		t.Errorf("header = %v, want typ at+jwt, kid kid-1, RS256", h)
	}
}

// Neither side may skip the audience: a token that names no recipient, or a
// verifier that checks for none, would accept a token minted for anyone.
func TestAudienceIsMandatory(t *testing.T) {
	initTest(t)
	if _, err := SignAccess("u", nil, time.Minute, ""); err == nil {
		t.Error("SECURITY: signed an access token with no audience")
	}
	if _, err := SignID("u", nil, time.Minute, ""); err == nil {
		t.Error("SECURITY: signed an ID token with no audience")
	}
	s, _ := SignAccess("u", nil, time.Minute, "app-central")
	if _, err := VerifyAccess(s, ""); err == nil {
		t.Error("SECURITY: verified a token without naming the audience")
	}
	// A token with no aud claim at all is refused by an audience-checking verifier.
	if _, err := VerifyAccess(forge(t, TypeAccess, "kid-1", time.Now().Add(time.Minute), nil), "app-central"); err == nil {
		t.Error("SECURITY: accepted a token with no aud claim")
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	initTest(t)
	s, _ := SignAccess("u", nil, time.Minute, "product:crm")
	for _, aud := range []string{"app-central", "product:erp", "product:crm2", "product"} {
		if _, err := VerifyAccess(s, aud); err == nil {
			t.Errorf("SECURITY: a product:crm token verified for %q", aud)
		}
	}
}

// An ID token handed to a product is not a credential for its API, and an access
// token is not proof of a sign-in: each verifier accepts only its own type.
func TestTokenTypesAreNotInterchangeable(t *testing.T) {
	initTest(t)
	id, err := SignID("u", map[string]any{"nonce": "n"}, time.Minute, "product-id")
	if err != nil {
		t.Fatal(err)
	}
	if h := header(t, id); h["typ"] != "JWT" {
		t.Errorf("ID token typ = %v, want JWT", h["typ"])
	}
	if _, err := VerifyAccess(id, "product-id"); err == nil {
		t.Error("SECURITY: an ID token verified as an access token")
	}
	if _, err := VerifyID(id, "product-id"); err != nil {
		t.Errorf("ID token failed its own verifier: %v", err)
	}
	at, _ := SignAccess("u", nil, time.Minute, "product-id")
	if _, err := VerifyID(at, "product-id"); err == nil {
		t.Error("SECURITY: an access token verified as an ID token")
	}
	// No typ at all is neither.
	if _, err := VerifyAccess(forge(t, "", "kid-1", time.Now().Add(time.Minute), []string{"a"}), "a"); err == nil {
		t.Error("SECURITY: a token with no typ verified as an access token")
	}
	// RFC 9068 lets the media type carry its prefix, and compares without case.
	if _, err := VerifyAccess(forge(t, "application/AT+JWT", "kid-1", time.Now().Add(time.Minute), []string{"a"}), "a"); err != nil {
		t.Errorf("application/at+jwt rejected: %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	initTest(t)
	s := forge(t, TypeAccess, "kid-1", time.Now().Add(-time.Minute), []string{"a"})
	if _, err := VerifyAccess(s, "a"); err == nil {
		t.Error("expected expired token to fail")
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	priv, pub := initTest(t)
	s, _ := SignAccess("u", nil, time.Minute, "a")
	// Re-init with a different expected issuer so the good token now mismatches.
	if err := Init(priv, pub, "kid-1", "https://evil.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccess(s, "a"); err == nil {
		t.Error("expected issuer mismatch to fail")
	}
}

func TestVerifyRejectsMissingKid(t *testing.T) {
	initTest(t)
	if _, err := VerifyAccess(forge(t, TypeAccess, "", time.Now().Add(time.Minute), []string{"a"}), "a"); err == nil {
		t.Error("a token without a kid verified")
	}
}

// The core security guarantee: a token forged with alg=HS256 (even bearing a
// known kid and the right typ) must be rejected, because verification pins
// RS256.
func TestVerifyRejectsAlgConfusion(t *testing.T) {
	initTest(t)
	tok, err := jwt.NewBuilder().Issuer("https://auth.test").Subject("attacker").Audience([]string{"a"}).
		IssuedAt(time.Now()).Expiration(time.Now().Add(time.Minute)).Build()
	if err != nil {
		t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, "kid-1")
	_ = hdrs.Set(jws.TypeKey, TypeAccess)
	forged, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, []byte("attacker-secret"), jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccess(string(forged), "a"); err == nil {
		t.Fatal("SECURITY: alg-confusion HS256 token was accepted")
	}
	// alg=none: header and claims with an empty signature.
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt","kid":"kid-1"}`))
	c := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"iss":"https://auth.test","sub":"x","aud":"a","iat":%d,"exp":%d}`, time.Now().Unix(), time.Now().Add(time.Hour).Unix())))
	if _, err := VerifyAccess(h+"."+c+".", "a"); err == nil {
		t.Fatal("SECURITY: alg=none token was accepted")
	}
}

// Regression (audit critical #2): a caller-supplied private claim must never be
// able to shadow a registered claim. Previously the claims map was applied AFTER
// the registered claims, so exp/sub/iss could be overridden — yielding a signed,
// never-expiring token that survives logout and revocation.
func TestSignRejectsReservedClaimOverride(t *testing.T) {
	initTest(t)
	for _, claim := range []string{"exp", "sub", "iss", "iat", "jti", "aud", "nbf"} {
		if _, err := SignAccess("u", map[string]any{claim: 0}, time.Minute, "a"); err == nil {
			t.Errorf("SECURITY: reserved claim %q was allowed to be overridden", claim)
		}
	}
}

func TestSignRejectsNonPositiveTTL(t *testing.T) {
	initTest(t)
	for _, ttl := range []time.Duration{0, -time.Minute} {
		if _, err := SignAccess("u", nil, ttl, "a"); err == nil {
			t.Errorf("SECURITY: ttl %v was accepted", ttl)
		}
	}
}

// Rotation: the new key signs, the old one still verifies what it signed, and
// both are published. Dropping the old key then refuses its tokens.
func TestVerifyOnlyKeyOverlapsRotation(t *testing.T) {
	oldPriv, oldPub := testPEMs(t)
	if err := Init(oldPriv, oldPub, "old", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	signedByOld, _ := SignAccess("u", nil, time.Minute, "a")

	newPriv, newPub := testPEMs(t)
	if err := Init(newPriv, newPub, "new", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	if err := AddVerifyKey("old", oldPub); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccess(signedByOld, "a"); err != nil {
		t.Errorf("a token signed before the rotation stopped verifying: %v", err)
	}
	signedByNew, _ := SignAccess("u", nil, time.Minute, "a")
	if h := header(t, signedByNew); h["kid"] != "new" {
		t.Errorf("new tokens signed with kid %v, want new", h["kid"])
	}
	b, _ := JWKS()
	set, err := jwk.Parse(b)
	if err != nil || set.Len() != 2 {
		t.Fatalf("JWKS has %d keys (%v), want the signer and the verify-only key", set.Len(), err)
	}

	// The verify-only key never signs: Init resets the keystore to the new key.
	if err := Init(newPriv, newPub, "new", "https://auth.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccess(signedByOld, "a"); err == nil {
		t.Error("a retired key's token still verified after the key was dropped")
	}
}

func TestAddVerifyKeyRefusesDuplicatesAndWeakKeys(t *testing.T) {
	_, pub := initTest(t)
	if err := AddVerifyKey("kid-1", pub); err == nil {
		t.Error("a second key under the signing key's kid was accepted")
	}
	if err := AddVerifyKey("", pub); err == nil {
		t.Error("a verify-only key without a kid was accepted")
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, weakPub := pemPair(t, weak)
	if err := AddVerifyKey("weak", weakPub); err == nil || !strings.Contains(err.Error(), "minimum is 2048") {
		t.Errorf("a 1024-bit verify-only key: err %v, want a refusal naming the floor", err)
	}
}

func TestJWKSPublishesOnlyPublicMaterial(t *testing.T) {
	initTest(t)
	b, err := JWKS()
	if err != nil {
		t.Fatal(err)
	}
	set, err := jwk.Parse(b)
	if err != nil {
		t.Fatalf("JWKS not parseable: %v", err)
	}
	if set.Len() != 1 {
		t.Errorf("JWKS has %d keys, want 1", set.Len())
	}
	for _, leak := range []string{`"d":`, `"p":`, `"q":`, `"dp":`} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("SECURITY: JWKS leaked private material %s", leak)
		}
	}
}

// A weak key is not a configuration preference. The public half is served from
// /.well-known/jwks.json, so anything short enough to factor hands an attacker
// the ability to mint valid tokens for any user in any company.
func TestInitRejectsUndersizedKey(t *testing.T) {
	// 1024 and the boundary case. Anything smaller cannot be constructed here --
	// Go's own crypto/rsa refuses to generate below 1024 -- but such a key can
	// still arrive as a PEM from an old openssl, which is what the floor guards
	// against.
	for _, bits := range []int{1024, 2047} {
		t.Run(fmt.Sprintf("%d-bit", bits), func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			privPEM, pubPEM := pemPair(t, key)

			if err := Init(privPEM, pubPEM, "weak-kid", "https://auth.test"); err == nil {
				t.Fatalf("accepted a %d-bit signing key; it would be published via JWKS "+
					"and can be factored into a token-forging capability", bits)
			} else if !strings.Contains(err.Error(), "minimum is 2048") {
				t.Fatalf("error %q does not say what the requirement is", err)
			}
		})
	}
}

// Two valid keys that are not a pair produce a system where logins succeed and
// every request afterwards is rejected — a failure whose symptom points nowhere
// near the cause.
func TestInitRejectsMismatchedPair(t *testing.T) {
	a, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	privPEM, _ := pemPair(t, a)
	_, pubPEM := pemPair(t, b)

	if err := Init(privPEM, pubPEM, "mismatch-kid", "https://auth.test"); err == nil {
		t.Fatal("accepted a public key that is not the private key's counterpart")
	} else if !strings.Contains(err.Error(), "counterpart") {
		t.Fatalf("error %q does not identify the mismatch", err)
	}
}

func pemPair(t *testing.T, key *rsa.PrivateKey) (privPEM, pubPEM string) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}
