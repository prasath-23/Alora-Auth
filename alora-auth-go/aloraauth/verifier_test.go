package aloraauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	keyOnce  sync.Once
	testKeys [2]*rsa.PrivateKey
)

// keys are generated once for the whole package: RSA generation is slow.
func rsaKey(t *testing.T, i int) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		for j := range testKeys {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			testKeys[j] = k
		}
	})
	return testKeys[i]
}

// issuerStub is App Central as a product sees it: a discovery document and a
// key set, whose published keys a test can change, counting key fetches.
type issuerStub struct {
	srv       *httptest.Server
	mu        sync.Mutex
	published map[string]*rsa.PrivateKey // kid -> key
	fetches   atomic.Int32
	docIssuer string // what the discovery document claims; "" = the real URL
}

func newIssuer(t *testing.T) *issuerStub {
	t.Helper()
	s := &issuerStub{published: map[string]*rsa.PrivateKey{"k1": rsaKey(t, 0)}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		iss := s.docIssuer
		if iss == "" {
			iss = s.srv.URL
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": s.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		s.fetches.Add(1)
		s.mu.Lock()
		defer s.mu.Unlock()
		keys := []map[string]string{}
		for kid, k := range s.published {
			keys = append(keys, map[string]string{
				"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *issuerStub) publish(keys map[string]*rsa.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.published = keys
}

// sign signs claims under header with key, RS256.
func sign(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// token is a good application token for product INV, changed by edit.
func (s *issuerStub) token(t *testing.T, edit func(h, c map[string]any)) string {
	t.Helper()
	now := time.Now().Unix()
	h := map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "k1"}
	c := map[string]any{
		"iss": s.srv.URL, "sub": "aci_1", "aud": []string{"product:INV"}, "exp": now + 600, "iat": now,
		"jti": "t-1", "client_id": "aci_1", "tenant_id": "co-1", "principal": "client", "scope": "grpc:read mcp:tools",
		"roles": []string{},
	}
	if edit != nil {
		edit(h, c)
	}
	key := rsaKey(t, 0)
	if kid, _ := h["kid"].(string); kid == "k2" {
		key = rsaKey(t, 1)
	}
	return sign(t, key, h, c)
}

func newVerifierFor(t *testing.T, s *issuerStub) *Verifier {
	t.Helper()
	v, err := NewVerifier(VerifierConfig{Issuer: s.srv.URL, Product: "INV"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyAcceptsAGoodToken(t *testing.T) {
	s := newIssuer(t)
	v := newVerifierFor(t, s)
	c, err := v.Verify(context.Background(), s.token(t, nil))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.Subject != "aci_1" || c.ClientID != "aci_1" || c.TenantID != "co-1" || !c.IsApplication() ||
		!c.HasScope("grpc:read") || !c.HasScope("mcp:tools") || c.HasScope("grpc:edit") || c.ID != "t-1" ||
		c.Issuer != s.srv.URL || c.ExpiresAt.IsZero() || c.IssuedAt.IsZero() {
		t.Errorf("claims = %+v", c)
	}
	// A person's token, with its audience as a single string and typ in its
	// media-type form.
	person, err := v.Verify(context.Background(), s.token(t, func(h, c map[string]any) {
		h["typ"] = "application/at+jwt"
		c["aud"] = "product:INV"
		c["principal"], c["scope"], c["roles"], c["email"] = "user", "", []string{"Editor"}, "a@b.test"
	}))
	if err != nil || person.IsApplication() || !person.HasRole("Editor") || person.Email != "a@b.test" || len(person.Scopes) != 0 {
		t.Errorf("a person's token: %+v, %v", person, err)
	}
}

// Every token that is not exactly App Central's access token for this product
// is refused, and the refusal says so (ErrInvalidToken).
func TestVerifyRefusesEveryOtherToken(t *testing.T) {
	s := newIssuer(t)
	v := newVerifierFor(t, s)
	now := time.Now().Unix()
	good := s.token(t, nil)
	parts := strings.Split(good, ".")
	for name, tok := range map[string]string{
		"another product's":  s.token(t, func(_, c map[string]any) { c["aud"] = []string{"product:OTHER"} }),
		"App Central's own":  s.token(t, func(_, c map[string]any) { c["aud"] = "app-central" }),
		"expired":            s.token(t, func(_, c map[string]any) { c["exp"] = now - 120 }),
		"with no expiry":     s.token(t, func(_, c map[string]any) { delete(c, "exp") }),
		"issued later":       s.token(t, func(_, c map[string]any) { c["iat"] = now + 600 }),
		"not valid yet":      s.token(t, func(_, c map[string]any) { c["nbf"] = now + 600 }),
		"another issuer's":   s.token(t, func(_, c map[string]any) { c["iss"] = "https://evil.example" }),
		"with no subject":    s.token(t, func(_, c map[string]any) { delete(c, "sub") }),
		"an ID token":        s.token(t, func(h, _ map[string]any) { h["typ"] = "JWT" }),
		"with no typ":        s.token(t, func(h, _ map[string]any) { delete(h, "typ") }),
		"alg none":           s.token(t, func(h, _ map[string]any) { h["alg"] = "none" }),
		"HS256":              s.token(t, func(h, _ map[string]any) { h["alg"] = "HS256" }),
		"RS512":              s.token(t, func(h, _ map[string]any) { h["alg"] = "RS512" }),
		"an unknown key":     s.token(t, func(h, _ map[string]any) { h["kid"] = "k9" }),
		"with no key id":     s.token(t, func(h, _ map[string]any) { delete(h, "kid") }),
		"tampered":           parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`)) + "." + parts[2],
		"unsigned":           parts[0] + "." + parts[1] + ".",
		"signed by another":  sign(t, rsaKey(t, 1), map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "k1"}, map[string]any{"iss": s.srv.URL}),
		"not a JWT":          "abc",
		"with junk segments": "a.b.c",
	} {
		if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v, want ErrInvalidToken", name, err)
		}
	}
}

// An unknown key id fetches the keys again — at most once a minute — so a new
// signing key is picked up, a retired one dropped, and tokens naming made-up
// keys cannot make the product hammer App Central.
func TestVerifyRefetchesKeysAtMostOnceAMinute(t *testing.T) {
	s := newIssuer(t)
	v := newVerifierFor(t, s)
	clock := time.Now()
	v.now = func() time.Time { return clock }

	if _, err := v.Verify(context.Background(), s.token(t, nil)); err != nil {
		t.Fatal(err)
	}
	if n := s.fetches.Load(); n != 1 {
		t.Fatalf("first use fetched %d times", n)
	}
	for i := 0; i < 5; i++ {
		_, _ = v.Verify(context.Background(), s.token(t, func(h, _ map[string]any) { h["kid"] = "made-up" }))
	}
	if n := s.fetches.Load(); n != 1 {
		t.Errorf("made-up key ids fetched %d times within the minute", n-1)
	}

	// App Central rotates to k2 and retires k1.
	s.publish(map[string]*rsa.PrivateKey{"k2": rsaKey(t, 1)})
	rotated := s.token(t, func(h, _ map[string]any) { h["kid"] = "k2" })
	if _, err := v.Verify(context.Background(), rotated); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a new key within the minute: %v", err)
	}
	clock = clock.Add(61 * time.Second)
	if _, err := v.Verify(context.Background(), rotated); err != nil {
		t.Fatalf("the new key after the minute: %v", err)
	}
	if _, err := v.Verify(context.Background(), s.token(t, nil)); !errors.Is(err, ErrInvalidToken) {
		t.Error("a retired key is still accepted")
	}
}

// Keys come from the discovery document only when it names the configured
// issuer; a failure to reach App Central is retried soon, not after a minute.
func TestVerifyTrustsOnlyItsIssuersDiscovery(t *testing.T) {
	s := newIssuer(t)
	s.docIssuer = "https://evil.example"
	v := newVerifierFor(t, s)
	if _, err := v.Verify(context.Background(), s.token(t, nil)); err == nil || errors.Is(err, ErrInvalidToken) {
		t.Errorf("a discovery document for another issuer: %v", err)
	}
	clock := time.Now()
	v.now = func() time.Time { return clock }
	s.docIssuer = ""
	clock = clock.Add(6 * time.Second)
	if _, err := v.Verify(context.Background(), s.token(t, nil)); err != nil {
		t.Errorf("after App Central answers properly: %v", err)
	}
	if _, err := NewVerifier(VerifierConfig{Issuer: s.srv.URL}); err == nil {
		t.Error("a verifier with no product was built")
	}
}
