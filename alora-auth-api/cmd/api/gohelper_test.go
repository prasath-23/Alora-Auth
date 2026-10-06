package main

// The Go helper (alora-auth-go/aloraauth) and App Central agree. The helper
// gets tokens from App Central's real TokenService and its real token endpoint,
// and verifies them — and a person's — with the keys App Central really
// publishes, exactly as a product using it would.

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/prasath-23/Alora-Auth/alora-auth-go/aloraauth"
)

func TestTheGoHelperAgreesWithAppCentral(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(1, "grpc:read", "api:read")
	p := app.products[0]
	web := httptest.NewServer(a.r) // App Central over HTTP: its token endpoint and its keys
	defer web.Close()
	verifier := func(product string) *aloraauth.Verifier {
		t.Helper()
		v, err := aloraauth.NewVerifier(aloraauth.VerifierConfig{
			Issuer: testIssuer, Product: product, JWKSURL: web.URL + "/.well-known/jwks.json",
		})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	v := verifier(p.Key)

	// Over gRPC: the helper's credentials against App Central's TokenService.
	creds, err := aloraauth.ClientCredentials(aloraauth.Config{
		Conn: a.grpcConn(), ClientID: app.id, ClientSecret: app.secret, Product: p.Key, Scopes: []string{"grpc:read"}, Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := creds.Token(t.Context())
	if err != nil {
		t.Fatalf("a token over gRPC: %v", err)
	}
	c, err := v.Verify(t.Context(), tok)
	if err != nil {
		t.Fatalf("the helper refused App Central's token: %v", err)
	}
	if !c.IsApplication() || c.Subject != app.id || c.ClientID != app.id || c.TenantID != app.co.ID ||
		!c.HasScope("grpc:read") || c.HasScope("api:read") || len(c.Roles) != 0 {
		t.Errorf("claims = %+v", c)
	}

	// Over HTTP: the helper's token source against the real token endpoint.
	ht, err := aloraauth.HTTPConfig{
		Issuer: web.URL, ClientID: app.id, ClientSecret: app.secret, Product: p.Key, Scopes: []string{"api:read"},
	}.TokenSource(t.Context()).Token()
	if err != nil {
		t.Fatalf("a token over HTTP: %v", err)
	}
	if c, err := v.Verify(t.Context(), ht.AccessToken); err != nil || !c.HasScope("api:read") || c.HasScope("grpc:read") {
		t.Errorf("the HTTP token: %+v, %v", c, err)
	}

	// A person's product token verifies as a person's.
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	person, err := verifier(l.p.Key).Verify(t.Context(), a.exchange(l.p, a.code(&l, f), f).AccessToken)
	if err != nil || person.IsApplication() || !person.HasRole("Viewer") || person.Email != l.m.Email {
		t.Errorf("a person's token: %+v, %v", person, err)
	}

	// Refused: a token for another product, and App Central's own.
	if _, err := verifier(l.p.Key).Verify(t.Context(), tok); !errors.Is(err, aloraauth.ErrInvalidToken) {
		t.Errorf("SECURITY: a token for one product verified for another: %v", err)
	}
	if _, err := v.Verify(t.Context(), l.s.Access); !errors.Is(err, aloraauth.ErrInvalidToken) {
		t.Errorf("SECURITY: App Central's own token verified for a product: %v", err)
	}
}
