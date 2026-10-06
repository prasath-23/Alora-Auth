package main

// The perimeter: probes, headers, error envelopes, load shedding, the published
// documents and who may read them, and what the API does with a bad token.

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alora/auth/internal/core/shared/crypto/jwtkeys"
)

func TestHealthEndpoints(t *testing.T) {
	a := newApp(t)
	for _, tc := range []struct{ path, wantStatus string }{
		{"/health", "ok"}, {"/health/ready", "ready"}, {"/health/pressure", "ok"},
	} {
		w := a.get(tc.path)
		expect(t, w, http.StatusOK, tc.path)
		if got := decode(t, w)["status"]; got != tc.wantStatus {
			t.Errorf("%s: status=%v, want %q", tc.path, got, tc.wantStatus)
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	a := newApp(t)
	// Verified on an ERROR response too: headers must not be skipped when a
	// request fails, which is exactly when a browser is most at risk.
	for _, path := range []string{"/health", "/nope", "/api/me"} {
		w := a.get(path)
		for h, want := range map[string]string{
			"Content-Security-Policy":           "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
			"X-Content-Type-Options":            "nosniff",
			"X-Frame-Options":                   "DENY",
			"Referrer-Policy":                   "no-referrer",
			"Cross-Origin-Opener-Policy":        "same-origin",
			"X-Permitted-Cross-Domain-Policies": "none",
		} {
			if got := w.Header().Get(h); got != want {
				t.Errorf("%s: header %s = %q, want %q", path, h, got, want)
			}
		}
		if w.Header().Get("X-Request-Id") == "" {
			t.Errorf("%s: missing X-Request-Id", path)
		}
		if w.Header().Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: HSTS sent outside production", path)
		}
	}
}

type pressureStub bool

func (p pressureStub) Overloaded() bool { return bool(p) }

// While memory is over its ceiling, the real chain sheds every route — public,
// authenticated (before authentication), the probes, even a miss — with a 503
// that still carries the perimeter's headers.
func TestUnderPressureShedsEveryRoute(t *testing.T) {
	a := newAppWith(t, nil, func(m *modules) { m.pressure = pressureStub(true) })
	for _, path := range []string{"/health", "/.well-known/jwks.json", "/api/admin/users", "/oauth/authorize", "/no-such-route"} {
		w := a.get(path)
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "10" {
			t.Errorf("%s: %d, Retry-After %q; want 503 and 10", path, w.Code, w.Header().Get("Retry-After"))
			continue
		}
		body := decode(t, w)
		if body["error"] != "Internal Server Error" || body["reqId"] != w.Header().Get("X-Request-Id") {
			t.Errorf("%s: body %s, want the ≥500 envelope carrying the request id", path, w.Body.String())
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: the shed response lost the security headers", path)
		}
	}
}

func TestNotFoundAndMethodNotAllowed(t *testing.T) {
	a := newApp(t)
	w := a.get("/definitely-not-a-route")
	expect(t, w, http.StatusNotFound, "unknown route")
	// The 404 envelope deliberately omits reqId.
	if strings.Contains(w.Body.String(), "reqId") {
		t.Errorf("404 body must not contain reqId: %s", w.Body.String())
	}
	expect(t, a.post("/health", nil), http.StatusMethodNotAllowed, "wrong verb")
	// The v1 routes are gone, not aliased.
	for _, old := range []string{"/auth/jwks", "/auth/session", "/auth/authorize", "/auth/token", "/auth/refresh", "/admin/users"} {
		if w := a.get(old); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("retired route %s answered %d", old, w.Code)
		}
	}
}

func TestJWKSPublishesOnlyPublicKeys(t *testing.T) {
	a := newApp(t)
	w := a.get("/.well-known/jwks.json")
	expect(t, w, http.StatusOK, "jwks")
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=300, must-revalidate" {
		t.Errorf("Cache-Control = %q", cc)
	}
	body := w.Body.String()
	// "d" is the RSA PRIVATE exponent; its presence would leak the signing key.
	for _, leak := range []string{`"d":`, `"p":`, `"q":`, "PRIVATE"} {
		if strings.Contains(body, leak) {
			t.Fatalf("SECURITY: JWKS leaked private material %q: %s", leak, body)
		}
	}
	for _, want := range []string{`"kty":"RSA"`, `"alg":"RS256"`, `"use":"sig"`, `"kid":"test-kid"`} {
		if !strings.Contains(body, want) {
			t.Errorf("JWKS missing %s: %s", want, body)
		}
	}
}

func TestDiscoveryDocument(t *testing.T) {
	a := newApp(t)
	w := a.get("/.well-known/openid-configuration")
	expect(t, w, http.StatusOK, "discovery")
	var d struct {
		Issuer                string   `json:"issuer"`
		AuthorizationEndpoint string   `json:"authorization_endpoint"`
		TokenEndpoint         string   `json:"token_endpoint"`
		JWKSURI               string   `json:"jwks_uri"`
		RevocationEndpoint    string   `json:"revocation_endpoint"`
		IntrospectionEndpoint string   `json:"introspection_endpoint"`
		ResponseTypes         []string `json:"response_types_supported"`
		GrantTypes            []string `json:"grant_types_supported"`
		AuthMethods           []string `json:"token_endpoint_auth_methods_supported"`
		Challenges            []string `json:"code_challenge_methods_supported"`
		Algs                  []string `json:"id_token_signing_alg_values_supported"`
		ISSParam              bool     `json:"authorization_response_iss_parameter_supported"`
	}
	decodeInto(t, w, &d)
	if d.Issuer != testIssuer || d.AuthorizationEndpoint != testIssuer+"/oauth/authorize" ||
		d.TokenEndpoint != testIssuer+"/oauth/token" || d.JWKSURI != testIssuer+"/.well-known/jwks.json" ||
		d.RevocationEndpoint != testIssuer+"/oauth/revoke" || d.IntrospectionEndpoint != testIssuer+"/oauth/introspect" {
		t.Errorf("endpoints = %+v", d)
	}
	// It must advertise only what is implemented.
	if !slices.Equal(d.ResponseTypes, []string{"code"}) || !slices.Equal(d.AuthMethods, []string{"client_secret_basic"}) ||
		!slices.Equal(d.Challenges, []string{"S256"}) || !slices.Equal(d.Algs, []string{"RS256"}) ||
		!slices.Equal(d.GrantTypes, []string{"authorization_code", "refresh_token", "client_credentials"}) || !d.ISSParam {
		t.Errorf("capabilities = %+v", d)
	}
}

// Only the published documents are readable cross-origin, by anyone, without
// credentials. Nothing else answers CORS at all — there is no origin list to get
// wrong.
func TestCORSOnlyOnWellKnown(t *testing.T) {
	a := newApp(t)
	for _, path := range []string{"/.well-known/jwks.json", "/.well-known/openid-configuration"} {
		w := a.get(path, header("Origin", "https://any.example"))
		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s: ACAO %q, want *", path, w.Header().Get("Access-Control-Allow-Origin"))
		}
		if w.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("SECURITY: %s allows credentials cross-origin", path)
		}
		if w.Header().Get("Cross-Origin-Resource-Policy") != "cross-origin" {
			t.Errorf("%s: CORP %q, want cross-origin", path, w.Header().Get("Cross-Origin-Resource-Policy"))
		}
	}
	pre := a.send(http.MethodOptions, "/.well-known/jwks.json", nil,
		header("Origin", "https://any.example"), header("Access-Control-Request-Method", "GET"))
	expect(t, pre, http.StatusNoContent, "well-known preflight")

	for _, path := range []string{"/health", "/api/me", "/auth/login/password", "/oauth/token"} {
		w := a.get(path, header("Origin", "http://localhost:5173"))
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("SECURITY: %s answered CORS for an origin: %q", path, got)
		}
		opt := a.send(http.MethodOptions, path, nil, header("Origin", "https://evil.example"),
			header("Access-Control-Request-Method", "POST"))
		if opt.Code < 400 || opt.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("SECURITY: preflight to %s answered %d with ACAO %q", path, opt.Code, opt.Header().Get("Access-Control-Allow-Origin"))
		}
	}
}

// Every one of these must be rejected with 401 before any handler runs.
func TestAPIRejectsBadCredentials(t *testing.T) {
	a := newApp(t)
	cases := []struct{ name, header string }{
		{"no header", ""},
		{"garbage token", "Bearer garbage"},
		{"empty bearer", "Bearer "},
		{"wrong scheme", "Basic YWJjOjEyMw=="},
		{"bare token, no scheme", "eyJhbGciOiJSUzI1NiJ9.e30.x"},
		// alg=none is THE classic JWT forgery; verification pins RS256.
		{"alg=none forgery", "Bearer eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.eyJzdWIiOiJhIiwidGVuYW50X2lkIjoiYiIsInNpZCI6ImMiLCJhdWQiOiJhcHAtY2VudHJhbCIsImV4cCI6OTk5OTk5OTk5OX0."},
		{"HS256 forgery", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJzdWIiOiJhIiwidGVuYW50X2lkIjoiYiIsInNpZCI6ImMiLCJhdWQiOiJhcHAtY2VudHJhbCIsImV4cCI6OTk5OTk5OTk5OX0.c2ln"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var opts []reqOpt
			if tc.header != "" {
				opts = append(opts, header("Authorization", tc.header))
			}
			expect(t, a.get("/api/me", opts...), http.StatusUnauthorized, tc.name)
		})
	}
}

// A validly signed App Central token is still refused when its session does not
// exist — only the database can say so, and it is asked on every request.
func TestSignedTokenWithoutASessionIsRejected(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	tok, err := jwtkeys.SignAccess(m.ID, map[string]any{"tenant_id": co.ID, "email": m.Email, "sid": "00000000-0000-0000-0000-000000000000"},
		15*time.Minute, "app-central")
	if err != nil {
		t.Fatal(err)
	}
	expect(t, a.get("/api/me", bearer(tok)), http.StatusUnauthorized, "token for a session that never existed")

	// A real session, but claimed for another user or another company.
	s := a.login(m)
	other := a.newMember(co, "")
	forged, _ := jwtkeys.SignAccess(other.ID, map[string]any{"tenant_id": co.ID, "email": other.Email, "sid": sessionID(t, s.Access)},
		15*time.Minute, "app-central")
	expect(t, a.get("/api/me", bearer(forged)), http.StatusUnauthorized, "another user's session")
	elsewhere := a.newCompany()
	forged2, _ := jwtkeys.SignAccess(m.ID, map[string]any{"tenant_id": elsewhere.ID, "email": m.Email, "sid": sessionID(t, s.Access)},
		15*time.Minute, "app-central")
	expect(t, a.get("/api/me", bearer(forged2)), http.StatusUnauthorized, "the session claimed for another company")
	// And a token with no session at all.
	nosid, _ := jwtkeys.SignAccess(m.ID, map[string]any{"tenant_id": co.ID, "email": m.Email}, 15*time.Minute, "app-central")
	expect(t, a.get("/api/me", bearer(nosid)), http.StatusUnauthorized, "no sid")
	// The genuine one works.
	expect(t, a.get("/api/me", bearer(s.Access)), http.StatusOK, "genuine")
}

// sessionID reads the sid claim of a token without verifying it (test only).
func sessionID(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := decodeSegment(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	sid, _ := claims["sid"].(string)
	return sid
}
