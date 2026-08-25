package main

// Integration tests exercise the REAL router, middleware chain and database, so
// they cannot drift from production the way a hand-rolled test harness would.
// Skipped unless ALORA_TEST_DB points at a migrated Postgres, keeping
// `go test ./...` green on a machine without Docker:
//
//	ALORA_TEST_DB=postgres://postgres:test@127.0.0.1:55533/alora_test go test ./cmd/api -v

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alora/auth/internal/admin"
	"github.com/alora/auth/internal/auth"
	"github.com/alora/auth/internal/config"
	"github.com/alora/auth/internal/crypto/jwtkeys"
	"github.com/alora/auth/internal/invitation"
	"github.com/alora/auth/internal/mailer"
	"github.com/alora/auth/internal/oauth"
	"github.com/alora/auth/internal/platform/audit"
	"github.com/alora/auth/internal/platform/database"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/alora/auth/internal/platform/logger"
	"github.com/alora/auth/internal/reset"
	"github.com/alora/auth/internal/session"
	"github.com/gin-gonic/gin"
)

func testEnv(t *testing.T) {
	t.Helper()
	dsn := os.Getenv("ALORA_TEST_DB")
	if dsn == "" {
		t.Skip("ALORA_TEST_DB not set; skipping integration tests")
	}
	priv, pub := os.Getenv("ALORA_TEST_PRIV"), os.Getenv("ALORA_TEST_PUB")
	if priv == "" || pub == "" {
		t.Skip("ALORA_TEST_PRIV/PUB not set; skipping integration tests")
	}
	t.Setenv("NODE_ENV", "test")
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("JWT_PRIVATE_KEY", priv)
	t.Setenv("JWT_PUBLIC_KEY", pub)
	t.Setenv("JWT_KEY_ID", "test-kid")
	t.Setenv("JWT_ISSUER", "https://auth.alora.test")
	t.Setenv("COOKIE_SECRET", "0123456789012345678901234567890123456789")
	t.Setenv("GOOGLE_CLIENT_ID", "gid")
	t.Setenv("GOOGLE_CLIENT_SECRET", "gsecret")
	t.Setenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:3099/auth/google/callback")
}

func newTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	testEnv(t)
	gin.SetMode(gin.TestMode)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := jwtkeys.Init(cfg.JWT.PrivateKeyPEM, cfg.JWT.PublicKeyPEM, cfg.JWT.KeyID, cfg.JWT.Issuer); err != nil {
		t.Fatalf("jwtkeys: %v", err)
	}
	pool, err := database.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("database: %v", err)
	}
	t.Cleanup(pool.Close)

	q := sqlc.New(pool)
	authRepo := auth.NewRepo(q)
	authSvc := auth.NewService(authRepo, cfg.JWT.AccessTTL, cfg.JWT.APIAudience)
	jar := httpx.NewCookieJar(cfg.Cookie.Domain, cfg.IsProd, cfg.Cookie.Secret)
	sessSvc := session.NewService(pool, q, cfg.JWT.RefreshTTL)
	oauthH := oauth.NewHandler(oauth.NewService(q), authSvc, sessSvc, jar)
	mail := mailer.New(cfg.Mail)
	auditLog := audit.New(audit.NewRepo(q), logger.New(false))
	inviteH := invitation.NewHandler(invitation.NewService(pool, q, cfg.FrontendURL), mail, auditLog, q)
	resetH := reset.NewHandler(reset.NewService(pool, q, cfg.FrontendURL), mail, auditLog)
	adminH := admin.New(pool, q, auditLog)
	googleH := oauth.NewGoogleHandler(oauth.NewService(q), oauth.GoogleConfig{
		ClientID: cfg.Google.ClientID, ClientSecret: cfg.Google.ClientSecret,
		RedirectURI: cfg.Google.RedirectURI, FrontendURL: cfg.FrontendURL,
	}, jar)
	r, err := newRouter(cfg, logger.New(false), q, authRepo, oauthH, inviteH, resetH, adminH, googleH)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	return r
}

func do(r *gin.Engine, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestHealthEndpoints(t *testing.T) {
	r := newTestRouter(t)
	for _, tc := range []struct{ path, wantStatus string }{
		{"/health", "ok"}, {"/health/ready", "ready"}, {"/health/pressure", "ok"},
	} {
		w := do(r, http.MethodGet, tc.path, nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", tc.path, w.Code)
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["status"] != tc.wantStatus {
			t.Errorf("%s: status=%v, want %q", tc.path, body["status"], tc.wantStatus)
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	r := newTestRouter(t)
	// Verified on an ERROR response too: headers must not be skipped when a
	// request fails, which is exactly when a browser is most at risk.
	for _, path := range []string{"/health", "/nope"} {
		w := do(r, http.MethodGet, path, nil)
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
	}
}

func TestHSTSOnlyInProd(t *testing.T) {
	r := newTestRouter(t) // NODE_ENV=test
	if h := do(r, http.MethodGet, "/health", nil).Header().Get("Strict-Transport-Security"); h != "" {
		t.Errorf("HSTS must not be sent outside production, got %q", h)
	}
}

func TestNotFoundAndMethodNotAllowed(t *testing.T) {
	r := newTestRouter(t)

	w := do(r, http.MethodGet, "/definitely-not-a-route", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown route: %d, want 404", w.Code)
	}
	// The 404 envelope deliberately omits reqId (Fastify parity).
	if strings.Contains(w.Body.String(), "reqId") {
		t.Errorf("404 body must not contain reqId: %s", w.Body.String())
	}

	if w := do(r, http.MethodPost, "/health", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("wrong verb: %d, want 405", w.Code)
	}
}

func TestJWKSExposesOnlyPublicKeyMaterial(t *testing.T) {
	r := newTestRouter(t)
	w := do(r, http.MethodGet, "/auth/jwks", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
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
	for _, want := range []string{`"kty":"RSA"`, `"alg":"RS256"`, `"use":"sig"`, `"kid":`} {
		if !strings.Contains(body, want) {
			t.Errorf("JWKS missing %s: %s", want, body)
		}
	}
}

// Every one of these must be rejected with 401.
func TestAdminRouteRejectsBadCredentials(t *testing.T) {
	r := newTestRouter(t)
	cases := []struct{ name, header string }{
		{"no header", ""},
		{"garbage token", "Bearer garbage"},
		{"empty bearer", "Bearer "},
		{"wrong scheme", "Basic YWJjOjEyMw=="},
		{"bare token, no scheme", "eyJhbGciOiJSUzI1NiJ9.e30.x"},
		// alg=none is THE classic JWT forgery; verification pins RS256.
		{"alg=none forgery", "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhIiwiY2xpZW50X2lkIjoiYiIsImV4cCI6OTk5OTk5OTk5OX0."},
		{"HS256 forgery", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIiwiY2xpZW50X2lkIjoiYiIsImV4cCI6OTk5OTk5OTk5OX0.c2ln"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := map[string]string{}
			if tc.header != "" {
				h["Authorization"] = tc.header
			}
			w := do(r, http.MethodGet, "/admin/me/features", h)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("status %d, want 401 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

// A signed-but-unknown user must still fail: the token is cryptographically
// valid, so only the DB freshness check can reject it.
func TestValidSignatureUnknownUserIsRejected(t *testing.T) {
	r := newTestRouter(t)
	tok, err := jwtkeys.Sign("00000000-0000-0000-0000-000000000000",
		map[string]any{"client_id": "no-such-tenant", "pv": 1, "roles": map[string]string{}},
		15*time.Minute, []string{"alora-auth-api"})
	if err != nil {
		t.Fatal(err)
	}
	w := do(r, http.MethodGet, "/admin/me/features", map[string]string{"Authorization": "Bearer " + tok})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for unknown user", w.Code)
	}
}

func TestCORSFailsClosed(t *testing.T) {
	r := newTestRouter(t)

	w := do(r, http.MethodGet, "/health", map[string]string{"Origin": "https://evil.example"})
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("SECURITY: untrusted origin allowed: %q", got)
	}

	w = do(r, http.MethodOptions, "/health", map[string]string{
		"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
	if w.Code != http.StatusForbidden {
		t.Errorf("evil preflight: %d, want 403", w.Code)
	}

	// Dev origins are permitted only because NODE_ENV != production.
	w = do(r, http.MethodGet, "/health", map[string]string{"Origin": "http://localhost:5173"})
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("localhost origin = %q, want echoed", got)
	}
	if !strings.Contains(w.Header().Get("Vary"), "Origin") {
		t.Error("Vary: Origin missing — a shared cache could cross tenants")
	}
	// Credentials + wildcard together would be a catastrophic misconfiguration.
	if w.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Error("SECURITY: wildcard ACAO with credentials")
	}
}
