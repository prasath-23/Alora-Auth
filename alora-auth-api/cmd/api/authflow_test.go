package main

// End-to-end coverage of the OAuth2 + PKCE login flow and refresh rotation,
// including the attack cases each control exists to stop. Runs against the real
// router and a real Postgres (see integration_test.go for the skip contract).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alora/auth/internal/admin"
	"github.com/alora/auth/internal/auth"
	"github.com/alora/auth/internal/config"
	"github.com/alora/auth/internal/crypto/jwtkeys"
	"github.com/alora/auth/internal/crypto/password"
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
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixture struct {
	r        *gin.Engine
	pool     *pgxpool.Pool
	q        *sqlc.Queries
	userID   string
	clientID string
	product  string
	email    string
	pass     string
	verifier string
	redirect string
}

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk~test-verifier-padding"

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newFlowFixture builds a router plus an isolated tenant/product/user. Each test
// gets unique rows so cases cannot interfere through shared state.
func newFlowFixture(t *testing.T) *fixture {
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
	ctx := context.Background()
	pool, err := database.New(ctx, cfg.DatabaseURL)
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

	f := &fixture{
		r: r, pool: pool, q: q,
		email:    fmt.Sprintf("user-%s@acme.test", randSuffix(t)),
		pass:     "correct horse battery staple",
		verifier: testVerifier,
		redirect: "https://crm.acme.test/callback",
	}
	seed(t, pool, f)
	return f
}

// randSuffix keeps seeded rows unique so parallel/repeated runs cannot collide
// on the tenant-unique indexes.
// queries exposes the sqlc handle so feature-specific tests can build their own
// handlers against the same pool.
func (f *fixture) queries() *sqlc.Queries { return f.q }

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

func seed(t *testing.T, pool *pgxpool.Pool, f *fixture) {
	t.Helper()
	ctx := context.Background()
	hash, err := password.Hash(f.pass)
	if err != nil {
		t.Fatal(err)
	}

	if err := pool.QueryRow(ctx,
		`INSERT INTO tbl_clients (name, is_active) VALUES ($1, true) RETURNING id`,
		"Acme "+randSuffix(t)).Scan(&f.clientID); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO tbl_products (key, name, base_url, is_active) VALUES ($1,$2,$3,true) RETURNING id`,
		"CRM-"+randSuffix(t), "CRM", "https://crm.acme.test").Scan(&f.product); err != nil {
		t.Fatalf("seed product: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tbl_client_products (client_id, product_id, is_active) VALUES ($1,$2,true)`,
		f.clientID, f.product); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO tbl_users (client_id, email, password_hash, account_type, is_active)
		 VALUES ($1,$2,$3,'EMAIL',true) RETURNING id`,
		f.clientID, strings.ToLower(f.email), hash).Scan(&f.userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func (f *fixture) post(path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, req)
	return w
}

func (f *fixture) authorizeBody() map[string]any {
	return map[string]any{
		"email": f.email, "password": f.pass, "product_id": f.product,
		"redirect_url": f.redirect, "code_challenge": challengeFor(f.verifier),
		"code_challenge_method": "S256",
	}
}

// getCode performs the credential leg and returns the authorization code.
func (f *fixture) getCode(t *testing.T) string {
	t.Helper()
	w := f.post("/auth/authorize", f.authorizeBody())
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Code == "" {
		t.Fatalf("authorize: no code in %s", w.Body.String())
	}
	return out.Code
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, ck := range w.Result().Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

// ---------- HAPPY PATH ----------

func TestLoginFlowEndToEnd(t *testing.T) {
	f := newFlowFixture(t)

	code := f.getCode(t)
	w := f.post("/auth/token", map[string]any{"code": code, "code_verifier": f.verifier, "redirect_url": f.redirect})
	if w.Code != http.StatusOK {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.TokenType != "Bearer" || tok.ExpiresIn != 900 || tok.AccessToken == "" {
		t.Fatalf("unexpected token response: %s", w.Body.String())
	}

	// The access token must verify and carry the tenant + roles claims.
	parsed, err := jwtkeys.Verify(tok.AccessToken, "alora-auth-api")
	if err != nil {
		t.Fatalf("minted token failed verification: %v", err)
	}
	if parsed.Subject() != f.userID {
		t.Errorf("sub = %q, want %q", parsed.Subject(), f.userID)
	}
	if cid, _ := parsed.Get("client_id"); cid != f.clientID {
		t.Errorf("client_id = %v, want %v", cid, f.clientID)
	}

	// Cookie hygiene.
	rt := cookieNamed(w, "alora_rt")
	if rt == nil || !rt.HttpOnly {
		t.Fatalf("refresh cookie missing or not HttpOnly: %+v", rt)
	}
	if rt.SameSite != http.SameSiteLaxMode {
		t.Errorf("refresh cookie SameSite = %v, want Lax", rt.SameSite)
	}
	at := cookieNamed(w, "alora_at")
	if at == nil || at.HttpOnly {
		t.Errorf("access cookie must exist and be JS-readable (HttpOnly=false): %+v", at)
	}

	// Refresh rotates to a DIFFERENT token.
	w2 := f.post("/auth/refresh", nil, rt)
	if w2.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", w2.Code, w2.Body.String())
	}
	rt2 := cookieNamed(w2, "alora_rt")
	if rt2 == nil || rt2.Value == rt.Value {
		t.Fatal("refresh did not rotate the token")
	}

	// Logout is 204 and clears both cookies.
	w3 := f.post("/auth/logout", nil, rt2)
	if w3.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", w3.Code)
	}
	if ck := cookieNamed(w3, "alora_rt"); ck == nil || ck.MaxAge >= 0 {
		t.Errorf("logout must clear the refresh cookie, got %+v", ck)
	}

	// The revoked token must no longer refresh.
	if w4 := f.post("/auth/refresh", nil, rt2); w4.Code != http.StatusUnauthorized {
		t.Errorf("refresh after logout: %d, want 401", w4.Code)
	}
}

// ---------- CREDENTIAL ATTACKS ----------

func TestAuthorizeRejectsBadCredentialsIdentically(t *testing.T) {
	f := newFlowFixture(t)

	mutate := func(fn func(map[string]any)) map[string]any {
		b := f.authorizeBody()
		fn(b)
		return b
	}
	cases := []struct {
		name string
		body map[string]any
	}{
		{"wrong password", mutate(func(b map[string]any) { b["password"] = "wrong password" })},
		{"unknown email", mutate(func(b map[string]any) { b["email"] = "nobody@nowhere.test" })},
	}
	var bodies []string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := f.post("/auth/authorize", tc.body)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401 (%s)", w.Code, w.Body.String())
			}
			bodies = append(bodies, w.Body.String())
		})
	}
	// Anti-enumeration: the two failures must be indistinguishable.
	if len(bodies) == 2 && !sameErrorMessage(bodies[0], bodies[1]) {
		t.Errorf("SECURITY: enumeration oracle — %q vs %q", bodies[0], bodies[1])
	}
}

func sameErrorMessage(a, b string) bool {
	var x, y map[string]any
	_ = json.Unmarshal([]byte(a), &x)
	_ = json.Unmarshal([]byte(b), &y)
	return x["error"] == y["error"]
}

// The code must only ever be deliverable to the product's own origin.
func TestAuthorizeRejectsOpenRedirect(t *testing.T) {
	f := newFlowFixture(t)
	for _, evil := range []string{
		"https://evil.example/callback",
		"https://crm.acme.test.evil.example/callback", // prefix-match trap
		"http://crm.acme.test/callback",               // scheme downgrade
	} {
		b := f.authorizeBody()
		b["redirect_url"] = evil
		if w := f.post("/auth/authorize", b); w.Code == http.StatusOK {
			t.Errorf("SECURITY: open redirect accepted: %s", evil)
		}
	}
}

func TestAuthorizeRejectsUnknownProductAndUnsubscribedTenant(t *testing.T) {
	f := newFlowFixture(t)

	b := f.authorizeBody()
	b["product_id"] = "00000000-0000-0000-0000-000000000000"
	if w := f.post("/auth/authorize", b); w.Code == http.StatusOK {
		t.Error("unknown product accepted")
	}

	// Drop the subscription: valid credentials must no longer yield a code.
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE tbl_client_products SET is_active=false WHERE client_id=$1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	if w := f.post("/auth/authorize", f.authorizeBody()); w.Code == http.StatusOK {
		t.Error("SECURITY: code issued for a tenant with no active subscription")
	}
}

func TestAuthorizeRejectsMalformedInput(t *testing.T) {
	f := newFlowFixture(t)
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing email", func(b map[string]any) { delete(b, "email") }},
		{"invalid email", func(b map[string]any) { b["email"] = "not-an-email" }},
		{"missing challenge", func(b map[string]any) { delete(b, "code_challenge") }},
		{"plain PKCE method", func(b map[string]any) { b["code_challenge_method"] = "plain" }},
		{"unknown field", func(b map[string]any) { b["is_global_admin"] = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := f.authorizeBody()
			tc.mutate(b)
			if w := f.post("/auth/authorize", b); w.Code != http.StatusBadRequest {
				t.Errorf("status %d, want 400 (%s)", w.Code, w.Body.String())
			}
		})
	}
}

// ---------- CODE / PKCE ATTACKS ----------

func TestTokenRejectsCodeReplayAndBadPKCE(t *testing.T) {
	f := newFlowFixture(t)

	// Single-use: the second redemption of the same code must fail.
	code := f.getCode(t)
	if w := f.post("/auth/token", map[string]any{"code": code, "code_verifier": f.verifier}); w.Code != http.StatusOK {
		t.Fatalf("first redemption: %d %s", w.Code, w.Body.String())
	}
	if w := f.post("/auth/token", map[string]any{"code": code, "code_verifier": f.verifier}); w.Code == http.StatusOK {
		t.Error("SECURITY: authorization code was redeemable twice")
	}

	// Wrong verifier: a stolen code alone must be useless.
	code2 := f.getCode(t)
	if w := f.post("/auth/token", map[string]any{
		"code": code2, "code_verifier": "wrong-verifier-that-is-long-enough-to-pass-length-validation",
	}); w.Code == http.StatusOK {
		t.Error("SECURITY: PKCE verifier was not enforced")
	}

	// Unknown code.
	if w := f.post("/auth/token", map[string]any{
		"code": "totally-unknown-code", "code_verifier": f.verifier,
	}); w.Code == http.StatusOK {
		t.Error("SECURITY: unknown code accepted")
	}
}

func TestTokenRejectsExpiredCode(t *testing.T) {
	f := newFlowFixture(t)
	code := f.getCode(t)
	// Age the code past its 2-minute TTL.
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE tbl_authorization_codes SET expires_at = now() - interval '1 second' WHERE code=$1`, code); err != nil {
		t.Fatal(err)
	}
	if w := f.post("/auth/token", map[string]any{"code": code, "code_verifier": f.verifier}); w.Code == http.StatusOK {
		t.Error("SECURITY: expired authorization code was accepted")
	}
}

// A user deactivated during the 2-minute code window must not receive a token.
func TestTokenRejectsDeactivatedUser(t *testing.T) {
	f := newFlowFixture(t)
	code := f.getCode(t)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE tbl_users SET is_active=false WHERE id=$1`, f.userID); err != nil {
		t.Fatal(err)
	}
	if w := f.post("/auth/token", map[string]any{"code": code, "code_verifier": f.verifier}); w.Code == http.StatusOK {
		t.Error("SECURITY: token issued to a deactivated user")
	}
}

// ---------- REFRESH-TOKEN REPLAY (the crown jewel) ----------

func TestRefreshReplayBurnsTokenFamily(t *testing.T) {
	f := newFlowFixture(t)

	code := f.getCode(t)
	w := f.post("/auth/token", map[string]any{"code": code, "code_verifier": f.verifier})
	rt1 := cookieNamed(w, "alora_rt")
	if rt1 == nil {
		t.Fatal("no refresh cookie")
	}

	// Legitimate rotation.
	w2 := f.post("/auth/refresh", nil, rt1)
	if w2.Code != http.StatusOK {
		t.Fatalf("rotation: %d %s", w2.Code, w2.Body.String())
	}
	rt2 := cookieNamed(w2, "alora_rt")

	// Age the family beyond the 30s grace window so the replay below is
	// unambiguously theft rather than a concurrent-tab race.
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE tbl_user_sessions SET revoked_at = now() - interval '5 minutes',
		 created_at = now() - interval '5 minutes' WHERE user_id=$1 AND revoked_at IS NOT NULL`,
		f.userID); err != nil {
		t.Fatal(err)
	}

	// ATTACK: replay the already-spent token.
	w3 := f.post("/auth/refresh", nil, rt1)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("replay: %d, want 401 (%s)", w3.Code, w3.Body.String())
	}

	// The whole family must now be burned — including the currently-valid rt2.
	var live int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM tbl_user_sessions WHERE user_id=$1 AND revoked_at IS NULL`,
		f.userID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Errorf("SECURITY: %d session(s) survived reuse detection — family not burned", live)
	}
	var burned int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM tbl_user_sessions WHERE user_id=$1 AND revoked_reason='REUSE_DETECTED'`,
		f.userID).Scan(&burned); err != nil {
		t.Fatal(err)
	}
	if burned == 0 {
		t.Error("SECURITY: no session marked REUSE_DETECTED — the nuke was rolled back")
	}

	// The valid successor must now also be rejected.
	if w4 := f.post("/auth/refresh", nil, rt2); w4.Code != http.StatusUnauthorized {
		t.Errorf("post-burn refresh: %d, want 401", w4.Code)
	}
}

func TestRefreshRejectsUnknownAndMalformedTokens(t *testing.T) {
	f := newFlowFixture(t)
	cases := []struct{ name, value string }{
		{"unknown token", strings.Repeat("a", 64)},
		{"too short", "abc"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := f.post("/auth/refresh", nil, &http.Cookie{Name: "alora_rt", Value: tc.value})
			if w.Code != http.StatusUnauthorized {
				t.Errorf("status %d, want 401", w.Code)
			}
		})
	}
	// No cookie at all.
	if w := f.post("/auth/refresh", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("no cookie: %d, want 401", w.Code)
	}
}

func TestLogoutIsIdempotentAndSilent(t *testing.T) {
	f := newFlowFixture(t)
	// Unknown token must still 204 — revealing existence would leak session state.
	if w := f.post("/auth/logout", nil, &http.Cookie{Name: "alora_rt", Value: strings.Repeat("b", 64)}); w.Code != http.StatusNoContent {
		t.Errorf("unknown token logout: %d, want 204", w.Code)
	}
	if w := f.post("/auth/logout", nil); w.Code != http.StatusNoContent {
		t.Errorf("no cookie logout: %d, want 204", w.Code)
	}
}

// ---------- DIRECT ADMIN LOGIN (/auth/session) ----------

func TestSessionLoginFlow(t *testing.T) {
	f := newFlowFixture(t)

	w := f.post("/auth/session", map[string]any{"email": f.email, "password": f.pass})
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}

	// The body must be EXACTLY the three token fields — no user object, no roles.
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 3 {
		t.Errorf("body has %d fields, want exactly 3: %s", len(body), w.Body.String())
	}
	for _, k := range []string{"access_token", "token_type", "expires_in"} {
		if _, ok := body[k]; !ok {
			t.Errorf("missing %q", k)
		}
	}
	for _, leak := range []string{"password", "roles", "client_id", "email"} {
		if _, present := body[leak]; present {
			t.Errorf("SECURITY: response leaked %q", leak)
		}
	}

	// Cookies are set and the session actually works.
	rt := cookieNamed(w, "alora_rt")
	if rt == nil || !rt.HttpOnly {
		t.Fatalf("refresh cookie missing/not HttpOnly: %+v", rt)
	}
	if w2 := f.post("/auth/refresh", nil, rt); w2.Code != http.StatusOK {
		t.Errorf("refresh after session login: %d", w2.Code)
	}
}

func TestSessionLoginRejectsBadCredentials(t *testing.T) {
	f := newFlowFixture(t)
	var bodies []string
	for _, tc := range []struct{ name, email, pass string }{
		{"wrong password", f.email, "not the password"},
		{"unknown email", "ghost@nowhere.test", f.pass},
	} {
		w := f.post("/auth/session", map[string]any{"email": tc.email, "password": tc.pass})
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", tc.name, w.Code)
		}
		if cookieNamed(w, "alora_rt") != nil {
			t.Errorf("SECURITY: %s issued a session cookie", tc.name)
		}
		bodies = append(bodies, w.Body.String())
	}
	if len(bodies) == 2 && !sameErrorMessage(bodies[0], bodies[1]) {
		t.Errorf("SECURITY: enumeration oracle — %q vs %q", bodies[0], bodies[1])
	}

	// Malformed input is a 400, not a 401 leak about the account.
	if w := f.post("/auth/session", map[string]any{"email": "not-an-email", "password": "x"}); w.Code != http.StatusBadRequest {
		t.Errorf("malformed: %d, want 400", w.Code)
	}
}

// A deactivated user must not be able to reach the admin portal.
func TestSessionLoginRejectsDeactivatedUser(t *testing.T) {
	f := newFlowFixture(t)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE tbl_users SET is_active=false WHERE id=$1`, f.userID); err != nil {
		t.Fatal(err)
	}
	if w := f.post("/auth/session", map[string]any{"email": f.email, "password": f.pass}); w.Code == http.StatusOK {
		t.Error("SECURITY: deactivated user logged into the admin portal")
	}
}
