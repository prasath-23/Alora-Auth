package main

// Federated-login coverage. A local stub stands in for Google's token/userinfo
// endpoints so the whole flow — state binding, replay, tenant policy, account
// linking — is exercised offline and deterministically.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alora/auth/internal/config"
	"github.com/alora/auth/internal/oauth"
	"github.com/alora/auth/internal/platform/httpx"
)

// googleStub serves the two endpoints the exchange touches.
func googleStub(t *testing.T, sub, email string, verified bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// No id_token, forcing the userinfo fallback path to be exercised too.
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "stub-access-token"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer stub-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": sub, "email": email, "email_verified": verified,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// googleFixture wires a fixture whose Google handler points at the stub.
func (f *fixture) withGoogle(t *testing.T, stub *httptest.Server) *oauth.GoogleHandler {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	jar := httpx.NewCookieJar(cfg.Cookie.Domain, cfg.IsProd, cfg.Cookie.Secret)
	g := oauth.NewGoogleHandler(oauth.NewService(f.queries()), oauth.GoogleConfig{
		ClientID: "gid", ClientSecret: "gsecret",
		RedirectURI: "http://127.0.0.1:3099/auth/google/callback",
		FrontendURL: cfg.FrontendURL,
	}, jar)
	g.SetEndpoints(stub.URL+"/token", stub.URL+"/userinfo")
	f.r.GET("/test/google", g.Start)
	f.r.GET("/test/google/callback", g.Callback)
	return g
}

func (f *fixture) get(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, req)
	return w
}

// startURL builds the /test/google query string.
func (f *fixture) startURL() string {
	q := url.Values{
		"product_id":     {f.product},
		"redirect_url":   {f.redirect},
		"code_challenge": {challengeFor(f.verifier)},
	}
	return "/test/google?" + q.Encode()
}

func TestGoogleStartValidatesAndSetsState(t *testing.T) {
	f := newFlowFixture(t)
	f.withGoogle(t, googleStub(t, "google-sub-1", f.email, true))

	w := f.get(f.startURL())
	if w.Code != http.StatusFound {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://accounts.google.com/") {
		t.Fatalf("unexpected redirect: %s", loc)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("state") == "" || u.Query().Get("nonce") == "" {
		t.Error("state/nonce missing from the Google URL")
	}
	if u.Query().Get("client_id") != "gid" {
		t.Errorf("client_id = %q", u.Query().Get("client_id"))
	}
	// The browser must receive the signed, HttpOnly state cookie.
	ck := cookieNamed(w, "alora_oauth_state")
	if ck == nil || !ck.HttpOnly {
		t.Fatalf("state cookie missing/not HttpOnly: %+v", ck)
	}
	if !strings.Contains(ck.Value, "|") {
		t.Error("state cookie is not signed")
	}
}

// An open redirect must be refused BEFORE the user is sent to Google.
func TestGoogleStartRejectsBadRedirectAndMissingParams(t *testing.T) {
	f := newFlowFixture(t)
	f.withGoogle(t, googleStub(t, "s", f.email, true))

	cases := map[string]url.Values{
		"evil redirect":     {"product_id": {f.product}, "redirect_url": {"https://evil.example/cb"}, "code_challenge": {challengeFor(f.verifier)}},
		"prefix trap":       {"product_id": {f.product}, "redirect_url": {"https://crm.acme.test.evil.example/cb"}, "code_challenge": {challengeFor(f.verifier)}},
		"missing product":   {"redirect_url": {f.redirect}, "code_challenge": {challengeFor(f.verifier)}},
		"missing challenge": {"product_id": {f.product}, "redirect_url": {f.redirect}},
		"plain method":      {"product_id": {f.product}, "redirect_url": {f.redirect}, "code_challenge": {challengeFor(f.verifier)}, "code_challenge_method": {"plain"}},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			if w := f.get("/test/google?" + q.Encode()); w.Code != http.StatusBadRequest {
				t.Errorf("status %d, want 400", w.Code)
			}
		})
	}
}

// beginFlow runs Start and returns (state, cookie).
func (f *fixture) beginFlow(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	w := f.get(f.startURL())
	if w.Code != http.StatusFound {
		t.Fatalf("start: %d", w.Code)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	return u.Query().Get("state"), cookieNamed(w, "alora_oauth_state")
}

// oauthEmail returns an address on a domain unique to this fixture's tenant.
// Verified domains are globally unique (client_domain_normalized_unique), so
// two tenants must never claim the same one.
func (f *fixture) oauthEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("oauth@t%s.test", randSuffix(t))
}

// seedOAuthUser creates an invited OAUTH_ONLY account plus a verified tenant
// domain, which is what the linking path requires.
func (f *fixture) seedOAuthUser(t *testing.T, email string) string {
	t.Helper()
	ctx := context.Background()
	domain := email[strings.LastIndex(email, "@")+1:]
	if _, err := f.pool.Exec(ctx,
		`UPDATE tbl_clients SET domain=$1, domain_verified_at=now() WHERE id=$2`,
		domain, f.clientID); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := f.pool.QueryRow(ctx,
		`INSERT INTO tbl_users (client_id, email, account_type, is_active)
		 VALUES ($1,$2,'OAUTH_ONLY',true) RETURNING id`, f.clientID, email).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestGoogleCallbackLinksAccountAndIssuesCode(t *testing.T) {
	f := newFlowFixture(t)
	email := f.oauthEmail(t)
	userID := f.seedOAuthUser(t, email)
	f.withGoogle(t, googleStub(t, "google-sub-"+randSuffix(t), email, true))

	state, ck := f.beginFlow(t)
	w := f.get("/test/google/callback?code=g-code&state="+state, ck)
	if w.Code != http.StatusFound {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "google_error") {
		t.Fatalf("callback errored: %s", loc)
	}
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code in redirect: %s", loc)
	}
	// It must redirect to the PRODUCT origin, never anywhere else.
	if !strings.HasPrefix(loc, "https://crm.acme.test") {
		t.Errorf("redirect target = %s, want the product origin", loc)
	}

	// The identity is now linked to the invited account.
	var linked string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT user_id FROM tbl_linked_identities WHERE provider='GOOGLE' AND user_id=$1`,
		userID).Scan(&linked); err != nil {
		t.Fatalf("identity not linked: %v", err)
	}

	// And the issued code redeems for a token via the normal /auth/token leg.
	tw := f.post("/auth/token", map[string]any{"code": code, "code_verifier": f.verifier})
	if tw.Code != http.StatusOK {
		t.Fatalf("token exchange: %d %s", tw.Code, tw.Body.String())
	}
}

func TestGoogleCallbackRejectsStateAttacks(t *testing.T) {
	f := newFlowFixture(t)
	email := f.oauthEmail(t)
	f.seedOAuthUser(t, email)
	f.withGoogle(t, googleStub(t, "google-sub-"+randSuffix(t), email, true))

	t.Run("no cookie", func(t *testing.T) {
		state, _ := f.beginFlow(t)
		w := f.get("/test/google/callback?code=g&state=" + state)
		assertGoogleError(t, w, "missing_state")
	})

	t.Run("mismatched cookie", func(t *testing.T) {
		state, _ := f.beginFlow(t)
		_, otherCk := f.beginFlow(t) // a cookie for a DIFFERENT state
		w := f.get("/test/google/callback?code=g&state="+state, otherCk)
		assertGoogleError(t, w, "state_mismatch")
	})

	t.Run("forged cookie signature", func(t *testing.T) {
		state, _ := f.beginFlow(t)
		w := f.get("/test/google/callback?code=g&state="+state,
			&http.Cookie{Name: "alora_oauth_state", Value: state + "|forged-signature"})
		assertGoogleError(t, w, "state_mismatch")
	})

	t.Run("replayed callback", func(t *testing.T) {
		state, ck := f.beginFlow(t)
		if w := f.get("/test/google/callback?code=g&state="+state, ck); w.Code != http.StatusFound {
			t.Fatalf("first callback: %d", w.Code)
		}
		// The state was consumed; a replay must fail.
		w := f.get("/test/google/callback?code=g&state="+state, ck)
		assertGoogleError(t, w, "state_expired")
	})

	t.Run("missing code", func(t *testing.T) {
		state, ck := f.beginFlow(t)
		w := f.get("/test/google/callback?state="+state, ck)
		assertGoogleError(t, w, "invalid_request")
	})
}

// An unverified Google email must never match a local account.
func TestGoogleCallbackRejectsUnverifiedEmail(t *testing.T) {
	f := newFlowFixture(t)
	email := f.oauthEmail(t)
	f.seedOAuthUser(t, email)
	f.withGoogle(t, googleStub(t, "sub-"+randSuffix(t), email, false)) // verified=false

	state, ck := f.beginFlow(t)
	assertGoogleError(t, f.get("/test/google/callback?code=g&state="+state, ck), "email_unverified")
}

// Federated login must NEVER auto-create an account.
func TestGoogleCallbackRefusesUnknownAccount(t *testing.T) {
	f := newFlowFixture(t)
	domain := "t" + randSuffix(t) + ".test"
	unknown := "stranger@" + domain
	// Verify the domain but create NO user for this address.
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE tbl_clients SET domain=$1, domain_verified_at=now() WHERE id=$2`,
		domain, f.clientID); err != nil {
		t.Fatal(err)
	}
	f.withGoogle(t, googleStub(t, "sub-"+randSuffix(t), unknown, true))

	state, ck := f.beginFlow(t)
	assertGoogleError(t, f.get("/test/google/callback?code=g&state="+state, ck), "account_not_found")

	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM tbl_users WHERE lower(email)=$1`, strings.ToLower(unknown)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("SECURITY: federated login auto-provisioned an account")
	}
}

// A tenant that has not enabled GOOGLE must not be reachable through it.
func TestGoogleCallbackHonoursTenantIdpPolicy(t *testing.T) {
	f := newFlowFixture(t)
	email := f.oauthEmail(t)
	f.seedOAuthUser(t, email)
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE tbl_clients SET allowed_idp_providers = ARRAY['EMAIL']::"IdpProvider"[] WHERE id=$1`,
		f.clientID); err != nil {
		t.Fatal(err)
	}
	f.withGoogle(t, googleStub(t, "sub-"+randSuffix(t), email, true))

	state, ck := f.beginFlow(t)
	assertGoogleError(t, f.get("/test/google/callback?code=g&state="+state, ck), "account_not_found")
}

func assertGoogleError(t *testing.T, w *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("status %d, want 302 (body: %s)", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "google_error="+wantCode) {
		t.Errorf("redirect = %s, want google_error=%s", loc, wantCode)
	}
}
