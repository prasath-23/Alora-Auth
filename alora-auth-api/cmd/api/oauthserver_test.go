package main

// App Central as the OpenID Provider of the company's products: the silent
// launch, the detour through the login page, every refusal of /oauth/authorize,
// client authentication, the code's bindings and single use, product refresh
// rotation and what it re-checks, revocation, introspection, audience
// separation in both directions, ID tokens, and key rotation.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/alora/auth/internal/core/shared/crypto/jwtkeys"
	"github.com/alora/auth/internal/core/shared/crypto/pkce"
)

// launched is a member of a company subscribed to a product, holding a role in
// it through a group, signed in at App Central.
type launched struct {
	co company
	m  member
	s  session
	p  product
}

func (a *app) setupProduct(role string) launched {
	a.t.Helper()
	co := a.newCompany()
	p := a.newProduct()
	a.subscribe(co, p)
	m := a.newMember(co, "")
	g := a.newGroup(co)
	a.grantGroup(co, g, p, role)
	a.join(m, g)
	return launched{co: co, m: m, s: a.login(m), p: p}
}

// code runs /oauth/authorize for a signed-in browser and returns the code,
// checking the redirect is exactly what RFC 6749 and RFC 9207 say. The browser's
// rotated session cookie is carried forward.
func (a *app) code(l *launched, f flow) string {
	a.t.Helper()
	w := a.authorize(l.s, f.query(l.p))
	if w.Code != http.StatusFound {
		a.t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	u := location(a.t, w)
	if got := u.Scheme + "://" + u.Host + u.Path; got != l.p.Redirect {
		a.t.Fatalf("redirected to %s, want %s", got, l.p.Redirect)
	}
	q := u.Query()
	if q.Get("state") != f.State || q.Get("iss") != testIssuer || q.Get("error") != "" || q.Get("code") == "" {
		a.t.Fatalf("authorize redirect = %s", u)
	}
	if ck := cookieNamed(w, centralCookie); ck != nil && ck.MaxAge > 0 {
		l.s.Cookie = ck
	}
	return q.Get("code")
}

type tokenSet struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// tokenCall posts a form to the token endpoint as the product.
func (a *app) tokenCall(p product, form url.Values) *httptest.ResponseRecorder {
	return a.post("/oauth/token", form, basic(p.ID, p.Secret))
}

func (a *app) exchange(p product, code string, f flow) tokenSet {
	a.t.Helper()
	w := a.tokenCall(p, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {p.Redirect}, "code_verifier": {f.Verifier},
	})
	expect(a.t, w, http.StatusOK, "code exchange")
	var ts tokenSet
	decodeInto(a.t, w, &ts)
	return ts
}

func (a *app) productRefresh(p product, rt string) *httptest.ResponseRecorder {
	return a.tokenCall(p, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
}

func oauthError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	return jsonField(w, "error")
}

// ---------- the launch ----------

func TestLaunchIsSilentAndTokensAreScopedToTheProduct(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Editor")
	f := newFlow(t)
	before := l.s.Cookie.Value
	code := a.code(&l, f)
	if l.s.Cookie.Value == before {
		t.Error("a silent authorize did not rotate the App Central session")
	}

	w := a.tokenCall(l.p, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {l.p.Redirect}, "code_verifier": {f.Verifier},
	})
	expect(t, w, http.StatusOK, "exchange")
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Errorf("token response caching headers: %v", w.Header())
	}
	var ts tokenSet
	decodeInto(t, w, &ts)
	if ts.TokenType != "Bearer" || ts.ExpiresIn != 900 || ts.RefreshToken == "" || ts.IDToken == "" || ts.Scope != "openid email" {
		t.Fatalf("token response = %s", w.Body.String())
	}

	// The access token is for THIS product only.
	aud := "product:" + l.p.Key
	tok, err := jwtkeys.VerifyAccess(ts.AccessToken, aud)
	if err != nil {
		t.Fatalf("product token does not verify for %s: %v", aud, err)
	}
	c := claims(t, ts.AccessToken)
	if !slices.Equal(tok.Audience(), []string{aud}) {
		t.Errorf("aud = %v, want exactly [%s]", tok.Audience(), aud)
	}
	if tok.Subject() != l.m.ID || c["client_id"] != l.p.ID || c["tenant_id"] != l.co.ID || c["email"] != l.m.Email {
		t.Errorf("claims = %v", c)
	}
	if roles, _ := c["roles"].([]any); len(roles) != 1 || roles[0] != "Editor" {
		t.Errorf("roles = %v, want [Editor]", c["roles"])
	}
	if c["sid"] == sessionID(t, l.s.Access) {
		t.Error("the product token's sid is the App Central session, not the product's own login")
	}
	if jwtHeader(t, ts.AccessToken)["typ"] != "at+jwt" {
		t.Errorf("typ = %v", jwtHeader(t, ts.AccessToken)["typ"])
	}
	if exp := int64(c["exp"].(float64)) - int64(c["iat"].(float64)); exp != 900 {
		t.Errorf("lifetime %ds, want 900", exp)
	}

	// The ID token tells the product who signed in, and binds its nonce.
	idt, err := jwtkeys.VerifyID(ts.IDToken, l.p.ID)
	if err != nil {
		t.Fatalf("ID token does not verify for the product: %v", err)
	}
	ic := claims(t, ts.IDToken)
	if idt.Subject() != l.m.ID || ic["nonce"] != f.Nonce || ic["sid"] != sessionID(t, l.s.Access) ||
		ic["email"] != l.m.Email || ic["tenant_id"] != l.co.ID || ic["auth_time"] == nil || ic["iss"] != testIssuer {
		t.Errorf("ID token claims = %v", ic)
	}
	if jwtHeader(t, ts.IDToken)["typ"] != "JWT" {
		t.Errorf("ID token typ = %v", jwtHeader(t, ts.IDToken)["typ"])
	}

	// Without openid, no ID token.
	f2 := newFlow(t)
	f2.Scope = "email"
	ts2 := a.exchange(l.p, a.code(&l, f2), f2)
	if ts2.IDToken != "" {
		t.Error("an ID token was issued without the openid scope")
	}
}

// With no App Central session, authorize sends the browser to the login page and
// resumes where it left off.
func TestAuthorizeDetoursThroughLoginAndResumes(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	q := f.query(l.p)

	w := a.get("/oauth/authorize?" + q.Encode())
	expect(t, w, http.StatusFound, "authorize without a session")
	u := location(t, w)
	if u.Scheme+"://"+u.Host+u.Path != testFrontend+"/login" {
		t.Fatalf("sent to %s, want App Central's login page", u)
	}
	returnTo := u.Query().Get("return_to")
	if !strings.HasPrefix(returnTo, "/oauth/authorize?") || !strings.Contains(returnTo, "client_id="+l.p.ID) {
		t.Fatalf("return_to = %q", returnTo)
	}

	// After signing in, following return_to issues the code silently.
	s := a.login(l.m)
	w = a.get(returnTo, withCookie(s.Cookie))
	expect(t, w, http.StatusFound, "resumed authorize")
	if got := location(t, w).Query(); got.Get("code") == "" || got.Get("state") != f.State {
		t.Errorf("resumed authorize redirected to %s", location(t, w))
	}

	// prompt=none never shows a page: it says login_required to the product.
	q.Set("prompt", "none")
	w = a.get("/oauth/authorize?" + q.Encode())
	expect(t, w, http.StatusFound, "prompt=none")
	if got := location(t, w).Query(); got.Get("error") != "login_required" || got.Get("state") != f.State || got.Get("iss") != testIssuer {
		t.Errorf("prompt=none redirected to %s", location(t, w))
	}

	// prompt=login signs in again even with a session, and the way back drops
	// the prompt so it does not loop.
	q.Set("prompt", "login")
	w = a.get("/oauth/authorize?"+q.Encode(), withCookie(s.Cookie))
	expect(t, w, http.StatusFound, "prompt=login")
	back := location(t, w).Query().Get("return_to")
	if location(t, w).Path != "/login" || strings.Contains(back, "prompt") {
		t.Errorf("prompt=login redirected to %s", location(t, w))
	}

	// A dead session cookie is cleared on the way to the login page.
	dead := &http.Cookie{Name: centralCookie, Value: strings.Repeat("d", 64)}
	w = a.get("/oauth/authorize?"+f.query(l.p).Encode(), withCookie(dead))
	expect(t, w, http.StatusFound, "dead session")
	if ck := cookieNamed(w, centralCookie); ck == nil || ck.MaxAge >= 0 {
		t.Errorf("a dead session cookie was not cleared: %+v", ck)
	}
}

// Until the client and its redirect URI are known good, nothing is sent to the
// redirect URI — that would make App Central an open redirector.
func TestAuthorizeNeverRedirectsForAnUntrustedClient(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	other := a.newProduct()
	cases := map[string]func(url.Values){
		"unknown client":            func(q url.Values) { q.Set("client_id", "00000000-0000-0000-0000-000000000000") },
		"missing client":            func(q url.Values) { q.Del("client_id") },
		"missing redirect":          func(q url.Values) { q.Del("redirect_uri") },
		"unregistered redirect":     func(q url.Values) { q.Set("redirect_uri", "https://evil.example/callback") },
		"prefix trap":               func(q url.Values) { q.Set("redirect_uri", l.p.Redirect+".evil.example") },
		"extra path":                func(q url.Values) { q.Set("redirect_uri", l.p.Redirect+"/x") },
		"trailing slash":            func(q url.Values) { q.Set("redirect_uri", l.p.Redirect+"/") },
		"scheme downgrade":          func(q url.Values) { q.Set("redirect_uri", strings.Replace(l.p.Redirect, "https", "http", 1)) },
		"query added":               func(q url.Values) { q.Set("redirect_uri", l.p.Redirect+"?next=/x") },
		"another product's":         func(q url.Values) { q.Set("redirect_uri", other.Redirect) },
		"another client, own redir": func(q url.Values) { q.Set("client_id", other.ID) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			q := f.query(l.p)
			mutate(q)
			w := a.authorize(l.s, q)
			if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
				t.Errorf("SECURITY: %d Location %q, want 400 and no redirect", w.Code, w.Header().Get("Location"))
			}
		})
	}
	// An inactive product is not a client at all.
	a.exec(`UPDATE tbl_products SET is_active = false WHERE id = $1`, l.p.ID)
	if w := a.authorize(l.s, f.query(l.p)); w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Errorf("inactive product: %d, want 400 and no redirect", w.Code)
	}
}

// Once the redirect URI is trusted, request errors go back to the product.
func TestAuthorizeReportsRequestErrorsToTheProduct(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	cases := map[string]struct {
		mutate func(url.Values)
		want   string
	}{
		"implicit flow":     {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		"no challenge":      {func(q url.Values) { q.Del("code_challenge") }, "invalid_request"},
		"plain PKCE":        {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		"no PKCE method":    {func(q url.Values) { q.Del("code_challenge_method") }, "invalid_request"},
		"short challenge":   {func(q url.Values) { q.Set("code_challenge", "abc") }, "invalid_request"},
		"unknown scope":     {func(q url.Values) { q.Set("scope", "openid admin") }, "invalid_scope"},
		"prompt none+login": {func(q url.Values) { q.Set("prompt", "none login") }, "invalid_request"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			q := f.query(l.p)
			tc.mutate(q)
			w := a.authorize(l.s, q)
			expect(t, w, http.StatusFound, name)
			got := location(t, w)
			if got.Scheme+"://"+got.Host+got.Path != l.p.Redirect || got.Query().Get("error") != tc.want ||
				got.Query().Get("state") != f.State || got.Query().Get("iss") != testIssuer || got.Query().Get("code") != "" {
				t.Errorf("redirected to %s, want error=%s with state and iss", got, tc.want)
			}
		})
	}
}

// Signed in, but not allowed in: no role, no live subscription.
func TestAuthorizeDeniesUsersWithoutAccess(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	outsider := a.newMember(l.co, "")
	outsiderSession := a.login(outsider)
	f := newFlow(t)
	denied := func(s session, what string) {
		t.Helper()
		w := a.authorize(s, f.query(l.p))
		expect(t, w, http.StatusFound, what)
		if got := location(t, w).Query(); got.Get("error") != "access_denied" || got.Get("code") != "" {
			t.Errorf("%s: redirected to %s, want access_denied", what, location(t, w))
		}
	}
	denied(outsiderSession, "no role")

	a.exec(`UPDATE tbl_client_products SET ends_at = now() - interval '1 minute' WHERE client_id = $1`, l.co.ID)
	denied(l.s, "subscription ended")
	a.exec(`UPDATE tbl_client_products SET ends_at = NULL, is_active = false WHERE client_id = $1`, l.co.ID)
	denied(l.s, "subscription switched off")
	a.exec(`UPDATE tbl_client_products SET is_active = true, starts_at = now() + interval '1 day' WHERE client_id = $1`, l.co.ID)
	denied(l.s, "subscription not started")
}

// ---------- the token endpoint ----------

func TestTokenEndpointAuthenticatesTheClient(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	other := a.newProduct()
	f := newFlow(t)
	code := a.code(&l, f)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {l.p.Redirect}, "code_verifier": {f.Verifier}}

	for name, opts := range map[string][]reqOpt{
		"no credentials":        nil,
		"wrong secret":          {basic(l.p.ID, "acs_wrong")},
		"unknown client":        {basic("00000000-0000-0000-0000-000000000000", l.p.Secret)},
		"secret for another id": {basic(other.ID, l.p.Secret)},
		"bearer, not basic":     {header("Authorization", "Bearer "+l.p.Secret)},
	} {
		w := a.post("/oauth/token", form, opts...)
		if w.Code != http.StatusUnauthorized || oauthError(t, w) != "invalid_client" ||
			w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: %d %s, want 401 invalid_client with WWW-Authenticate", name, w.Code, w.Body.String())
		}
	}
	// Another product authenticating with its OWN valid credentials is still not
	// the code's client — and it cannot burn the code by trying.
	if w := a.post("/oauth/token", form, basic(other.ID, other.Secret)); w.Code != http.StatusBadRequest || oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: another product redeeming the code: %d %s", w.Code, w.Body.String())
	}
	// One method only: a secret in the body is refused, not merged.
	body := url.Values{"client_secret": {l.p.Secret}}
	for k, v := range form {
		body[k] = v
	}
	if w := a.post("/oauth/token", body, basic(l.p.ID, l.p.Secret)); oauthError(t, w) != "invalid_client" {
		t.Errorf("client_secret in the body: %s", w.Body.String())
	}
	// A product with no secret yet cannot authenticate at all.
	a.exec(`UPDATE tbl_products SET client_secret_hash = NULL WHERE id = $1`, other.ID)
	if w := a.post("/oauth/token", form, basic(other.ID, other.Secret)); w.Code != http.StatusUnauthorized {
		t.Errorf("a product with no secret authenticated: %d", w.Code)
	}
	// Not a form: refused before the client is even looked at.
	if w := a.post("/oauth/token", map[string]any{"grant_type": "authorization_code"}, basic(l.p.ID, l.p.Secret)); w.Code != http.StatusBadRequest || oauthError(t, w) != "invalid_request" {
		t.Errorf("JSON body: %d %s", w.Code, w.Body.String())
	}
	// Parameters are read from the body only, never the query string.
	if w := a.post("/oauth/token?"+form.Encode(), url.Values{}, basic(l.p.ID, l.p.Secret)); oauthError(t, w) != "invalid_request" {
		t.Errorf("parameters in the query: %s", w.Body.String())
	}
	if w := a.post("/oauth/token", url.Values{"grant_type": {"password"}}, basic(l.p.ID, l.p.Secret)); oauthError(t, w) != "unsupported_grant_type" {
		t.Errorf("password grant: %s", w.Body.String())
	}
	if w := a.post("/oauth/token", url.Values{"grant_type": {"refresh_token", "refresh_token"}}, basic(l.p.ID, l.p.Secret)); oauthError(t, w) != "invalid_request" {
		t.Errorf("repeated parameter: %s", w.Body.String())
	}
	// The genuine exchange still works: nothing above consumed the code.
	a.exchange(l.p, code, f)
}

func TestCodeIsBoundToClientRedirectAndVerifier(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	other := a.newProduct()
	a.subscribe(l.co, other)

	try := func(p product, f flow, code, redirect, verifier string) *httptest.ResponseRecorder {
		return a.tokenCall(p, url.Values{"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {redirect}, "code_verifier": {verifier}})
	}
	for name, run := range map[string]func(code string, f flow) *httptest.ResponseRecorder{
		"another client redeems it": func(code string, f flow) *httptest.ResponseRecorder {
			return try(other, f, code, l.p.Redirect, f.Verifier)
		},
		"another redirect URI": func(code string, f flow) *httptest.ResponseRecorder {
			return try(l.p, f, code, l.p.Redirect+"/x", f.Verifier)
		},
		"no redirect URI": func(code string, f flow) *httptest.ResponseRecorder {
			return try(l.p, f, code, "", f.Verifier)
		},
		"wrong verifier": func(code string, f flow) *httptest.ResponseRecorder {
			v, _ := pkce.NewVerifier()
			return try(l.p, f, code, l.p.Redirect, v)
		},
		"no verifier": func(code string, f flow) *httptest.ResponseRecorder {
			return try(l.p, f, code, l.p.Redirect, "")
		},
		"unknown code": func(code string, f flow) *httptest.ResponseRecorder {
			return try(l.p, f, "not-a-code", l.p.Redirect, f.Verifier)
		},
	} {
		f := newFlow(t)
		code := a.code(&l, f)
		w := run(code, f)
		if w.Code != http.StatusBadRequest || (oauthError(t, w) != "invalid_grant" && oauthError(t, w) != "invalid_request") {
			t.Errorf("SECURITY: %s: %d %s, want invalid_grant", name, w.Code, w.Body.String())
		}
	}

	// A code past its two minutes is dead.
	f := newFlow(t)
	code := a.code(&l, f)
	a.exec(`UPDATE tbl_authorization_codes SET expires_at = now() - interval '1 second' WHERE user_id = $1 AND used_at IS NULL`, l.m.ID)
	if w := try(l.p, f, code, l.p.Redirect, f.Verifier); oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: expired code: %s", w.Body.String())
	}
	// A user deactivated in the code's window gets nothing.
	f = newFlow(t)
	code = a.code(&l, f)
	a.exec(`UPDATE tbl_users SET is_active = false WHERE id = $1`, l.m.ID)
	if w := try(l.p, f, code, l.p.Redirect, f.Verifier); oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: code of a deactivated user: %s", w.Body.String())
	}
	// Only hashes are stored.
	if n := a.count(`SELECT count(*) FROM tbl_authorization_codes WHERE code_hash = $1`, code); n != 0 {
		t.Error("SECURITY: an authorization code is stored in the clear")
	}
}

// A code redeemed twice leaked: the login the first redemption opened is ended.
func TestCodeReplayRevokesTheLoginItOpened(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	code := a.code(&l, f)
	ts := a.exchange(l.p, code, f)

	w := a.tokenCall(l.p, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {l.p.Redirect}, "code_verifier": {f.Verifier}})
	if oauthError(t, w) != "invalid_grant" {
		t.Fatalf("SECURITY: a code redeemed twice: %s", w.Body.String())
	}
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: the login a replayed code opened survived: %s", w.Body.String())
	}
	if n := a.count(`SELECT count(*) FROM tbl_session_families WHERE user_id = $1 AND kind = 'PRODUCT' AND revoked_reason = 'REUSE_DETECTED'`, l.m.ID); n != 1 {
		t.Errorf("%d product logins marked REUSE_DETECTED, want 1", n)
	}
	// The App Central session is untouched.
	expect(t, a.get("/api/me", bearer(l.s.Access)), http.StatusOK, "App Central session")
}

// ---------- product refresh ----------

func TestProductRefreshRotatesAndReuseBurnsOnlyThatProduct(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	second := a.newProduct()
	a.subscribe(l.co, second)
	a.grant(l.m, second, "Admin")

	fa := newFlow(t)
	tsA := a.exchange(l.p, a.code(&l, fa), fa)
	lb := l
	lb.p = second
	fb := newFlow(t)
	tsB := a.exchange(second, a.code(&lb, fb), fb)
	l.s = lb.s // the browser's cookie rotated again

	w := a.productRefresh(l.p, tsA.RefreshToken)
	expect(t, w, http.StatusOK, "refresh A")
	var next tokenSet
	decodeInto(t, w, &next)
	if next.RefreshToken == "" || next.RefreshToken == tsA.RefreshToken || next.IDToken != "" {
		t.Fatalf("refresh = %s", w.Body.String())
	}
	if _, err := jwtkeys.VerifyAccess(next.AccessToken, "product:"+l.p.Key); err != nil {
		t.Errorf("refreshed token: %v", err)
	}
	// Another product cannot use A's refresh token, and trying burns nothing.
	if w := a.productRefresh(second, next.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: product B redeemed product A's refresh token: %s", w.Body.String())
	}
	expect(t, a.productRefresh(l.p, next.RefreshToken), http.StatusOK, "A's token after B tried it")

	// Replay the spent token after the grace window: A's login burns, B's and
	// App Central's live on.
	a.exec(`UPDATE tbl_user_sessions SET revoked_at = now() - interval '5 minutes'
	        WHERE revoked_at IS NOT NULL AND revoked_reason IS NULL AND user_id = $1`, l.m.ID)
	if w := a.productRefresh(l.p, tsA.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Fatalf("SECURITY: a replayed refresh token: %s", w.Body.String())
	}
	var live int
	a.scalar(&live, `SELECT count(*) FROM tbl_session_families f
	                 JOIN tbl_products p ON p.id = f.product_id
	                 WHERE f.user_id = $1 AND p.id = $2 AND f.revoked_at IS NULL`, l.m.ID, l.p.ID)
	if live != 0 {
		t.Error("SECURITY: product A's login survived the replay")
	}
	expect(t, a.productRefresh(second, tsB.RefreshToken), http.StatusOK, "product B after A's burn")
	expect(t, a.get("/api/me", bearer(l.s.Access)), http.StatusOK, "App Central after A's burn")
}

// Losing access ends the product login at its next refresh, for good.
func TestProductRefreshEndsWhenAccessIsLost(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)

	a.exec(`DELETE FROM tbl_group_product_grants WHERE client_id = $1`, l.co.ID)
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Fatalf("refresh after access was lost: %s", w.Body.String())
	}
	if n := a.count(`SELECT count(*) FROM tbl_session_families WHERE user_id = $1 AND revoked_reason = 'ACCESS_LOST'`, l.m.ID); n != 1 {
		t.Errorf("%d logins marked ACCESS_LOST, want 1", n)
	}
	// Access coming back does not revive the ended login.
	g := a.newGroup(l.co)
	a.grantGroup(l.co, g, l.p, "Viewer")
	a.join(l.m, g)
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("a login ended for lost access came back: %s", w.Body.String())
	}
}

// Roles are re-read at every refresh: a changed role reaches the product within
// one token's lifetime.
func TestProductRefreshCarriesCurrentRoles(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)
	a.grant(l.m, l.p, "Admin") // a direct grant on top of the group's Viewer
	w := a.productRefresh(l.p, ts.RefreshToken)
	expect(t, w, http.StatusOK, "refresh")
	roles, _ := claims(t, jsonField(w, "access_token"))["roles"].([]any)
	if len(roles) != 2 || roles[0] != "Admin" || roles[1] != "Viewer" {
		t.Errorf("roles after the grant = %v, want [Admin Viewer]", roles)
	}
}

// App Central logout ends every product login under the session.
func TestCentralLogoutStopsProductRenewal(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)
	expect(t, a.post("/auth/central/logout", nil, withCookie(l.s.Cookie)), http.StatusNoContent, "logout")
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Fatalf("SECURITY: a product renewed after App Central logout: %s", w.Body.String())
	}
	if n := a.count(`SELECT count(*) FROM tbl_session_families WHERE user_id = $1 AND kind = 'PRODUCT' AND revoked_reason = 'LOGOUT'`, l.m.ID); n != 1 {
		t.Errorf("%d product logins ended by the logout, want 1", n)
	}
}

// ---------- audience separation ----------

func TestAudiencesAreSeparatedBothWays(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	other := a.newProduct()
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)

	// A product token is not a credential for App Central's API...
	for _, path := range []string{"/api/me", "/api/me/apps", "/api/admin/users", "/api/owner/companies"} {
		if w := a.get(path, bearer(ts.AccessToken)); w.Code != http.StatusUnauthorized {
			t.Errorf("SECURITY: a product token reached %s: %d", path, w.Code)
		}
	}
	// ...nor is an ID token...
	if w := a.get("/api/me", bearer(ts.IDToken)); w.Code != http.StatusUnauthorized {
		t.Errorf("SECURITY: an ID token reached /api/me: %d", w.Code)
	}
	// ...and App Central's token is not a credential for any product.
	if _, err := jwtkeys.VerifyAccess(l.s.Access, "product:"+l.p.Key); err == nil {
		t.Error("SECURITY: the App Central token verifies for a product")
	}
	// Nor is one product's token another's.
	if _, err := jwtkeys.VerifyAccess(ts.AccessToken, "product:"+other.Key); err == nil {
		t.Error("SECURITY: product A's token verifies for product B")
	}
}

// ---------- revocation and introspection ----------

func TestRevokeEndsOnlyTheCallersOwnLogin(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	other := a.newProduct()
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)

	// Another product revoking it: 200, and nothing happens.
	expect(t, a.post("/oauth/revoke", url.Values{"token": {ts.RefreshToken}}, basic(other.ID, other.Secret)), http.StatusOK, "foreign revoke")
	w := a.productRefresh(l.p, ts.RefreshToken)
	expect(t, w, http.StatusOK, "still live after a foreign revoke")
	var cur tokenSet
	decodeInto(t, w, &cur)
	// Unknown tokens are fine too.
	expect(t, a.post("/oauth/revoke", url.Values{"token": {"nonsense"}}, basic(l.p.ID, l.p.Secret)), http.StatusOK, "unknown")
	// Credentials are still required.
	expect(t, a.post("/oauth/revoke", url.Values{"token": {ts.RefreshToken}}), http.StatusUnauthorized, "no credentials")

	// By access token: the login it belongs to ends.
	f2 := newFlow(t)
	ts2 := a.exchange(l.p, a.code(&l, f2), f2)
	expect(t, a.post("/oauth/revoke", url.Values{"token": {ts2.AccessToken}}, basic(l.p.ID, l.p.Secret)), http.StatusOK, "revoke by access token")
	if w := a.productRefresh(l.p, ts2.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("revoked by access token, yet refreshes: %s", w.Body.String())
	}
	// By refresh token.
	expect(t, a.post("/oauth/revoke", url.Values{"token": {cur.RefreshToken}}, basic(l.p.ID, l.p.Secret)), http.StatusOK, "revoke")
	if w := a.productRefresh(l.p, cur.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("revoked, yet refreshes: %s", w.Body.String())
	}
	expect(t, a.get("/api/me", bearer(l.s.Access)), http.StatusOK, "a product sign-out leaves App Central signed in")
}

func TestIntrospectionReflectsTheLiveState(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	other := a.newProduct()
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)

	intro := func(p product, tok string) map[string]any {
		t.Helper()
		w := a.post("/oauth/introspect", url.Values{"token": {tok}}, basic(p.ID, p.Secret))
		expect(t, w, http.StatusOK, "introspect")
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Error("introspection response is cacheable")
		}
		return decode(t, w)
	}
	got := intro(l.p, ts.AccessToken)
	if got["active"] != true || got["sub"] != l.m.ID || got["client_id"] != l.p.ID || got["tenant_id"] != l.co.ID ||
		got["aud"] != "product:"+l.p.Key || got["iss"] != testIssuer {
		t.Fatalf("introspection = %v", got)
	}
	if got := intro(l.p, ts.RefreshToken); got["active"] != true || got["token_type"] != "refresh_token" {
		t.Errorf("refresh token introspection = %v", got)
	}
	// Another product may not learn anything about it.
	if got := intro(other, ts.AccessToken); len(got) != 1 || got["active"] != false {
		t.Errorf("SECURITY: another product's introspection = %v", got)
	}
	for _, junk := range []string{"", "garbage", l.s.Access, ts.IDToken} {
		if got := intro(l.p, junk); got["active"] != false {
			t.Errorf("SECURITY: %.20q introspected active", junk)
		}
	}
	// A role change stales the token at once for a product that introspects.
	a.grant(l.m, l.p, "Admin")
	a.exec(`UPDATE tbl_users SET permissions_version = permissions_version + 1 WHERE id = $1`, l.m.ID)
	if got := intro(l.p, ts.AccessToken); got["active"] != false {
		t.Errorf("a token with stale roles introspected active: %v", got)
	}
	// App Central logout ends it too.
	w := a.productRefresh(l.p, ts.RefreshToken)
	var fresh tokenSet
	decodeInto(t, w, &fresh)
	if got := intro(l.p, fresh.AccessToken); got["active"] != true {
		t.Fatalf("a fresh token introspected inactive: %v", got)
	}
	expect(t, a.post("/auth/central/logout", nil, withCookie(l.s.Cookie)), http.StatusNoContent, "logout")
	if got := intro(l.p, fresh.AccessToken); got["active"] != false {
		t.Errorf("SECURITY: a token of a signed-out session introspected active: %v", got)
	}
	if got := intro(l.p, fresh.RefreshToken); got["active"] != false {
		t.Errorf("SECURITY: a refresh token of a signed-out session introspected active: %v", got)
	}
}

// ---------- key rotation ----------

// A token signed before a rotation keeps verifying while its key is published
// verify-only; new tokens use the new key; both keys are in the JWKS.
func TestKeyRotationWithAVerifyOnlyKey(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	old := a.exchange(l.p, a.code(&l, f), f)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	newPriv := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	newPub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	rotated := newAppWith(t, map[string]string{
		"JWT_PRIVATE_KEY": newPriv, "JWT_PUBLIC_KEY": newPub, "JWT_KEY_ID": "rotated-kid",
		"JWT_VERIFY_KEYS": "test-kid=" + strings.ReplaceAll(os.Getenv("ALORA_TEST_PUB"), "\n", `\n`),
	}, nil)

	jwks := rotated.get("/.well-known/jwks.json").Body.String()
	if !strings.Contains(jwks, `"kid":"rotated-kid"`) || !strings.Contains(jwks, `"kid":"test-kid"`) {
		t.Fatalf("JWKS during rotation = %s", jwks)
	}
	if _, err := jwtkeys.VerifyAccess(old.AccessToken, "product:"+l.p.Key); err != nil {
		t.Errorf("a token signed before the rotation stopped verifying: %v", err)
	}
	w := rotated.productRefresh(l.p, old.RefreshToken)
	expect(t, w, http.StatusOK, "refresh after rotation")
	if kid := jwtHeader(t, jsonField(w, "access_token"))["kid"]; kid != "rotated-kid" {
		t.Errorf("new token signed with %v, want rotated-kid", kid)
	}
}
