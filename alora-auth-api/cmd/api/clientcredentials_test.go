package main

// The client-credentials grant: an API client — an application with no person
// behind it — gets a token for one product on its list, for the scopes it holds.
// Products and API clients share one token endpoint and one way of
// authenticating, but not their grants: products sign people in, API clients
// use client credentials, and neither may use the other's.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alora/auth/internal/core/shared/crypto/jwtkeys"
)

// application is an API client of a company, set up through the admin door:
// products on its list, scopes, and a secret.
type application struct {
	co       company
	admin    session
	id       string
	secret   string
	secretID string
	products []product
}

// newApplication creates an API client holding the scopes named, with a list of
// n products its company subscribes to and that accept API clients.
func (a *app) newApplication(n int, scopes ...string) application {
	a.t.Helper()
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	c := a.newAPIClient(s, "App "+randSuffix(a.t))
	app := application{co: co, admin: s, id: c.ID}
	ids := []string{}
	for i := 0; i < n; i++ {
		p := a.newProduct()
		a.subscribe(co, p)
		a.acceptAPIClients(p, true)
		app.products = append(app.products, p)
		ids = append(ids, p.ID)
	}
	expect(a.t, a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/products", map[string]any{"product_ids": ids}, bearer(s.Access)),
		http.StatusOK, "products")
	if scopes == nil {
		scopes = []string{}
	}
	expect(a.t, a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/scopes", map[string]any{"scopes": scopes}, bearer(s.Access)),
		http.StatusOK, "scopes")
	sec, code := a.newSecret(s, c.ID, nil)
	if code != http.StatusCreated {
		a.t.Fatalf("secret: %d", code)
	}
	app.secret, app.secretID = sec.ClientSecret, sec.ID
	return app
}

// clientCredentials asks the token endpoint for a token as an API client.
func (a *app) clientCredentials(id, secret, resource, scope string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"client_credentials"}}
	if resource != "" {
		form.Set("resource", resource)
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	return a.post("/oauth/token", form, basic(id, secret))
}

func (a *app) appToken(app application, p product, scope string) tokenSet {
	a.t.Helper()
	w := a.clientCredentials(app.id, app.secret, "product:"+p.Key, scope)
	expect(a.t, w, http.StatusOK, "client credentials")
	var ts tokenSet
	decodeInto(a.t, w, &ts)
	return ts
}

func (a *app) introspectAs(p product, token string) map[string]any {
	a.t.Helper()
	w := a.post("/oauth/introspect", url.Values{"token": {token}}, basic(p.ID, p.Secret))
	expect(a.t, w, http.StatusOK, "introspect")
	return decode(a.t, w)
}

// An API client gets a token for each product on its list: for that product
// alone, carrying the scopes asked for — or all it holds — and nothing a
// person's token carries.
func TestClientCredentialsIssueAProductToken(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(2, "api:read", "grpc:read")
	crm, hr := app.products[0], app.products[1]

	w := a.clientCredentials(app.id, app.secret, "product:"+crm.Key, "")
	expect(t, w, http.StatusOK, "all its scopes")
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", w.Header().Get("Cache-Control"))
	}
	body := decode(t, w)
	if body["token_type"] != "Bearer" || body["expires_in"] != float64(900) || body["scope"] != "api:read grpc:read" {
		t.Errorf("body = %v", body)
	}
	for _, none := range []string{"refresh_token", "id_token"} {
		if _, ok := body[none]; ok {
			t.Errorf("an application's token response carries %s", none)
		}
	}
	tok := body["access_token"].(string)
	if _, err := jwtkeys.VerifyAccess(tok, "product:"+crm.Key); err != nil {
		t.Fatalf("the token does not verify for its product: %v", err)
	}
	c := claims(t, tok)
	if c["sub"] != app.id || c["client_id"] != app.id || c["tenant_id"] != app.co.ID || c["principal"] != "client" ||
		c["scope"] != "api:read grpc:read" || c["sid"] != app.secretID {
		t.Errorf("claims = %v", c)
	}
	if roles, ok := c["roles"].([]any); !ok || len(roles) != 0 {
		t.Errorf("roles = %v, want an empty list", c["roles"])
	}
	for _, none := range []string{"email", "pv"} {
		if _, ok := c[none]; ok {
			t.Errorf("an application's token carries %s", none)
		}
	}
	if jwtHeader(t, tok)["typ"] != "at+jwt" {
		t.Errorf("typ = %v", jwtHeader(t, tok)["typ"])
	}
	if _, err := jwtkeys.VerifyAccess(tok, "product:"+hr.Key); err == nil {
		t.Error("SECURITY: a token for one product verifies for another")
	}

	// A subset, and the second product on its list.
	if ts := a.appToken(app, hr, "grpc:read"); ts.Scope != "grpc:read" || claims(t, ts.AccessToken)["scope"] != "grpc:read" {
		t.Errorf("a subset = %q", ts.Scope)
	}
	// A person's product token now says it speaks for a person.
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	if c := claims(t, a.exchange(l.p, a.code(&l, f), f).AccessToken); c["principal"] != "user" {
		t.Errorf("a person's token: principal %v", c["principal"])
	}
}

// Every way a token can be refused, each with its own answer: invalid_client
// for credentials, invalid_target for the product, invalid_scope for the scope,
// unauthorized_client for a grant the client may not use.
func TestClientCredentialsRefusals(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(1, "api:read")
	p := app.products[0]
	resource := "product:" + p.Key
	must := func(w *httptest.ResponseRecorder, status int, code, what string) {
		t.Helper()
		if w.Code != status || oauthError(t, w) != code {
			t.Errorf("%s: %d %s, want %d %s", what, w.Code, w.Body.String(), status, code)
		}
	}
	// Credentials.
	must(a.clientCredentials(app.id, app.secret+"x", resource, ""), 401, "invalid_client", "a wrong secret")
	must(a.clientCredentials("aci_"+noSuchID, app.secret, resource, ""), 401, "invalid_client", "an unknown client")
	must(a.clientCredentials(app.id, p.Secret, resource, ""), 401, "invalid_client", "a product's secret")
	w := a.clientCredentials(app.id, "nope", resource, "")
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("an invalid_client answer has no WWW-Authenticate")
	}
	w = a.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "resource": {resource},
		"client_id": {app.id}, "client_secret": {app.secret}})
	must(w, 401, "invalid_client", "a secret in the body")

	// The product.
	other := a.newProduct()
	a.acceptAPIClients(other, true)
	for what, r := range map[string]string{
		"no resource": "", "a resource that is not a product": "https://" + p.Key,
		"an unknown product": "product:NOPE-" + randSuffix(t), "a product not on the list": "product:" + other.Key,
		"an empty key": "product:",
	} {
		must(a.clientCredentials(app.id, app.secret, r, ""), 400, "invalid_target", what)
	}

	// The scope.
	must(a.clientCredentials(app.id, app.secret, resource, "api:edit"), 400, "invalid_scope", "a scope it lacks")
	must(a.clientCredentials(app.id, app.secret, resource, "users:read"), 400, "invalid_scope", "a person's scope")
	must(a.clientCredentials(app.id, app.secret, resource, "api:read nonsense"), 400, "invalid_scope", "an unknown scope")
	empty := a.newApplication(1)
	must(a.clientCredentials(empty.id, empty.secret, "product:"+empty.products[0].Key, ""), 400, "invalid_scope", "no scope at all")

	// The grant, both ways.
	must(a.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "resource": {resource}}, basic(p.ID, p.Secret)),
		400, "unauthorized_client", "a product using client_credentials")
	for _, form := range []url.Values{
		{"grant_type": {"authorization_code"}, "code": {"x"}, "redirect_uri": {p.Redirect}, "code_verifier": {"y"}},
		{"grant_type": {"refresh_token"}, "refresh_token": {"x"}},
	} {
		must(a.post("/oauth/token", form, basic(app.id, app.secret)), 400, "unauthorized_client", "an API client using "+form.Get("grant_type"))
	}
	must(a.post("/oauth/token", url.Values{"grant_type": {"password"}}, basic(app.id, app.secret)), 400, "unsupported_grant_type", "a grant nobody may use")
	// Still fine after all that.
	a.appToken(app, p, "")
}

// Whatever turns a client, its secret, its company, the product or the
// subscription off stops its tokens at once.
func TestClientCredentialsFollowEverySwitch(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(1, "api:read")
	p := app.products[0]
	resource := "product:" + p.Key
	ok := func(what string) {
		t.Helper()
		expect(t, a.clientCredentials(app.id, app.secret, resource, ""), http.StatusOK, what)
	}
	refused := func(code, what string) {
		t.Helper()
		if w := a.clientCredentials(app.id, app.secret, resource, ""); oauthError(t, w) != code {
			t.Errorf("SECURITY: %s: %d %s, want %s", what, w.Code, w.Body.String(), code)
		}
	}
	for _, sw := range []struct {
		what, off, on, code string
	}{
		{"the client switched off", `UPDATE tbl_api_clients SET is_active = false WHERE id = $1`,
			`UPDATE tbl_api_clients SET is_active = true WHERE id = $1`, "invalid_client"},
		{"the company suspended", `UPDATE tbl_clients SET is_active = false WHERE id = (SELECT client_id FROM tbl_api_clients WHERE id = $1)`,
			`UPDATE tbl_clients SET is_active = true WHERE id = (SELECT client_id FROM tbl_api_clients WHERE id = $1)`, "invalid_client"},
		{"the secret expired", `UPDATE tbl_api_client_secrets SET expires_at = now() - interval '1 second' WHERE api_client_id = $1`,
			`UPDATE tbl_api_client_secrets SET expires_at = NULL WHERE api_client_id = $1`, "invalid_client"},
		{"the product switched off", `UPDATE tbl_products SET is_active = false WHERE id IN (SELECT product_id FROM tbl_api_client_products WHERE api_client_id = $1)`,
			`UPDATE tbl_products SET is_active = true WHERE id IN (SELECT product_id FROM tbl_api_client_products WHERE api_client_id = $1)`, "invalid_target"},
		{"the product no longer accepting API clients", `UPDATE tbl_products SET accepts_api_clients = false WHERE id IN (SELECT product_id FROM tbl_api_client_products WHERE api_client_id = $1)`,
			`UPDATE tbl_products SET accepts_api_clients = true WHERE id IN (SELECT product_id FROM tbl_api_client_products WHERE api_client_id = $1)`, "invalid_target"},
		{"the subscription switched off", `UPDATE tbl_client_products cp SET is_active = false FROM tbl_api_client_products ap WHERE ap.api_client_id = $1 AND cp.client_id = ap.client_id AND cp.product_id = ap.product_id`,
			`UPDATE tbl_client_products cp SET is_active = true FROM tbl_api_client_products ap WHERE ap.api_client_id = $1 AND cp.client_id = ap.client_id AND cp.product_id = ap.product_id`, "invalid_target"},
		{"the subscription ended", `UPDATE tbl_client_products cp SET ends_at = now() - interval '1 second' FROM tbl_api_client_products ap WHERE ap.api_client_id = $1 AND cp.client_id = ap.client_id AND cp.product_id = ap.product_id`,
			`UPDATE tbl_client_products cp SET ends_at = NULL FROM tbl_api_client_products ap WHERE ap.api_client_id = $1 AND cp.client_id = ap.client_id AND cp.product_id = ap.product_id`, "invalid_target"},
	} {
		ok("before " + sw.what)
		a.exec(sw.off, app.id)
		refused(sw.code, sw.what)
		a.exec(sw.on, app.id)
	}
	ok("with everything back on")

	// Off the list: invalid_target, like a product it never had.
	expect(t, a.send(http.MethodPut, "/api/admin/api-clients/"+app.id+"/products", map[string]any{"product_ids": []string{}}, bearer(app.admin.Access)),
		http.StatusOK, "empty the list")
	refused("invalid_target", "off the list")
}

// Two secrets are live during a rotation, and both earn tokens; a revoked one
// earns none, from that moment.
func TestRotatingASecretKeepsTokensFlowing(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(1, "api:read")
	resource := "product:" + app.products[0].Key
	second, code := a.newSecret(app.admin, app.id, nil)
	if code != http.StatusCreated {
		t.Fatalf("second secret: %d", code)
	}
	expect(t, a.clientCredentials(app.id, app.secret, resource, ""), http.StatusOK, "the first secret")
	w := a.clientCredentials(app.id, second.ClientSecret, resource, "")
	expect(t, w, http.StatusOK, "the second secret")
	if claims(t, jsonField(w, "access_token"))["sid"] != second.ID {
		t.Error("a token does not name the secret it was issued under")
	}
	expect(t, a.send(http.MethodDelete, "/api/admin/api-clients/"+app.id+"/secrets/"+app.secretID, nil, bearer(app.admin.Access)),
		http.StatusNoContent, "revoke the first")
	if w := a.clientCredentials(app.id, app.secret, resource, ""); oauthError(t, w) != "invalid_client" {
		t.Errorf("SECURITY: a revoked secret: %d %s", w.Code, w.Body.String())
	}
	expect(t, a.clientCredentials(app.id, second.ClientSecret, resource, ""), http.StatusOK, "the second, after the rotation")
}

// A product introspecting an application's token learns who it speaks for and
// what it may do — and that it stops being active the moment anything it rests
// on is gone.
func TestIntrospectingAnApplicationsToken(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(2, "api:read", "mcp:tools")
	p, other := app.products[0], app.products[1]
	tok := a.appToken(app, p, "").AccessToken

	got := a.introspectAs(p, tok)
	if got["active"] != true || got["principal"] != "client" || got["sub"] != app.id || got["client_id"] != app.id ||
		got["tenant_id"] != app.co.ID || got["scope"] != "api:read mcp:tools" || got["aud"] != "product:"+p.Key {
		t.Fatalf("introspection = %v", got)
	}
	if _, ok := got["roles"]; ok {
		t.Errorf("an application's introspection carries roles: %v", got["roles"])
	}
	if got := a.introspectAs(other, tok); got["active"] != false {
		t.Errorf("SECURITY: another product introspected it active: %v", got)
	}
	// A person's token introspects as a person's.
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	if got := a.introspectAs(l.p, a.exchange(l.p, a.code(&l, f), f).AccessToken); got["principal"] != "user" {
		t.Errorf("a person's token: %v", got)
	}

	inactiveAfter := func(what string, change func()) {
		t.Helper()
		fresh := a.appToken(app, p, "").AccessToken
		if got := a.introspectAs(p, fresh); got["active"] != true {
			t.Fatalf("before %s: %v", what, got)
		}
		change()
		if got := a.introspectAs(p, fresh); got["active"] != false {
			t.Errorf("SECURITY: active after %s: %v", what, got)
		}
	}
	inactiveAfter("a scope it carries is taken away", func() {
		expect(t, a.send(http.MethodPut, "/api/admin/api-clients/"+app.id+"/scopes", map[string]any{"scopes": []string{"api:read"}},
			bearer(app.admin.Access)), http.StatusOK, "narrow the scopes")
	})
	a.exec(`SELECT stp_SetApiClientScopes($1, $2, ARRAY['api:read', 'mcp:tools'])`, app.id, app.co.ID)
	inactiveAfter("the client is switched off", func() {
		a.exec(`UPDATE tbl_api_clients SET is_active = false WHERE id = $1`, app.id)
	})
	a.exec(`UPDATE tbl_api_clients SET is_active = true WHERE id = $1`, app.id)
	inactiveAfter("the product comes off its list", func() {
		expect(t, a.send(http.MethodPut, "/api/admin/api-clients/"+app.id+"/products", map[string]any{"product_ids": []string{other.ID}},
			bearer(app.admin.Access)), http.StatusOK, "take the product off")
	})
	expect(t, a.send(http.MethodPut, "/api/admin/api-clients/"+app.id+"/products", map[string]any{"product_ids": []string{p.ID, other.ID}},
		bearer(app.admin.Access)), http.StatusOK, "put it back")
	inactiveAfter("its secret is revoked", func() {
		expect(t, a.send(http.MethodDelete, "/api/admin/api-clients/"+app.id+"/secrets/"+app.secretID, nil, bearer(app.admin.Access)),
			http.StatusNoContent, "revoke")
	})
}

// App Central's own API accepts App Central's tokens only; the products' OAuth
// endpoints other than the token endpoint are the products' own; and an API
// client cannot start a sign-in.
func TestApplicationTokensAndClientsStayInTheirLane(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(1, "api:edit")
	tok := a.appToken(app, app.products[0], "").AccessToken
	if w := a.get("/api/me", bearer(tok)); w.Code != http.StatusUnauthorized {
		t.Errorf("SECURITY: an application's token opened App Central's API: %d", w.Code)
	}
	for _, path := range []string{"/oauth/revoke", "/oauth/introspect"} {
		w := a.post(path, url.Values{"token": {tok}}, basic(app.id, app.secret))
		if w.Code != http.StatusBadRequest || oauthError(t, w) != "unauthorized_client" {
			t.Errorf("SECURITY: an API client at %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	q := url.Values{"response_type": {"code"}, "client_id": {app.id}, "redirect_uri": {"https://evil.example/cb"},
		"scope": {"openid"}, "state": {"s"}, "code_challenge": {"x"}, "code_challenge_method": {"S256"}}
	if w := a.get("/oauth/authorize?" + q.Encode()); w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Errorf("SECURITY: an API client started a sign-in: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// When a secret and its client last earned a token is stamped, at most once a
// minute each.
func TestLastUseIsStampedAtMostOnceAMinute(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(1, "api:read")
	stamps := func() (secret, client *time.Time) {
		t.Helper()
		if err := a.pool.QueryRow(t.Context(), `SELECT x.last_used_at, a.last_used_at FROM tbl_api_client_secrets x
		        JOIN tbl_api_clients a ON a.id = x.api_client_id WHERE x.id = $1`, app.secretID).Scan(&secret, &client); err != nil {
			t.Fatal(err)
		}
		return secret, client
	}
	if s, c := stamps(); s != nil || c != nil {
		t.Fatalf("stamped before any token: %v %v", s, c)
	}
	a.appToken(app, app.products[0], "")
	s1, c1 := stamps()
	if s1 == nil || c1 == nil {
		t.Fatal("a token was issued but nothing was stamped")
	}
	a.appToken(app, app.products[0], "")
	if s2, c2 := stamps(); !s2.Equal(*s1) || !c2.Equal(*c1) {
		t.Errorf("stamped twice within the minute: %v → %v, %v → %v", s1, s2, c1, c2)
	}
	// The detail page shows it.
	d := a.apiClientDetail(app.admin, app.id)
	var lastUsed struct {
		LastUsedAt *time.Time `json:"last_used_at"`
		Secrets    []struct {
			LastUsedAt *time.Time `json:"last_used_at"`
		} `json:"secrets"`
	}
	decodeInto(t, a.get("/api/admin/api-clients/"+app.id, bearer(app.admin.Access)), &lastUsed)
	if lastUsed.LastUsedAt == nil || len(lastUsed.Secrets) != 1 || lastUsed.Secrets[0].LastUsedAt == nil || d.ID != app.id {
		t.Errorf("the detail = %+v", lastUsed)
	}
}

// Many wrong secrets against API client ids from one address run out of budget,
// just as against products.
func TestFailedAPIClientAuthenticationIsBudgeted(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(1, "api:read")
	resource := "product:" + app.products[0].Key
	limited := false
	for i := 0; i < 40 && !limited; i++ {
		w := a.clientCredentials("aci_"+strings.Repeat("0", 8)+"-"+randSuffix(t), "guess", resource, "")
		limited = w.Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("SECURITY: failed API-client authentications are not budgeted")
	}
	if w := a.clientCredentials(app.id, app.secret, resource, ""); w.Code != http.StatusTooManyRequests {
		t.Errorf("the address kept its budget for a correct secret: %d", w.Code)
	}
}
