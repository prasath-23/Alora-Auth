package main

// Company OIDC SSO, against a stub provider: registration through the Owner
// console, the round trip and its binding to the browser, every way an ID token
// can be wrong, and the linking rules — by subject once linked, by verified
// address at a registered domain the first time, never creating an account.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

type ssoSetup struct {
	co     company
	domain string
	conn   string
	policy string
	stub   *idpStub
	owner  session
}

// setupSSO registers a stub provider as a company's SSO connection, puts the
// company's domain on it, and makes an SSO-only policy the company default —
// all through the Owner console.
func (a *app) setupSSO() ssoSetup {
	a.t.Helper()
	sfx := randSuffix(a.t)
	domain := "sso-" + sfx + ".test"
	co := a.newCompany(domain)
	stub := newIdPStub(a.t, "client-"+sfx, "s3cret/"+sfx+"+")
	os := a.login(a.newOwner())
	base := "/api/owner/companies/" + co.ID

	w := a.ownerCall(os, http.MethodPost, base+"/sso-connections", co.ID, map[string]any{
		"name": "Stub " + sfx, "issuer": stub.srv.URL, "client_id": stub.clientID,
		"client_secret": stub.secret, "is_active": true,
	})
	expect(a.t, w, http.StatusCreated, "register connection")
	conn := jsonField(w, "id")
	expect(a.t, a.ownerCall(os, http.MethodPut, base+"/sso-connections/"+conn+"/domains", co.ID,
		map[string]any{"domains": []string{strings.ToUpper(domain)}}), http.StatusNoContent, "domains")
	w = a.ownerCall(os, http.MethodPost, base+"/login-policies", co.ID, map[string]any{
		"name": "SSO only", "allow_password": false, "allow_google": false, "sso_connection_id": conn, "priority": 10,
	})
	expect(a.t, w, http.StatusCreated, "policy")
	pid := jsonField(w, "id")
	expect(a.t, a.ownerCall(os, http.MethodPut, base+"/login-policies/"+pid+"/default", co.ID, nil), http.StatusNoContent, "default")
	return ssoSetup{co: co, domain: domain, conn: conn, policy: pid, stub: stub, owner: os}
}

func TestSSOSignsInAndLinksBySubject(t *testing.T) {
	a := newApp(t)
	sso := a.setupSSO()
	alice := a.newPasswordless(sso.co, "alice@"+sso.domain)

	st := a.start("/auth/sso/start?connection_id="+sso.conn+"&return_to=/apps", sso.stub)
	code := sso.stub.vouch(st, sso.stub.sign(sso.stub.claimsFor("idp-sub-1", "Alice@"+sso.domain, true, st.nonce)))
	s := a.signedIn(a.callback("/auth/sso/callback", st, code), "/apps")
	if c := claims(t, s.Access); c["sub"] != alice.ID || c["tenant_id"] != sso.co.ID {
		t.Fatalf("signed in as %v", c)
	}
	var method, connID string
	a.scalar(&method, `SELECT auth_method::text FROM tbl_session_families WHERE id = $1`, sessionID(t, s.Access))
	a.scalar(&connID, `SELECT auth_connection_id FROM tbl_session_families WHERE id = $1`, sessionID(t, s.Access))
	if method != "OIDC" || connID != sso.conn {
		t.Errorf("session signed in with %s at %s, want OIDC at the connection", method, connID)
	}
	if n := a.count(`SELECT count(*) FROM tbl_linked_identities WHERE user_id = $1 AND provider = 'OIDC'
	                 AND connection_id = $2 AND provider_id = 'idp-sub-1'`, alice.ID, sso.conn); n != 1 {
		t.Fatalf("%d links, want the subject linked once", n)
	}

	// Linked by subject: a later sign-in names the account even when the
	// provider now reports another address.
	st = a.start("/auth/sso/start?email=alice@"+sso.domain, sso.stub)
	code = sso.stub.vouch(st, sso.stub.sign(sso.stub.claimsFor("idp-sub-1", "renamed@elsewhere.test", false, st.nonce)))
	s = a.signedIn(a.callback("/auth/sso/callback", st, code), "/")
	if claims(t, s.Access)["sub"] != alice.ID {
		t.Error("a linked subject did not sign in its account")
	}
}

// The callback must come back to the browser that started the round trip, once.
func TestSSOCallbackIsBoundToTheBrowser(t *testing.T) {
	a := newApp(t)
	sso := a.setupSSO()
	a.newPasswordless(sso.co, "bob@"+sso.domain)
	good := func(st started) string {
		return sso.stub.vouch(st, sso.stub.sign(sso.stub.claimsFor("bob-sub", "bob@"+sso.domain, true, st.nonce)))
	}

	st := a.start("/auth/sso/start?connection_id="+sso.conn, sso.stub)
	code := good(st)
	// Without the browser's cookie: somebody else's callback.
	a.failedWith(a.get("/auth/sso/callback?"+url.Values{"state": {st.state}, "code": {code}}.Encode()), "sso_error", "state_mismatch")
	// With a cookie bound to another sign-in.
	other := a.start("/auth/sso/start?connection_id="+sso.conn, sso.stub)
	a.failedWith(a.get("/auth/sso/callback?"+url.Values{"state": {st.state}, "code": {code}}.Encode(), withCookie(other.cookie)),
		"sso_error", "state_mismatch")
	// The genuine one works exactly once.
	a.signedIn(a.callback("/auth/sso/callback", st, code), "/")
	a.failedWith(a.callback("/auth/sso/callback", st, good(st)), "sso_error", "state_expired")
	// A pending sign-in expires.
	late := a.start("/auth/sso/start?connection_id="+sso.conn, sso.stub)
	a.exec(`UPDATE tbl_login_states SET expires_at = now() - interval '1 second' WHERE kind = 'OIDC'`)
	a.failedWith(a.callback("/auth/sso/callback", late, good(late)), "sso_error", "state_expired")
	// The provider declining is reported as such.
	cancel := a.start("/auth/sso/start?connection_id="+sso.conn, sso.stub)
	a.failedWith(a.get("/auth/sso/callback?"+url.Values{"state": {cancel.state}, "error": {"access_denied"}}.Encode(), withCookie(cancel.cookie)),
		"sso_error", "cancelled")
	// No code at all.
	nocode := a.start("/auth/sso/start?connection_id="+sso.conn, sso.stub)
	a.failedWith(a.callback("/auth/sso/callback", nocode, ""), "sso_error", "invalid_request")
}

// Every one of these is an ID token a hostile provider, a replay or a
// misconfiguration could present. None signs anyone in.
func TestSSORefusesBadIDTokens(t *testing.T) {
	a := newApp(t)
	sso := a.setupSSO()
	carol := a.newPasswordless(sso.co, "carol@"+sso.domain)
	other := newIdPStub(t, sso.stub.clientID, sso.stub.secret)

	cases := map[string]func(st started) string{
		"wrong issuer": func(st started) string {
			c := sso.stub.claimsFor("carol-sub", "carol@"+sso.domain, true, st.nonce)
			c["iss"] = other.srv.URL
			return sso.stub.sign(c)
		},
		"wrong audience": func(st started) string {
			c := sso.stub.claimsFor("carol-sub", "carol@"+sso.domain, true, st.nonce)
			c["aud"] = "another-client"
			return sso.stub.sign(c)
		},
		"foreign azp": func(st started) string {
			c := sso.stub.claimsFor("carol-sub", "carol@"+sso.domain, true, st.nonce)
			c["azp"] = "another-client"
			return sso.stub.sign(c)
		},
		"expired": func(st started) string {
			c := sso.stub.claimsFor("carol-sub", "carol@"+sso.domain, true, st.nonce)
			c["exp"] = time.Now().Add(-10 * time.Minute).Unix()
			return sso.stub.sign(c)
		},
		"nonce of another sign-in": func(st started) string {
			return sso.stub.sign(sso.stub.claimsFor("carol-sub", "carol@"+sso.domain, true, "not-the-nonce"))
		},
		"alg none": func(st started) string {
			return unsignedToken(sso.stub.claimsFor("carol-sub", "carol@"+sso.domain, true, st.nonce))
		},
		"HS256 keyed with the public key": func(st started) string {
			return sso.stub.hs256(sso.stub.claimsFor("carol-sub", "carol@"+sso.domain, true, st.nonce))
		},
		"signed by another key": func(st started) string {
			return other.signWith(sso.stub.claimsFor("carol-sub", "carol@"+sso.domain, true, st.nonce), jwa.RS256, other.key, "stub-kid")
		},
		"unknown kid": func(st started) string {
			return sso.stub.signWith(sso.stub.claimsFor("carol-sub", "carol@"+sso.domain, true, st.nonce), jwa.RS256, sso.stub.key, "rotated-away")
		},
		// OpenID Connect Core §2: a subject is at most 255 characters.
		"a subject past the standard's 255 characters": func(st started) string {
			return sso.stub.sign(sso.stub.claimsFor(strings.Repeat("s", 256), "carol@"+sso.domain, true, st.nonce))
		},
		"a subject no index can hold": func(st started) string {
			return sso.stub.sign(sso.stub.claimsFor(letters(3000), "carol@"+sso.domain, true, st.nonce))
		},
		"a subject holding a NUL": func(st started) string {
			return sso.stub.sign(sso.stub.claimsFor("carol\x00sub", "carol@"+sso.domain, true, st.nonce))
		},
	}
	for name, mint := range cases {
		t.Run(name, func(t *testing.T) {
			st := a.start("/auth/sso/start?connection_id="+sso.conn, sso.stub)
			a.failedWith(a.callback("/auth/sso/callback", st, sso.stub.vouch(st, mint(st))), "sso_error", "exchange_failed")
		})
	}
	// A code the provider never issued: the exchange itself fails.
	st := a.start("/auth/sso/start?connection_id="+sso.conn, sso.stub)
	a.failedWith(a.callback("/auth/sso/callback", st, "made-up-code"), "sso_error", "exchange_failed")
	if n := a.count(`SELECT count(*) FROM tbl_linked_identities WHERE provider_id = 'carol-sub' OR user_id = $1`, carol.ID); n != 0 {
		t.Errorf("SECURITY: a refused token left %d links", n)
	}
}

// A provider's claims at the edges of what can be stored. A subject of exactly
// the standard's 255 characters links and signs in. An address that is no
// address — it holds a NUL, or runs past 320 characters — counts as none, so the
// sign-in fails as it would without one: never as a server error.
func TestSSOClaimsAtTheLimits(t *testing.T) {
	a := newApp(t)
	sso := a.setupSSO()
	hana := a.newPasswordless(sso.co, "hana@"+sso.domain)
	try := func(sub, email string) *httptest.ResponseRecorder {
		st := a.start("/auth/sso/start?connection_id="+sso.conn, sso.stub)
		return a.callback("/auth/sso/callback", st, sso.stub.vouch(st, sso.stub.sign(sso.stub.claimsFor(sub, email, true, st.nonce))))
	}
	a.failedWith(try("hana-sub", "hana\x00@"+sso.domain), "sso_error", "account_unavailable")
	a.failedWith(try("hana-sub", strings.Repeat("h", 320)+"@"+sso.domain), "sso_error", "account_unavailable")
	if n := a.count(`SELECT count(*) FROM tbl_linked_identities WHERE user_id = $1`, hana.ID); n != 0 {
		t.Fatalf("SECURITY: an address that is no address linked %d identities", n)
	}

	sub := strings.Repeat("s", 247) + randSuffixN(8)
	s := a.signedIn(try(sub, hana.Email), "/")
	if claims(t, s.Access)["sub"] != hana.ID {
		t.Fatalf("signed in as %v", claims(t, s.Access))
	}
	if n := a.count(`SELECT count(*) FROM tbl_linked_identities WHERE user_id = $1 AND provider_id = $2`, hana.ID, sub); n != 1 {
		t.Fatalf("%d links for a 255-character subject, want 1", n)
	}
}

// The first sign-in links by address, and only when everything lines up.
func TestSSOFirstLinkRules(t *testing.T) {
	a := newApp(t)
	sso := a.setupSSO()
	dave := a.newPasswordless(sso.co, "dave@"+sso.domain)
	// The same address in ANOTHER company: never linked by this connection.
	elsewhere := a.newCompany()
	stranger := a.newMember(elsewhere, "eve@"+sso.domain)

	try := func(sub, email string, verified bool) *httptest.ResponseRecorder {
		st := a.start("/auth/sso/start?connection_id="+sso.conn, sso.stub)
		return a.callback("/auth/sso/callback", st, sso.stub.vouch(st, sso.stub.sign(sso.stub.claimsFor(sub, email, verified, st.nonce))))
	}
	// An unverified address proves nothing.
	a.failedWith(try("dave-sub", dave.Email, false), "sso_error", "email_unverified")
	// An address at a domain not registered on the connection.
	a.failedWith(try("dave-sub", "dave@not-"+sso.domain, true), "sso_error", "account_unavailable")
	// No account: SSO never creates one.
	a.failedWith(try("frank-sub", "frank@"+sso.domain, true), "sso_error", "account_unavailable")
	if n := a.count(`SELECT count(*) FROM tbl_users WHERE email = $1`, "frank@"+sso.domain); n != 0 {
		t.Fatal("SECURITY: an SSO sign-in created an account")
	}
	// Another company's account with the address stays untouched.
	a.failedWith(try("eve-sub", stranger.Email, true), "sso_error", "account_unavailable")
	if n := a.count(`SELECT count(*) FROM tbl_linked_identities WHERE user_id = $1`, stranger.ID); n != 0 {
		t.Fatal("SECURITY: a connection linked another company's account")
	}
	// A connection the Owner trusts to assert addresses links unverified ones.
	a.exec(`UPDATE tbl_sso_connections SET trust_unverified_email = true WHERE id = $1`, sso.conn)
	a.signedIn(try("dave-sub", dave.Email, false), "/")
	// Once linked, the account is bound to that subject: another subject with
	// the same address does not take it over.
	a.failedWith(try("mallory-sub", dave.Email, true), "sso_error", "account_unavailable")
}

// The login policy still decides: a user whose policy names another method, or
// another connection, is not signed in by this one.
func TestSSOHonoursTheUsersPolicy(t *testing.T) {
	a := newApp(t)
	sso := a.setupSSO()
	gina := a.newPasswordless(sso.co, "gina@"+sso.domain)
	a.exec(`INSERT INTO tbl_login_policies (client_id, name, allow_password, allow_google, priority) VALUES ($1, 'Pw', true, false, 20)`, sso.co.ID)
	a.exec(`UPDATE tbl_users SET login_policy_id = (SELECT id FROM tbl_login_policies WHERE client_id = $1 AND name = 'Pw') WHERE id = $2`, sso.co.ID, gina.ID)
	st := a.start("/auth/sso/start?connection_id="+sso.conn, sso.stub)
	a.failedWith(a.callback("/auth/sso/callback", st, sso.stub.vouch(st, sso.stub.sign(sso.stub.claimsFor("gina-sub", gina.Email, true, st.nonce)))),
		"sso_error", "account_unavailable")
}

func TestSSOStartResolvesTheConnection(t *testing.T) {
	a := newApp(t)
	sso := a.setupSSO()
	// By the address's domain.
	a.start("/auth/sso/start?email=anyone@"+strings.ToUpper(sso.domain), sso.stub)
	// Nothing to start at.
	for name, q := range map[string]string{
		"unknown domain":     "email=x@unknown-" + randSuffix(t) + ".test",
		"unknown connection": "connection_id=00000000-0000-0000-0000-000000000000",
		"nothing":            "",
	} {
		w := a.get("/auth/sso/start?" + q)
		expect(t, w, http.StatusFound, name)
		if got := location(t, w); got.Path != "/login" || got.Query().Get("sso_error") != "sso_unavailable" {
			t.Errorf("%s: %s", name, got)
		}
	}
	// An inactive connection is not offered, and a suspended company's neither.
	a.exec(`UPDATE tbl_sso_connections SET is_active = false WHERE id = $1`, sso.conn)
	if got := location(t, a.get("/auth/sso/start?connection_id="+sso.conn)); got.Query().Get("sso_error") != "sso_unavailable" {
		t.Errorf("inactive connection: %s", got)
	}
	a.exec(`UPDATE tbl_sso_connections SET is_active = true WHERE id = $1`, sso.conn)
	a.exec(`UPDATE tbl_clients SET is_active = false WHERE id = $1`, sso.co.ID)
	if got := location(t, a.get("/auth/sso/start?connection_id="+sso.conn)); got.Query().Get("sso_error") != "sso_unavailable" {
		t.Errorf("suspended company: %s", got)
	}
	// Discovery offers the connection for the domain, and only the domain.
	a.exec(`UPDATE tbl_clients SET is_active = true WHERE id = $1`, sso.co.ID)
	d := decode(t, a.post("/auth/login/discover", map[string]any{"email": "someone@" + sso.domain}))
	if sso, _ := d["sso"].(map[string]any); sso == nil || sso["connection_id"] == nil || d["password"] != false {
		t.Errorf("discovery = %v", d)
	}
}

// The secret is sealed to its own connection: stored only as ciphertext, never
// returned, and useless on any other row.
func TestSSOSecretIsSealedToItsConnection(t *testing.T) {
	a := newApp(t)
	sso := a.setupSSO()
	var cipher []byte
	var keyID string
	a.scalar(&cipher, `SELECT client_secret_ciphertext FROM tbl_sso_connections WHERE id = $1`, sso.conn)
	a.scalar(&keyID, `SELECT secret_key_id FROM tbl_sso_connections WHERE id = $1`, sso.conn)
	if strings.Contains(string(cipher), sso.stub.secret) || keyID != "test-k1" {
		t.Fatalf("SECURITY: the secret is not sealed (key %q)", keyID)
	}
	w := a.ownerCall(sso.owner, http.MethodGet, "/api/owner/companies/"+sso.co.ID+"/sso-connections", "", nil)
	expect(t, w, http.StatusOK, "list")
	if strings.Contains(w.Body.String(), sso.stub.secret) || !strings.Contains(w.Body.String(), `"has_secret":true`) {
		t.Errorf("SECURITY: the list shows %s", w.Body.String())
	}

	// A ciphertext copied onto another connection's row does not open there.
	other := a.setupSSO()
	a.exec(`UPDATE tbl_sso_connections SET client_secret_ciphertext = $1 WHERE id = $2`, cipher, other.conn)
	if got := location(t, a.get("/auth/sso/start?connection_id="+other.conn)); got.Query().Get("sso_error") != "sso_unavailable" {
		t.Errorf("SECURITY: a transplanted ciphertext opened: %s", got)
	}

	// The test action reaches the provider through the guarded client.
	w = a.ownerCall(sso.owner, http.MethodPost, "/api/owner/companies/"+sso.co.ID+"/sso-connections/"+sso.conn+"/test", sso.co.ID, nil)
	expect(t, w, http.StatusOK, "test connection")
	if jsonField(w, "issuer") != sso.stub.srv.URL {
		t.Errorf("test = %s", w.Body.String())
	}
}

func TestSSOConnectionAdministration(t *testing.T) {
	a := newApp(t)
	sso := a.setupSSO()
	base := "/api/owner/companies/" + sso.co.ID + "/sso-connections"
	for name, body := range map[string]map[string]any{
		"relative issuer": {"name": "x", "issuer": "/idp", "client_id": "c", "is_active": true},
		"issuer w/ query": {"name": "x", "issuer": "https://idp.test/?a=1", "client_id": "c", "is_active": true},
		"no client id":    {"name": "x", "issuer": "https://idp.test", "is_active": true},
	} {
		expect(t, a.ownerCall(sso.owner, http.MethodPost, base, sso.co.ID, body), http.StatusBadRequest, name)
	}
	// The same issuer and client id twice.
	expect(t, a.ownerCall(sso.owner, http.MethodPost, base, sso.co.ID, map[string]any{
		"name": "Again", "issuer": sso.stub.srv.URL, "client_id": sso.stub.clientID, "is_active": true,
	}), http.StatusConflict, "duplicate registration")
	// A domain is on one connection only, and never another company's.
	other := a.setupSSO()
	expect(t, a.ownerCall(other.owner, http.MethodPut, "/api/owner/companies/"+other.co.ID+"/sso-connections/"+other.conn+"/domains",
		other.co.ID, map[string]any{"domains": []string{sso.domain}}), http.StatusConflict, "another company's domain")
	// An update without a secret keeps the stored one.
	var before []byte
	a.scalar(&before, `SELECT client_secret_ciphertext FROM tbl_sso_connections WHERE id = $1`, sso.conn)
	expect(t, a.ownerCall(sso.owner, http.MethodPatch, base+"/"+sso.conn, sso.co.ID, map[string]any{
		"name": "Renamed", "issuer": sso.stub.srv.URL, "client_id": sso.stub.clientID, "is_active": true,
	}), http.StatusOK, "update")
	var after []byte
	a.scalar(&after, `SELECT client_secret_ciphertext FROM tbl_sso_connections WHERE id = $1`, sso.conn)
	if string(after) != string(before) {
		t.Error("an update without a secret replaced the stored one")
	}
	// Another company's connection cannot be edited through this path.
	expect(t, a.ownerCall(sso.owner, http.MethodPatch, base+"/"+other.conn, sso.co.ID, map[string]any{
		"name": "x", "issuer": "https://idp.test", "client_id": "c", "is_active": true,
	}), http.StatusNotFound, "another company's connection")
}
