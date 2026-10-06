package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Who may call what, on every route under /api. Every credential that is not a
// live App Central session of the caller is a 401 on every route; every Owner
// route is refused to everyone but an Owner who signed in recently; and every
// Owner write names its company twice.

// signAs signs claims with key under kid and typ — the forgeries the real
// signer will not make: a stranger's key, another issuer, a future start.
func signAs(t *testing.T, alg jwa.SignatureAlgorithm, key any, kid, typ string, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		if err := tok.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)
	_ = hdrs.Set(jws.TypeKey, typ)
	s, err := jwt.Sign(tok, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(s)
}

// realKey is App Central's signing key as the tests configure it.
func realKey(t *testing.T) jwk.Key {
	t.Helper()
	k, err := jwk.ParseKey([]byte(os.Getenv("ALORA_TEST_PRIV")), jwk.WithPEM(true))
	if err != nil {
		t.Fatalf("test signing key: %v", err)
	}
	return k
}

// goodClaims are the claims App Central itself would put in m's token for s.
func goodClaims(m member, s session) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": testIssuer, "aud": "app-central", "sub": m.ID, "tenant_id": m.ClientID, "email": m.Email,
		"sid": sessionIDOf(s), "iat": now, "exp": now.Add(15 * time.Minute),
	}
}

// sessionIDOf reads a token's sid without a *testing.T.
func sessionIDOf(s session) string {
	parts := strings.Split(s.Access, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c map[string]any
	_ = json.Unmarshal(raw, &c)
	sid, _ := c["sid"].(string)
	return sid
}

func with(claims map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for key, val := range claims {
		out[key] = val
	}
	if v == nil {
		delete(out, k)
	} else {
		out[k] = v
	}
	return out
}

// apiRoutes is every route under /api, with a concrete path for it.
func apiRoutes(a *app) [][2]string {
	var out [][2]string
	for _, r := range a.r.Routes() {
		if !strings.HasPrefix(r.Path, "/api/") {
			continue
		}
		segs := strings.Split(r.Path, "/")
		for i, s := range segs {
			if strings.HasPrefix(s, ":") {
				segs[i] = noSuchID
			}
		}
		out = append(out, [2]string{r.Method, strings.Join(segs, "/")})
	}
	return out
}

func TestEveryAPIRouteRefusesEveryBadCredential(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co, elsewhere := a.newCompany(), a.newCompany()
	m, other := a.newMember(co, ""), a.newMember(co, "")
	ms, os_ := a.login(m), a.login(other)
	key := realKey(t)
	good := goodClaims(m, ms)
	const kid = "test-kid"

	// The forging is sound: App Central's own claims under its own key pass.
	expect(t, a.get("/api/me", bearer(signAs(t, jwa.RS256, key, kid, "at+jwt", good))), http.StatusOK, "the positive control")

	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// The classic confusion: HS256 keyed with App Central's own public key, in
	// either encoding an attacker might try.
	pubPEM := []byte(os.Getenv("ALORA_TEST_PUB"))
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		t.Fatal("test public key is not PEM")
	}
	unsignedClaims, _ := json.Marshal(good)
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt","kid":"test-kid"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(unsignedClaims) + "."

	// Sessions that were real, then ended or were stripped of their standing.
	signedOut := a.login(a.newMember(co, ""))
	expect(t, a.post("/auth/central/logout", nil, withCookie(signedOut.Cookie)), http.StatusNoContent, "sign out")
	deactivated := a.newMember(co, "")
	ds := a.login(deactivated)
	a.exec(`UPDATE tbl_users SET is_active = false WHERE id = $1`, deactivated.ID)
	deleted := a.newMember(co, "")
	dls := a.login(deleted)
	a.exec(`UPDATE tbl_users SET deleted_at = now() WHERE id = $1`, deleted.ID)
	suspendedCo := a.newCompany()
	sus := a.login(a.newMember(suspendedCo, ""))
	a.exec(`UPDATE tbl_clients SET is_active = false WHERE id = $1`, suspendedCo.ID)
	// Product tokens: a person's and an application's.
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	person := a.exchange(l.p, a.code(&l, f), f)
	app := a.newApplication(1, "api:read")
	application := a.appToken(app, app.products[0], "")

	creds := []struct{ name, header string }{
		{"no credential", ""},
		{"an empty bearer", "Bearer "},
		{"garbage", "Bearer garbage"},
		{"Basic credentials", "Basic " + base64.StdEncoding.EncodeToString([]byte(m.Email+":"+testPassword))},
		{"a lower-case scheme and garbage", "bearer x.y.z"},
		{"alg none", "Bearer " + unsigned},
		{"HS256 keyed with the public key's DER", "Bearer " + signAs(t, jwa.HS256, block.Bytes, kid, "at+jwt", good)},
		{"HS256 keyed with the public key's PEM", "Bearer " + signAs(t, jwa.HS256, pubPEM, kid, "at+jwt", good)},
		{"a stranger's key under App Central's kid", "Bearer " + signAs(t, jwa.RS256, stranger, kid, "at+jwt", good)},
		{"an unknown kid", "Bearer " + signAs(t, jwa.RS256, key, "no-such-kid", "at+jwt", good)},
		{"expired", "Bearer " + signAs(t, jwa.RS256, key, kid, "at+jwt", with(with(good, "exp", time.Now().Add(-time.Hour)), "iat", time.Now().Add(-2*time.Hour)))},
		{"not yet valid", "Bearer " + signAs(t, jwa.RS256, key, kid, "at+jwt", with(good, "nbf", time.Now().Add(time.Hour)))},
		{"another issuer", "Bearer " + signAs(t, jwa.RS256, key, kid, "at+jwt", with(good, "iss", "https://evil.example"))},
		{"another audience", "Bearer " + signAs(t, jwa.RS256, key, kid, "at+jwt", with(good, "aud", "product:"+l.p.Key))},
		{"an ID token's type", "Bearer " + signAs(t, jwa.RS256, key, kid, "JWT", good)},
		{"no session", "Bearer " + signAs(t, jwa.RS256, key, kid, "at+jwt", with(good, "sid", nil))},
		{"no company", "Bearer " + signAs(t, jwa.RS256, key, kid, "at+jwt", with(good, "tenant_id", nil))},
		{"no subject", "Bearer " + signAs(t, jwa.RS256, key, kid, "at+jwt", with(good, "sub", nil))},
		{"another user's session", "Bearer " + signAs(t, jwa.RS256, key, kid, "at+jwt", with(good, "sid", sessionIDOf(os_)))},
		{"the session claimed in another company", "Bearer " + signAs(t, jwa.RS256, key, kid, "at+jwt", with(good, "tenant_id", elsewhere.ID))},
		{"a product login's session", "Bearer " + signAs(t, jwa.RS256, key, kid, "at+jwt", with(with(with(good, "sub", l.m.ID), "tenant_id", l.co.ID), "sid", sessionID(t, person.AccessToken)))},
		{"a signed-out session", "Bearer " + signedOut.Access},
		{"a deactivated user", "Bearer " + ds.Access},
		{"a deleted user", "Bearer " + dls.Access},
		{"a suspended company", "Bearer " + sus.Access},
		{"a person's product token", "Bearer " + person.AccessToken},
		{"an application's product token", "Bearer " + application.AccessToken},
	}

	routes := apiRoutes(a)
	sent := 0
	for _, c := range creds {
		for _, r := range routes {
			var opts []reqOpt
			if c.header != "" {
				opts = append(opts, header("Authorization", c.header))
			}
			var body any
			if r[0] != http.MethodGet && r[0] != http.MethodDelete {
				body = map[string]any{}
			}
			w := a.send(r[0], r[1], body, opts...)
			sent++
			if w.Code != http.StatusUnauthorized || jsonField(w, "error") != "Unauthorized" || jsonField(w, "reqId") == "" {
				t.Errorf("SECURITY: %s on %s %s: %d %s, want 401", c.name, r[0], r[1], w.Code, clip(w.Body.String()))
			}
		}
	}
	t.Logf("%d credentials × %d routes = %d refused requests", len(creds), len(routes), sent)
}

func TestEveryOwnerRouteIsTheOwnersAlone(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	delegate := a.newMember(co, "")
	a.giveExtras(delegate, "users:edit", "groups:edit", "invitations:edit", "sessions:edit", "products:read", "company:edit", "api-clients:edit")
	manager := a.newMember(co, "")
	a.makeManager(a.newGroup(co), manager, a.newAdmin(co))
	pl := a.platform()
	staleOwner := a.newOwner()
	sos := a.login(staleOwner)
	a.exec(`UPDATE tbl_session_families SET authenticated_at = now() - interval '13 hours' WHERE id = $1`, sessionID(t, sos.Access))
	owner := a.login(a.newOwner())

	callers := []struct {
		name   string
		s      *session
		status int
		error  string
	}{
		{"anonymous", nil, http.StatusUnauthorized, "Unauthorized"},
		{"a member", ptr(a.login(a.newMember(co, ""))), http.StatusForbidden, "Forbidden"},
		{"a delegate holding every scope", ptr(a.login(delegate)), http.StatusForbidden, "Forbidden"},
		{"a group manager", ptr(a.login(manager)), http.StatusForbidden, "Forbidden"},
		{"a company Admin", ptr(a.login(a.newAdmin(co))), http.StatusForbidden, "Forbidden"},
		{"a platform Admin who is not an Owner", ptr(a.login(a.newAdmin(pl))), http.StatusForbidden, "Forbidden"},
		{"an Owner who signed in 13 hours ago", &sos, http.StatusForbidden, "Recent sign-in required"},
	}
	var owned [][2]string
	for _, r := range apiRoutes(a) {
		if strings.HasPrefix(r[1], "/api/owner") {
			owned = append(owned, r)
		}
	}
	for _, c := range callers {
		for _, r := range owned {
			var opts []reqOpt
			if c.s != nil {
				opts = append(opts, bearer(c.s.Access))
			}
			opts = append(opts, header("X-Alora-Target-Company", noSuchID))
			w := a.send(r[0], r[1], map[string]any{}, opts...)
			if w.Code != c.status || jsonField(w, "error") != c.error {
				t.Errorf("SECURITY: %s on %s %s: %d %s, want %d %s", c.name, r[0], r[1], w.Code, clip(w.Body.String()), c.status, c.error)
			}
		}
	}
	// The Owner passes the guard on every one of them.
	for _, r := range owned {
		w := a.send(r[0], r[1], map[string]any{}, bearer(owner.Access), header("X-Alora-Target-Company", noSuchID))
		if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden || w.Code >= 500 {
			t.Errorf("the Owner on %s %s: %d %s", r[0], r[1], w.Code, clip(w.Body.String()))
		}
	}
	t.Logf("%d Owner routes × %d callers", len(owned), len(callers)+1)
}

func ptr(s session) *session { return &s }

// Every Owner write under a company names that company twice — in the path and
// in X-Alora-Target-Company — and without the echo nothing is written.
func TestEveryOwnerWriteNamesItsCompanyTwice(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	owner := a.login(a.newOwner())
	w := a.newSweepWorld(owner)
	other := a.newCompany()
	before := a.fingerprint(w.co.ID)
	writes, reads := 0, 0
	for _, r := range a.r.Routes() {
		if !strings.HasPrefix(r.Path, "/api/owner/companies/:cid") {
			continue
		}
		path := w.fill(r.Path, "", "")
		if r.Method == http.MethodGet {
			reads++
			if res := a.send(r.Method, path, nil, bearer(owner.Access)); res.Code != http.StatusOK {
				t.Errorf("GET %s needs no echo: %d %s", r.Path, res.Code, clip(res.Body.String()))
			}
			continue
		}
		writes++
		for name, cid := range map[string]string{"no header": "", "another company": other.ID, "garbage": "x", "the company, upper-cased": strings.ToUpper(w.co.ID)} {
			opts := []reqOpt{bearer(owner.Access)}
			if cid != "" {
				opts = append(opts, header("X-Alora-Target-Company", cid))
			}
			if res := a.send(r.Method, path, w.template(r.Method+" "+r.Path), opts...); res.Code != http.StatusBadRequest {
				t.Errorf("SECURITY: %s %s with %s: %d %s, want 400", r.Method, r.Path, name, res.Code, clip(res.Body.String()))
			}
		}
	}
	if changed := changedTables(before, a.fingerprint(w.co.ID)); len(changed) > 0 {
		t.Errorf("SECURITY: writes without the right echo changed %v", changed)
	}
	if writes < 30 || reads < 10 {
		t.Fatalf("only %d writes and %d reads under a company: the route table has changed shape", writes, reads)
	}
	t.Logf("%d Owner writes refused without the echo, %d reads served", writes, reads)
}
