package main

// App Central sign-in: the password path and its generic refusals, the company
// chooser, the session cookie, rotation and replay, the absolute cap, logout of
// the whole tree, suspended companies, and the cross-site defences.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alora/auth/internal/core/shared/crypto/jwtkeys"
)

// ---------- password sign-in ----------

func TestPasswordLoginIssuesSessionAndToken(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")

	w := a.post("/auth/login/password", map[string]any{"email": strings.ToUpper(m.Email), "password": m.Password})
	expect(t, w, http.StatusOK, "login")
	body := decode(t, w)
	if body["status"] != "authenticated" || body["token_type"] != "Bearer" || body["expires_in"] != float64(900) {
		t.Fatalf("body = %v", body)
	}
	for _, leak := range []string{"refresh_token", "password", "roles", "companies"} {
		if _, ok := body[leak]; ok {
			t.Errorf("SECURITY: login response carries %q", leak)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", w.Header().Get("Cache-Control"))
	}

	// The access token is App Central's alone: {sub, tenant_id, email, sid} and
	// a snapshot of the person's App Central access (scope, products, av, pv —
	// scopes_test.go), audience app-central, typ at+jwt.
	tok := body["access_token"].(string)
	parsed, err := jwtkeys.VerifyAccess(tok, "app-central")
	if err != nil {
		t.Fatalf("App Central token does not verify: %v", err)
	}
	c := claims(t, tok)
	if parsed.Subject() != m.ID || c["tenant_id"] != co.ID || c["email"] != m.Email || c["sid"] == "" {
		t.Errorf("claims = %v", c)
	}
	if _, has := c["roles"]; has {
		t.Error("SECURITY: the App Central token carries product roles")
	}
	if jwtHeader(t, tok)["typ"] != "at+jwt" {
		t.Errorf("typ = %v", jwtHeader(t, tok)["typ"])
	}

	// Cookie hygiene: host-only, HttpOnly, Lax, the whole site, and no Domain.
	ck := cookieNamed(w, centralCookie)
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" || ck.MaxAge <= 0 {
		t.Fatalf("session cookie = %+v", ck)
	}
	if ck.MaxAge > int((7*24*time.Hour).Seconds())+5 {
		t.Errorf("session cookie lives %ds, beyond the 7-day idle timeout", ck.MaxAge)
	}
	// No v1 cookie survives.
	for _, old := range []string{"alora_rt", "alora_at", "alora_oauth_state"} {
		if cookieNamed(w, old) != nil {
			t.Errorf("SECURITY: retired cookie %s was set", old)
		}
	}

	// The token works against App Central's API.
	me := a.get("/api/me", bearer(tok))
	expect(t, me, http.StatusOK, "/api/me")
	if got := decode(t, me); got["id"] != m.ID || got["email"] != m.Email {
		t.Errorf("/api/me = %v", got)
	}
}

func TestPasswordLoginRefusalsAreIndistinguishable(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	sso := a.newMember(co, "")
	// An account whose own policy allows only Google: a correct password must
	// get exactly the same answer as a wrong one.
	a.exec(`INSERT INTO tbl_login_policies (client_id, name, allow_password, allow_google, priority)
	        VALUES ($1, 'Google only', false, true, 50)`, co.ID)
	var pid string
	a.scalar(&pid, `SELECT id FROM tbl_login_policies WHERE client_id = $1 AND name = 'Google only'`, co.ID)
	a.exec(`UPDATE tbl_users SET login_policy_id = $1 WHERE id = $2`, pid, sso.ID)
	inactive := a.newMember(co, "")
	a.exec(`UPDATE tbl_users SET is_active = false WHERE id = $1`, inactive.ID)

	cases := []struct{ name, email, pass string }{
		{"wrong password", m.Email, "not the password"},
		{"unknown address", "ghost-" + randSuffix(t) + "@nowhere.test", testPassword},
		{"right password, policy forbids passwords", sso.Email, testPassword},
		{"deactivated account", inactive.Email, testPassword},
	}
	var bodies []string
	for _, tc := range cases {
		w := a.post("/auth/login/password", map[string]any{"email": tc.email, "password": tc.pass})
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401 (%s)", tc.name, w.Code, w.Body.String())
		}
		if cookieNamed(w, centralCookie) != nil || cookieNamed(w, "alora_choose") != nil {
			t.Errorf("SECURITY: %s set a cookie", tc.name)
		}
		bodies = append(bodies, decode(t, w)["error"].(string))
	}
	for i := range bodies {
		if bodies[i] != "Invalid email or password" {
			t.Errorf("SECURITY: %s answered %q — an enumeration oracle", cases[i].name, bodies[i])
		}
	}
	// Malformed input is a 400, not a 401 that says anything about the account.
	expect(t, a.post("/auth/login/password", map[string]any{"email": "not-an-email", "password": "x"}),
		http.StatusBadRequest, "malformed")
	expect(t, a.post("/auth/login/password", map[string]any{"email": m.Email, "password": "x", "is_admin": true}),
		http.StatusBadRequest, "unknown field")
}

// A company with is_active=false is out: the gate shuts every door at once —
// nobody in it signs in, and existing tokens and refreshes stop working. This
// flips the flag directly to exercise the gate itself; suspending through the
// Owner console additionally ENDS the sessions (so reactivation cannot revive
// them), which TestSuspendingACompanyEndsItsSessionsForGood covers.
func TestSuspendedCompanyIsLockedOut(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	s := a.login(m)

	a.exec(`UPDATE tbl_clients SET is_active = false WHERE id = $1`, co.ID)
	expect(t, a.post("/auth/login/password", map[string]any{"email": m.Email, "password": m.Password}),
		http.StatusUnauthorized, "login into a suspended company")
	expect(t, a.get("/api/me", bearer(s.Access)), http.StatusUnauthorized, "an existing token of a suspended company")
	_, w := a.refresh(s)
	expect(t, w, http.StatusUnauthorized, "refresh in a suspended company")
}

// ---------- the company chooser ----------

func TestChooserAppearsOnlyAfterThePassword(t *testing.T) {
	a := newApp(t)
	coA, coB, coC := a.newCompany(), a.newCompany(), a.newCompany()
	email := "multi-" + randSuffix(t) + "@shared.test"
	inA := a.newMember(coA, email)
	inB := a.newMember(coB, email)
	// The same address in a third company with ANOTHER password: never offered.
	c := a.newMember(coC, email)
	a.exec(`UPDATE tbl_users SET password_hash = $1 WHERE id = $2`, hashOf(t, "a different password"), c.ID)

	// A wrong password reveals nothing — not even that there is a choice.
	w := a.post("/auth/login/password", map[string]any{"email": email, "password": "wrong"})
	expect(t, w, http.StatusUnauthorized, "wrong password")

	w = a.post("/auth/login/password", map[string]any{"email": email, "password": testPassword, "return_to": "/apps"})
	expect(t, w, http.StatusOK, "login")
	var out struct {
		Status    string `json:"status"`
		Companies []struct {
			ClientID string `json:"client_id"`
			Name     string `json:"name"`
		} `json:"companies"`
		AccessToken string `json:"access_token"`
		ReturnTo    string `json:"return_to"`
	}
	decodeInto(t, w, &out)
	if out.Status != "choose_company" || out.AccessToken != "" || cookieNamed(w, centralCookie) != nil {
		t.Fatalf("a choice must precede any session: %s", w.Body.String())
	}
	offered := map[string]bool{}
	for _, cc := range out.Companies {
		offered[cc.ClientID] = true
	}
	if len(out.Companies) != 2 || !offered[coA.ID] || !offered[coB.ID] {
		t.Fatalf("offered %v, want exactly the two companies the password opens", out.Companies)
	}
	if out.ReturnTo != "/apps" {
		t.Errorf("return_to = %q", out.ReturnTo)
	}
	ticket := cookieNamed(w, "alora_choose")
	if ticket == nil || !ticket.HttpOnly || ticket.SameSite != http.SameSiteLaxMode {
		t.Fatalf("chooser cookie = %+v", ticket)
	}

	// The list can be read again while the choice is pending.
	cw := a.get("/auth/login/choices", withCookie(ticket))
	expect(t, cw, http.StatusOK, "choices")
	if !strings.Contains(cw.Body.String(), coA.ID) || strings.Contains(cw.Body.String(), coC.ID) {
		t.Errorf("choices = %s", cw.Body.String())
	}
	// Choosing a company that is not on offer changes nothing.
	expect(t, a.post("/auth/login/choose", map[string]any{"client_id": coC.ID}, withCookie(ticket)),
		http.StatusUnauthorized, "choosing a company not on offer")
	// A forged ticket is refused before any lookup.
	forged := &http.Cookie{Name: "alora_choose", Value: strings.Repeat("x", 43) + "|bad"}
	expect(t, a.post("/auth/login/choose", map[string]any{"client_id": coB.ID}, withCookie(forged)),
		http.StatusUnauthorized, "forged ticket")

	cw = a.post("/auth/login/choose", map[string]any{"client_id": coB.ID}, withCookie(ticket))
	expect(t, cw, http.StatusOK, "choose")
	if decode(t, cw)["status"] != "authenticated" || cookieNamed(cw, centralCookie) == nil {
		t.Fatalf("choose did not sign in: %s", cw.Body.String())
	}
	tok := jsonField(cw, "access_token")
	if c := claims(t, tok); c["sub"] != inB.ID || c["tenant_id"] != coB.ID {
		t.Errorf("signed in as %v, want the account in company B", c)
	}
	// Single use: the same ticket opens nothing twice.
	expect(t, a.post("/auth/login/choose", map[string]any{"client_id": coA.ID}, withCookie(ticket)),
		http.StatusUnauthorized, "replayed ticket")
	_ = inA
}

// When the password opens accounts in several companies but only one of them
// allows passwords, there is nothing to choose.
func TestChooserOffersOnlyWhatPolicyAllows(t *testing.T) {
	a := newApp(t)
	coA, coB := a.newCompany(), a.newCompany()
	email := "pol-" + randSuffix(t) + "@shared.test"
	a.newMember(coA, email)
	inB := a.newMember(coB, email)
	a.exec(`UPDATE tbl_login_policies SET allow_password = false WHERE client_id = $1 AND is_default`, coA.ID)

	w := a.post("/auth/login/password", map[string]any{"email": email, "password": testPassword})
	expect(t, w, http.StatusOK, "login")
	if decode(t, w)["status"] != "authenticated" || claims(t, jsonField(w, "access_token"))["sub"] != inB.ID {
		t.Fatalf("want a direct sign-in to company B: %s", w.Body.String())
	}
}

// ---------- the session ----------

func TestCentralRefreshRotatesAndDetectsReplay(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	s1 := a.login(m)

	s2, w := a.refresh(s1)
	expect(t, w, http.StatusOK, "refresh")
	if s2.Cookie == nil || s2.Cookie.Value == s1.Cookie.Value || s2.Access == "" {
		t.Fatal("refresh did not rotate the token")
	}
	if sessionID(t, s2.Access) != sessionID(t, s1.Access) {
		t.Error("a refresh started a new session instead of continuing the family")
	}
	expect(t, a.get("/api/me", bearer(s2.Access)), http.StatusOK, "new token")
	// The old token is still within its lifetime and its session is live.
	expect(t, a.get("/api/me", bearer(s1.Access)), http.StatusOK, "old token, live session")

	// Age the rotation beyond the grace window so the replay below is theft.
	a.exec(`UPDATE tbl_user_sessions SET revoked_at = now() - interval '5 minutes'
	        WHERE user_id = $1 AND revoked_at IS NOT NULL`, m.ID)
	_, w = a.refresh(s1)
	expect(t, w, http.StatusUnauthorized, "replay of a spent token")
	if ck := cookieNamed(w, centralCookie); ck == nil || ck.MaxAge >= 0 {
		t.Errorf("a failed refresh must clear the cookie, got %+v", ck)
	}
	// The family is burned: the live successor dies too, and so do the tokens.
	_, w = a.refresh(s2)
	expect(t, w, http.StatusUnauthorized, "the successor after the burn")
	expect(t, a.get("/api/me", bearer(s2.Access)), http.StatusUnauthorized, "a token of the burned session")
	if n := a.count(`SELECT count(*) FROM tbl_session_families WHERE user_id = $1 AND revoked_reason = 'REUSE_DETECTED'`, m.ID); n != 1 {
		t.Errorf("%d families marked REUSE_DETECTED, want 1", n)
	}
}

func TestCentralRefreshRefusesJunk(t *testing.T) {
	a := newApp(t)
	for name, v := range map[string]string{"unknown": strings.Repeat("a", 64), "short": "abc", "empty": ""} {
		_, w := a.refresh(session{Cookie: &http.Cookie{Name: centralCookie, Value: v}})
		expect(t, w, http.StatusUnauthorized, name)
	}
	_, w := a.refresh(session{})
	expect(t, w, http.StatusUnauthorized, "no cookie")
}

// The absolute cap holds however often the session is refreshed.
func TestAbsoluteCapEndsTheSession(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	s := a.login(m)
	a.exec(`UPDATE tbl_session_families SET absolute_expires_at = now() - interval '1 second' WHERE user_id = $1`, m.ID)
	_, w := a.refresh(s)
	expect(t, w, http.StatusUnauthorized, "refresh past the absolute cap")
	expect(t, a.get("/api/me", bearer(s.Access)), http.StatusUnauthorized, "token past the absolute cap")
}

// Each rotation's token expires at the idle timeout, never beyond the cap.
func TestRefreshNeverExtendsPastTheCap(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	s := a.login(m)
	a.exec(`UPDATE tbl_session_families SET absolute_expires_at = now() + interval '1 hour' WHERE user_id = $1`, m.ID)
	s2, w := a.refresh(s)
	expect(t, w, http.StatusOK, "refresh")
	if s2.Cookie.MaxAge > 3600+5 {
		t.Errorf("cookie Max-Age %d outlives the family's cap", s2.Cookie.MaxAge)
	}
	var capped bool
	a.scalar(&capped, `SELECT bool_and(s.expires_at <= f.absolute_expires_at)
	                   FROM tbl_user_sessions s JOIN tbl_session_families f ON f.id = s.family_id
	                   WHERE s.user_id = $1 AND s.revoked_at IS NULL`, m.ID)
	if !capped {
		t.Error("a session token outlives its family's absolute cap")
	}
}

func TestLogoutEndsTheSessionAndIsSilent(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	s := a.login(m)

	w := a.post("/auth/central/logout", nil, withCookie(s.Cookie))
	expect(t, w, http.StatusNoContent, "logout")
	if ck := cookieNamed(w, centralCookie); ck == nil || ck.MaxAge >= 0 {
		t.Errorf("logout must clear the cookie, got %+v", ck)
	}
	expect(t, a.get("/api/me", bearer(s.Access)), http.StatusUnauthorized, "token after logout")
	_, rw := a.refresh(s)
	expect(t, rw, http.StatusUnauthorized, "refresh after logout")
	if n := a.count(`SELECT count(*) FROM tbl_session_families WHERE user_id = $1 AND revoked_reason = 'LOGOUT'`, m.ID); n != 1 {
		t.Errorf("%d families marked LOGOUT, want 1", n)
	}
	// Unknown or absent sessions still 204: existence is not disclosed.
	expect(t, a.post("/auth/central/logout", nil, withCookie(&http.Cookie{Name: centralCookie, Value: strings.Repeat("b", 64)})),
		http.StatusNoContent, "unknown")
	expect(t, a.post("/auth/central/logout", nil), http.StatusNoContent, "none")
}

// ---------- cross-site defences ----------

// Login CSRF: a hostile page can POST a text/plain or form-encoded body
// cross-site with no preflight. Every JSON endpoint refuses anything but
// application/json — and sets no cookie.
func TestJSONEndpointsRejectOtherBodies(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	body := `{"email":"` + m.Email + `","password":"` + m.Password + `"}`
	for _, path := range []string{"/auth/login/password", "/auth/login/choose", "/auth/login/discover", "/auth/accept-invitation", "/auth/reset-password"} {
		for _, ctype := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""} {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			if ctype != "" {
				req.Header.Set("Content-Type", ctype)
			}
			w := httptest.NewRecorder()
			a.r.ServeHTTP(w, req)
			if path == "/auth/reset-password" {
				// The reset endpoint collapses every body problem into one message,
				// so its status is 400 — still no redemption.
				if w.Code != http.StatusBadRequest {
					t.Errorf("%s with %q: %d, want 400", path, ctype, w.Code)
				}
			} else if path == "/auth/login/choose" {
				if w.Code != http.StatusUnauthorized && w.Code != http.StatusUnsupportedMediaType {
					t.Errorf("%s with %q: %d", path, ctype, w.Code)
				}
			} else if w.Code != http.StatusUnsupportedMediaType {
				t.Errorf("%s with %q: %d, want 415", path, ctype, w.Code)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Errorf("SECURITY: %s with %q set cookies", path, ctype)
			}
		}
	}
	// JSON with parameters still works.
	req := httptest.NewRequest(http.MethodPost, "/auth/login/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	a.r.ServeHTTP(w, req)
	expect(t, w, http.StatusOK, "JSON login")
}

// A cookie-bearing POST from another site — or a sibling subdomain, which
// SameSite does not stop — is refused, whatever it carries.
func TestSessionRoutesRefuseCrossSiteRequests(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	s := a.login(m)

	for _, tc := range []struct {
		name string
		opts []reqOpt
		want int
	}{
		{"cross-site fetch", []reqOpt{header("Sec-Fetch-Site", "cross-site")}, http.StatusForbidden},
		{"sibling subdomain", []reqOpt{header("Sec-Fetch-Site", "same-site")}, http.StatusForbidden},
		{"foreign Origin, no fetch metadata", []reqOpt{header("Origin", "https://evil.example")}, http.StatusForbidden},
		{"null Origin", []reqOpt{header("Origin", "null")}, http.StatusForbidden},
		{"same origin", []reqOpt{header("Sec-Fetch-Site", "same-origin")}, http.StatusOK},
		{"App Central's Origin", []reqOpt{header("Origin", testFrontend)}, http.StatusOK},
	} {
		// Refresh, the most attractive target: it mints a token from the cookie.
		opts := append([]reqOpt{withCookie(s.Cookie)}, tc.opts...)
		w := a.post("/auth/central/refresh", nil, opts...)
		if w.Code != tc.want {
			t.Errorf("%s: refresh %d, want %d", tc.name, w.Code, tc.want)
		}
		if w.Code == http.StatusOK {
			s = session{Access: jsonField(w, "access_token"), Cookie: cookieNamed(w, centralCookie)}
		}
		lw := a.post("/auth/login/password", map[string]any{"email": m.Email, "password": m.Password}, tc.opts...)
		if lw.Code != tc.want {
			t.Errorf("%s: login %d, want %d", tc.name, lw.Code, tc.want)
		}
	}
	// Logout from another site must not end the session either.
	w := a.post("/auth/central/logout", nil, withCookie(s.Cookie), header("Sec-Fetch-Site", "cross-site"))
	expect(t, w, http.StatusForbidden, "cross-site logout")
	expect(t, a.get("/api/me", bearer(s.Access)), http.StatusOK, "session survives a cross-site logout attempt")
}

// ---------- discovery ----------

// Discovery answers by domain, so every address at a domain — with an account
// or without — gets the same answer.
func TestDiscoveryRevealsNothingAboutAccounts(t *testing.T) {
	a := newApp(t)
	domain := "disc-" + randSuffix(t) + ".test"
	co := a.newCompany(domain)
	m := a.newMember(co, "real@"+domain)

	ask := func(email string) string {
		w := a.post("/auth/login/discover", map[string]any{"email": email})
		expect(t, w, http.StatusOK, "discover "+email)
		return w.Body.String()
	}
	if ask(m.Email) != ask("nobody@"+domain) {
		t.Error("SECURITY: discovery tells an existing account from a missing one")
	}
	if got := decode(t, a.post("/auth/login/discover", map[string]any{"email": "x@unknown-" + randSuffix(t) + ".test"})); got["password"] != true {
		t.Errorf("unknown domain: %v, want the defaults", got)
	}
	// The company's default policy decides what its domain is offered.
	a.exec(`UPDATE tbl_login_policies SET allow_google = false WHERE client_id = $1 AND is_default`, co.ID)
	got := decode(t, a.post("/auth/login/discover", map[string]any{"email": m.Email}))
	if got["password"] != true || got["google"] != false || got["sso"] != nil {
		t.Errorf("verified domain: %v, want password only", got)
	}
}
