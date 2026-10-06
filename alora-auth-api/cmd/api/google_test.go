package main

// Google sign-in, against the same stub provider standing in for Google: the
// round trip, the ID token's checks, linking by subject and by verified
// address, the chooser across companies, and the policy that must allow it.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// withGoogleStub points the app's Google preset at a stub registered with the
// test's Google client.
func (a *app) withGoogleStub() *idpStub {
	a.t.Helper()
	stub := newIdPStub(a.t, "gid", "gsecret")
	a.m.google.SetIssuer(stub.srv.URL)
	return stub
}

func TestGoogleSignInLinksAVerifiedAddress(t *testing.T) {
	a := newApp(t)
	g := a.withGoogleStub()
	co := a.newCompany()
	m := a.newMember(co, "")

	st := a.start("/auth/google/start?return_to=/apps", g)
	if location(t, a.get("/auth/google/start")).Query().Get("prompt") != "select_account" {
		t.Error("Google is not asked to let the user choose an account")
	}
	code := g.vouch(st, g.sign(g.claimsFor("google-sub-"+randSuffix(t), strings.ToUpper(m.Email), true, st.nonce)))
	s := a.signedIn(a.callback("/auth/google/callback", st, code), "/apps")
	if claims(t, s.Access)["sub"] != m.ID {
		t.Fatalf("signed in as %v", claims(t, s.Access))
	}
	var method string
	a.scalar(&method, `SELECT auth_method::text FROM tbl_session_families WHERE id = $1`, sessionID(t, s.Access))
	if method != "GOOGLE" {
		t.Errorf("auth_method = %s", method)
	}
	if n := a.count(`SELECT count(*) FROM tbl_linked_identities WHERE user_id = $1 AND provider = 'GOOGLE'`, m.ID); n != 1 {
		t.Errorf("%d Google links, want 1", n)
	}
}

func TestGoogleSignInRefusals(t *testing.T) {
	a := newApp(t)
	g := a.withGoogleStub()
	co := a.newCompany()
	m := a.newMember(co, "")

	// An unverified address proves nothing, and links nothing.
	st := a.start("/auth/google/start", g)
	a.failedWith(a.callback("/auth/google/callback", st, g.vouch(st, g.sign(g.claimsFor("g-unverified", m.Email, false, st.nonce)))),
		"google_error", "email_unverified")
	// No account with the address: Google never creates one.
	st = a.start("/auth/google/start", g)
	a.failedWith(a.callback("/auth/google/callback", st, g.vouch(st, g.sign(g.claimsFor("g-nobody", "nobody-"+randSuffix(t)+"@gmail.test", true, st.nonce)))),
		"google_error", "account_unavailable")
	// A bad ID token.
	st = a.start("/auth/google/start", g)
	c := g.claimsFor("g-x", m.Email, true, st.nonce)
	c["aud"] = "not-our-client"
	a.failedWith(a.callback("/auth/google/callback", st, g.vouch(st, g.sign(c))), "google_error", "exchange_failed")
	st = a.start("/auth/google/start", g)
	a.failedWith(a.callback("/auth/google/callback", st, g.vouch(st, unsignedToken(g.claimsFor("g-x", m.Email, true, st.nonce)))),
		"google_error", "exchange_failed")
	// Not started by this browser.
	st = a.start("/auth/google/start", g)
	a.failedWith(a.get("/auth/google/callback?"+url.Values{"state": {st.state}, "code": {"x"}}.Encode()), "google_error", "state_mismatch")
	// A subject past the standard's 255 characters, or one the database cannot
	// store, is a malformed token; an address holding a NUL is no address.
	for _, sub := range []string{strings.Repeat("g", 256), letters(3000), "g\x00sub"} {
		st = a.start("/auth/google/start", g)
		a.failedWith(a.callback("/auth/google/callback", st, g.vouch(st, g.sign(g.claimsFor(sub, m.Email, true, st.nonce)))),
			"google_error", "exchange_failed")
	}
	st = a.start("/auth/google/start", g)
	a.failedWith(a.callback("/auth/google/callback", st, g.vouch(st, g.sign(g.claimsFor("g-nul", m.Email+"\x00", true, st.nonce)))),
		"google_error", "email_unverified")
	if n := a.count(`SELECT count(*) FROM tbl_linked_identities WHERE user_id = $1`, m.ID); n != 0 {
		t.Errorf("SECURITY: refused sign-ins left %d links", n)
	}

	// A company whose policy does not allow Google: its account is neither
	// signed in nor linked, and the answer is the same as for no account.
	a.exec(`UPDATE tbl_login_policies SET allow_google = false WHERE client_id = $1 AND is_default`, co.ID)
	st = a.start("/auth/google/start", g)
	a.failedWith(a.callback("/auth/google/callback", st, g.vouch(st, g.sign(g.claimsFor("g-pol", m.Email, true, st.nonce)))),
		"google_error", "account_unavailable")
	if n := a.count(`SELECT count(*) FROM tbl_linked_identities WHERE user_id = $1`, m.ID); n != 0 {
		t.Error("SECURITY: an account whose policy refuses Google acquired a Google link")
	}
}

// A linked account is found by Google's stable subject whatever the address
// says now, and an account already linked to one Google identity is not rebound
// to another that merely shows the same address.
func TestGoogleLinksAreBySubject(t *testing.T) {
	a := newApp(t)
	g := a.withGoogleStub()
	co := a.newCompany()
	m := a.newMember(co, "")
	sub := "g-stable-" + randSuffix(t)

	st := a.start("/auth/google/start", g)
	a.signedIn(a.callback("/auth/google/callback", st, g.vouch(st, g.sign(g.claimsFor(sub, m.Email, true, st.nonce)))), "/")
	// Same subject, new unverified address: still the same account.
	st = a.start("/auth/google/start", g)
	s := a.signedIn(a.callback("/auth/google/callback", st, g.vouch(st, g.sign(g.claimsFor(sub, "changed@elsewhere.test", false, st.nonce)))), "/")
	if claims(t, s.Access)["sub"] != m.ID {
		t.Error("the linked subject did not sign in its account")
	}
	// Another Google identity showing the same verified address is refused.
	st = a.start("/auth/google/start", g)
	a.failedWith(a.callback("/auth/google/callback", st, g.vouch(st, g.sign(g.claimsFor("g-intruder", m.Email, true, st.nonce)))),
		"google_error", "account_unavailable")
}

// One Google identity proving accounts in several companies gets the chooser,
// after the round trip, never before it.
func TestGoogleChooserAcrossCompanies(t *testing.T) {
	a := newApp(t)
	g := a.withGoogleStub()
	coA, coB := a.newCompany(), a.newCompany()
	email := "shared-" + randSuffix(t) + "@gmail.test"
	a.newMember(coA, email)
	inB := a.newPasswordless(coB, email)

	st := a.start("/auth/google/start?return_to=/profile", g)
	w := a.callback("/auth/google/callback", st, g.vouch(st, g.sign(g.claimsFor("g-shared", email, true, st.nonce))))
	expect(t, w, http.StatusFound, "callback")
	if u := location(t, w); u.Path != "/login" || u.Query().Get("choose") != "1" {
		t.Fatalf("callback went to %s, want the chooser", u)
	}
	if ck := cookieNamed(w, centralCookie); ck != nil && ck.MaxAge > 0 {
		t.Fatal("a session was opened before the choice")
	}
	ticket := cookieNamed(w, "alora_choose")
	cw := a.get("/auth/login/choices", withCookie(ticket))
	expect(t, cw, http.StatusOK, "choices")
	if !strings.Contains(cw.Body.String(), coA.ID) || !strings.Contains(cw.Body.String(), coB.ID) {
		t.Fatalf("choices = %s", cw.Body.String())
	}
	cw = a.post("/auth/login/choose", map[string]any{"client_id": coB.ID}, withCookie(ticket))
	expect(t, cw, http.StatusOK, "choose")
	if claims(t, jsonField(cw, "access_token"))["sub"] != inB.ID || jsonField(cw, "return_to") != "/profile" {
		t.Errorf("choose = %s", cw.Body.String())
	}
	var method string
	a.scalar(&method, `SELECT auth_method::text FROM tbl_session_families WHERE id = $1`, sessionID(t, jsonField(cw, "access_token")))
	if method != "GOOGLE" {
		t.Errorf("the chosen session is %s, want GOOGLE", method)
	}
}

// A return path that would leave App Central is dropped, not followed.
func TestGoogleReturnPathStaysOnAppCentral(t *testing.T) {
	a := newApp(t)
	g := a.withGoogleStub()
	co := a.newCompany()
	m := a.newMember(co, "")
	for _, evil := range []string{"https://evil.example/", "//evil.example", `/\evil.example`, "javascript:alert(1)"} {
		st := a.start("/auth/google/start?return_to="+url.QueryEscape(evil), g)
		w := a.callback("/auth/google/callback", st, g.vouch(st, g.sign(g.claimsFor("g-ret-"+randSuffix(t), m.Email, true, st.nonce))))
		if got := location(t, w); got.Host != "central.alora.test" || got.Path != "/" {
			t.Errorf("SECURITY: return_to %q led to %s", evil, got)
		}
		a.exec(`DELETE FROM tbl_linked_identities WHERE user_id = $1`, m.ID)
	}
}

func TestGoogleDisabledWithoutAClient(t *testing.T) {
	a := newAppWith(t, map[string]string{"GOOGLE_CLIENT_ID": "", "GOOGLE_CLIENT_SECRET": "", "GOOGLE_REDIRECT_URI": ""}, nil)
	w := a.get("/auth/google/start")
	expect(t, w, http.StatusFound, "start")
	if got := location(t, w); got.Path != "/login" || got.Query().Get("google_error") != "google_disabled" {
		t.Errorf("start without a Google client went to %s", got)
	}
	if d := decode(t, a.post("/auth/login/discover", map[string]any{"email": "x@y.test"})); d["google"] != false {
		t.Errorf("discovery offers Google without a client: %v", d)
	}
}
