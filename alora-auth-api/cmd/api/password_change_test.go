package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// POST /api/me/change-password re-proves the current password — that is what
// keeps a stolen access token from becoming a permanent takeover — and then
// ends every session of the account.

const newPassword = "a-different-passphrase"

func changePassword(a *app, s session, current, next string) *httptest.ResponseRecorder {
	return a.post("/api/me/change-password", map[string]any{"current_password": current, "new_password": next}, bearer(s.Access))
}

func TestChangePasswordEndsEverySession(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)
	other := a.login(l.m) // the same account in a second browser

	expect(t, changePassword(a, l.s, l.m.Password, newPassword), http.StatusNoContent, "change password")

	for name, s := range map[string]session{"this browser": l.s, "another browser": other} {
		if _, w := a.refresh(s); w.Code != http.StatusUnauthorized {
			t.Errorf("SECURITY: %s's session still refreshes after a password change: %d", name, w.Code)
		}
	}
	if w := a.get("/api/me", bearer(other.Access)); w.Code != http.StatusUnauthorized {
		t.Errorf("SECURITY: an access token of an ended session still works: %d", w.Code)
	}
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: a product renewed after the password change: %s", w.Body.String())
	}

	// The new password opens the account; the old one no longer does.
	old := map[string]any{"email": l.m.Email, "password": l.m.Password}
	expect(t, a.post("/auth/login/password", old), http.StatusUnauthorized, "the old password")
	l.m.Password = newPassword
	a.login(l.m)
}

// A wrong current password is 403, not 401: the token was fine, and a 401 tells
// a client to refresh and send the same guess again. Nothing changes.
func TestChangePasswordRefusesAWrongCurrentPassword(t *testing.T) {
	a := newApp(t)
	m := a.newMember(a.newCompany(), "")
	s := a.login(m)

	w := changePassword(a, s, "not-the-password", newPassword)
	expect(t, w, http.StatusForbidden, "a wrong current password")
	if msg := jsonField(w, "error"); msg != "Current password is incorrect" {
		t.Errorf("error = %q", msg)
	}
	if _, w := a.refresh(s); w.Code != http.StatusOK {
		t.Errorf("a refused change ended the session: %d", w.Code)
	}
	a.login(m) // the password is unchanged
}

func TestChangePasswordValidatesTheRequest(t *testing.T) {
	a := newApp(t)
	m := a.newMember(a.newCompany(), "")
	s := a.login(m)

	for name, body := range map[string]map[string]any{
		"a new password under 8 characters": {"current_password": m.Password, "new_password": "short"},
		"no current password":               {"new_password": newPassword},
		"an unknown field":                  {"current_password": m.Password, "new_password": newPassword, "is_admin": true},
	} {
		w := a.post("/api/me/change-password", body, bearer(s.Access))
		expect(t, w, http.StatusBadRequest, name)
	}
	body := map[string]any{"current_password": m.Password, "new_password": newPassword}
	expect(t, a.post("/api/me/change-password", body), http.StatusUnauthorized, "no token")
	a.login(m) // nothing above changed the password
}

// A stolen token gets five guesses at the current password per fifteen
// minutes for the ACCOUNT, however many addresses it is used from — and the
// budget is the account's alone.
func TestChangePasswordIsThrottledPerAccount(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	s := a.login(m)

	for i := 0; i < 5; i++ {
		expect(t, changePassword(a, s, "a-guess", newPassword), http.StatusForbidden, "a guess")
	}
	w := changePassword(a, s, m.Password, newPassword)
	expect(t, w, http.StatusTooManyRequests, "the sixth attempt, even with the right password")
	if w.Header().Get("Retry-After") == "" {
		t.Error("a 429 without Retry-After")
	}

	other := a.newMember(co, "")
	expect(t, changePassword(a, a.login(other), "a-guess", newPassword), http.StatusForbidden, "another account's first guess")
}
