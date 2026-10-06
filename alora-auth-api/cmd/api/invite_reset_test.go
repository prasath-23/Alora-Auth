package main

// Onboarding and recovery: invitations into groups, their redemption under the
// invitee's login policy, and administrator-issued password resets.

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tokenOf(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil || u.Query().Get("token") == "" {
		t.Fatalf("link %q carries no token", link)
	}
	return u.Query().Get("token")
}

// invite has an Admin of co invite a fresh address into the given groups.
func (a *app) invite(s session, groups ...string) (email, token string) {
	a.t.Helper()
	email = "invitee-" + randSuffix(a.t) + "@acme.test"
	if groups == nil {
		groups = []string{}
	}
	w := a.post("/api/admin/invitations", map[string]any{"email": email, "group_ids": groups}, bearer(s.Access))
	expect(a.t, w, http.StatusCreated, "invite")
	return email, tokenOf(a.t, jsonField(w, "invite_url"))
}

func TestInvitationJoinsItsGroups(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.newAdmin(co)
	s := a.login(admin)
	p := a.newProduct("Viewer")
	a.subscribe(co, p)
	g := a.newGroup(co)
	a.grantGroup(co, g, p, "Viewer")

	email, tok := a.invite(s, g)
	// The link opens the page the UI actually serves.
	router, err := os.ReadFile(filepath.Join("..", "..", "..", "alora-auth-ui", "src", "app", "router.jsx"))
	if err == nil && !strings.Contains(string(router), "'/accept-invitation'") {
		t.Error("the UI router has no /accept-invitation route")
	}

	w := a.get("/auth/accept-invitation/lookup?token=" + url.QueryEscape(tok))
	expect(t, w, http.StatusOK, "lookup")
	var prev struct {
		Email      string   `json:"email"`
		ClientName string   `json:"client_name"`
		Groups     []string `json:"groups"`
		Methods    struct {
			Password bool `json:"password"`
			Google   bool `json:"google"`
			SSO      bool `json:"sso"`
		} `json:"methods"`
	}
	decodeInto(t, w, &prev)
	if prev.Email != email || prev.ClientName != co.Name || len(prev.Groups) != 1 || !prev.Methods.Password || !prev.Methods.Google || prev.Methods.SSO {
		t.Fatalf("preview = %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Error("SECURITY: the preview echoes a token")
	}

	expect(t, a.post("/auth/accept-invitation", map[string]any{"token": tok, "password": testPassword}), http.StatusNoContent, "accept")
	newbie := a.login(member{Email: email, Password: testPassword})
	apps := a.get("/api/me/apps", bearer(newbie.Access))
	if !strings.Contains(apps.Body.String(), p.ID) {
		t.Errorf("the invitee did not get the group's product: %s", apps.Body.String())
	}
	// Single use.
	expect(t, a.post("/auth/accept-invitation", map[string]any{"token": tok, "password": testPassword}), http.StatusBadRequest, "accept twice")
	expect(t, a.get("/auth/accept-invitation/lookup?token="+url.QueryEscape(tok)), http.StatusBadRequest, "lookup after use")
	// Only the hash is stored.
	if n := a.count(`SELECT count(*) FROM tbl_invitations WHERE token_hash = $1`, tok); n != 0 {
		t.Error("SECURITY: an invitation token is stored in the clear")
	}
}

func TestInvitationRules(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	existing := a.newMember(co, "")
	foreignGroup := a.newGroup(a.newCompany())

	expect(t, a.post("/api/admin/invitations", map[string]any{"email": existing.Email}, bearer(s.Access)), http.StatusConflict, "an existing member")
	email, _ := a.invite(s)
	expect(t, a.post("/api/admin/invitations", map[string]any{"email": email}, bearer(s.Access)), http.StatusConflict, "a pending invitation")
	expect(t, a.post("/api/admin/invitations", map[string]any{"email": "x-" + randSuffix(t) + "@acme.test", "group_ids": []string{foreignGroup}}, bearer(s.Access)),
		http.StatusBadRequest, "another company's group")
	expect(t, a.post("/api/admin/invitations", map[string]any{"email": "x@acme.test", "client_id": co.ID}, bearer(s.Access)),
		http.StatusBadRequest, "a client_id field")

	// Revocation, scoped to the company.
	w := a.get("/api/admin/invitations", bearer(s.Access))
	expect(t, w, http.StatusOK, "list")
	var list []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	decodeInto(t, w, &list)
	var id string
	for _, i := range list {
		if i.Email == email {
			id = i.ID
		}
	}
	if id == "" || strings.Contains(w.Body.String(), "token") {
		t.Fatalf("list = %s", w.Body.String())
	}
	other := a.login(a.newAdmin(a.newCompany()))
	expect(t, a.send(http.MethodDelete, "/api/admin/invitations/"+id, nil, bearer(other.Access)), http.StatusNotFound, "another company revoking")
	expect(t, a.send(http.MethodDelete, "/api/admin/invitations/"+id, nil, bearer(s.Access)), http.StatusNoContent, "revoke")
	expect(t, a.send(http.MethodDelete, "/api/admin/invitations/"+id, nil, bearer(s.Access)), http.StatusNotFound, "revoke twice")

	// Unknown, junk and oversized tokens all look alike.
	for _, tok := range []string{"nope", strings.Repeat("z", 64), strings.Repeat("z", 300)} {
		w := a.get("/auth/accept-invitation/lookup?token=" + tok)
		if w.Code != http.StatusBadRequest || jsonField(w, "error") != "Invitation not found, expired, or already used" {
			t.Errorf("lookup %.10q: %d %s", tok, w.Code, w.Body.String())
		}
	}
}

// How an invitee may accept follows the login policy they will have.
func TestInvitationAcceptanceFollowsThePolicy(t *testing.T) {
	a := newApp(t)
	os := a.login(a.newOwner())
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	// A group whose members sign in with Google only.
	g := a.newGroup(co)
	gp := a.newPolicy(os, co, "Google", false, true, 30)
	expect(t, a.ownerCall(os, http.MethodPut, "/api/owner/companies/"+co.ID+"/groups/"+g+"/login-policy", co.ID,
		map[string]any{"policy_id": gp}), http.StatusNoContent, "group policy")

	email, tok := a.invite(s, g)
	var prev struct {
		Methods map[string]bool `json:"methods"`
	}
	decodeInto(t, a.get("/auth/accept-invitation/lookup?token="+url.QueryEscape(tok)), &prev)
	if prev.Methods["password"] || !prev.Methods["google"] {
		t.Fatalf("methods = %v, want Google only", prev.Methods)
	}
	expect(t, a.post("/auth/accept-invitation", map[string]any{"token": tok, "password": testPassword}), http.StatusBadRequest, "a password under a Google-only policy")
	expect(t, a.post("/auth/accept-invitation/federated", map[string]any{"token": tok}), http.StatusNoContent, "federated")
	var accountType string
	a.scalar(&accountType, `SELECT account_type::text FROM tbl_users WHERE email = $1 AND client_id = $2`, email, co.ID)
	if accountType != "OAUTH_ONLY" {
		t.Errorf("account type %s, want OAUTH_ONLY", accountType)
	}

	// The default policy (password and Google) allows either.
	_, tok2 := a.invite(s)
	expect(t, a.post("/auth/accept-invitation/federated", map[string]any{"token": tok2}), http.StatusNoContent, "federated under the default")
	// A password-only default refuses the passwordless route.
	var def string
	a.scalar(&def, `SELECT id FROM tbl_login_policies WHERE client_id = $1 AND is_default`, co.ID)
	a.exec(`UPDATE tbl_login_policies SET allow_google = false WHERE id = $1`, def)
	_, tok3 := a.invite(s)
	expect(t, a.post("/auth/accept-invitation/federated", map[string]any{"token": tok3}), http.StatusBadRequest, "passwordless under a password-only policy")
	expect(t, a.post("/auth/accept-invitation", map[string]any{"token": tok3, "password": "short"}), http.StatusBadRequest, "a too-short password")
}

func TestPasswordResetEndsEverySession(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)
	admin := a.login(a.newAdmin(l.co))

	w := a.post("/api/admin/users/"+l.m.ID+"/password-reset", nil, bearer(admin.Access))
	expect(t, w, http.StatusOK, "issue")
	tok := tokenOf(t, jsonField(w, "reset_url"))
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("the reset link response is cacheable")
	}
	// Re-issuing kills the earlier link.
	w2 := a.post("/api/admin/users/"+l.m.ID+"/password-reset", nil, bearer(admin.Access))
	tok2 := tokenOf(t, jsonField(w2, "reset_url"))
	expect(t, a.post("/auth/reset-password", map[string]any{"token": tok, "new_password": "a new long password"}), http.StatusBadRequest, "the superseded link")

	expect(t, a.post("/auth/reset-password", map[string]any{"token": tok2, "new_password": "a new long password"}), http.StatusNoContent, "reset")
	expect(t, a.get("/api/me", bearer(l.s.Access)), http.StatusUnauthorized, "the App Central session after the reset")
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: a product login survived the reset: %s", w.Body.String())
	}
	expect(t, a.post("/auth/login/password", map[string]any{"email": l.m.Email, "password": testPassword}), http.StatusUnauthorized, "the old password")
	a.login(member{Email: l.m.Email, Password: "a new long password"})
	expect(t, a.post("/auth/reset-password", map[string]any{"token": tok2, "new_password": "another long password"}), http.StatusBadRequest, "the link twice")

	// Another company's user is not found; a malformed body says nothing more.
	stranger := a.newMember(a.newCompany(), "")
	expect(t, a.post("/api/admin/users/"+stranger.ID+"/password-reset", nil, bearer(admin.Access)), http.StatusNotFound, "another company's user")
	w = a.post("/auth/reset-password", map[string]any{"token": "x", "new_password": "short", "extra": 1})
	if w.Code != http.StatusBadRequest || jsonField(w, "error") != "Invalid or expired reset token" {
		t.Errorf("malformed reset: %d %s", w.Code, w.Body.String())
	}
}

// A reset link cannot revive a deactivated account.
func TestResetCannotReviveADeactivatedUser(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	admin := a.login(a.newAdmin(co))
	tok := tokenOf(t, jsonField(a.post("/api/admin/users/"+m.ID+"/password-reset", nil, bearer(admin.Access)), "reset_url"))
	a.exec(`UPDATE tbl_users SET is_active = false WHERE id = $1`, m.ID)
	expect(t, a.post("/auth/reset-password", map[string]any{"token": tok, "new_password": "a new long password"}), http.StatusBadRequest, "reset a deactivated user")
}

// In production, with no mail configured, a reset link is never handed back.
func TestResetLinkIsNeverReturnedInProduction(t *testing.T) {
	a := newAppWith(t, map[string]string{
		"NODE_ENV": "production", "JWT_ISSUER": testIssuer, "FRONTEND_URL": testFrontend,
		"GOOGLE_REDIRECT_URI": testFrontend + "/auth/google/callback",
	}, nil)
	co := a.newCompany()
	m := a.newMember(co, "")
	admin := a.newAdmin(co)
	// Production cookies carry the __Host- prefix.
	w := a.post("/auth/login/password", map[string]any{"email": admin.Email, "password": admin.Password})
	expect(t, w, http.StatusOK, "login")
	ck := cookieNamed(w, "__Host-alora_cs")
	if ck == nil || !ck.Secure || ck.Domain != "" || ck.Path != "/" || !ck.HttpOnly {
		t.Fatalf("production session cookie = %+v", ck)
	}
	w = a.post("/api/admin/users/"+m.ID+"/password-reset", nil, bearer(jsonField(w, "access_token")))
	expect(t, w, http.StatusServiceUnavailable, "reset without mail in production")
	if strings.Contains(w.Body.String(), "reset-password") {
		t.Fatal("SECURITY: a reset link was returned in production")
	}
	if h := a.get("/health").Header().Get("Strict-Transport-Security"); h == "" {
		t.Error("no HSTS in production")
	}
}
