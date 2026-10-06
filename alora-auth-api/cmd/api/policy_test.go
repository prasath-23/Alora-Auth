package main

// Login policies: which one applies (the user's own, else the highest-priority
// group's, else the company default), that it is enforced at sign-in AND at
// every refresh, that an Owner can always get a locked-out company back, and
// the rules the Owner console holds policies to.

import (
	"net/http"
	"testing"
)

// newPolicy creates a policy through the console and returns its id.
func (a *app) newPolicy(s session, co company, name string, password, google bool, priority int) string {
	a.t.Helper()
	w := a.ownerCall(s, http.MethodPost, "/api/owner/companies/"+co.ID+"/login-policies", co.ID, map[string]any{
		"name": name, "allow_password": password, "allow_google": google, "priority": priority,
	})
	expect(a.t, w, http.StatusCreated, "create policy "+name)
	return jsonField(w, "id")
}

func (a *app) policyOf(s session, co company, uid string) map[string]any {
	a.t.Helper()
	w := a.ownerCall(s, http.MethodGet, "/api/owner/companies/"+co.ID+"/users/"+uid, "", nil)
	expect(a.t, w, http.StatusOK, "user detail")
	return decode(a.t, w)["login_policy"].(map[string]any)
}

func TestPolicyResolutionOrder(t *testing.T) {
	a := newApp(t)
	os := a.login(a.newOwner())
	co := a.newCompany()
	m := a.newMember(co, "")
	base := "/api/owner/companies/" + co.ID

	if p := a.policyOf(os, co, m.ID); p["source"] != "DEFAULT" || p["name"] != "Default" {
		t.Fatalf("with nothing assigned: %v", p)
	}
	// A group's policy beats the default; among groups, the highest priority wins.
	low := a.newPolicy(os, co, "Low", true, false, 5)
	high := a.newPolicy(os, co, "High", false, true, 50)
	g1, g2 := a.newGroup(co), a.newGroup(co)
	a.join(m, g1)
	a.join(m, g2)
	expect(t, a.ownerCall(os, http.MethodPut, base+"/groups/"+g1+"/login-policy", co.ID, map[string]any{"policy_id": low}), http.StatusNoContent, "g1")
	if p := a.policyOf(os, co, m.ID); p["source"] != "GROUP" || p["id"] != low {
		t.Errorf("one group policy: %v", p)
	}
	expect(t, a.ownerCall(os, http.MethodPut, base+"/groups/"+g2+"/login-policy", co.ID, map[string]any{"policy_id": high}), http.StatusNoContent, "g2")
	if p := a.policyOf(os, co, m.ID); p["source"] != "GROUP" || p["id"] != high {
		t.Errorf("two group policies: %v, want the higher priority", p)
	}
	// The user's own assignment beats every group.
	expect(t, a.ownerCall(os, http.MethodPut, base+"/users/"+m.ID+"/login-policy", co.ID, map[string]any{"policy_id": low}), http.StatusNoContent, "user")
	if p := a.policyOf(os, co, m.ID); p["source"] != "USER" || p["id"] != low {
		t.Errorf("own policy: %v", p)
	}
	// And clearing it falls back again.
	expect(t, a.ownerCall(os, http.MethodPut, base+"/users/"+m.ID+"/login-policy", co.ID, map[string]any{"policy_id": nil}), http.StatusNoContent, "clear")
	if p := a.policyOf(os, co, m.ID); p["source"] != "GROUP" || p["id"] != high {
		t.Errorf("after clearing: %v", p)
	}
	// Behaviour follows: High allows no password.
	expect(t, a.post("/auth/login/password", map[string]any{"email": m.Email, "password": m.Password}),
		http.StatusUnauthorized, "password under a Google-only group policy")
}

// A policy change reaches sessions already open: at their next refresh the
// whole sign-in ends — App Central's session and every product login under it.
func TestTightenedPolicyEndsSessionsAtRefresh(t *testing.T) {
	a := newApp(t)
	os := a.login(a.newOwner())
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)

	var def string
	a.scalar(&def, `SELECT id FROM tbl_login_policies WHERE client_id = $1 AND is_default`, l.co.ID)
	expect(t, a.ownerCall(os, http.MethodPatch, "/api/owner/companies/"+l.co.ID+"/login-policies/"+def, l.co.ID, map[string]any{
		"name": "Default", "allow_password": false, "allow_google": true, "priority": 0,
	}), http.StatusOK, "tighten")

	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Fatalf("SECURITY: a product login renewed under a policy that no longer allows its sign-in: %s", w.Body.String())
	}
	_, w := a.refresh(l.s)
	expect(t, w, http.StatusUnauthorized, "App Central refresh after the policy tightened")
	if n := a.count(`SELECT count(*) FROM tbl_session_families WHERE user_id = $1 AND revoked_reason = 'POLICY'`, l.m.ID); n != 2 {
		t.Errorf("%d families ended by the policy, want the central session and its product login", n)
	}
	expect(t, a.post("/auth/login/password", map[string]any{"email": l.m.Email, "password": l.m.Password}),
		http.StatusUnauthorized, "a new password sign-in")
}

// Break-glass: the Owner signs in under the PLATFORM company's policy, so no
// company's policy can lock the Owner out — and the Owner can always relax a
// policy that locked a company out of itself.
func TestOwnerIsNeverLockedOutByACompanyPolicy(t *testing.T) {
	a := newApp(t)
	owner := a.newOwner()
	os := a.login(owner)
	co := a.newCompany()
	m := a.newMember(co, "")
	var def string
	a.scalar(&def, `SELECT id FROM tbl_login_policies WHERE client_id = $1 AND is_default`, co.ID)
	lock := map[string]any{"name": "Default", "allow_password": false, "allow_google": true, "priority": 0}
	expect(t, a.ownerCall(os, http.MethodPatch, "/api/owner/companies/"+co.ID+"/login-policies/"+def, co.ID, lock), http.StatusOK, "lock")
	expect(t, a.post("/auth/login/password", map[string]any{"email": m.Email, "password": m.Password}), http.StatusUnauthorized, "locked out")

	// The Owner is unaffected...
	a.login(owner)
	// ...and lets the company back in.
	lock["allow_password"] = true
	expect(t, a.ownerCall(os, http.MethodPatch, "/api/owner/companies/"+co.ID+"/login-policies/"+def, co.ID, lock), http.StatusOK, "unlock")
	a.login(m)
}

func TestPolicyAdministrationRules(t *testing.T) {
	a := newApp(t)
	os := a.login(a.newOwner())
	co := a.newCompany()
	other := a.newCompany()
	base := "/api/owner/companies/" + co.ID + "/login-policies"

	expect(t, a.ownerCall(os, http.MethodPost, base, co.ID, map[string]any{
		"name": "Nothing", "allow_password": false, "allow_google": false, "priority": 3,
	}), http.StatusBadRequest, "a policy allowing no method")
	p1 := a.newPolicy(os, co, "One", true, true, 7)
	expect(t, a.ownerCall(os, http.MethodPost, base, co.ID, map[string]any{
		"name": "Two", "allow_password": true, "allow_google": true, "priority": 7,
	}), http.StatusConflict, "a taken priority")
	expect(t, a.ownerCall(os, http.MethodPost, base, co.ID, map[string]any{
		"name": "one", "allow_password": true, "allow_google": true, "priority": 8,
	}), http.StatusConflict, "a taken name")
	// An SSO connection must be the company's own.
	sso := a.setupSSO()
	expect(t, a.ownerCall(os, http.MethodPost, base, co.ID, map[string]any{
		"name": "Foreign SSO", "allow_password": false, "allow_google": false, "sso_connection_id": sso.conn, "priority": 9,
	}), http.StatusBadRequest, "another company's connection")
	// Another company's policy is not found here, and cannot be assigned here.
	otherPolicy := a.newPolicy(os, other, "Theirs", true, false, 4)
	expect(t, a.ownerCall(os, http.MethodPut, base+"/"+otherPolicy+"/default", co.ID, nil), http.StatusNotFound, "another company's policy as default")
	m := a.newMember(co, "")
	expect(t, a.ownerCall(os, http.MethodPut, "/api/owner/companies/"+co.ID+"/users/"+m.ID+"/login-policy", co.ID,
		map[string]any{"policy_id": otherPolicy}), http.StatusBadRequest, "another company's policy on a user")

	// The default cannot be deleted; an assigned policy cannot either.
	var def string
	a.scalar(&def, `SELECT id FROM tbl_login_policies WHERE client_id = $1 AND is_default`, co.ID)
	expect(t, a.ownerCall(os, http.MethodDelete, base+"/"+def, co.ID, nil), http.StatusConflict, "delete the default")
	expect(t, a.ownerCall(os, http.MethodPut, "/api/owner/companies/"+co.ID+"/users/"+m.ID+"/login-policy", co.ID,
		map[string]any{"policy_id": p1}), http.StatusNoContent, "assign")
	expect(t, a.ownerCall(os, http.MethodDelete, base+"/"+p1, co.ID, nil), http.StatusConflict, "delete an assigned policy")
	// Making another the default moves the flag: still exactly one.
	expect(t, a.ownerCall(os, http.MethodPut, base+"/"+p1+"/default", co.ID, nil), http.StatusNoContent, "move the default")
	if n := a.count(`SELECT count(*) FROM tbl_login_policies WHERE client_id = $1 AND is_default`, co.ID); n != 1 {
		t.Errorf("%d default policies, want 1", n)
	}
	expect(t, a.ownerCall(os, http.MethodDelete, base+"/"+def, co.ID, nil), http.StatusNoContent, "delete the former default")
	w := a.ownerCall(os, http.MethodGet, base, "", nil)
	expect(t, w, http.StatusOK, "list")
	var list []map[string]any
	decodeInto(t, w, &list)
	if len(list) != 1 || list[0]["id"] != p1 || list[0]["is_default"] != true {
		t.Errorf("policies = %s", w.Body.String())
	}
}
