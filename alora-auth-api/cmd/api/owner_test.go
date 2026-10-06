package main

// The Owner console: who may use it and for how long after signing in, the
// target echo on writes, ids that stay scoped to the company in the path, the
// double audit trail, and everything the Owner alone may do — companies,
// subscriptions, product registration, what groups grant, direct grants.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ownerCall is a request of an Owner's session; writes echo the target company.
func (a *app) ownerCall(s session, method, path, cid string, body any) *httptest.ResponseRecorder {
	opts := []reqOpt{bearer(s.Access)}
	if cid != "" {
		opts = append(opts, header("X-Alora-Target-Company", cid))
	}
	return a.send(method, path, body, opts...)
}

func TestOwnerConsoleNeedsAnOwnerWhoSignedInRecently(t *testing.T) {
	a := newApp(t)
	owner := a.newOwner()
	s := a.login(owner)
	expect(t, a.get("/api/owner/companies", bearer(s.Access)), http.StatusOK, "an Owner")
	if me := decode(t, a.get("/api/me", bearer(s.Access))); me["is_owner"] != true {
		t.Errorf("/api/me = %v", me)
	}

	// An Admin of the platform company is not an Owner.
	pa := a.newAdmin(a.platform())
	expect(t, a.get("/api/owner/companies", bearer(a.login(pa).Access)), http.StatusForbidden, "a platform Admin")
	// Nor is an Admin of any company.
	co := a.newCompany()
	expect(t, a.get("/api/owner/companies", bearer(a.login(a.newAdmin(co)).Access)), http.StatusForbidden, "a company Admin")

	// A sign-in older than twelve hours is not enough, however the session was
	// kept alive, and refreshing does not change when its user signed in.
	a.exec(`UPDATE tbl_session_families SET authenticated_at = now() - interval '13 hours' WHERE user_id = $1`, owner.ID)
	w := a.get("/api/owner/companies", bearer(s.Access))
	expect(t, w, http.StatusForbidden, "stale sign-in")
	if decode(t, w)["error"] != "Recent sign-in required" {
		t.Errorf("stale sign-in answered %s", w.Body.String())
	}
	s2, _ := a.refresh(s)
	expect(t, a.get("/api/owner/companies", bearer(s2.Access)), http.StatusForbidden, "refreshed, still stale")
	expect(t, a.get("/api/me", bearer(s2.Access)), http.StatusOK, "the session itself is fine")
	// Signing in again restores it.
	expect(t, a.get("/api/owner/companies", bearer(a.login(owner).Access)), http.StatusOK, "fresh sign-in")

	// Losing Owner standing takes effect at once.
	fresh := a.login(owner)
	a.exec(`DELETE FROM tbl_platform_owners WHERE user_id = $1`, owner.ID)
	expect(t, a.get("/api/owner/companies", bearer(fresh.Access)), http.StatusForbidden, "former Owner, same token")
}

// Every write names its company twice — in the path and in a header — so a slip
// cannot land on the wrong one.
func TestOwnerWritesEchoTheTargetCompany(t *testing.T) {
	a := newApp(t)
	s := a.login(a.newOwner())
	co, other := a.newCompany(), a.newCompany()
	path := "/api/owner/companies/" + co.ID
	for name, cid := range map[string]string{"no header": "", "another company": other.ID, "garbage": "x"} {
		w := a.ownerCall(s, http.MethodPatch, path, cid, map[string]any{"name": "Renamed"})
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, w.Code)
		}
	}
	var name string
	a.scalar(&name, `SELECT name FROM tbl_clients WHERE id = $1`, co.ID)
	if name == "Renamed" {
		t.Fatal("SECURITY: a write without the right target echo was applied")
	}
	expect(t, a.ownerCall(s, http.MethodPatch, path, co.ID, map[string]any{"name": "Renamed"}), http.StatusOK, "echoed")
	// Reads need no echo.
	expect(t, a.ownerCall(s, http.MethodGet, path, "", nil), http.StatusOK, "read")
	expect(t, a.ownerCall(s, http.MethodGet, "/api/owner/companies/00000000-0000-0000-0000-000000000000", "", nil),
		http.StatusNotFound, "unknown company")
}

// The Owner reaches every company, but an id of one company never resolves
// under another's path.
func TestOwnerIDsStayScopedToThePathCompany(t *testing.T) {
	a := newApp(t)
	s := a.login(a.newOwner())
	coA, coB := a.newCompany(), a.newCompany()
	inA := a.newMember(coA, "")
	inB := a.newMember(coB, "")
	groupB := a.newGroup(coB)

	w := a.ownerCall(s, http.MethodGet, "/api/owner/companies/"+coA.ID+"/users?take=100", "", nil)
	expect(t, w, http.StatusOK, "list A's users")
	if !strings.Contains(w.Body.String(), inA.ID) || strings.Contains(w.Body.String(), inB.ID) {
		t.Fatalf("A's users = %s", w.Body.String())
	}
	for name, path := range map[string]string{
		"B's user under A":  "/api/owner/companies/" + coA.ID + "/users/" + inB.ID,
		"B's group under A": "/api/owner/companies/" + coA.ID + "/groups/" + groupB,
	} {
		expect(t, a.ownerCall(s, http.MethodGet, path, "", nil), http.StatusNotFound, name)
	}
	w = a.ownerCall(s, http.MethodPatch, "/api/owner/companies/"+coA.ID+"/users/"+inB.ID, coA.ID, map[string]any{"is_active": false})
	expect(t, w, http.StatusNotFound, "deactivate B's user under A")
	w = a.ownerCall(s, http.MethodPost, "/api/owner/companies/"+coA.ID+"/groups/"+groupB+"/members", coA.ID, map[string]any{"user_id": inA.ID})
	expect(t, w, http.StatusNotFound, "join A's user to B's group")
	var active bool
	a.scalar(&active, `SELECT is_active FROM tbl_users WHERE id = $1`, inB.ID)
	if !active {
		t.Fatal("SECURITY: a user of B was deactivated through A's path")
	}
}

// Creating a company creates its Admins group and its default policy with it,
// and the Owner then invites its first Admin.
func TestOwnerCreatesACompanyAndItsFirstAdmin(t *testing.T) {
	a := newApp(t)
	owner := a.newOwner()
	s := a.login(owner)
	name := "Newco " + randSuffix(t)
	w := a.ownerCall(s, http.MethodPost, "/api/owner/companies", "", map[string]any{"name": name})
	expect(t, w, http.StatusCreated, "create")
	cid := jsonField(w, "id")
	if n := a.count(`SELECT count(*) FROM tbl_groups WHERE client_id = $1 AND system_key = 'ADMINS'`, cid); n != 1 {
		t.Errorf("%d Admins groups, want 1", n)
	}
	if n := a.count(`SELECT count(*) FROM tbl_login_policies WHERE client_id = $1 AND is_default AND allow_password AND allow_google`, cid); n != 1 {
		t.Errorf("%d default policies, want 1", n)
	}
	var isPlatform bool
	a.scalar(&isPlatform, `SELECT is_platform FROM tbl_clients WHERE id = $1`, cid)
	if isPlatform {
		t.Fatal("SECURITY: the console created a second platform company")
	}
	expect(t, a.ownerCall(s, http.MethodPost, "/api/owner/companies", "", map[string]any{"name": "x", "is_platform": true}),
		http.StatusBadRequest, "is_platform is not settable")

	var admins string
	a.scalar(&admins, `SELECT id FROM tbl_groups WHERE client_id = $1 AND system_key = 'ADMINS'`, cid)
	email := "first-" + randSuffix(t) + "@newco.test"
	w = a.ownerCall(s, http.MethodPost, "/api/owner/companies/"+cid+"/invitations", cid,
		map[string]any{"email": email, "group_ids": []string{admins}})
	expect(t, w, http.StatusCreated, "invite")
	var byOwner *string
	a.scalar(&byOwner, `SELECT invited_by_owner_id FROM tbl_invitations WHERE email = $1`, email)
	if byOwner == nil || *byOwner != owner.ID {
		t.Errorf("invited_by_owner_id = %v, want the Owner", byOwner)
	}
	u, _ := url.Parse(jsonField(w, "invite_url"))
	expect(t, a.post("/auth/accept-invitation", map[string]any{"token": u.Query().Get("token"), "password": testPassword}),
		http.StatusNoContent, "accept")
	first := a.login(member{Email: email, Password: testPassword})
	if me := decode(t, a.get("/api/me", bearer(first.Access))); me["is_admin"] != true {
		t.Errorf("the first Admin is not an Admin: %v", me)
	}
}

// An Owner's action on a company appears in BOTH trails: the platform's, naming
// the Owner, and the company's own, naming no actor.
func TestOwnerActionsAreAuditedInBothTrails(t *testing.T) {
	a := newApp(t)
	owner := a.newOwner()
	s := a.login(owner)
	co := a.newCompany()
	w := a.ownerCall(s, http.MethodPost, "/api/owner/companies/"+co.ID+"/groups", co.ID,
		map[string]any{"name": "Audited " + randSuffix(t)})
	expect(t, w, http.StatusCreated, "create a group")

	var platformRows, companyRows int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		platformRows = a.count(`SELECT count(*) FROM tbl_audit_logs
		                        WHERE event_type = 'group.created' AND actor_user_id = $1 AND client_id = $2
		                          AND event_metadata->>'target_client_id' = $3`, owner.ID, a.platform().ID, co.ID)
		companyRows = a.count(`SELECT count(*) FROM tbl_audit_logs
		                       WHERE event_type = 'group.created' AND client_id = $1 AND actor_user_id IS NULL
		                         AND event_metadata->>'by_owner' = $2`, co.ID, owner.ID)
		if platformRows == 1 && companyRows == 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("audit rows: platform %d, company %d; want one each", platformRows, companyRows)
}

// What a group grants flows into its members' access, and changing it stales
// their product tokens.
func TestGroupProductGrantsFlowIntoAccess(t *testing.T) {
	a := newApp(t)
	s := a.login(a.newOwner())
	co := a.newCompany()
	p := a.newProduct("Viewer", "Editor")
	a.subscribe(co, p)
	m := a.newMember(co, "")
	base := "/api/owner/companies/" + co.ID

	w := a.ownerCall(s, http.MethodPost, base+"/groups", co.ID, map[string]any{
		"name": "Editors", "scopes": []string{"users:read"},
		"product_grants": []map[string]string{{"product_id": p.ID, "role_name": "Editor"}},
	})
	expect(t, w, http.StatusCreated, "create group")
	gid := jsonField(w, "id")
	expect(t, a.ownerCall(s, http.MethodPost, base+"/groups/"+gid+"/members", co.ID, map[string]any{"user_id": m.ID}),
		http.StatusCreated, "add member")

	detail := decode(t, a.ownerCall(s, http.MethodGet, base+"/users/"+m.ID, "", nil))
	access := detail["access"].([]any)
	if len(access) != 1 {
		t.Fatalf("access = %v", access)
	}
	if got := access[0].(map[string]any); got["source"] != "GROUP" || got["role_name"] != "Editor" || got["group_id"] != gid {
		t.Errorf("access = %v", got)
	}
	var pv0 int
	a.scalar(&pv0, `SELECT permissions_version FROM tbl_users WHERE id = $1`, m.ID)
	expect(t, a.ownerCall(s, http.MethodPut, base+"/groups/"+gid+"/product-grants", co.ID, map[string]any{
		"product_grants": []map[string]string{{"product_id": p.ID, "role_name": "Viewer"}},
	}), http.StatusNoContent, "change the grant")
	var pv1 int
	a.scalar(&pv1, `SELECT permissions_version FROM tbl_users WHERE id = $1`, m.ID)
	if pv1 <= pv0 {
		t.Errorf("permissions_version %d → %d: a grant change did not stale the member's tokens", pv0, pv1)
	}

	// Grants must name a subscribed product and a role in its catalogue.
	unsubscribed := a.newProduct()
	for name, grants := range map[string][]map[string]string{
		"unsubscribed product": {{"product_id": unsubscribed.ID, "role_name": "Viewer"}},
		"unknown role":         {{"product_id": p.ID, "role_name": "Emperor"}},
	} {
		w := a.ownerCall(s, http.MethodPut, base+"/groups/"+gid+"/product-grants", co.ID, map[string]any{"product_grants": grants})
		expect(t, w, http.StatusBadRequest, name)
	}
	expect(t, a.ownerCall(s, http.MethodPut, base+"/groups/"+gid+"/scopes", co.ID, map[string]any{"scopes": []string{"users:everything"}}),
		http.StatusBadRequest, "unknown scope")
	// The Admins group can be neither renamed nor deleted, nor re-scoped: it
	// holds every scope.
	expect(t, a.ownerCall(s, http.MethodPatch, base+"/groups/"+co.AdminsID, co.ID, map[string]any{"name": "Rebels"}),
		http.StatusConflict, "rename Admins")
	expect(t, a.ownerCall(s, http.MethodDelete, base+"/groups/"+co.AdminsID, co.ID, nil), http.StatusConflict, "delete Admins")
	expect(t, a.ownerCall(s, http.MethodPut, base+"/groups/"+co.AdminsID+"/scopes", co.ID, map[string]any{"scopes": []string{"users:read"}}),
		http.StatusConflict, "re-scope Admins")
	// An ordinary group can be deleted, and its members lose what it granted.
	expect(t, a.ownerCall(s, http.MethodDelete, base+"/groups/"+gid, co.ID, nil), http.StatusNoContent, "delete group")
	if n := a.count(`SELECT count(*) FROM vw_EffectiveProductRole WHERE user_id = $1`, m.ID); n != 0 {
		t.Errorf("%d roles survive the group's deletion", n)
	}
}

func TestOwnerDirectGrants(t *testing.T) {
	a := newApp(t)
	s := a.login(a.newOwner())
	co := a.newCompany()
	p := a.newProduct("Viewer")
	m := a.newMember(co, "")
	path := "/api/owner/companies/" + co.ID + "/users/" + m.ID + "/grants/" + p.ID
	expect(t, a.ownerCall(s, http.MethodPut, path, co.ID, map[string]any{"role_name": "Viewer"}), http.StatusConflict, "unsubscribed")
	a.subscribe(co, p)
	expect(t, a.ownerCall(s, http.MethodPut, path, co.ID, map[string]any{"role_name": "Emperor"}), http.StatusBadRequest, "unknown role")
	expect(t, a.ownerCall(s, http.MethodPut, path, co.ID, map[string]any{"role_name": "Viewer"}), http.StatusNoContent, "grant")
	expect(t, a.ownerCall(s, http.MethodPut, path, co.ID, map[string]any{"role_name": "Viewer"}), http.StatusNoContent, "re-grant")
	expect(t, a.ownerCall(s, http.MethodDelete, path, co.ID, nil), http.StatusNoContent, "revoke")
	expect(t, a.ownerCall(s, http.MethodDelete, path, co.ID, nil), http.StatusNotFound, "revoke twice")
}

func TestPlatformCompanyCannotBeSuspended(t *testing.T) {
	a := newApp(t)
	s := a.login(a.newOwner())
	pl := a.platform()
	for name, body := range map[string]map[string]any{
		"is_active false":       {"is_active": false},
		"status SUSPENDED":      {"subscription_status": "SUSPENDED"},
		"status CANCELLED":      {"subscription_status": "CANCELLED"},
		"rename and deactivate": {"name": "x", "is_active": false},
	} {
		expect(t, a.ownerCall(s, http.MethodPatch, "/api/owner/companies/"+pl.ID, pl.ID, body), http.StatusConflict, name)
	}
	var active bool
	a.scalar(&active, `SELECT is_active FROM tbl_clients WHERE id = $1`, pl.ID)
	if !active {
		t.Fatal("SECURITY: the platform company was suspended")
	}
	// An ordinary company can be, and that locks its people out at once.
	co := a.newCompany()
	m := a.newMember(co, "")
	ms := a.login(m)
	expect(t, a.ownerCall(s, http.MethodPatch, "/api/owner/companies/"+co.ID, co.ID, map[string]any{"is_active": false}),
		http.StatusOK, "suspend")
	expect(t, a.get("/api/me", bearer(ms.Access)), http.StatusUnauthorized, "a member of the suspended company")
}

// Suspending a company through the Owner console ENDS its sessions — central and
// product alike — and reactivating it does NOT bring them back. A suspension
// made over a compromise must not be quietly undone by turning the company on
// again. Mirrors TestDeactivationEndsEverySession, at company scope.
func TestSuspendingACompanyEndsItsSessionsForGood(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f) // a live product login under the central one
	os := a.login(a.newOwner())

	expect(t, a.ownerCall(os, http.MethodPatch, "/api/owner/companies/"+l.co.ID, l.co.ID,
		map[string]any{"is_active": false}), http.StatusOK, "suspend the company")

	// Every door is shut, and the sessions are ENDED rather than merely gated.
	expect(t, a.get("/api/me", bearer(l.s.Access)), http.StatusUnauthorized, "central token after suspend")
	if _, w := a.refresh(l.s); w.Code != http.StatusUnauthorized {
		t.Errorf("central refresh after suspend: %d", w.Code)
	}
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: a suspended company's product login renewed: %s", w.Body.String())
	}
	if n := a.count(`SELECT count(*) FROM tbl_user_sessions WHERE client_id = $1 AND revoked_at IS NULL`, l.co.ID); n != 0 {
		t.Errorf("%d sessions survived the suspension", n)
	}
	if n := a.count(`SELECT count(*) FROM tbl_session_families WHERE client_id = $1 AND revoked_reason = 'SUSPENDED'`, l.co.ID); n == 0 {
		t.Error("no families were marked SUSPENDED")
	}

	// Reactivating the company does NOT revive the old sessions.
	expect(t, a.ownerCall(os, http.MethodPatch, "/api/owner/companies/"+l.co.ID, l.co.ID,
		map[string]any{"is_active": true}), http.StatusOK, "reactivate")
	expect(t, a.get("/api/me", bearer(l.s.Access)), http.StatusUnauthorized, "an old token after reactivation")
	if _, w := a.refresh(l.s); w.Code != http.StatusUnauthorized {
		t.Errorf("an old refresh worked after reactivation: %d", w.Code)
	}
}

func TestOwnerCompanyDomain(t *testing.T) {
	a := newApp(t)
	s := a.login(a.newOwner())
	coA, coB := a.newCompany(), a.newCompany()
	domain := "dom-" + randSuffix(t) + ".test"
	w := a.ownerCall(s, http.MethodPut, "/api/owner/companies/"+coA.ID+"/domain", coA.ID, map[string]any{"domain": strings.ToUpper(domain), "verified": true})
	expect(t, w, http.StatusOK, "set domain")
	if d := decode(t, w); d["domain"] != domain || d["domain_verified_at"] == nil {
		t.Errorf("domain = %v", d)
	}
	expect(t, a.ownerCall(s, http.MethodPut, "/api/owner/companies/"+coB.ID+"/domain", coB.ID, map[string]any{"domain": domain, "verified": true}),
		http.StatusConflict, "another company verifying the same domain")
}

func TestOwnerSubscriptions(t *testing.T) {
	a := newApp(t)
	s := a.login(a.newOwner())
	l := a.setupProduct("Viewer")
	base := "/api/owner/companies/" + l.co.ID + "/subscriptions"
	w := a.ownerCall(s, http.MethodGet, base, "", nil)
	expect(t, w, http.StatusOK, "list")
	if !strings.Contains(w.Body.String(), l.p.ID) {
		t.Errorf("subscriptions = %s", w.Body.String())
	}
	expect(t, a.ownerCall(s, http.MethodPut, base+"/"+l.p.ID, l.co.ID, map[string]any{"is_active": false}), http.StatusNoContent, "switch off")
	f := newFlow(t)
	w = a.authorize(l.s, f.query(l.p))
	if location(t, w).Query().Get("error") != "access_denied" {
		t.Errorf("authorize after the subscription ended: %s", w.Header().Get("Location"))
	}
	expect(t, a.ownerCall(s, http.MethodPut, base+"/"+l.p.ID, l.co.ID, map[string]any{"is_active": true, "seat_limit": 10}), http.StatusNoContent, "switch on")
	expect(t, a.ownerCall(s, http.MethodPut, base+"/00000000-0000-0000-0000-000000000000", l.co.ID, map[string]any{"is_active": true}),
		http.StatusNotFound, "unknown product")
}

// A URL is judged by its text as well as its parse. url.Parse lower-cases the
// scheme and leaves the fragment of a lone "#" empty, but the value is stored as
// given and the tables' checks read the text. Each of these is the caller's 400
// in words, never a table's refusal surfacing as a 500, and an ordinary URL is
// still taken.
func TestURLsAreJudgedByTheirText(t *testing.T) {
	a := newApp(t)
	s := a.login(a.newOwner())
	w := a.ownerCall(s, http.MethodPost, "/api/owner/products", "", map[string]any{"key": "U" + randSuffix(t), "name": "Urls"})
	expect(t, w, http.StatusCreated, "register")
	base := "/api/owner/products/" + jsonField(w, "id")
	co := a.newCompany()
	for _, u := range []string{"https://ledger.test/cb#", "https://ledger.test/#", "HTTPS://LEDGER.TEST/CB", "Https://ledger.test/cb"} {
		for what, w := range map[string]*httptest.ResponseRecorder{
			"a redirect URI": a.ownerCall(s, http.MethodPut, base+"/redirect-uris", "", map[string]any{"redirect_uris": []string{u}}),
			"a launch URI": a.ownerCall(s, http.MethodPost, "/api/owner/products", "", map[string]any{
				"key": "U" + randSuffix(t), "name": "x", "initiate_login_uri": u}),
			"a base URL": a.ownerCall(s, http.MethodPatch, base, "", map[string]any{"name": "Urls", "base_url": u, "is_active": true}),
		} {
			expect(t, w, http.StatusBadRequest, what+" "+u)
			if !strings.Contains(w.Body.String(), "must be an absolute https URL with no fragment") {
				t.Errorf("%s %s: %s, want the rule in words", what, u, w.Body.String())
			}
		}
	}
	for _, iss := range []string{"HTTPS://SSO.TEST", "https://sso.test#", "https://sso.test?", "https://sso.test?x=1"} {
		w := a.ownerCall(s, http.MethodPost, "/api/owner/companies/"+co.ID+"/sso-connections", co.ID, map[string]any{
			"name": "S " + randSuffix(t), "issuer": iss, "client_id": "c-" + randSuffix(t), "client_secret": "s", "is_active": true,
		})
		expect(t, w, http.StatusBadRequest, "issuer "+iss)
		if !strings.Contains(w.Body.String(), "The issuer must be an absolute https URL") {
			t.Errorf("issuer %s: %s, want the rule in words", iss, w.Body.String())
		}
	}
	expect(t, a.ownerCall(s, http.MethodPut, base+"/redirect-uris", "", map[string]any{
		"redirect_uris": []string{"https://ledger.test/cb?x=1", "http://localhost:4100/cb", "https://[::1]:8443/cb"}}),
		http.StatusNoContent, "ordinary redirect URIs")
}

// Registering a product: the key, the exact redirect URIs, the role catalogue,
// and a client secret shown exactly once.
func TestOwnerRegistersAProduct(t *testing.T) {
	a := newApp(t)
	s := a.login(a.newOwner())
	key := "K" + randSuffix(t)
	w := a.ownerCall(s, http.MethodPost, "/api/owner/products", "", map[string]any{
		"key": key, "name": "Ledger", "base_url": "https://ledger.test", "initiate_login_uri": "https://ledger.test/login",
	})
	expect(t, w, http.StatusCreated, "register")
	pid := jsonField(w, "id")
	if d := decode(t, w); d["has_secret"] != false || d["key"] != key {
		t.Errorf("registration = %v", d)
	}
	expect(t, a.ownerCall(s, http.MethodPost, "/api/owner/products", "", map[string]any{"key": key, "name": "Dup"}),
		http.StatusConflict, "duplicate key")
	for name, body := range map[string]map[string]any{
		"bad key":            {"key": "no spaces!", "name": "x"},
		"relative base url":  {"key": "K" + randSuffix(t), "name": "x", "base_url": "/app"},
		"initiate with hash": {"key": "K" + randSuffix(t), "name": "x", "initiate_login_uri": "https://a.test/login#x"},
	} {
		expect(t, a.ownerCall(s, http.MethodPost, "/api/owner/products", "", body), http.StatusBadRequest, name)
	}

	base := "/api/owner/products/" + pid
	expect(t, a.ownerCall(s, http.MethodPut, base+"/redirect-uris", "", map[string]any{"redirect_uris": []string{"https://ledger.test/cb#frag"}}),
		http.StatusBadRequest, "fragment")
	expect(t, a.ownerCall(s, http.MethodPut, base+"/redirect-uris", "", map[string]any{"redirect_uris": []string{"https://ledger.test/cb", "https://ledger.test/cb2"}}),
		http.StatusNoContent, "redirect uris")
	expect(t, a.ownerCall(s, http.MethodPut, base+"/roles", "", map[string]any{"roles": []string{"1bad"}}), http.StatusBadRequest, "bad role")
	expect(t, a.ownerCall(s, http.MethodPut, base+"/roles", "", map[string]any{"roles": []string{"Admin", "Clerk"}}), http.StatusNoContent, "roles")

	w = a.ownerCall(s, http.MethodPost, base+"/client-secret", "", nil)
	expect(t, w, http.StatusOK, "issue secret")
	secret := jsonField(w, "client_secret")
	if !strings.HasPrefix(secret, "acs_") || jsonField(w, "client_id") != pid || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("secret response = %s", w.Body.String())
	}
	got := a.ownerCall(s, http.MethodGet, base, "", nil)
	if strings.Contains(got.Body.String(), secret) || decode(t, got)["has_secret"] != true {
		t.Errorf("SECURITY: the registration shows %s", got.Body.String())
	}
	if n := a.count(`SELECT count(*) FROM tbl_products WHERE client_secret_hash = $1`, secret); n != 0 {
		t.Fatal("SECURITY: the client secret is stored in the clear")
	}
	var reg struct {
		RedirectURIs []string `json:"redirect_uris"`
		Roles        []string `json:"roles"`
	}
	_ = json.Unmarshal(got.Body.Bytes(), &reg)
	if len(reg.RedirectURIs) != 2 || len(reg.Roles) != 2 {
		t.Errorf("registration = %s", got.Body.String())
	}

	// The secret authenticates at the token endpoint; rotating retires it.
	intro := func(sec string) int {
		return a.post("/oauth/introspect", url.Values{"token": {"x"}}, basic(pid, sec)).Code
	}
	if code := intro(secret); code != http.StatusOK {
		t.Fatalf("the new secret does not authenticate: %d", code)
	}
	w = a.ownerCall(s, http.MethodPost, base+"/client-secret", "", nil)
	if code := intro(secret); code != http.StatusUnauthorized {
		t.Errorf("SECURITY: a rotated-away secret still authenticates: %d", code)
	}
	if code := intro(jsonField(w, "client_secret")); code != http.StatusOK {
		t.Errorf("the rotated secret does not authenticate: %d", code)
	}

	// A role still granted cannot be dropped from the catalogue.
	co := a.newCompany()
	a.subscribe(co, product{ID: pid})
	a.grant(a.newMember(co, ""), product{ID: pid}, "Clerk")
	expect(t, a.ownerCall(s, http.MethodPut, base+"/roles", "", map[string]any{"roles": []string{"Admin"}}), http.StatusConflict, "drop a granted role")
	expect(t, a.ownerCall(s, http.MethodPost, "/api/owner/products/00000000-0000-0000-0000-000000000000/client-secret", "", nil),
		http.StatusNotFound, "unknown product")
}
