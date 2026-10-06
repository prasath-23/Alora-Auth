package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/jwtkeys"
	"github.com/alora/auth/internal/middlewares"
)

// Who may do what in App Central. Every /api/admin route names one scope. A
// person's scopes are their groups' plus their own extras, and the Admins group
// holds every scope. Two rules keep delegation from becoming escalation:
//
//  1. nobody gives or takes away a scope they do not hold themselves;
//  2. nobody acts on someone with more access than they have.
//
// The Owner is bound by neither. The login token carries a snapshot of all of
// it; App Central itself decides every request from the database.

const noSuchID = "00000000-0000-0000-0000-000000000000"

// refusedByGuard reports a 403 from a route's scope guard. The two rules refuse
// in their own words, so a route that let the caller through is never mistaken
// for one that did not.
func refusedByGuard(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusForbidden && jsonField(w, "error") == "Forbidden"
}

func refusedBy(w *httptest.ResponseRecorder, err string) bool {
	return w.Code == http.StatusForbidden && jsonField(w, "error") == err
}

const (
	ruleOne = "You can only give or take away scopes you hold yourself"
	ruleTwo = "You can only manage people who have no more access than you"
)

// adminRoute is one /api/admin route: its pattern as registered, a concrete
// path that touches nothing when the guard lets it through, and its scope.
type adminRoute struct{ method, pattern, path, scope string }

var adminRoutes = []adminRoute{
	{"GET", "/api/admin/users", "/api/admin/users", shared.ScopeUsersRead},
	{"GET", "/api/admin/users/:id", "/api/admin/users/" + noSuchID, shared.ScopeUsersRead},
	{"PATCH", "/api/admin/users/:id", "/api/admin/users/" + noSuchID, shared.ScopeUsersEdit},
	{"PUT", "/api/admin/users/:id/scopes", "/api/admin/users/" + noSuchID + "/scopes", shared.ScopeUsersEdit},
	{"POST", "/api/admin/users/:id/password-reset", "/api/admin/users/" + noSuchID + "/password-reset", shared.ScopeUsersEdit},
	{"GET", "/api/admin/invitations", "/api/admin/invitations", shared.ScopeInvitationsRead},
	{"POST", "/api/admin/invitations", "/api/admin/invitations", shared.ScopeInvitationsEdit},
	{"DELETE", "/api/admin/invitations/:id", "/api/admin/invitations/" + noSuchID, shared.ScopeInvitationsEdit},
	{"GET", "/api/admin/groups", "/api/admin/groups", shared.ScopeGroupsRead},
	{"GET", "/api/admin/groups/:id", "/api/admin/groups/" + noSuchID, shared.ScopeGroupsRead},
	{"POST", "/api/admin/groups", "/api/admin/groups", shared.ScopeGroupsEdit},
	{"PATCH", "/api/admin/groups/:id", "/api/admin/groups/" + noSuchID, shared.ScopeGroupsEdit},
	{"DELETE", "/api/admin/groups/:id", "/api/admin/groups/" + noSuchID, shared.ScopeGroupsEdit},
	{"PUT", "/api/admin/groups/:id/scopes", "/api/admin/groups/" + noSuchID + "/scopes", shared.ScopeGroupsEdit},
	{"POST", "/api/admin/groups/:id/members", "/api/admin/groups/" + noSuchID + "/members", shared.ScopeGroupsEdit},
	{"DELETE", "/api/admin/groups/:id/members/:userId", "/api/admin/groups/" + noSuchID + "/members/" + noSuchID, shared.ScopeGroupsEdit},
	{"POST", "/api/admin/groups/:id/managers", "/api/admin/groups/" + noSuchID + "/managers", shared.ScopeGroupsEdit},
	{"DELETE", "/api/admin/groups/:id/managers/:userId", "/api/admin/groups/" + noSuchID + "/managers/" + noSuchID, shared.ScopeGroupsEdit},
	{"GET", "/api/admin/sessions", "/api/admin/sessions", shared.ScopeSessionsRead},
	{"DELETE", "/api/admin/sessions/:id", "/api/admin/sessions/" + noSuchID, shared.ScopeSessionsEdit},
	{"GET", "/api/admin/products", "/api/admin/products", shared.ScopeProductsRead},
	{"GET", "/api/admin/client", "/api/admin/client", shared.ScopeCompanyRead},
	{"PATCH", "/api/admin/client", "/api/admin/client", shared.ScopeCompanyEdit},
	{"GET", "/api/admin/api-clients", "/api/admin/api-clients", shared.ScopeAPIClientsRead},
	{"POST", "/api/admin/api-clients", "/api/admin/api-clients", shared.ScopeAPIClientsEdit},
	{"GET", "/api/admin/api-clients/:id", "/api/admin/api-clients/aci_" + noSuchID, shared.ScopeAPIClientsRead},
	{"PATCH", "/api/admin/api-clients/:id", "/api/admin/api-clients/aci_" + noSuchID, shared.ScopeAPIClientsEdit},
	{"DELETE", "/api/admin/api-clients/:id", "/api/admin/api-clients/aci_" + noSuchID, shared.ScopeAPIClientsEdit},
	{"PUT", "/api/admin/api-clients/:id/scopes", "/api/admin/api-clients/aci_" + noSuchID + "/scopes", shared.ScopeAPIClientsEdit},
	{"PUT", "/api/admin/api-clients/:id/products", "/api/admin/api-clients/aci_" + noSuchID + "/products", shared.ScopeAPIClientsEdit},
	{"POST", "/api/admin/api-clients/:id/secrets", "/api/admin/api-clients/aci_" + noSuchID + "/secrets", shared.ScopeAPIClientsEdit},
	{"DELETE", "/api/admin/api-clients/:id/secrets/:sid", "/api/admin/api-clients/aci_" + noSuchID + "/secrets/" + noSuchID, shared.ScopeAPIClientsEdit},
}

// Every /api/admin route answers its scope's holders and refuses everyone else
// at the guard; Read never opens an Edit route. The table is checked against
// the router itself, so a route added without a row here fails the test.
func TestEveryAdminRouteNeedsItsScope(t *testing.T) {
	// Some three hundred requests from one test address: past the global budget.
	a := newAppWith(t, map[string]string{"RATE_LIMIT_GLOBAL_MAX": "100000"}, nil)
	registered := map[string]bool{}
	for _, r := range a.r.Routes() {
		if strings.HasPrefix(r.Path, "/api/admin") {
			registered[r.Method+" "+r.Path] = true
		}
	}
	for _, r := range adminRoutes {
		if !registered[r.method+" "+r.pattern] {
			t.Errorf("the table names %s %s, which is not a route", r.method, r.pattern)
		}
		delete(registered, r.method+" "+r.pattern)
	}
	for k := range registered {
		t.Errorf("%s is a route with no scope in this table", k)
	}

	co := a.newCompany()
	body := func(method string) any {
		if method == http.MethodGet || method == http.MethodDelete {
			return nil
		}
		return map[string]any{}
	}
	check := func(who string, s session, held shared.ScopeSet) {
		t.Helper()
		for _, r := range adminRoutes {
			w := a.send(r.method, r.path, body(r.method), bearer(s.Access))
			if held.Has(r.scope) == refusedByGuard(w) {
				t.Errorf("%s: %s %s answered %d %s", who, r.method, r.pattern, w.Code, w.Body.String())
			}
		}
	}
	check("a member with no scope", a.login(a.newMember(co, "")), shared.NewScopeSet())
	for _, scope := range shared.GrantableScopes() {
		m := a.newMember(co, "")
		a.join(m, a.newGroup(co, scope))
		full, _ := shared.NormalizeScopes([]string{scope})
		check("holding "+scope, a.login(m), shared.NewScopeSet(full...))
	}
	check("an Admin", a.login(a.newAdmin(co)), shared.NewScopeSet(shared.GrantableScopes()...))
}

func meOf(t *testing.T, a *app, s session) (scopes []string, me map[string]any) {
	t.Helper()
	w := a.get("/api/me", bearer(s.Access))
	expect(t, w, http.StatusOK, "me")
	me = decode(t, w)
	for _, v := range me["scopes"].([]any) {
		scopes = append(scopes, v.(string))
	}
	return scopes, me
}

// A person's scopes are the union of their groups' and their extras, each with
// its source; the Admins group holds them all; and a product role named
// "Admin" confers nothing in App Central.
func TestScopesComeFromGroupsExtrasAndTheAdminsGroup(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	g := a.newGroup(co, shared.ScopeUsersRead)
	a.join(m, g)
	a.giveExtras(m, shared.ScopeSessionsRead)

	scopes, me := meOf(t, a, a.login(m))
	if want := []string{"apps:read", "sessions:read", "users:read"}; !slices.Equal(scopes, want) {
		t.Errorf("scopes = %v, want %v", scopes, want)
	}
	sources := map[string]string{}
	for _, v := range me["scope_sources"].([]any) {
		src := v.(map[string]any)
		sources[src["scope"].(string)] = src["source"].(string)
		if src["source"] == "GROUP" && src["group_id"] != g {
			t.Errorf("a group scope names group %v, want %s", src["group_id"], g)
		}
	}
	if sources["users:read"] != "GROUP" || sources["sessions:read"] != "EXTRA" {
		t.Errorf("scope sources = %v", me["scope_sources"])
	}

	admin := a.newAdmin(co)
	a.newAdmin(co) // so that the first may leave the Admins group
	as := a.login(admin)
	scopes, me = meOf(t, a, as)
	if want := append([]string{"apps:read"}, shared.NewScopeSet(shared.GrantableScopes()...).Sorted()...); !slices.Equal(scopes, want) ||
		me["is_admin"] != true {
		t.Errorf("an Admin's scopes = %v, want every scope", scopes)
	}

	plain := a.newMember(co, "")
	p := a.newProduct("Admin")
	a.subscribe(co, p)
	a.grant(plain, p, "Admin")
	ps := a.login(plain)
	if scopes, _ := meOf(t, a, ps); !slices.Equal(scopes, []string{"apps:read"}) {
		t.Errorf("a product role named Admin gave %v", scopes)
	}
	if w := a.get("/api/admin/users", bearer(ps.Access)); !refusedByGuard(w) {
		t.Errorf("SECURITY: a product 'Admin' reached the admin area: %d", w.Code)
	}

	// Losing the Admins group takes effect on the very next request, with the
	// same token, and the response says the token is out of date.
	var removed int
	a.scalar(&removed, `SELECT stp_RemoveGroupMember($1, $2, $3)`, admin.ID, co.AdminsID, co.ID)
	if removed != 1 {
		t.Fatalf("remove from Admins = %d", removed)
	}
	w := a.get("/api/admin/users", bearer(as.Access))
	if !refusedByGuard(w) {
		t.Errorf("SECURITY: a former Admin, same token: %d", w.Code)
	}
	if w.Header().Get(middlewares.TokenStaleHeader) != "1" {
		t.Error("a former Admin's token was not flagged stale")
	}
	expect(t, a.get("/api/me", bearer(as.Access)), http.StatusOK, "still signed in")
}

// The login token carries everything about App Central: the scope list and the
// products the person may open — keys only, no roles; roles belong in each
// product's own token.
func TestTheLoginTokenCarriesScopeAndProducts(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	crm, hr := a.newProduct("Viewer"), a.newProduct("Viewer")
	a.subscribe(co, crm)
	a.subscribe(co, hr)
	m := a.newMember(co, "")
	g := a.newGroup(co, shared.ScopeUsersEdit)
	a.grantGroup(co, g, crm, "Viewer")
	a.join(m, g)
	a.grant(m, hr, "Viewer")

	c := claims(t, a.login(m).Access)
	if c["scope"] != "apps:read users:edit users:read" {
		t.Errorf("scope = %v", c["scope"])
	}
	got := []string{}
	for _, v := range c["products"].([]any) {
		got = append(got, v.(string))
	}
	want := []string{crm.Key, hr.Key}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("products = %v, want %v", got, want)
	}
	if _, ok := c["roles"]; ok {
		t.Error("the login token carries roles; they belong in product tokens")
	}
	for _, k := range []string{"av", "pv"} {
		if _, ok := c[k].(float64); !ok {
			t.Errorf("claim %s = %v", k, c[k])
		}
	}

	owner := claims(t, a.login(a.newOwner()).Access)
	if !strings.HasSuffix(owner["scope"].(string), " owner") || !strings.Contains(owner["scope"].(string), "users:edit") {
		t.Errorf("an Owner's scope = %v", owner["scope"])
	}
	if tok, err := jwtkeys.VerifyAccess(a.login(m).Access, "app-central"); err != nil || tok == nil {
		t.Fatalf("the login token does not verify for app-central: %v", err)
	}
}

// A change to someone's access is enforced on their very next request; the
// response says their token no longer describes them, and the next token does.
func TestAStaleTokenIsFlaggedAndTheNextOneIsCurrent(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	m := a.newMember(co, "")
	g := a.newGroup(co, shared.ScopeUsersRead)
	a.join(m, g)
	s := a.login(m)

	w := a.get("/api/admin/users", bearer(s.Access))
	expect(t, w, http.StatusOK, "with users:read")
	if w.Header().Get(middlewares.TokenStaleHeader) != "" {
		t.Error("a current token was flagged stale")
	}

	a.exec(`SELECT stp_SetGroupScopes($1, $2, $3)`, g, co.ID, []string{shared.ScopeSessionsRead})
	w = a.get("/api/admin/users", bearer(s.Access))
	if !refusedByGuard(w) {
		t.Fatalf("SECURITY: a removed scope still worked: %d", w.Code)
	}
	if w.Header().Get(middlewares.TokenStaleHeader) != "1" {
		t.Error("a token describing removed access was not flagged")
	}
	expect(t, a.get("/api/admin/sessions", bearer(s.Access)), http.StatusOK, "the new scope, same token")

	s2, rw := a.refresh(s)
	expect(t, rw, http.StatusOK, "refresh")
	if c := claims(t, s2.Access); c["scope"] != "apps:read sessions:read" {
		t.Errorf("the refreshed token's scope = %v", c["scope"])
	}
	if w := a.get("/api/admin/sessions", bearer(s2.Access)); w.Header().Get(middlewares.TokenStaleHeader) != "" {
		t.Error("the refreshed token is flagged stale")
	}

	// Product access too: a new grant stales the products claim.
	p := a.newProduct("Viewer")
	a.subscribe(co, p)
	a.grant(m, p, "Viewer")
	if w := a.get("/api/me", bearer(s2.Access)); w.Header().Get(middlewares.TokenStaleHeader) != "1" {
		t.Error("a token missing a newly granted product was not flagged")
	}
}

// Rule 1: nobody gives or takes away a scope they do not hold. It covers a
// group's scopes, creating and deleting groups, adding someone to a group, an
// invitation into one, and a person's extras.
func TestRuleOneYouCanOnlyGiveWhatYouHold(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.login(a.newAdmin(co))
	d := a.newMember(co, "")
	a.join(d, a.newGroup(co, shared.ScopeGroupsEdit, shared.ScopeUsersEdit, shared.ScopeInvitationsEdit))
	ds := a.login(d)
	sessionsGroup := a.newGroup(co, shared.ScopeSessionsRead)

	// Creating a group: only scopes you hold.
	w := a.post("/api/admin/groups", map[string]any{"name": "Readers " + randSuffix(t), "scopes": []string{"users:read"}}, bearer(ds.Access))
	expect(t, w, http.StatusCreated, "a group giving a held scope")
	readers := jsonField(w, "id")
	w = a.post("/api/admin/groups", map[string]any{"name": "Watchers " + randSuffix(t), "scopes": []string{"sessions:read"}}, bearer(ds.Access))
	if !refusedBy(w, ruleOne) {
		t.Errorf("SECURITY: a group giving an unheld scope was created: %d %s", w.Code, w.Body.String())
	}

	// Changing a group's scopes: what is added AND what is removed must be held.
	w = a.send(http.MethodPut, "/api/admin/groups/"+sessionsGroup+"/scopes",
		map[string]any{"scopes": []string{"sessions:read", "users:read"}}, bearer(ds.Access))
	expect(t, w, http.StatusOK, "adding a held scope beside an unheld one")
	w = a.send(http.MethodPut, "/api/admin/groups/"+sessionsGroup+"/scopes",
		map[string]any{"scopes": []string{"users:read"}}, bearer(ds.Access))
	if !refusedBy(w, ruleOne) {
		t.Errorf("SECURITY: an unheld scope was taken away: %d", w.Code)
	}
	w = a.send(http.MethodDelete, "/api/admin/groups/"+sessionsGroup, nil, bearer(ds.Access))
	if !refusedBy(w, ruleOne) {
		t.Errorf("SECURITY: a group giving an unheld scope was deleted: %d", w.Code)
	}

	// Joining a group gives its scopes; the Admins group gives every scope.
	target := a.newMember(co, "")
	for name, gid := range map[string]string{"a group with an unheld scope": sessionsGroup, "the Admins group": co.AdminsID} {
		w := a.post("/api/admin/groups/"+gid+"/members", map[string]any{"user_id": target.ID}, bearer(ds.Access))
		if !refusedBy(w, ruleOne) {
			t.Errorf("SECURITY: added someone to %s: %d", name, w.Code)
		}
		w = a.post("/api/admin/groups/"+gid+"/members", map[string]any{"user_id": d.ID}, bearer(ds.Access))
		if !refusedBy(w, ruleOne) {
			t.Errorf("SECURITY: added THEMSELVES to %s: %d", name, w.Code)
		}
	}
	expect(t, a.post("/api/admin/groups/"+readers+"/members", map[string]any{"user_id": target.ID}, bearer(ds.Access)),
		http.StatusCreated, "adding someone to a group whose scopes are all held")

	// An invitation into a group gives its scopes on acceptance.
	w = a.post("/api/admin/invitations", map[string]any{"email": "x-" + randSuffix(t) + "@acme.test", "group_ids": []string{sessionsGroup}}, bearer(ds.Access))
	if !refusedBy(w, ruleOne) {
		t.Errorf("SECURITY: invited someone into a group with an unheld scope: %d", w.Code)
	}
	expect(t, a.post("/api/admin/invitations", map[string]any{"email": "y-" + randSuffix(t) + "@acme.test", "group_ids": []string{readers}}, bearer(ds.Access)),
		http.StatusCreated, "an invitation into a group whose scopes are all held")

	// Extras: the same.
	plain := a.newMember(co, "")
	expect(t, a.send(http.MethodPut, "/api/admin/users/"+plain.ID+"/scopes", map[string]any{"scopes": []string{"users:read"}}, bearer(ds.Access)),
		http.StatusOK, "a held scope as an extra")
	w = a.send(http.MethodPut, "/api/admin/users/"+plain.ID+"/scopes", map[string]any{"scopes": []string{"sessions:read"}}, bearer(ds.Access))
	if !refusedBy(w, ruleOne) {
		t.Errorf("SECURITY: an unheld scope was given as an extra: %d", w.Code)
	}
	// Nobody edits their own extras.
	expect(t, a.send(http.MethodPut, "/api/admin/users/"+d.ID+"/scopes", map[string]any{"scopes": []string{}}, bearer(ds.Access)),
		http.StatusBadRequest, "one's own extras")
	// An Admin holds everything, so can do all of the above.
	expect(t, a.send(http.MethodPut, "/api/admin/groups/"+sessionsGroup+"/scopes", map[string]any{"scopes": []string{}}, bearer(admin.Access)),
		http.StatusOK, "an Admin taking scopes away")
}

// Rule 2: nobody acts on someone with more access than they have — not to
// deactivate them, reset their password, change their extras or their groups.
func TestRuleTwoYouCanOnlyManagePeopleWithNoMoreAccess(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	d := a.newMember(co, "")
	a.join(d, a.newGroup(co, shared.ScopeUsersEdit, shared.ScopeGroupsEdit))
	ds := a.login(d)
	helper := a.newGroup(co, shared.ScopeUsersRead)

	peer := a.newMember(co, "") // users:read only: no more than d
	a.join(peer, helper)
	above := a.newMember(co, "") // sessions:read: something d does not hold
	a.giveExtras(above, shared.ScopeSessionsRead)
	admin := a.newAdmin(co)

	for name, id := range map[string]string{"someone with a scope d lacks": above.ID, "an Admin": admin.ID} {
		for what, w := range map[string]*httptest.ResponseRecorder{
			"deactivate":     a.send(http.MethodPatch, "/api/admin/users/"+id, map[string]any{"is_active": false}, bearer(ds.Access)),
			"reset":          a.post("/api/admin/users/"+id+"/password-reset", nil, bearer(ds.Access)),
			"set extras":     a.send(http.MethodPut, "/api/admin/users/"+id+"/scopes", map[string]any{"scopes": []string{"users:read"}}, bearer(ds.Access)),
			"add to a group": a.post("/api/admin/groups/"+helper+"/members", map[string]any{"user_id": id}, bearer(ds.Access)),
		} {
			if !refusedBy(w, ruleTwo) {
				t.Errorf("SECURITY: %s %s: %d %s", what, name, w.Code, w.Body.String())
			}
		}
	}
	expect(t, a.post("/api/admin/users/"+peer.ID+"/password-reset", nil, bearer(ds.Access)), http.StatusOK, "reset a peer")
	expect(t, a.send(http.MethodDelete, "/api/admin/groups/"+helper+"/members/"+peer.ID, nil, bearer(ds.Access)),
		http.StatusNoContent, "remove a peer from a group")
	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+peer.ID, map[string]any{"is_active": false}, bearer(ds.Access)),
		http.StatusOK, "deactivate a peer")

	// The Owner is bound by neither rule.
	owner := a.login(a.newOwner())
	w := a.ownerCall(owner, http.MethodPut, "/api/owner/companies/"+co.ID+"/users/"+above.ID+"/scopes", co.ID,
		map[string]any{"scopes": []string{"sessions:edit"}})
	expect(t, w, http.StatusOK, "the Owner changing anyone's extras")
	if a.count(`SELECT count(*) FROM tbl_user_scopes WHERE user_id = $1 AND scope = 'sessions:edit'
	            AND granted_by_owner_id IS NOT NULL AND granted_by_user_id IS NULL`, above.ID) != 1 {
		t.Error("an Owner's grant is not attributed to the Owner")
	}

	// Nobody but an Owner acts on an Owner — not even an Admin of the platform
	// company, who holds every scope an Owner holds.
	pl := a.platform()
	platformAdmin := a.login(a.newAdmin(pl))
	target := a.newOwner()
	if w := a.post("/api/admin/users/"+target.ID+"/password-reset", nil, bearer(platformAdmin.Access)); !refusedBy(w, ruleTwo) {
		t.Errorf("SECURITY: a platform Admin reset an Owner's password: %d %s", w.Code, w.Body.String())
	}
	expect(t, a.ownerCall(owner, http.MethodPost, "/api/owner/companies/"+pl.ID+"/users/"+target.ID+"/password-reset", pl.ID, nil),
		http.StatusOK, "an Owner resetting another Owner's password")
}

// Scopes are validated against the catalogue: an unknown one, or an API
// client's scope given to a person, is refused before anything is written; an
// edit scope always brings its read scope.
func TestScopesAreValidatedAndCompleted(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	g := a.newGroup(co)
	m := a.newMember(co, "")
	for _, bad := range [][]string{{"users:everything"}, {"api:read"}, {"owner"}, {"apps:read"}, {""}} {
		w := a.send(http.MethodPut, "/api/admin/groups/"+g+"/scopes", map[string]any{"scopes": bad}, bearer(s.Access))
		expect(t, w, http.StatusBadRequest, "group scopes "+strings.Join(bad, ","))
		w = a.send(http.MethodPut, "/api/admin/users/"+m.ID+"/scopes", map[string]any{"scopes": bad}, bearer(s.Access))
		expect(t, w, http.StatusBadRequest, "extras "+strings.Join(bad, ","))
	}
	w := a.send(http.MethodPut, "/api/admin/groups/"+g+"/scopes", map[string]any{"scopes": []string{"users:edit"}}, bearer(s.Access))
	expect(t, w, http.StatusOK, "edit alone")
	var out struct {
		Scopes []string `json:"scopes"`
	}
	decodeInto(t, w, &out)
	if !slices.Equal(out.Scopes, []string{"users:edit", "users:read"}) {
		t.Errorf("edit did not bring read: %v", out.Scopes)
	}
	// Every scope list is in one order, the token's: the group reads back as written.
	decodeInto(t, a.get("/api/admin/groups/"+g, bearer(s.Access)), &out)
	if !slices.Equal(out.Scopes, []string{"users:edit", "users:read"}) {
		t.Errorf("the group reads back as %v", out.Scopes)
	}
	// The database refuses what the service would: no unknown scope can be stored.
	if _, err := a.pool.Exec(t.Context(), `INSERT INTO tbl_group_scopes (group_id, client_id, scope) VALUES ($1, $2, 'users:everything')`, g, co.ID); err == nil {
		t.Error("the database stored an unknown scope")
	}
	if _, err := a.pool.Exec(t.Context(), `INSERT INTO tbl_user_scopes (user_id, client_id, scope) VALUES ($1, $2, 'mcp:tools')`, m.ID, co.ID); err == nil {
		t.Error("the database stored an API client's scope for a person")
	}
}

// A group of ANOTHER company gives nothing here: the composite keys refuse the
// rows outright, whatever the application does.
func TestScopesDoNotCrossCompanies(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	m := a.newMember(co, "")
	g := a.newGroup(other, shared.ScopeUsersRead)
	if _, err := a.pool.Exec(t.Context(), `INSERT INTO tbl_user_groups (user_id, group_id, client_id) VALUES ($1, $2, $3)`,
		m.ID, g, co.ID); err == nil {
		t.Fatal("SECURITY: a membership of another company's group was accepted")
	}
	if _, err := a.pool.Exec(t.Context(), `INSERT INTO tbl_group_scopes (group_id, client_id, scope) VALUES ($1, $2, 'users:read')`,
		g, co.ID); err == nil {
		t.Fatal("SECURITY: a group scope filed under another company was accepted")
	}
	if _, err := a.pool.Exec(t.Context(), `INSERT INTO tbl_user_scopes (user_id, client_id, scope) VALUES ($1, $2, 'users:read')`,
		m.ID, other.ID); err == nil {
		t.Fatal("SECURITY: an extra filed under another company was accepted")
	}
	s := a.login(m)
	if w := a.get("/api/admin/users", bearer(s.Access)); !refusedByGuard(w) {
		t.Errorf("SECURITY: no scope here, yet %d", w.Code)
	}
	// Another company's group is not found through the admin area.
	admin := a.login(a.newAdmin(co))
	expect(t, a.send(http.MethodPut, "/api/admin/groups/"+g+"/scopes", map[string]any{"scopes": []string{}}, bearer(admin.Access)),
		http.StatusNotFound, "another company's group")
}

// Groups are the company's to manage with groups:edit — but which products a
// group opens stays the Owner's decision, and the Admins group is fixed.
func TestProductAccessAndTheAdminsGroupStayTheOwners(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	p := a.newProduct("Viewer")
	a.subscribe(co, p)

	w := a.post("/api/admin/groups", map[string]any{
		"name": "Viewers " + randSuffix(t), "product_grants": []map[string]string{{"product_id": p.ID, "role_name": "Viewer"}},
	}, bearer(s.Access))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Only the Owner") {
		t.Errorf("SECURITY: an Admin gave a group products: %d %s", w.Code, w.Body.String())
	}
	g := a.newGroup(co, shared.ScopeUsersRead)
	a.grantGroup(co, g, p, "Viewer")
	for _, k := range []string{"PUT /api/admin/groups/" + g + "/product-grants", "PUT /api/admin/groups/" + g + "/login-policy"} {
		method, path, _ := strings.Cut(k, " ")
		if w := a.send(method, path, map[string]any{}, bearer(s.Access)); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("SECURITY: %s answered an Admin: %d", k, w.Code)
		}
	}
	w = a.send(http.MethodDelete, "/api/admin/groups/"+g, nil, bearer(s.Access))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "only the Owner") {
		t.Errorf("an Admin deleted a group that gives products: %d %s", w.Code, w.Body.String())
	}
	owner := a.login(a.newOwner())
	expect(t, a.ownerCall(owner, http.MethodDelete, "/api/owner/companies/"+co.ID+"/groups/"+g, co.ID, nil),
		http.StatusNoContent, "the Owner deleting it")

	for name, req := range map[string]struct {
		method string
		path   string
		body   any
	}{
		"rename":  {http.MethodPatch, "/api/admin/groups/" + co.AdminsID, map[string]any{"name": "Rebels"}},
		"rescope": {http.MethodPut, "/api/admin/groups/" + co.AdminsID + "/scopes", map[string]any{"scopes": []string{}}},
		"delete":  {http.MethodDelete, "/api/admin/groups/" + co.AdminsID, nil},
	} {
		expect(t, a.send(req.method, req.path, req.body, bearer(s.Access)), http.StatusConflict, name+" the Admins group")
	}
	expect(t, a.ownerCall(owner, http.MethodPut, "/api/owner/companies/"+co.ID+"/groups/"+co.AdminsID+"/scopes", co.ID,
		map[string]any{"scopes": []string{}}), http.StatusConflict, "the Owner rescoping the Admins group")
}
