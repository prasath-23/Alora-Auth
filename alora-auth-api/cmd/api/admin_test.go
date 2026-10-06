package main

// A company's administration, weighted toward the failure modes that matter in
// a multi-company identity provider: crossing into another company, escalating
// privilege, and locking the company out of itself.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/alora/auth/internal/core/shared"
)

// Who may do what — scopes, their sources and the two rules — is scopes_test.go.

// ---------- users ----------

func TestUsersAreCompanyScoped(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	admin := a.newAdmin(co)
	stranger := a.newMember(other, "")
	s := a.login(admin)

	w := a.get("/api/admin/users?take=100", bearer(s.Access))
	expect(t, w, http.StatusOK, "list")
	body := w.Body.String()
	if strings.Contains(body, stranger.ID) {
		t.Fatal("SECURITY: another company's user appeared in the list")
	}
	for _, leak := range []string{"password_hash", "argon2", "deleted_at", "permissions_version"} {
		if strings.Contains(body, leak) {
			t.Errorf("SECURITY: the list leaked %q", leak)
		}
	}
	expect(t, a.get("/api/admin/users/"+stranger.ID, bearer(s.Access)), http.StatusNotFound, "another company's user")
	w = a.get("/api/admin/users/"+admin.ID, bearer(s.Access))
	expect(t, w, http.StatusOK, "own user")
	d := decode(t, w)
	if d["is_admin"] != true || d["login_policy"] == nil {
		t.Errorf("detail = %v", d)
	}
	if lp := d["login_policy"].(map[string]any); lp["source"] != "DEFAULT" || lp["name"] != "Default" {
		t.Errorf("login policy = %v", lp)
	}
	// A cursor from another company does not resolve.
	expect(t, a.get("/api/admin/users?cursor="+stranger.ID, bearer(s.Access)), http.StatusBadRequest, "foreign cursor")
	expect(t, a.get("/api/admin/users?take=0", bearer(s.Access)), http.StatusBadRequest, "take=0")
	expect(t, a.get("/api/admin/users?take=101", bearer(s.Access)), http.StatusBadRequest, "take=101")
}

// Search is a literal, case-insensitive substring match: "_" and "%" cannot
// widen it, and a backslash is an ordinary character.
func TestUserSearchIsLiteral(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	sfx := randSuffix(t)
	underscore := a.newMember(co, "lit_1-"+sfx+"@acme.test").ID
	lookalike := a.newMember(co, "litx1-"+sfx+"@acme.test").ID
	percent := a.newMember(co, "100%-"+sfx+"@acme.test").ID

	search := func(term string) []string {
		t.Helper()
		w := a.get("/api/admin/users?take=100&search="+url.QueryEscape(term), bearer(s.Access))
		expect(t, w, http.StatusOK, "search "+term)
		var page struct {
			Users []struct {
				ID string `json:"id"`
			} `json:"users"`
		}
		decodeInto(t, w, &page)
		ids := []string{}
		for _, u := range page.Users {
			ids = append(ids, u.ID)
		}
		slices.Sort(ids)
		return ids
	}
	sorted := func(ids ...string) []string { out := append([]string{}, ids...); slices.Sort(out); return out }
	for _, c := range []struct {
		term string
		want []string
	}{
		{"LIT_1-" + sfx, sorted(underscore)},
		{"_1-" + sfx, sorted(underscore)},
		{"%-" + sfx, sorted(percent)},
		{`\`, sorted()},
		{sfx, sorted(underscore, lookalike, percent)},
	} {
		if got := search(c.term); !slices.Equal(got, c.want) {
			t.Errorf("search %q = %v, want %v", c.term, got, c.want)
		}
	}
}

// A long list, walked page by page however it is walked, lists every person
// exactly once: across people who share a creation time (a batch made in one
// transaction ties on created_at, and only the id breaks the tie), at every page
// size, with a search narrowing it, and while people keep arriving. No page is
// empty, and the last one says there is no next.
func TestTheUserListPagesEveryoneExactlyOnce(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	tag := randSuffix(t)
	a.exec(`INSERT INTO tbl_users (client_id, email, account_type)
	        SELECT $1, 'tie-' || $2 || '-' || g || '@acme.test', 'OAUTH_ONLY' FROM generate_series(1, 150) g`, co.ID, tag)
	a.exec(`INSERT INTO tbl_users (client_id, email, account_type)
	        SELECT $1, 'find-' || $2 || '-' || g || '@acme.test', 'OAUTH_ONLY' FROM generate_series(1, 90) g`, co.ID, tag)
	for i := 0; i < 5; i++ {
		a.newPasswordless(co, fmt.Sprintf("one-%s-%d@acme.test", tag, i))
	}
	ids := func(where string) map[string]bool {
		out := map[string]bool{}
		rows, err := a.pool.Query(context.Background(), `SELECT id FROM tbl_users WHERE client_id = $1 AND deleted_at IS NULL `+where, co.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out[id] = true
		}
		return out
	}
	everyone, found := ids(""), ids(`AND email LIKE 'find-%'`)
	if len(everyone) != 246 || len(found) != 90 {
		t.Fatalf("seeded %d people, %d findable", len(everyone), len(found))
	}

	walk := func(take int, search string, between func()) []string {
		var out []string
		cursor := ""
		for page := 0; ; page++ {
			q := url.Values{"take": {strconv.Itoa(take)}}
			if cursor != "" {
				q.Set("cursor", cursor)
			}
			if search != "" {
				q.Set("search", search)
			}
			w := a.get("/api/admin/users?"+q.Encode(), bearer(s.Access))
			expect(t, w, http.StatusOK, fmt.Sprintf("page %d of take=%d", page, take))
			var p struct {
				Users []struct {
					ID string `json:"id"`
				} `json:"users"`
				NextCursor *string `json:"nextCursor"`
			}
			decodeInto(t, w, &p)
			if len(p.Users) == 0 || len(p.Users) > take {
				t.Fatalf("take=%d: page %d holds %d people", take, page, len(p.Users))
			}
			for _, u := range p.Users {
				out = append(out, u.ID)
			}
			if between != nil {
				between()
			}
			if p.NextCursor == nil {
				return out
			}
			cursor = *p.NextCursor
			if page > 2*len(everyone) {
				t.Fatal("the walk never ends")
			}
		}
	}
	exactlyOnce := func(what string, got []string, want map[string]bool, others bool) {
		t.Helper()
		seen := map[string]int{}
		for _, id := range got {
			seen[id]++
		}
		for id, n := range seen {
			if n > 1 {
				t.Errorf("%s: %s listed %d times", what, id, n)
			}
			if !want[id] && !others {
				t.Errorf("%s: %s listed, but should not be", what, id)
			}
		}
		for id := range want {
			if seen[id] == 0 {
				t.Errorf("%s: %s never listed", what, id)
			}
		}
	}
	for _, take := range []int{1, 7, 41, 100} {
		exactlyOnce(fmt.Sprintf("take=%d", take), walk(take, "", nil), everyone, false)
	}
	exactlyOnce("a search", walk(10, "find-"+tag, nil), found, false)
	// People arrive between pages: each listed at most once, nobody missed.
	arriving := 0
	exactlyOnce("while people arrive", walk(10, "", func() {
		arriving++
		a.exec(`INSERT INTO tbl_users (client_id, email, account_type)
		        SELECT $1, 'late-' || $2 || '-' || $3 || '-' || g || '@acme.test', 'OAUTH_ONLY' FROM generate_series(1, 3) g`,
			co.ID, tag, strconv.Itoa(arriving))
	}), everyone, true)
}

func TestDeactivationGuards(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	admin := a.newAdmin(co)
	s := a.login(admin)
	stranger := a.newMember(other, "")

	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+admin.ID, map[string]any{"is_active": false}, bearer(s.Access)),
		http.StatusBadRequest, "self")
	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+stranger.ID, map[string]any{"is_active": false}, bearer(s.Access)),
		http.StatusNotFound, "another company's")
	var active bool
	a.scalar(&active, `SELECT is_active FROM tbl_users WHERE id = $1`, stranger.ID)
	if !active {
		t.Fatal("SECURITY: another company's user was deactivated")
	}
	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+stranger.ID, map[string]any{"is_active": false, "is_admin": true}, bearer(s.Access)),
		http.StatusBadRequest, "unknown field")

	// Someone holding users:edit may deactivate a member — not an Admin, who
	// has more access than they do.
	member := a.newMember(co, "")
	other2 := a.newAdmin(co)
	d := a.newMember(co, "")
	a.join(d, a.newGroup(co, shared.ScopeUsersEdit))
	ds := a.login(d)
	if w := a.send(http.MethodPatch, "/api/admin/users/"+other2.ID, map[string]any{"is_active": false}, bearer(ds.Access)); !refusedBy(w, ruleTwo) {
		t.Errorf("SECURITY: users:edit deactivating an Admin: %d %s", w.Code, w.Body.String())
	}
	if w := a.post("/api/admin/users/"+other2.ID+"/password-reset", nil, bearer(ds.Access)); !refusedBy(w, ruleTwo) {
		t.Errorf("SECURITY: users:edit resetting an Admin: %d %s", w.Code, w.Body.String())
	}
	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+member.ID, map[string]any{"is_active": false}, bearer(ds.Access)),
		http.StatusOK, "a delegate deactivating a member")
	expect(t, a.post("/api/admin/users/"+member.ID+"/password-reset", nil, bearer(ds.Access)),
		http.StatusOK, "a delegate resetting a member")
}

// The company's last active Admin can be neither deactivated nor removed from
// the Admins group: a company with no Admin can only be rescued by an Owner.
func TestTheLastAdminCannotBeRemoved(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	first := a.newAdmin(co)
	second := a.newAdmin(co)
	s1 := a.login(first)

	// Two Admins: one may remove the other.
	expect(t, a.send(http.MethodDelete, "/api/admin/groups/"+co.AdminsID+"/members/"+second.ID, nil, bearer(s1.Access)),
		http.StatusNoContent, "remove the second Admin")
	// Now first is the last: nobody may remove or deactivate them — not even
	// themselves.
	expect(t, a.send(http.MethodDelete, "/api/admin/groups/"+co.AdminsID+"/members/"+first.ID, nil, bearer(s1.Access)),
		http.StatusConflict, "remove the last Admin")
	a.join(second, co.AdminsID)
	a.exec(`UPDATE tbl_users SET is_active = false WHERE id = $1`, second.ID)
	expect(t, a.send(http.MethodDelete, "/api/admin/groups/"+co.AdminsID+"/members/"+first.ID, nil, bearer(s1.Access)),
		http.StatusConflict, "remove the last ACTIVE Admin")
	// An Owner deactivating the last active Admin is refused too.
	owner := a.newOwner()
	ownerSession := a.login(owner)
	w := a.send(http.MethodPatch, "/api/owner/companies/"+co.ID+"/users/"+first.ID, map[string]any{"is_active": false},
		bearer(ownerSession.Access), header("X-Alora-Target-Company", co.ID))
	expect(t, w, http.StatusConflict, "deactivate the last active Admin")
}

// Deactivation ends every session of the user at once — App Central's and every
// product's.
func TestDeactivationEndsEverySession(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)
	admin := a.newAdmin(l.co)
	as := a.login(admin)

	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+l.m.ID, map[string]any{"is_active": false}, bearer(as.Access)),
		http.StatusOK, "deactivate")
	expect(t, a.get("/api/me", bearer(l.s.Access)), http.StatusUnauthorized, "their App Central token")
	_, w := a.refresh(l.s)
	expect(t, w, http.StatusUnauthorized, "their App Central refresh")
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: a deactivated user's product login renewed: %s", w.Body.String())
	}
	if n := a.count(`SELECT count(*) FROM tbl_user_sessions WHERE user_id = $1 AND revoked_at IS NULL`, l.m.ID); n != 0 {
		t.Errorf("%d sessions survived deactivation", n)
	}
	// Reactivating does not bring the sessions back.
	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+l.m.ID, map[string]any{"is_active": true}, bearer(as.Access)),
		http.StatusOK, "reactivate")
	expect(t, a.get("/api/me", bearer(l.s.Access)), http.StatusUnauthorized, "an old token after reactivation")
}

// A session that outlives its user's deactivation — as a sign-in racing the
// deactivation could leave one — still cannot be used or renewed, nor can its
// product logins: every request and every refresh asks whether the user is
// active now, not only the deactivation that revokes.
func TestASessionOutlivingItsUsersDeactivationIsDead(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)
	a.exec(`UPDATE tbl_users SET is_active = false WHERE id = $1`, l.m.ID) // behind the API's back: nothing revoked
	if n := a.count(`SELECT count(*) FROM tbl_user_sessions WHERE user_id = $1 AND revoked_at IS NULL`, l.m.ID); n == 0 {
		t.Fatal("the test needs the sessions left live")
	}
	expect(t, a.get("/api/me", bearer(l.s.Access)), http.StatusUnauthorized, "their App Central token")
	_, w := a.refresh(l.s)
	expect(t, w, http.StatusUnauthorized, "their App Central refresh")
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: a deactivated user's product login renewed: %s", w.Body.String())
	}
}

// ---------- sessions ----------

func TestAdminSessionsListAndRevokeTheTree(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer")
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)
	admin := a.newAdmin(l.co)
	as := a.login(admin)

	w := a.get("/api/admin/sessions", bearer(as.Access))
	expect(t, w, http.StatusOK, "list")
	var list []struct {
		ID         string  `json:"id"`
		Email      string  `json:"email"`
		Kind       string  `json:"kind"`
		ProductKey *string `json:"product_key"`
		AuthMethod string  `json:"auth_method"`
	}
	decodeInto(t, w, &list)
	central := sessionID(t, l.s.Access)
	var sawCentral, sawProduct bool
	for _, s := range list {
		// An admin revoking a session has to know whose it is.
		if s.ID == central && s.Kind == "CENTRAL" && s.AuthMethod == "EMAIL" && s.Email == l.m.Email {
			sawCentral = true
		}
		if s.Kind == "PRODUCT" && s.ProductKey != nil && *s.ProductKey == l.p.Key && s.Email == l.m.Email {
			sawProduct = true
		}
	}
	if !sawCentral || !sawProduct {
		t.Fatalf("sessions = %s", w.Body.String())
	}
	for _, leak := range []string{"refresh_token", "token_hash", "user_id"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("SECURITY: the session list leaked %q", leak)
		}
	}

	// Another company's session cannot be touched.
	other := a.newCompany()
	otherSession := a.login(a.newMember(other, ""))
	expect(t, a.send(http.MethodDelete, "/api/admin/sessions/"+sessionID(t, otherSession.Access), nil, bearer(as.Access)),
		http.StatusNotFound, "another company's session")
	expect(t, a.get("/api/me", bearer(otherSession.Access)), http.StatusOK, "the other company's session survives")

	// Revoking the App Central session ends the product login under it.
	expect(t, a.send(http.MethodDelete, "/api/admin/sessions/"+central, nil, bearer(as.Access)), http.StatusNoContent, "revoke")
	expect(t, a.get("/api/me", bearer(l.s.Access)), http.StatusUnauthorized, "revoked App Central session")
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("the product login outlived its revoked session: %s", w.Body.String())
	}
	if n := a.count(`SELECT count(*) FROM tbl_session_families WHERE user_id = $1 AND revoked_reason = 'ADMIN'`, l.m.ID); n != 2 {
		t.Errorf("%d families revoked by the Admin, want 2 (central and product)", n)
	}
}

// ---------- groups, products, company ----------

// An Admin manages the company's groups — their names, their scopes, their
// members — but not which products a group opens: those routes do not exist
// under /api/admin.
func TestAdminsManageGroupsButNotWhatProductsTheyOpen(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.newAdmin(co)
	s := a.login(admin)
	g := a.newGroup(co, shared.ScopeUsersRead)
	m := a.newMember(co, "")

	w := a.get("/api/admin/groups", bearer(s.Access))
	expect(t, w, http.StatusOK, "list groups")
	if !strings.Contains(w.Body.String(), `"system_key":"ADMINS"`) {
		t.Errorf("the Admins group is missing from %s", w.Body.String())
	}
	expect(t, a.post("/api/admin/groups/"+g+"/members", map[string]any{"email": strings.ToUpper(m.Email)}, bearer(s.Access)),
		http.StatusCreated, "add by email")
	expect(t, a.post("/api/admin/groups/"+g+"/members", map[string]any{"user_id": m.ID}, bearer(s.Access)),
		http.StatusConflict, "add twice")
	expect(t, a.post("/api/admin/groups/"+g+"/members", map[string]any{}, bearer(s.Access)),
		http.StatusBadRequest, "neither id nor email")
	stranger := a.newMember(a.newCompany(), "")
	expect(t, a.post("/api/admin/groups/"+g+"/members", map[string]any{"user_id": stranger.ID}, bearer(s.Access)),
		http.StatusNotFound, "another company's user")
	d := decode(t, a.get("/api/admin/groups/"+g, bearer(s.Access)))
	if members := d["members"].([]any); len(members) != 1 {
		t.Errorf("members = %v", members)
	}

	// A group's whole life, through the admin area.
	name := "Helpdesk " + randSuffix(t)
	w = a.post("/api/admin/groups", map[string]any{"name": name, "scopes": []string{"sessions:edit"}}, bearer(s.Access))
	expect(t, w, http.StatusCreated, "create")
	var created struct {
		ID     string   `json:"id"`
		Scopes []string `json:"scopes"`
	}
	decodeInto(t, w, &created)
	if !slices.Equal(created.Scopes, []string{"sessions:edit", "sessions:read"}) {
		t.Errorf("created with scopes %v", created.Scopes)
	}
	expect(t, a.post("/api/admin/groups", map[string]any{"name": name}, bearer(s.Access)), http.StatusConflict, "a taken name")
	expect(t, a.send(http.MethodPatch, "/api/admin/groups/"+created.ID, map[string]any{"name": name + " team"}, bearer(s.Access)),
		http.StatusNoContent, "rename")
	expect(t, a.send(http.MethodPut, "/api/admin/groups/"+created.ID+"/scopes", map[string]any{"scopes": []string{"users:read"}}, bearer(s.Access)),
		http.StatusOK, "rescope")
	var scopes []string
	a.scalar(&scopes, `SELECT coalesce(array_agg(scope ORDER BY scope), '{}') FROM tbl_group_scopes WHERE group_id = $1`, created.ID)
	if !slices.Equal(scopes, []string{"users:read"}) {
		t.Errorf("stored scopes = %v", scopes)
	}
	expect(t, a.send(http.MethodDelete, "/api/admin/groups/"+created.ID, nil, bearer(s.Access)), http.StatusNoContent, "delete")
	if n := a.count(`SELECT count(*) FROM tbl_group_scopes WHERE group_id = $1`, created.ID); n != 0 {
		t.Errorf("%d scope rows outlived their group", n)
	}

	for _, k := range []string{"PUT /api/admin/groups/" + g + "/product-grants", "PUT /api/admin/groups/" + g + "/login-policy",
		"PUT /api/admin/groups/" + g + "/features", "PUT /api/admin/users/" + m.ID + "/permissions/x",
		"PUT /api/admin/users/" + m.ID + "/grants/x"} {
		method, path, _ := strings.Cut(k, " ")
		if w := a.send(method, path, map[string]any{}, bearer(s.Access)); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("SECURITY: an Admin reached %s: %d", k, w.Code)
		}
	}
	// And an Admin is not an Owner.
	expect(t, a.get("/api/owner/companies", bearer(s.Access)), http.StatusForbidden, "an Admin on the Owner console")
}

func TestAdminMayOnlyRenameTheCompany(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	w := a.send(http.MethodPatch, "/api/admin/client", map[string]any{"name": "Renamed Co"}, bearer(s.Access))
	expect(t, w, http.StatusOK, "rename")
	if decode(t, w)["name"] != "Renamed Co" {
		t.Errorf("rename = %s", w.Body.String())
	}
	for _, field := range []string{"is_active", "subscription_status", "domain_verified_at", "max_seats", "require_mfa"} {
		body := map[string]any{"name": "x", field: false}
		if w := a.send(http.MethodPatch, "/api/admin/client", body, bearer(s.Access)); w.Code != http.StatusBadRequest {
			t.Errorf("SECURITY: an Admin changed %s: %d", field, w.Code)
		}
	}
	expect(t, a.get("/api/admin/client", bearer(s.Access)), http.StatusOK, "read")
}

func TestAdminProductsAreTheCompanysSubscriptions(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	mine, notMine := a.newProduct(), a.newProduct()
	a.subscribe(co, mine)
	w := a.get("/api/admin/products", bearer(s.Access))
	expect(t, w, http.StatusOK, "products")
	if !strings.Contains(w.Body.String(), mine.ID) || strings.Contains(w.Body.String(), notMine.ID) {
		t.Errorf("products = %s", w.Body.String())
	}
	for _, leak := range []string{"client_secret", "secret_hash", "redirect"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("SECURITY: the subscription list leaked %q", leak)
		}
	}
}

// ---------- apps ----------

func TestMyAppsListsOnlyWhatIMayLaunch(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Editor")
	a.newProduct() // exists, but the company does not subscribe to it
	w := a.get("/api/me/apps", bearer(l.s.Access))
	expect(t, w, http.StatusOK, "apps")
	var apps []struct {
		ProductID string   `json:"product_id"`
		Key       string   `json:"key"`
		Roles     []string `json:"roles"`
		LaunchURL string   `json:"launch_url"`
	}
	decodeInto(t, w, &apps)
	if len(apps) != 1 || apps[0].ProductID != l.p.ID || !slices.Equal(apps[0].Roles, []string{"Editor"}) {
		t.Fatalf("apps = %s", w.Body.String())
	}
	u, err := url.Parse(apps[0].LaunchURL)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != l.p.Initiate ||
		u.Query().Get("iss") != testIssuer || u.Query().Get("target_link_uri") != l.p.Base {
		t.Errorf("launch_url = %s", apps[0].LaunchURL)
	}
	// Access is gone the moment the subscription is.
	a.exec(`UPDATE tbl_client_products SET is_active = false WHERE client_id = $1`, l.co.ID)
	w = a.get("/api/me/apps", bearer(l.s.Access))
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("apps after the subscription ended = %s", w.Body.String())
	}
}
