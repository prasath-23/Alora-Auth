package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alora/auth/internal/core/shared"
)

// The group-manager routes at their edges: every shape of request they accept
// and refuse, the race between a dismissal and a manager's change, and what the
// manager sees of a group.

// Appointing takes a person by id as well as by address, through both doors,
// and refuses every malformed request before anything is written.
func TestAppointingTakesAnIDAndRefusesMalformedRequests(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	as := a.login(a.newAdmin(co))
	g := a.newGroup(co)
	path := "/api/admin/groups/" + g + "/managers"

	byID := a.newMember(co, "")
	expect(t, a.post(path, map[string]any{"user_id": byID.ID}, bearer(as.Access)), http.StatusCreated, "by id")
	for name, c := range map[string]struct {
		body   any
		status int
	}{
		"a malformed id":          {map[string]any{"user_id": "not-a-uuid"}, http.StatusBadRequest},
		"a malformed email":       {map[string]any{"email": "not an address"}, http.StatusBadRequest},
		"an unknown field":        {map[string]any{"email": a.newMember(co, "").Email, "role": "owner"}, http.StatusBadRequest},
		"an address too long":     {map[string]any{"email": strings.Repeat("a", 320) + "@acme.test"}, http.StatusBadRequest},
		"a body that is not JSON": {"email=someone@acme.test", http.StatusUnsupportedMediaType},
	} {
		if w := a.post(path, c.body, bearer(as.Access)); w.Code != c.status {
			t.Errorf("%s: %d %s, want %d", name, w.Code, w.Body.String(), c.status)
		}
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"signed out":             a.post(path, map[string]any{"email": byID.Email}),
		"signed out, dismissing": a.send(http.MethodDelete, path+"/"+byID.ID, nil),
	} {
		expect(t, w, http.StatusUnauthorized, name)
	}
	expect(t, a.send(http.MethodDelete, path+"/not-a-uuid", nil, bearer(as.Access)), http.StatusNotFound, "dismissing a malformed id")
	expect(t, a.send(http.MethodPost, "/api/admin/groups/not-a-uuid/managers", map[string]any{"email": byID.Email}, bearer(as.Access)),
		http.StatusNotFound, "a malformed group id")
	if n := a.count(`SELECT count(*) FROM tbl_group_managers WHERE group_id = $1`, g); n != 1 {
		t.Errorf("the group has %d managers after the refusals, want 1", n)
	}

	// The Owner's door: by id, and only with the company echoed in the header.
	os := a.login(a.newOwner())
	opath := "/api/owner/companies/" + co.ID + "/groups/" + g + "/managers"
	lead := a.newMember(co, "")
	for _, cid := range []string{"", other.ID, "garbage"} {
		if w := a.ownerCall(os, http.MethodPost, opath, cid, map[string]any{"user_id": lead.ID}); w.Code != http.StatusBadRequest {
			t.Errorf("target header %q: %d, want 400", cid, w.Code)
		}
	}
	expect(t, a.ownerCall(os, http.MethodPost, opath, co.ID, map[string]any{"user_id": lead.ID}), http.StatusCreated, "Owner, by id")
	if w := a.ownerCall(os, http.MethodDelete, opath+"/"+lead.ID, other.ID, nil); w.Code != http.StatusBadRequest {
		t.Errorf("Owner dismissal with another company's header: %d, want 400", w.Code)
	}
	// Another company's group through the right door is simply not there.
	expect(t, a.ownerCall(os, http.MethodPost, "/api/owner/companies/"+other.ID+"/groups/"+g+"/managers", other.ID,
		map[string]any{"user_id": lead.ID}), http.StatusNotFound, "a group through another company's door")
}

// The manager's door takes a member by id as well as by address, and refuses
// every malformed request; a malformed group or member id is simply not found.
func TestTheManagerDoorTakesAnIDAndRefusesMalformedRequests(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	g := a.newGroup(co)
	lead := a.newMember(co, "")
	a.makeManager(g, lead, a.newAdmin(co))
	ls := a.login(lead)
	path := "/api/me/managed-groups/" + g + "/members"

	m := a.newMember(co, "")
	expect(t, a.post(path, map[string]any{"user_id": m.ID}, bearer(ls.Access)), http.StatusCreated, "by id")
	expect(t, a.send(http.MethodDelete, path+"/"+m.ID, nil, bearer(ls.Access)), http.StatusNoContent, "remove")
	for name, c := range map[string]struct {
		body   any
		status int
	}{
		"a malformed id":          {map[string]any{"user_id": "not-a-uuid"}, http.StatusBadRequest},
		"a malformed email":       {map[string]any{"email": "@"}, http.StatusBadRequest},
		"an unknown field":        {map[string]any{"email": m.Email, "group_id": g}, http.StatusBadRequest},
		"a body that is not JSON": {"email=" + m.Email, http.StatusUnsupportedMediaType},
	} {
		if w := a.post(path, c.body, bearer(ls.Access)); w.Code != c.status {
			t.Errorf("%s: %d %s, want %d", name, w.Code, w.Body.String(), c.status)
		}
	}
	expect(t, a.post(path, map[string]any{"email": m.Email}), http.StatusUnauthorized, "signed out, adding")
	expect(t, a.send(http.MethodDelete, path+"/"+m.ID, nil), http.StatusUnauthorized, "signed out, removing")
	expect(t, a.get("/api/me/managed-groups/not-a-uuid", bearer(ls.Access)), http.StatusNotFound, "a malformed group id")
	expect(t, a.post("/api/me/managed-groups/not-a-uuid/members", map[string]any{"email": m.Email}, bearer(ls.Access)),
		http.StatusNotFound, "adding to a malformed group id")
	expect(t, a.send(http.MethodDelete, path+"/not-a-uuid", nil, bearer(ls.Access)), http.StatusNotFound, "a malformed member id")
	if a.isMember(g, m.ID) {
		t.Error("a refused request changed the group")
	}
}

// Dismissal and a manager's change serialise on the group row: a change that
// arrives while a dismissal is in progress waits for it, and is then refused;
// so is one that arrives while the group is being deleted.
func TestAManagersChangeWaitsForADismissalInProgress(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.newAdmin(co)
	ctx := context.Background()

	for _, c := range []struct {
		name string
		end  string // the statement that takes the manager's rights away
	}{
		{"a dismissal", `SELECT stp_RemoveGroupManager($1, $2, $3)`},
		{"the group's deletion", `SELECT stp_DeleteGroup($1, $2)`},
	} {
		g := a.newGroup(co)
		lead, someone := a.newMember(co, ""), a.newMember(co, "")
		a.makeManager(g, lead, admin)

		tx, err := a.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		args := []any{g, co.ID, lead.ID}
		if strings.Contains(c.end, "DeleteGroup") {
			args = args[:2]
		}
		if _, err := tx.Exec(ctx, c.end, args...); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		done := make(chan int, 1)
		go func() {
			var n int
			if err := a.pool.QueryRow(ctx, `SELECT stp_ManagerAddGroupMember($1, $2, $3, $4)`, lead.ID, someone.ID, g, co.ID).Scan(&n); err != nil {
				n = -99
			}
			done <- n
		}()
		select {
		case n := <-done:
			_ = tx.Rollback(ctx)
			t.Fatalf("%s: the manager's change did not wait for it (%d)", c.name, n)
		case <-time.After(300 * time.Millisecond):
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case n := <-done:
			if n != -1 {
				t.Errorf("SECURITY: %s committed first, yet the manager's change answered %d, want -1", c.name, n)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the manager's change never finished", c.name)
		}
		if a.isMember(g, someone.ID) {
			t.Errorf("SECURITY: %s: a member was added by someone who no longer managed the group", c.name)
		}
	}

	// The other way round: a change in progress finishes first, and the
	// dismissal waits for it.
	g := a.newGroup(co)
	lead, someone := a.newMember(co, ""), a.newMember(co, "")
	a.makeManager(g, lead, admin)
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT stp_ManagerAddGroupMember($1, $2, $3, $4)`, lead.ID, someone.ID, g, co.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the change in progress: %d, %v", n, err)
	}
	done := make(chan int, 1)
	go func() {
		var d int
		if err := a.pool.QueryRow(ctx, `SELECT stp_RemoveGroupManager($1, $2, $3)`, g, co.ID, lead.ID).Scan(&d); err != nil {
			d = -99
		}
		done <- d
	}()
	select {
	case d := <-done:
		_ = tx.Rollback(ctx)
		t.Fatalf("the dismissal did not wait for the change in progress (%d)", d)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if d := <-done; d != 1 {
		t.Errorf("the dismissal after the change: %d, want 1", d)
	}
	if !a.isMember(g, someone.ID) {
		t.Error("the change that finished first was lost")
	}
}

// An Admin who also manages a group has both doors, each with its own rules;
// the Owner, too, can be a group's manager in the platform company.
func TestManagersWhoAlsoHoldMoreUseBothDoors(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin, other := a.newAdmin(co), a.newAdmin(co)
	g := a.newGroup(co, shared.ScopeUsersRead)
	a.makeManager(g, admin, other)
	as := a.login(admin)
	m := a.newMember(co, "")
	expect(t, a.managedAdd(as, g, m.Email), http.StatusCreated, "an Admin through the manager's door")
	expect(t, a.send(http.MethodDelete, "/api/admin/groups/"+g+"/members/"+m.ID, nil, bearer(as.Access)),
		http.StatusNoContent, "the same Admin through the admin door")
	// Through the manager's door they are a manager like any other: never on
	// their own membership, though the admin door lets an Admin change it.
	if w := a.managedAdd(as, g, admin.Email); !refusedBy(w, managersSelf) {
		t.Errorf("an Admin, as a manager, added themselves: %d %s", w.Code, w.Body.String())
	}
	expect(t, a.post("/api/admin/groups/"+g+"/members", map[string]any{"email": admin.Email}, bearer(as.Access)),
		http.StatusCreated, "an Admin adds themselves through the admin door")

	pl := a.platform()
	o1, o2 := a.newOwner(), a.newOwner()
	pg := a.newGroup(pl)
	w := a.ownerCall(a.login(o2), http.MethodPost, "/api/owner/companies/"+pl.ID+"/groups/"+pg+"/managers", pl.ID,
		map[string]any{"email": o1.Email})
	expect(t, w, http.StatusCreated, "an Owner appoints another Owner")
	o1s := a.login(o1)
	expect(t, a.get("/api/me/managed-groups/"+pg, bearer(o1s.Access)), http.StatusOK, "an Owner reads the group they manage")
	expect(t, a.managedAdd(o1s, pg, a.newMember(pl, "").Email), http.StatusCreated, "an Owner adds through the manager's door")
}

// The budget belongs to an account: one manager spending theirs costs another
// nothing.
func TestTheManagerBudgetIsPerAccount(t *testing.T) {
	a := newAppWith(t, map[string]string{"RATE_LIMIT_GLOBAL_MAX": "100000"}, nil)
	co := a.newCompany()
	admin := a.newAdmin(co)
	g := a.newGroup(co)
	first, second := a.newMember(co, ""), a.newMember(co, "")
	a.makeManager(g, first, admin)
	a.makeManager(g, second, admin)
	fs, ss := a.login(first), a.login(second)
	for i := 0; i < 60; i++ {
		a.managedAdd(fs, g, fmt.Sprintf("probe-%d-%s@acme.test", i, randSuffix(t)))
	}
	expect(t, a.managedAdd(fs, g, a.newMember(co, "").Email), http.StatusTooManyRequests, "the first manager, spent")
	expect(t, a.managedAdd(ss, g, a.newMember(co, "").Email), http.StatusCreated, "the second manager, untouched")
}

// A manager sees what the group gives — scopes, apps, sign-in policy — and its
// managers, but never a soft-deleted one; a renamed group shows its new name in
// /api/me, while the token names groups by id and so needs no new one.
func TestWhatAManagerSeesOfTheirGroup(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.newAdmin(co)
	p := a.newProduct("Viewer")
	a.subscribe(co, p)
	g := a.newGroup(co, shared.ScopeSessionsEdit)
	a.grantGroup(co, g, p, "Viewer")
	lead, gone := a.newMember(co, ""), a.newMember(co, "")
	a.makeManager(g, lead, admin)
	a.makeManager(g, gone, admin)
	a.exec(`UPDATE tbl_users SET deleted_at = now() WHERE id = $1`, gone.ID)
	ls := a.login(lead)

	w := a.get("/api/me/managed-groups/"+g, bearer(ls.Access))
	expect(t, w, http.StatusOK, "their group")
	var page struct {
		Scopes        []string `json:"scopes"`
		ProductGrants []struct {
			ProductKey string `json:"product_key"`
			RoleName   string `json:"role_name"`
		} `json:"product_grants"`
		Managers []managerRow `json:"managers"`
	}
	decodeInto(t, w, &page)
	if !slices.Equal(page.Scopes, []string{shared.ScopeSessionsEdit, shared.ScopeSessionsRead}) {
		t.Errorf("scopes %v", page.Scopes)
	}
	if len(page.ProductGrants) != 1 || page.ProductGrants[0].ProductKey != p.Key || page.ProductGrants[0].RoleName != "Viewer" {
		t.Errorf("apps %+v", page.ProductGrants)
	}
	if len(page.Managers) != 1 || page.Managers[0].UserID != lead.ID {
		t.Errorf("managers %+v: a soft-deleted manager must not be listed", page.Managers)
	}
	if strings.Contains(w.Body.String(), gone.ID) || strings.Contains(w.Body.String(), gone.Email) {
		t.Error("the group's page disclosed a deleted manager")
	}

	renamed := "Renamed " + randSuffix(t)
	expect(t, a.send(http.MethodPatch, "/api/admin/groups/"+g, map[string]any{"name": renamed, "description": ""},
		bearer(a.login(admin).Access)), http.StatusNoContent, "rename")
	w = a.get("/api/me", bearer(ls.Access))
	if !strings.Contains(w.Body.String(), renamed) {
		t.Errorf("/api/me shows the old name: %s", w.Body.String())
	}
}
