package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/alora/auth/internal/database/services/productpermissions"
)

// Every change to what someone may use stales their tokens in the SAME database
// statement as the change itself, so the two cannot come apart: a product that
// introspects sees the change at once, and the next refresh re-mints from the
// current state.

func pvOf(a *app, userID string) int {
	a.t.Helper()
	var n int
	a.scalar(&n, `SELECT permissions_version FROM tbl_users WHERE id = $1`, userID)
	return n
}

func TestEveryAccessChangeBumpsTheVersionExactlyOnce(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	p := a.newProduct()
	a.subscribe(co, p)
	m := a.newMember(co, "")
	g := a.newGroup(co)
	s := a.login(a.newAdmin(co))

	step := func(what string, do func()) {
		t.Helper()
		before := pvOf(a, m.ID)
		do()
		if after := pvOf(a, m.ID); after != before+1 {
			t.Errorf("%s: permissions_version %d -> %d, want exactly one bump", what, before, after)
		}
	}
	step("joining a group", func() {
		w := a.post("/api/admin/groups/"+g+"/members", map[string]any{"user_id": m.ID}, bearer(s.Access))
		expect(t, w, http.StatusCreated, "add member")
	})
	step("leaving a group", func() {
		w := a.send(http.MethodDelete, "/api/admin/groups/"+g+"/members/"+m.ID, nil, bearer(s.Access))
		expect(t, w, http.StatusNoContent, "remove member")
	})
	step("a direct grant", func() { a.grant(m, p, "Viewer") })
	step("revoking a direct grant", func() {
		n, err := productpermissions.NewProductPermissionDbService(a.owner).Delete(context.Background(), m.ID, co.ID, p.ID)
		if err != nil || n != 1 {
			t.Fatalf("revoke: %d, %v", n, err)
		}
	})
	a.join(m, g)
	owner := a.login(a.newOwner())
	step("deleting a group they are in", func() {
		w := a.ownerCall(owner, http.MethodDelete, "/api/owner/companies/"+co.ID+"/groups/"+g, co.ID, nil)
		expect(t, w, http.StatusNoContent, "delete group")
	})
}

// A deleted group stops granting at once: its members' product tokens go
// inactive for a product that introspects, and their next refresh ends the
// login instead of renewing access they no longer have.
func TestDeletingAGroupEndsWhatItGranted(t *testing.T) {
	a := newApp(t)
	l := a.setupProduct("Viewer") // the member holds Viewer through a group
	f := newFlow(t)
	ts := a.exchange(l.p, a.code(&l, f), f)

	var groupID string
	a.scalar(&groupID, `SELECT group_id FROM tbl_user_groups WHERE user_id = $1`, l.m.ID)
	owner := a.login(a.newOwner())
	w := a.ownerCall(owner, http.MethodDelete, "/api/owner/companies/"+l.co.ID+"/groups/"+groupID, l.co.ID, nil)
	expect(t, w, http.StatusNoContent, "delete group")

	intro := a.post("/oauth/introspect", url.Values{"token": {ts.AccessToken}}, basic(l.p.ID, l.p.Secret))
	expect(t, intro, http.StatusOK, "introspect")
	if got := decode(t, intro); got["active"] != false {
		t.Errorf("SECURITY: a token granted only by a deleted group introspected active: %v", got)
	}
	if w := a.productRefresh(l.p, ts.RefreshToken); oauthError(t, w) != "invalid_grant" {
		t.Errorf("SECURITY: a product renewed access a deleted group granted: %s", w.Body.String())
	}
}

// The OAuth endpoints' own budget is keyed by the client id, which the caller
// chooses; failed client authentications are budgeted per address as well, so
// cycling made-up ids buys no extra guesses. Success costs nothing.
func TestFailedClientAuthenticationIsBudgetedPerAddress(t *testing.T) {
	a := newApp(t)
	p := a.newProduct()
	introspect := func(id, secret string) *httptest.ResponseRecorder {
		return a.post("/oauth/introspect", url.Values{"token": {"x"}}, basic(id, secret))
	}
	for i := 0; i < 30; i++ {
		expect(t, introspect(p.ID, p.Secret), http.StatusOK, "an authenticated call")
	}
	for i := 0; i < 20; i++ {
		expect(t, introspect("made-up-"+randSuffix(t), "a-guess"), http.StatusUnauthorized, "a guess")
	}
	w := introspect(p.ID, p.Secret)
	expect(t, w, http.StatusTooManyRequests, "after 20 failures, even with the right secret")
	if w.Header().Get("Retry-After") == "" {
		t.Error("a 429 without Retry-After")
	}
}

// versionsOf reads a user's (permissions_version, admin_version).
func versionsOf(a *app, userID string) (pv, av int) {
	a.t.Helper()
	pv = pvOf(a, userID)
	a.scalar(&av, `SELECT admin_version FROM tbl_users WHERE id = $1`, userID)
	return pv, av
}

// Running a group is App Central access, so every appointment change bumps the
// person's admin_version exactly once, and never their product access; what a
// manager does to a member bumps the member, never the manager; and deleting a
// group bumps everyone it touched once — once, too, for someone who was both a
// member and a manager.
func TestManagerChangesBumpTheVersionsExactlyOnce(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	as := a.login(a.newAdmin(co))
	g := a.newGroup(co)
	lead, m := a.newMember(co, ""), a.newMember(co, "")

	step := func(what string, who member, dpv, dav int, do func()) {
		t.Helper()
		pv, av := versionsOf(a, who.ID)
		do()
		if pv2, av2 := versionsOf(a, who.ID); pv2 != pv+dpv || av2 != av+dav {
			t.Errorf("%s: versions (pv %d, av %d) -> (%d, %d), want +%d and +%d", what, pv, av, pv2, av2, dpv, dav)
		}
	}
	step("appointing", lead, 0, 1, func() { expect(t, a.appoint(as, g, lead.Email), http.StatusCreated, "appoint") })
	ls := a.login(lead)
	step("a manager adding a member: the member", m, 1, 1, func() {
		expect(t, a.managedAdd(ls, g, m.Email), http.StatusCreated, "add")
	})
	step("a manager removing a member: the member", m, 1, 1, func() {
		expect(t, a.managedRemove(ls, g, m.ID), http.StatusNoContent, "remove")
	})
	step("a manager adding a member: the manager", lead, 0, 0, func() {
		expect(t, a.managedAdd(ls, g, m.Email), http.StatusCreated, "add again")
	})
	step("dismissing", lead, 0, 1, func() { expect(t, a.dismiss(as, g, lead.ID), http.StatusNoContent, "dismiss") })

	both, onlyManager := a.newMember(co, ""), a.newMember(co, "")
	a.join(both, g)
	a.makeManager(g, both, a.newAdmin(co))
	a.makeManager(g, onlyManager, a.newAdmin(co))
	pvM, avM := versionsOf(a, m.ID)
	pvB, avB := versionsOf(a, both.ID)
	pvO, avO := versionsOf(a, onlyManager.ID)
	expect(t, a.send(http.MethodDelete, "/api/admin/groups/"+g, nil, bearer(as.Access)), http.StatusNoContent, "delete the group")
	for _, c := range []struct {
		who      string
		id       string
		pv, av   int
		dpv, dav int
	}{
		{"a member", m.ID, pvM, avM, 1, 1},
		{"a member and manager", both.ID, pvB, avB, 1, 1},
		{"a manager", onlyManager.ID, pvO, avO, 0, 1},
	} {
		if pv, av := versionsOf(a, c.id); pv != c.pv+c.dpv || av != c.av+c.dav {
			t.Errorf("deleting the group, %s: (pv %d, av %d) -> (%d, %d), want +%d and +%d", c.who, c.pv, c.av, pv, av, c.dpv, c.dav)
		}
	}
	if n := a.count(`SELECT count(*) FROM tbl_group_managers WHERE group_id = $1`, g); n != 0 {
		t.Errorf("%d appointments outlived their group", n)
	}
}
