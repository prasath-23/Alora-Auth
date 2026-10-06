package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/middlewares"
)

// Group managers run one group: they add and remove its members, and nothing
// else, without groups:edit for the whole company. Appointing one is handing
// the group out (rule 1), and rule 2 measures people by their reach — the
// scopes they hold plus those of the groups they manage — whoever acts, and on
// whomever.

const managersSelf = "A group's managers can't add or remove themselves or each other; an Admin does that"

func (a *app) appoint(s session, groupID, email string) *httptest.ResponseRecorder {
	return a.post("/api/admin/groups/"+groupID+"/managers", map[string]any{"email": email}, bearer(s.Access))
}

func (a *app) dismiss(s session, groupID, userID string) *httptest.ResponseRecorder {
	return a.send(http.MethodDelete, "/api/admin/groups/"+groupID+"/managers/"+userID, nil, bearer(s.Access))
}

func (a *app) managedAdd(s session, groupID, email string) *httptest.ResponseRecorder {
	return a.post("/api/me/managed-groups/"+groupID+"/members", map[string]any{"email": email}, bearer(s.Access))
}

func (a *app) managedRemove(s session, groupID, userID string) *httptest.ResponseRecorder {
	return a.send(http.MethodDelete, "/api/me/managed-groups/"+groupID+"/members/"+userID, nil, bearer(s.Access))
}

// makeManager appoints someone in the database, attributed to by.
func (a *app) makeManager(groupID string, m, by member) {
	a.t.Helper()
	var n int
	a.scalar(&n, `SELECT stp_AddGroupManager($1, $2, $3, $4, NULL)`, groupID, m.ClientID, m.ID, by.ID)
	if n != 1 {
		a.t.Fatalf("appoint %s: %d", m.Email, n)
	}
}

func (a *app) isMember(groupID, userID string) bool {
	return a.count(`SELECT count(*) FROM tbl_user_groups WHERE group_id = $1 AND user_id = $2`, groupID, userID) == 1
}

// managesOf is /api/me's manages, as group ids.
func managesOf(t *testing.T, a *app, s session) []string {
	t.Helper()
	w := a.get("/api/me", bearer(s.Access))
	expect(t, w, http.StatusOK, "me")
	var me struct {
		Manages []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"manages"`
	}
	decodeInto(t, w, &me)
	ids := []string{}
	for _, g := range me.Manages {
		ids = append(ids, g.ID)
	}
	return ids
}

type managerRow struct {
	UserID           string `json:"user_id"`
	Email            string `json:"email"`
	AppointedByEmail string `json:"appointed_by_email"`
	AppointedByOwner bool   `json:"appointed_by_owner"`
}

type groupPage struct {
	ID              string       `json:"id"`
	LoginPolicyName *string      `json:"login_policy_name"`
	Managers        []managerRow `json:"managers"`
	Members         []struct {
		UserID string `json:"user_id"`
	} `json:"members"`
}

// audited waits for an audit row in a company's trail with the event and every
// detail given.
func audited(t *testing.T, a *app, companyID, event string, want map[string]string) {
	t.Helper()
	q := `SELECT count(*) FROM tbl_audit_logs WHERE client_id = $1 AND event_type = $2`
	args := []any{companyID, event}
	for k, v := range want {
		args = append(args, v)
		q += fmt.Sprintf(" AND event_metadata->>'%s' = $%d", k, len(args))
	}
	deadline := time.Now().Add(3 * time.Second)
	for a.count(q, args...) == 0 {
		if time.Now().After(deadline) {
			t.Errorf("no %s %v in the trail of %s", event, want, companyID)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// An Admin appoints a manager: the group's page names them and who appointed
// them, their open page is told its token is stale, /api/me and the next token
// name the group — and being a manager is not a scope. Dismissing undoes it.
func TestAnAdminAppointsAndDismissesAGroupManager(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.newAdmin(co)
	as := a.login(admin)
	g := a.newGroup(co, shared.ScopeSessionsRead)
	lead := a.newMember(co, "")
	ls := a.login(lead) // signed in before the appointment

	w := a.appoint(as, g, lead.Email)
	expect(t, w, http.StatusCreated, "appoint")
	if jsonField(w, "group_id") != g || jsonField(w, "user_id") != lead.ID {
		t.Fatalf("appointment: %s", w.Body.String())
	}
	w = a.get("/api/admin/groups/"+g, bearer(as.Access))
	expect(t, w, http.StatusOK, "the group's page")
	var page groupPage
	decodeInto(t, w, &page)
	want := managerRow{UserID: lead.ID, Email: lead.Email, AppointedByEmail: admin.Email}
	if len(page.Managers) != 1 || page.Managers[0] != want {
		t.Fatalf("managers %+v, want [%+v]", page.Managers, want)
	}

	// The manager's open page is told its token is out of date...
	w = a.get("/api/me", bearer(ls.Access))
	if w.Header().Get(middlewares.TokenStaleHeader) != "1" {
		t.Error("appointing did not stale the manager's token")
	}
	if got := managesOf(t, a, ls); !slices.Equal(got, []string{g}) {
		t.Errorf("me.manages = %v, want [%s]", got, g)
	}
	// ...and the next token names the group. Nothing else changed: being a
	// manager is not a scope.
	fresh, rw := a.refresh(ls)
	expect(t, rw, http.StatusOK, "refresh")
	c := claims(t, fresh.Access)
	if got, _ := c["manages"].([]any); len(got) != 1 || got[0] != g {
		t.Errorf("token manages = %v, want [%s]", c["manages"], g)
	}
	if c["scope"] != shared.ScopeApps {
		t.Errorf("a manager's token scope = %v, want %s alone", c["scope"], shared.ScopeApps)
	}

	expect(t, a.dismiss(as, g, lead.ID), http.StatusNoContent, "dismiss")
	if w := a.get("/api/me", bearer(fresh.Access)); w.Header().Get(middlewares.TokenStaleHeader) != "1" {
		t.Error("dismissing did not stale the former manager's token")
	}
	if got := managesOf(t, a, fresh); len(got) != 0 {
		t.Errorf("after dismissal me.manages = %v", got)
	}
	again, rw := a.refresh(fresh)
	expect(t, rw, http.StatusOK, "refresh")
	if got, _ := claims(t, again.Access)["manages"].([]any); got == nil || len(got) != 0 {
		t.Errorf("after dismissal the token's manages = %v, want []", claims(t, again.Access)["manages"])
	}
	audited(t, a, co.ID, "group.manager_added", map[string]string{"group_id": g, "user_id": lead.ID})
	audited(t, a, co.ID, "group.manager_removed", map[string]string{"group_id": g, "user_id": lead.ID})
}

// Appointing and dismissing need groups:edit, every scope the group gives, and
// no less reach than the person's. Nobody appoints themselves, the Admins group
// never has managers, and only the company's own live people can be appointed.
func TestAppointingAManagerIsGuarded(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	admin := a.newAdmin(co)
	as := a.login(admin)
	g := a.newGroup(co, shared.ScopeUsersRead)

	reader := a.newMember(co, "")
	a.join(reader, a.newGroup(co, shared.ScopeGroupsRead))
	if w := a.appoint(a.login(reader), g, a.newMember(co, "").Email); !refusedByGuard(w) {
		t.Errorf("groups:read appointed: %d %s", w.Code, w.Body.String())
	}
	// groups:edit, but not users:read, which the group gives: rule 1.
	editor := a.newMember(co, "")
	a.join(editor, a.newGroup(co, shared.ScopeGroupsEdit))
	es := a.login(editor)
	if w := a.appoint(es, g, a.newMember(co, "").Email); !refusedBy(w, ruleOne) {
		t.Errorf("rule 1: %d %s", w.Code, w.Body.String())
	}
	// Both — but the person holds more: rule 2.
	editor2 := a.newMember(co, "")
	a.join(editor2, a.newGroup(co, shared.ScopeGroupsEdit, shared.ScopeUsersRead))
	e2 := a.login(editor2)
	above := a.newMember(co, "")
	a.giveExtras(above, shared.ScopeSessionsRead)
	if w := a.appoint(e2, g, above.Email); !refusedBy(w, ruleTwo) {
		t.Errorf("rule 2, by what they hold: %d %s", w.Code, w.Body.String())
	}
	// Reach counts what someone could hand out as a manager already.
	runsMore := a.newMember(co, "")
	a.makeManager(a.newGroup(co, shared.ScopeSessionsEdit), runsMore, admin)
	if w := a.appoint(e2, g, runsMore.Email); !refusedBy(w, ruleTwo) {
		t.Errorf("rule 2, by what they manage: %d %s", w.Code, w.Body.String())
	}
	peer := a.newMember(co, "")
	expect(t, a.appoint(e2, g, peer.Email), http.StatusCreated, "within both rules")

	expect(t, a.appoint(as, g, admin.Email), http.StatusBadRequest, "yourself")
	expect(t, a.appoint(as, co.AdminsID, peer.Email), http.StatusConflict, "the Admins group")
	expect(t, a.appoint(as, g, peer.Email), http.StatusConflict, "twice")
	expect(t, a.appoint(as, g, "nobody-"+randSuffix(t)+"@acme.test"), http.StatusNotFound, "an unknown address")
	stranger := a.newMember(other, "")
	expect(t, a.appoint(as, g, stranger.Email), http.StatusNotFound, "another company's person, by address")
	expect(t, a.post("/api/admin/groups/"+g+"/managers", map[string]any{"user_id": stranger.ID}, bearer(as.Access)),
		http.StatusNotFound, "another company's person, by id")
	gone := a.newMember(co, "")
	a.exec(`UPDATE tbl_users SET deleted_at = now() WHERE id = $1`, gone.ID)
	expect(t, a.appoint(as, g, gone.Email), http.StatusNotFound, "a deleted person")
	expect(t, a.appoint(as, a.newGroup(other), peer.Email), http.StatusNotFound, "another company's group")
	expect(t, a.post("/api/admin/groups/"+g+"/managers", map[string]any{}, bearer(as.Access)), http.StatusBadRequest, "nobody named")

	// Nobody but an Owner acts on an Owner, a platform Admin included.
	pl := a.platform()
	owner := a.newOwner()
	if w := a.appoint(a.login(a.newAdmin(pl)), a.newGroup(pl), owner.Email); !refusedBy(w, ruleTwo) {
		t.Errorf("a platform Admin appointed an Owner: %d %s", w.Code, w.Body.String())
	}

	// Dismissing follows the same rules.
	expect(t, a.dismiss(as, g, a.newMember(co, "").ID), http.StatusNotFound, "someone who does not manage it")
	if w := a.dismiss(es, g, peer.ID); !refusedBy(w, ruleOne) {
		t.Errorf("dismissal, rule 1: %d %s", w.Code, w.Body.String())
	}
	a.makeManager(g, runsMore, admin)
	if w := a.dismiss(e2, g, runsMore.ID); !refusedBy(w, ruleTwo) {
		t.Errorf("dismissal, rule 2: %d %s", w.Code, w.Body.String())
	}
	expect(t, a.dismiss(e2, g, peer.ID), http.StatusNoContent, "dismissal within both rules")
	if n := a.count(`SELECT count(*) FROM tbl_group_managers WHERE group_id = $1`, g); n != 1 {
		t.Errorf("the group has %d managers, want 1 (runsMore)", n)
	}
}

// The Owner appoints in any company, repeating it in the target header, bound
// by neither scope rule — but the Admins group still has no managers — and the
// appointment is in both trails.
func TestTheOwnerAppointsGroupManagers(t *testing.T) {
	a := newApp(t)
	owner := a.newOwner()
	os := a.login(owner)
	co := a.newCompany()
	g := a.newGroup(co, shared.ScopeUsersEdit)
	base := "/api/owner/companies/" + co.ID + "/groups/"
	lead := a.newMember(co, "")
	a.giveExtras(lead, shared.ScopeSessionsEdit) // more than the Owner holds as scopes

	if w := a.ownerCall(os, http.MethodPost, base+g+"/managers", "", map[string]any{"email": lead.Email}); w.Code != http.StatusBadRequest {
		t.Errorf("without the target header: %d", w.Code)
	}
	expect(t, a.ownerCall(os, http.MethodPost, base+g+"/managers", co.ID, map[string]any{"email": lead.Email}),
		http.StatusCreated, "appoint")
	w := a.ownerCall(os, http.MethodGet, base+g, "", nil)
	expect(t, w, http.StatusOK, "the group's page")
	var page groupPage
	decodeInto(t, w, &page)
	if want := (managerRow{UserID: lead.ID, Email: lead.Email, AppointedByEmail: owner.Email, AppointedByOwner: true}); len(page.Managers) != 1 || page.Managers[0] != want {
		t.Errorf("managers %+v, want [%+v]", page.Managers, want)
	}
	expect(t, a.ownerCall(os, http.MethodPost, base+co.AdminsID+"/managers", co.ID, map[string]any{"email": lead.Email}),
		http.StatusConflict, "the Admins group")
	audited(t, a, a.platform().ID, "group.manager_added", map[string]string{"group_id": g, "target_client_id": co.ID})
	audited(t, a, co.ID, "group.manager_added", map[string]string{"group_id": g, "by_owner": owner.ID})
	expect(t, a.ownerCall(os, http.MethodDelete, base+g+"/managers/"+lead.ID, co.ID, nil), http.StatusNoContent, "dismiss")
	audited(t, a, co.ID, "group.manager_removed", map[string]string{"group_id": g, "by_owner": owner.ID})
}

// A manager with no scope of their own sees the groups they run and nothing
// else; they add someone, who then has the group's access, and remove them
// again. The group's page shows them the sign-in policy it carries.
func TestAManagerRunsTheirGroup(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.newAdmin(co)
	p := a.newProduct("Viewer")
	a.subscribe(co, p)
	g := a.newGroup(co, shared.ScopeSessionsRead)
	a.grantGroup(co, g, p, "Viewer")
	var policy string
	a.scalar(&policy, `SELECT id FROM stp_CreateLoginPolicy($1, $2, true, false, NULL, 50)`, co.ID, "Field "+randSuffix(t))
	a.exec(`SELECT stp_SetGroupLoginPolicy($1, $2, $3)`, g, co.ID, policy)
	a.newGroup(co, shared.ScopeUsersRead) // another group, not theirs
	lead := a.newMember(co, "")
	a.makeManager(g, lead, admin)
	ls := a.login(lead)

	w := a.get("/api/me/managed-groups", bearer(ls.Access))
	expect(t, w, http.StatusOK, "list")
	var list []struct {
		ID string `json:"id"`
	}
	decodeInto(t, w, &list)
	if len(list) != 1 || list[0].ID != g {
		t.Fatalf("the manager's list: %s", w.Body.String())
	}
	w = a.get("/api/me/managed-groups/"+g, bearer(ls.Access))
	expect(t, w, http.StatusOK, "their group")
	var page groupPage
	decodeInto(t, w, &page)
	if len(page.Members) != 0 || len(page.Managers) != 1 || page.Managers[0].UserID != lead.ID {
		t.Errorf("their group's page: %s", w.Body.String())
	}
	if page.LoginPolicyName == nil || !strings.HasPrefix(*page.LoginPolicyName, "Field ") {
		t.Errorf("login_policy_name = %v, want the group's policy", page.LoginPolicyName)
	}

	colleague := a.newMember(co, "")
	expect(t, a.managedAdd(ls, g, colleague.Email), http.StatusCreated, "add")
	var by string
	a.scalar(&by, `SELECT assigned_by FROM tbl_user_groups WHERE group_id = $1 AND user_id = $2`, g, colleague.ID)
	if by != lead.ID {
		t.Errorf("assigned_by = %q, want the manager", by)
	}
	cs := a.login(colleague)
	if scopes, _ := meOf(t, a, cs); !slices.Contains(scopes, shared.ScopeSessionsRead) {
		t.Errorf("the new member's scopes %v lack the group's", scopes)
	}
	w = a.get("/api/me/apps", bearer(cs.Access))
	if !strings.Contains(w.Body.String(), p.Key) {
		t.Errorf("the new member cannot open the group's app: %s", w.Body.String())
	}
	// Their access came from this group, so the manager can take them out again.
	expect(t, a.managedRemove(ls, g, colleague.ID), http.StatusNoContent, "remove")
	if a.isMember(g, colleague.ID) {
		t.Error("removed, yet still a member")
	}
	audited(t, a, co.ID, "group.member_added", map[string]string{"group_id": g, "user_id": colleague.ID, "by_manager": "true"})
	audited(t, a, co.ID, "group.member_removed", map[string]string{"group_id": g, "user_id": colleague.ID, "by_manager": "true"})
}

// A manager's door opens only on the groups they run, and even there never on
// themselves, their fellow managers, anyone above their reach or an Owner; it
// gives them nothing in the admin area.
func TestAManagerStaysInTheirLane(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	admin := a.newAdmin(co)
	g := a.newGroup(co, shared.ScopeSessionsRead)
	notTheirs := a.newGroup(co)
	lead, colead := a.newMember(co, ""), a.newMember(co, "")
	a.makeManager(g, lead, admin)
	a.makeManager(g, colead, admin)
	ls := a.login(lead)
	anyone := a.newMember(co, "")

	for _, gid := range []string{notTheirs, a.newGroup(other), noSuchID} {
		expect(t, a.get("/api/me/managed-groups/"+gid, bearer(ls.Access)), http.StatusNotFound, "read "+gid)
		expect(t, a.managedAdd(ls, gid, anyone.Email), http.StatusNotFound, "add to "+gid)
		expect(t, a.managedRemove(ls, gid, anyone.ID), http.StatusNotFound, "remove from "+gid)
	}
	if a.isMember(notTheirs, anyone.ID) {
		t.Fatal("SECURITY: a manager changed a group they do not manage")
	}
	// An Admin who does not manage the group has no manager's door onto it.
	as := a.login(admin)
	expect(t, a.get("/api/me/managed-groups/"+g, bearer(as.Access)), http.StatusNotFound, "an Admin, not its manager")
	if w := a.get("/api/me/managed-groups", bearer(as.Access)); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("an Admin who manages nothing lists %s", w.Body.String())
	}

	// Never themselves or a fellow manager, adding or removing.
	a.join(colead, g)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"add themselves":      a.managedAdd(ls, g, lead.Email),
		"add a co-manager":    a.managedAdd(ls, g, colead.Email),
		"remove a co-manager": a.managedRemove(ls, g, colead.ID),
	} {
		if !refusedBy(w, managersSelf) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	a.join(lead, g)
	if w := a.managedRemove(ls, g, lead.ID); !refusedBy(w, managersSelf) {
		t.Errorf("remove themselves: %d %s", w.Code, w.Body.String())
	}

	// Rule 2 by reach: someone holding more than the manager's reach is out of
	// bounds, however they came to be in the group.
	above := a.newMember(co, "")
	a.giveExtras(above, shared.ScopeUsersRead)
	if w := a.managedAdd(ls, g, above.Email); !refusedBy(w, ruleTwo) {
		t.Errorf("add someone above: %d %s", w.Code, w.Body.String())
	}
	a.join(above, g)
	if w := a.managedRemove(ls, g, above.ID); !refusedBy(w, ruleTwo) {
		t.Errorf("remove someone above: %d %s", w.Code, w.Body.String())
	}
	// Reach counts what the member could hand out as a manager themselves.
	runsMore := a.newMember(co, "")
	a.makeManager(a.newGroup(co, shared.ScopeUsersEdit), runsMore, admin)
	if w := a.managedAdd(ls, g, runsMore.Email); !refusedBy(w, ruleTwo) {
		t.Errorf("add someone who runs a group reaching further: %d %s", w.Code, w.Body.String())
	}
	// Managing a group that gives users:read brings them within reach.
	a.makeManager(a.newGroup(co, shared.ScopeUsersRead), lead, admin)
	expect(t, a.managedRemove(ls, g, above.ID), http.StatusNoContent, "within reach through another group they run")

	// Nobody but an Owner acts on an Owner — not even a manager whose group gives
	// every scope, so that reach alone would allow it.
	pl := a.platform()
	pg := a.newGroup(pl, shared.GrantableScopes()...)
	platformLead := a.newMember(pl, "")
	a.makeManager(pg, platformLead, a.newAdmin(pl))
	if w := a.managedAdd(a.login(platformLead), pg, a.newOwner().Email); !refusedBy(w, ruleTwo) {
		t.Errorf("a manager added an Owner: %d %s", w.Code, w.Body.String())
	}

	// A manager is not a groups:edit holder.
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/admin/groups"},
		{http.MethodPost, "/api/admin/groups/" + g + "/members"},
		{http.MethodPut, "/api/admin/groups/" + g + "/scopes"},
		{http.MethodPatch, "/api/admin/groups/" + g},
		{http.MethodDelete, "/api/admin/groups/" + g},
		{http.MethodPost, "/api/admin/groups/" + g + "/managers"},
	} {
		if w := a.send(r.method, r.path, map[string]any{}, bearer(ls.Access)); !refusedByGuard(w) {
			t.Errorf("%s %s answered a manager %d %s", r.method, r.path, w.Code, w.Body.String())
		}
	}

	peer := a.newMember(co, "")
	expect(t, a.managedAdd(ls, g, peer.Email), http.StatusCreated, "add")
	expect(t, a.managedAdd(ls, g, peer.Email), http.StatusConflict, "add twice")
	expect(t, a.managedRemove(ls, g, a.newMember(co, "").ID), http.StatusNotFound, "remove a non-member")
	expect(t, a.managedAdd(ls, g, "nobody-"+randSuffix(t)+"@acme.test"), http.StatusNotFound, "an unknown address")
	expect(t, a.managedAdd(ls, g, a.newMember(other, "").Email), http.StatusNotFound, "another company's person")
	expect(t, a.post("/api/me/managed-groups/"+g+"/members", map[string]any{}, bearer(ls.Access)), http.StatusBadRequest, "nobody named")
}

// Dismissal takes effect at the manager's next request, token unchanged — and
// the procedure itself refuses a manager who has been dismissed, whatever the
// API checked before.
func TestADismissedManagerIsRefusedAtOnce(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.newAdmin(co)
	g := a.newGroup(co)
	lead := a.newMember(co, "")
	a.makeManager(g, lead, admin)
	ls := a.login(lead)
	expect(t, a.get("/api/me/managed-groups/"+g, bearer(ls.Access)), http.StatusOK, "while a manager")

	expect(t, a.dismiss(a.login(admin), g, lead.ID), http.StatusNoContent, "dismiss")
	w := a.get("/api/me/managed-groups/"+g, bearer(ls.Access))
	expect(t, w, http.StatusNotFound, "the same token, after dismissal")
	if w.Header().Get(middlewares.TokenStaleHeader) != "1" {
		t.Error("the dismissed manager's token was not flagged stale")
	}
	someone := a.newMember(co, "")
	expect(t, a.managedAdd(ls, g, someone.Email), http.StatusNotFound, "add after dismissal")

	var n int
	a.scalar(&n, `SELECT stp_ManagerAddGroupMember($1, $2, $3, $4)`, lead.ID, someone.ID, g, co.ID)
	if n != -1 {
		t.Errorf("the procedure let a dismissed manager add a member: %d", n)
	}
	// And, on its own, a manager changing the membership of a manager.
	colead := a.newMember(co, "")
	a.makeManager(g, colead, admin)
	a.makeManager(g, lead, admin)
	for _, who := range []member{lead, colead} {
		a.scalar(&n, `SELECT stp_ManagerAddGroupMember($1, $2, $3, $4)`, lead.ID, who.ID, g, co.ID)
		if n != -3 {
			t.Errorf("the procedure let a manager add a manager (%s): %d", who.Email, n)
		}
	}
	a.join(colead, g)
	a.scalar(&n, `SELECT stp_ManagerRemoveGroupMember($1, $2, $3, $4)`, lead.ID, colead.ID, g, co.ID)
	if n != -3 || !a.isMember(g, colead.ID) {
		t.Errorf("the procedure let a manager remove a manager: %d", n)
	}
	expect(t, a.dismiss(a.login(admin), g, lead.ID), http.StatusNoContent, "dismiss again")
	a.join(someone, g)
	a.scalar(&n, `SELECT stp_ManagerRemoveGroupMember($1, $2, $3, $4)`, lead.ID, someone.ID, g, co.ID)
	if n != -1 || !a.isMember(g, someone.ID) {
		t.Errorf("the procedure let a dismissed manager remove a member: %d", n)
	}
}

// Rule 2 protects managers too: someone who could not run their groups cannot
// act on them — deactivate, reset, re-scope or regroup them — until they are
// dismissed.
func TestReachProtectsAGroupsManager(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.newAdmin(co)
	runs := a.newGroup(co, shared.ScopeGroupsEdit)
	lead := a.newMember(co, "") // holds no scope, but runs a group that gives groups:edit
	a.makeManager(runs, lead, admin)

	helper := a.newMember(co, "")
	a.giveExtras(helper, shared.ScopeUsersEdit)
	hs := a.login(helper)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"deactivate": a.send(http.MethodPatch, "/api/admin/users/"+lead.ID, map[string]any{"is_active": false}, bearer(hs.Access)),
		"reset":      a.post("/api/admin/users/"+lead.ID+"/password-reset", nil, bearer(hs.Access)),
		"re-scope":   a.send(http.MethodPut, "/api/admin/users/"+lead.ID+"/scopes", map[string]any{"scopes": []string{}}, bearer(hs.Access)),
	} {
		if !refusedBy(w, ruleTwo) {
			t.Errorf("%s a manager reaching further: %d %s", name, w.Code, w.Body.String())
		}
	}
	// Regrouping: groups:edit is not enough to move a manager whose group gives
	// users:read.
	lead2 := a.newMember(co, "")
	a.makeManager(a.newGroup(co, shared.ScopeUsersRead), lead2, admin)
	grouper := a.newMember(co, "")
	a.giveExtras(grouper, shared.ScopeGroupsEdit)
	if w := a.post("/api/admin/groups/"+a.newGroup(co)+"/members", map[string]any{"email": lead2.Email},
		bearer(a.login(grouper).Access)); !refusedBy(w, ruleTwo) {
		t.Errorf("regroup a manager reaching further: %d %s", w.Code, w.Body.String())
	}

	// Dismissed, they are within reach again.
	expect(t, a.dismiss(a.login(admin), runs, lead.ID), http.StatusNoContent, "dismiss")
	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+lead.ID, map[string]any{"is_active": false}, bearer(hs.Access)),
		http.StatusOK, "deactivate once dismissed")
}

// The manager's door is exactly these routes, open to anyone signed in and
// empty for anyone who manages nothing.
func TestTheManagerDoorIsExactlyTheseRoutes(t *testing.T) {
	a := newApp(t)
	want := []string{
		"GET /api/me/managed-groups",
		"GET /api/me/managed-groups/:gid",
		"POST /api/me/managed-groups/:gid/members",
		"DELETE /api/me/managed-groups/:gid/members/:uid",
	}
	var got []string
	for _, r := range a.r.Routes() {
		if strings.HasPrefix(r.Path, "/api/me/managed-groups") {
			got = append(got, r.Method+" "+r.Path)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("manager door routes %v, want %v", got, want)
	}
	for _, path := range []string{"/api/me/managed-groups", "/api/me/managed-groups/" + noSuchID} {
		expect(t, a.get(path), http.StatusUnauthorized, "signed out: "+path)
	}
}

// A manager's writes have a budget of their own, per account.
func TestTheManagerDoorWritesAreBudgeted(t *testing.T) {
	a := newAppWith(t, map[string]string{"RATE_LIMIT_GLOBAL_MAX": "100000"}, nil)
	co := a.newCompany()
	g := a.newGroup(co)
	lead := a.newMember(co, "")
	a.makeManager(g, lead, a.newAdmin(co))
	ls := a.login(lead)
	for i := 0; i < 60; i++ {
		if w := a.managedAdd(ls, g, fmt.Sprintf("probe-%d-%s@acme.test", i, randSuffix(t))); w.Code != http.StatusNotFound {
			t.Fatalf("write %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	w := a.managedRemove(ls, g, noSuchID)
	expect(t, w, http.StatusTooManyRequests, "the 61st write")
	if w.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on the refusal")
	}
	expect(t, a.get("/api/me/managed-groups/"+g, bearer(ls.Access)), http.StatusOK, "reads are not budgeted")
}
