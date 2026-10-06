package main

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/alora/auth/internal/core/shared"
)

// Admin writes racing each other. Each limit, uniqueness and last-one-standing
// rule must hold when the requests arrive at once, not just one after another:
// only a lock or a unique index — never a check followed by a write — keeps it.

func count(codes []int, status int) int {
	n := 0
	for _, c := range codes {
		if c == status {
			n++
		}
	}
	return n
}

func times(n int, do func() *httptest.ResponseRecorder) []func() *httptest.ResponseRecorder {
	out := make([]func() *httptest.ResponseRecorder, n)
	for i := range out {
		out[i] = do
	}
	return out
}

// Twelve new secrets at once for one API client: exactly two are made, since at
// most two may be live.
func TestConcurrentSecretsNeverExceedTwoLive(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	c := a.newAPIClient(s, "Racing "+randSuffix(t))
	codes := race(times(12, func() *httptest.ResponseRecorder {
		return a.post("/api/admin/api-clients/"+c.ID+"/secrets", map[string]any{}, bearer(s.Access))
	})...)
	if count(codes, http.StatusCreated) != 2 || count(codes, http.StatusConflict) != 10 {
		t.Fatalf("statuses %v, want two 201 and ten 409", codes)
	}
	if n := a.count(`SELECT count(*) FROM tbl_api_client_secrets WHERE api_client_id = $1 AND revoked_at IS NULL`, c.ID); n != 2 {
		t.Fatalf("%d live secrets, want 2", n)
	}
}

// The same person appointed to the same group ten times at once: one
// appointment, one version bump.
func TestConcurrentAppointmentsMakeOne(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	g := a.newGroup(co)
	m := a.newMember(co, "")
	_, av := versionsOf(a, m.ID)
	codes := race(times(10, func() *httptest.ResponseRecorder { return a.appoint(s, g, m.Email) })...)
	if count(codes, http.StatusCreated) != 1 || count(codes, http.StatusConflict) != 9 {
		t.Fatalf("statuses %v, want one 201 and nine 409", codes)
	}
	if n := a.count(`SELECT count(*) FROM tbl_group_managers WHERE group_id = $1`, g); n != 1 {
		t.Fatalf("%d appointments, want 1", n)
	}
	if _, av2 := versionsOf(a, m.ID); av2 != av+1 {
		t.Errorf("admin_version %d -> %d, want exactly one bump", av, av2)
	}
}

// Ten groups of one name, ten API clients of one name, ten memberships of one
// person in one group, ten invitations of one address — each made once.
func TestConcurrentDuplicatesAreMadeOnce(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	g := a.newGroup(co)
	m := a.newMember(co, "")
	name := "Same " + randSuffix(t)
	email := "twice-" + randSuffix(t) + "@acme.test"
	for _, c := range []struct {
		what  string
		do    func() *httptest.ResponseRecorder
		count func() int
	}{
		{"a group name", func() *httptest.ResponseRecorder {
			return a.post("/api/admin/groups", map[string]any{"name": name}, bearer(s.Access))
		}, func() int {
			return a.count(`SELECT count(*) FROM tbl_groups WHERE client_id = $1 AND lower(name) = lower($2)`, co.ID, name)
		}},
		{"an API client name", func() *httptest.ResponseRecorder {
			return a.post("/api/admin/api-clients", map[string]any{"name": name}, bearer(s.Access))
		}, func() int {
			return a.count(`SELECT count(*) FROM tbl_api_clients WHERE client_id = $1 AND lower(name) = lower($2)`, co.ID, name)
		}},
		{"a membership", func() *httptest.ResponseRecorder {
			return a.post("/api/admin/groups/"+g+"/members", map[string]any{"user_id": m.ID}, bearer(s.Access))
		}, func() int {
			return a.count(`SELECT count(*) FROM tbl_user_groups WHERE group_id = $1 AND user_id = $2`, g, m.ID)
		}},
		{"a pending invitation", func() *httptest.ResponseRecorder {
			return a.post("/api/admin/invitations", map[string]any{"email": email, "group_ids": []string{}}, bearer(s.Access))
		}, func() int {
			return a.count(`SELECT count(*) FROM tbl_invitations WHERE client_id = $1 AND lower(email) = lower($2) AND status = 'PENDING'`, co.ID, email)
		}},
	} {
		codes := race(times(10, c.do)...)
		if count(codes, http.StatusCreated) != 1 || count(codes, http.StatusConflict) != 9 {
			t.Errorf("%s ten times at once: statuses %v, want one 201 and nine 409", c.what, codes)
		}
		if n := c.count(); n != 1 {
			t.Errorf("SECURITY: %s ten times at once left %d rows, want 1", c.what, n)
		}
	}
}

// An invitation past its expiry, which the sweep has not yet marked, never
// blocks a new one to the address — and the address still has one live link.
func TestAnExpiredInvitationNeverBlocksANewOne(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	email := "again-" + randSuffix(t) + "@acme.test"
	invite := func() *httptest.ResponseRecorder {
		return a.post("/api/admin/invitations", map[string]any{"email": email, "group_ids": []string{}}, bearer(s.Access))
	}
	expect(t, invite(), http.StatusCreated, "the first invitation")
	expect(t, invite(), http.StatusConflict, "a second while the first is live")
	a.exec(`UPDATE tbl_invitations SET expires_at = now() - interval '1 minute' WHERE client_id = $1 AND email = $2`, co.ID, email)
	expect(t, invite(), http.StatusCreated, "a new one after the first expired")
	pending := `SELECT count(*) FROM tbl_invitations WHERE client_id = $1 AND email = $2 AND status = 'PENDING'`
	if n := a.count(pending, co.ID, email); n != 1 {
		t.Fatalf("%d pending invitations, want 1", n)
	}
	if n := a.count(`SELECT count(*) FROM tbl_invitations WHERE client_id = $1 AND email = $2 AND status = 'EXPIRED'`, co.ID, email); n != 1 {
		t.Fatalf("the expired invitation was not marked expired (%d)", n)
	}
}

// A company's last two Admins remove each other at the same moment: one
// removal wins, and the company keeps an Admin.
func TestTheLastTwoAdminsCannotRemoveEachOtherAtOnce(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	for round := 0; round < 5; round++ {
		co := a.newCompany()
		one, two := a.newAdmin(co), a.newAdmin(co)
		s1, s2 := a.login(one), a.login(two)
		codes := race(
			func() *httptest.ResponseRecorder {
				return a.send(http.MethodDelete, "/api/admin/groups/"+co.AdminsID+"/members/"+two.ID, nil, bearer(s1.Access))
			},
			func() *httptest.ResponseRecorder {
				return a.send(http.MethodDelete, "/api/admin/groups/"+co.AdminsID+"/members/"+one.ID, nil, bearer(s2.Access))
			},
		)
		if count(codes, http.StatusNoContent) != 1 || codes[0] >= 500 || codes[1] >= 500 {
			t.Errorf("round %d: statuses %v, want exactly one removal and a clean refusal", round, codes)
		}
		left := a.count(`SELECT count(*) FROM tbl_user_groups ug JOIN tbl_users u ON u.id = ug.user_id
		                 WHERE ug.group_id = $1 AND u.is_active AND u.deleted_at IS NULL`, co.AdminsID)
		if left != 1 {
			t.Fatalf("SECURITY: round %d left the company with %d active Admins", round, left)
		}
	}
}

// Eight different scope sets written to one group at once: the group ends with
// exactly one of them, never a blend.
func TestConcurrentScopeWritesEndInOneWholeSet(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	g := a.newGroup(co)
	sets := [][]string{
		{"users:read"}, {"users:edit"}, {"groups:read", "sessions:read"}, {"invitations:edit"},
		{"company:edit", "products:read"}, {"api-clients:read"}, {}, {"sessions:edit", "users:read"},
	}
	var reqs []func() *httptest.ResponseRecorder
	for _, set := range sets {
		set := set
		reqs = append(reqs, func() *httptest.ResponseRecorder {
			return a.send(http.MethodPut, "/api/admin/groups/"+g+"/scopes", map[string]any{"scopes": set}, bearer(s.Access))
		})
	}
	if codes := race(reqs...); count(codes, http.StatusOK) != len(sets) {
		t.Fatalf("statuses %v, want every write to succeed", codes)
	}
	var got struct {
		Scopes []string `json:"scopes"`
	}
	decodeInto(t, a.get("/api/admin/groups/"+g, bearer(s.Access)), &got)
	for _, set := range sets {
		want, err := shared.NormalizeScopes(set)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(want, " ") == strings.Join(got.Scopes, " ") {
			return
		}
	}
	t.Fatalf("the group ended with %v, which is none of the sets written", got.Scopes)
}

// A group deleted while members are being added to it: every request answers
// cleanly, and nothing of the group outlives it.
func TestDeletingAGroupWhileItIsBeingJoined(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	for round := 0; round < 5; round++ {
		g := a.newGroup(co, "sessions:read")
		var reqs []func() *httptest.ResponseRecorder
		for i := 0; i < 6; i++ {
			m := a.newMember(co, "")
			reqs = append(reqs, func() *httptest.ResponseRecorder {
				return a.post("/api/admin/groups/"+g+"/members", map[string]any{"user_id": m.ID}, bearer(s.Access))
			})
		}
		reqs = append(reqs, func() *httptest.ResponseRecorder {
			return a.send(http.MethodDelete, "/api/admin/groups/"+g, nil, bearer(s.Access))
		})
		for _, c := range race(reqs...) {
			if c >= 500 {
				t.Fatalf("round %d: a %d while deleting and joining at once", round, c)
			}
		}
		if n := a.count(`SELECT count(*) FROM tbl_user_groups WHERE group_id = $1`, g); n != 0 {
			t.Errorf("round %d: %d memberships outlived their group", round, n)
		}
	}
}

// The storm: six companies at once, each with its Admin working flat out —
// groups made, renamed, re-scoped, joined, left and deleted; invitations sent
// and revoked; API clients made, given secrets and switched off — with a
// cross-company attempt mixed in. Nothing answers with a server error, no list
// shows another company's things, and every company keeps its rules.
func TestAStormOfAdminWorkAcrossCompanies(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	type co struct {
		company
		s       session
		members []member
		group   string
	}
	var cos []co
	for i := 0; i < 6; i++ {
		c := a.newCompany()
		x := co{company: c, s: a.login(a.newAdmin(c)), group: a.newGroup(c)}
		for j := 0; j < 5; j++ {
			x.members = append(x.members, a.newMember(c, ""))
		}
		cos = append(cos, x)
	}
	var mu sync.Mutex
	var bad []string
	note := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if len(bad) < 40 {
			bad = append(bad, fmt.Sprintf(format, args...))
		}
	}
	var wg sync.WaitGroup
	const workers, rounds = 4, 30
	for ci := range cos {
		for wi := 0; wi < workers; wi++ {
			wg.Add(1)
			go func(me co, other co, seed uint64) {
				defer wg.Done()
				r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
				auth := bearer(me.s.Access)
				groups := []string{me.group}
				for i := 0; i < rounds; i++ {
					var w *httptest.ResponseRecorder
					var what string
					pick := groups[r.IntN(len(groups))]
					m := me.members[r.IntN(len(me.members))]
					switch r.IntN(12) {
					case 0:
						what = "create a group"
						w = a.post("/api/admin/groups", map[string]any{"name": "Storm " + randSuffixN(8)}, auth)
						if w.Code == http.StatusCreated {
							groups = append(groups, jsonField(w, "id"))
						}
					case 1:
						what = "rename a group"
						w = a.send(http.MethodPatch, "/api/admin/groups/"+pick, map[string]any{"name": "Renamed " + randSuffixN(8), "description": ""}, auth)
					case 2:
						what = "re-scope a group"
						w = a.send(http.MethodPut, "/api/admin/groups/"+pick+"/scopes", map[string]any{"scopes": []string{"sessions:read"}}, auth)
					case 3:
						what = "add a member"
						w = a.post("/api/admin/groups/"+pick+"/members", map[string]any{"user_id": m.ID}, auth)
					case 4:
						what = "remove a member"
						w = a.send(http.MethodDelete, "/api/admin/groups/"+pick+"/members/"+m.ID, nil, auth)
					case 5:
						what = "delete a group"
						if pick != me.group {
							w = a.send(http.MethodDelete, "/api/admin/groups/"+pick, nil, auth)
						}
					case 6:
						what = "invite and revoke"
						w = a.post("/api/admin/invitations", map[string]any{"email": "storm-" + randSuffixN(10) + "@acme.test", "group_ids": []string{}}, auth)
					case 7:
						what = "an API client and a secret"
						w = a.post("/api/admin/api-clients", map[string]any{"name": "Storm " + randSuffixN(8)}, auth)
						if w.Code == http.StatusCreated {
							w = a.post("/api/admin/api-clients/"+jsonField(w, "id")+"/secrets", map[string]any{}, auth)
						}
					case 8:
						what = "list users"
						w = a.get("/api/admin/users", auth)
					case 9:
						what = "list groups"
						w = a.get("/api/admin/groups", auth)
					case 10:
						what = "read another company's group"
						w = a.get("/api/admin/groups/"+other.group, auth)
						if w.Code != http.StatusNotFound {
							note("SECURITY: %s: %d", what, w.Code)
						}
					case 11:
						what = "who am I"
						w = a.get("/api/me", auth)
					}
					if w == nil {
						continue
					}
					if w.Code >= 500 {
						note("%s in %s: %d %s", what, me.ID, w.Code, clip(w.Body.String()))
					}
					if w.Code == http.StatusOK && strings.HasPrefix(what, "list") {
						body := w.Body.String()
						for _, x := range other.members {
							if strings.Contains(body, x.ID) {
								note("SECURITY: %s shows another company's member", what)
							}
						}
						if strings.Contains(body, other.group) {
							note("SECURITY: %s shows another company's group", what)
						}
					}
				}
			}(cos[ci], cos[(ci+1)%len(cos)], uint64(ci*100+wi+1))
		}
	}
	wg.Wait()
	for _, b := range bad {
		t.Error(b)
	}
	// Every company keeps its rules.
	for _, c := range cos {
		if n := a.count(`SELECT count(*) FROM tbl_user_groups ug JOIN tbl_users u ON u.id = ug.user_id
		                 WHERE ug.group_id = $1 AND u.is_active`, c.AdminsID); n < 1 {
			t.Errorf("SECURITY: a company was left with no active Admin")
		}
		if n := a.count(`SELECT count(*) FROM (SELECT api_client_id FROM tbl_api_client_secrets
		                 WHERE client_id = $1 AND revoked_at IS NULL GROUP BY api_client_id HAVING count(*) > 2) x`, c.ID); n != 0 {
			t.Errorf("%d API clients hold more than two live secrets", n)
		}
		var listed []struct {
			ID          string `json:"id"`
			MemberCount int    `json:"member_count"`
		}
		decodeInto(t, a.get("/api/admin/groups", bearer(c.s.Access)), &listed)
		for _, g := range listed {
			actual := a.count(`SELECT count(*) FROM tbl_user_groups ug JOIN tbl_users u ON u.id = ug.user_id
			                   WHERE ug.group_id = $1 AND u.deleted_at IS NULL`, g.ID)
			if actual != g.MemberCount {
				t.Errorf("group %s lists %d members but has %d", g.ID, g.MemberCount, actual)
			}
		}
	}
	if n := a.count(`SELECT count(*) FROM tbl_group_managers gm JOIN tbl_groups g ON g.id = gm.group_id WHERE g.system_key IS NOT NULL`); n != 0 {
		t.Errorf("SECURITY: %d managers on a system group", n)
	}
}
