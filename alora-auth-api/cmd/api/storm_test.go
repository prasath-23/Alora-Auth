package main

// A storm of everyone's work at once, across many companies. Admins change
// groups, scopes, people, invitations and API clients; group managers run their
// groups; members sign in, renew and look around while their Admin deactivates
// and reactivates them; API clients take tokens while their secrets are rotated;
// and everyone reaches for another company's things. Nothing answers with a
// server error, nothing crosses a company, and afterwards every company's rules
// hold — above all, nobody deactivated keeps a session that works.

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type stormCompany struct {
	co        company
	adminM    member
	admin     session
	manager   member
	mgr       session
	managed   string
	members   []member
	appID     string
	appSecret string
	product   product
}

func TestAStormOfEveryonesWorkAcrossManyCompanies(t *testing.T) {
	if testing.Short() {
		t.Skip("the storm takes a while")
	}
	a := newAppWith(t, hostileEnv, nil)
	const companies, people, rounds = 12, 8, 60
	var world []*stormCompany
	for i := 0; i < companies; i++ {
		co := a.newCompany()
		adminM := a.newAdmin(co)
		s := &stormCompany{co: co, adminM: adminM, admin: a.login(adminM), managed: a.newGroup(co), manager: a.newMember(co, "")}
		a.makeManager(s.managed, s.manager, adminM)
		s.mgr = a.login(s.manager)
		for j := 0; j < people; j++ {
			s.members = append(s.members, a.newMember(co, ""))
		}
		s.product = a.newProduct()
		a.subscribe(co, s.product)
		a.acceptAPIClients(s.product, true)
		c := a.newAPIClient(s.admin, "Storm app "+randSuffix(t))
		expect(t, a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/products", map[string]any{"product_ids": []string{s.product.ID}},
			bearer(s.admin.Access)), http.StatusOK, "products")
		expect(t, a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/scopes", map[string]any{"scopes": []string{"api:read"}},
			bearer(s.admin.Access)), http.StatusOK, "scopes")
		sec, code := a.newSecret(s.admin, c.ID, nil)
		if code != http.StatusCreated {
			t.Fatalf("secret: %d", code)
		}
		s.appID, s.appSecret = c.ID, sec.ClientSecret
		world = append(world, s)
	}

	var mu sync.Mutex
	var bad []string
	sent := 0
	note := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if len(bad) < 60 {
			bad = append(bad, fmt.Sprintf(format, args...))
		}
	}
	// Every session a member ever held, to try once the storm is over.
	cookies := map[string][]*http.Cookie{}
	keep := func(userID string, ck *http.Cookie) {
		mu.Lock()
		defer mu.Unlock()
		cookies[userID] = append(cookies[userID], ck)
	}
	judge := func(who, what string, w *httptest.ResponseRecorder, want ...int) {
		mu.Lock()
		sent++
		mu.Unlock()
		if w == nil {
			return
		}
		if w.Code >= 500 {
			note("%s: %s: %d %s", who, what, w.Code, clip(w.Body.String()))
			return
		}
		if len(want) > 0 {
			for _, c := range want {
				if w.Code == c {
					return
				}
			}
			note("%s: %s: %d, want one of %v (%s)", who, what, w.Code, want, clip(w.Body.String()))
		}
	}

	var wg sync.WaitGroup
	for ci, me := range world {
		other := world[(ci+1)%len(world)]
		run := func(role string, seed uint64, step func(r *rand.Rand)) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
				for i := 0; i < rounds; i++ {
					step(r)
				}
			}()
		}
		seed := uint64(ci*10 + 1)
		// Two Admins' worth of work on the one company, at once.
		for k := 0; k < 2; k++ {
			groups := []string{me.managed}
			var secrets []string
			run("admin", seed+uint64(k), func(r *rand.Rand) {
				auth := bearer(me.admin.Access)
				m := me.members[r.IntN(len(me.members))]
				pick := groups[r.IntN(len(groups))]
				switch r.IntN(11) {
				case 0:
					w := a.post("/api/admin/groups", map[string]any{"name": "Storm " + randSuffixN(8)}, auth)
					judge("admin", "create a group", w, http.StatusCreated)
					if w.Code == http.StatusCreated {
						groups = append(groups, jsonField(w, "id"))
					}
				case 1:
					judge("admin", "re-scope a group", a.send(http.MethodPut, "/api/admin/groups/"+pick+"/scopes",
						map[string]any{"scopes": [][]string{{}, {"sessions:read"}, {"users:read"}}[r.IntN(3)]}, auth),
						http.StatusOK, http.StatusNotFound)
				case 2:
					judge("admin", "add a member", a.post("/api/admin/groups/"+pick+"/members", map[string]any{"user_id": m.ID}, auth),
						http.StatusCreated, http.StatusNoContent, http.StatusOK, http.StatusConflict, http.StatusNotFound)
				case 3:
					judge("admin", "remove a member", a.send(http.MethodDelete, "/api/admin/groups/"+pick+"/members/"+m.ID, nil, auth),
						http.StatusNoContent, http.StatusNotFound)
				case 4:
					if pick != me.managed {
						judge("admin", "delete a group", a.send(http.MethodDelete, "/api/admin/groups/"+pick, nil, auth),
							http.StatusNoContent, http.StatusNotFound)
					}
				case 5, 6:
					judge("admin", "deactivate or reactivate", a.send(http.MethodPatch, "/api/admin/users/"+m.ID,
						map[string]any{"is_active": r.IntN(2) == 0}, auth), http.StatusOK, http.StatusNoContent)
				case 7:
					email := fmt.Sprintf("storm-%d@%s.test", r.IntN(4), strings.ToLower(me.co.ID[:8]))
					judge("admin", "invite", a.post("/api/admin/invitations", map[string]any{"email": email, "group_ids": []string{}}, auth),
						http.StatusCreated, http.StatusConflict)
				case 8:
					w := a.post("/api/admin/api-clients/"+me.appID+"/secrets", map[string]any{}, auth)
					judge("admin", "a new secret", w, http.StatusCreated, http.StatusConflict)
					if w.Code == http.StatusCreated {
						secrets = append(secrets, jsonField(w, "id"))
					}
				case 9:
					if len(secrets) > 0 {
						judge("admin", "revoke a secret", a.send(http.MethodDelete, "/api/admin/api-clients/"+me.appID+"/secrets/"+secrets[0], nil, auth),
							http.StatusNoContent, http.StatusNotFound)
						secrets = secrets[1:]
					}
				case 10:
					judge("admin", "another company's user", a.get("/api/admin/users/"+other.members[0].ID, auth), http.StatusNotFound)
				}
			})
		}
		// The manager runs their group, and only it.
		run("manager", seed+3, func(r *rand.Rand) {
			auth := bearer(me.mgr.Access)
			m := me.members[r.IntN(len(me.members))]
			switch r.IntN(4) {
			case 0:
				judge("manager", "add to the group", a.post("/api/me/managed-groups/"+me.managed+"/members", map[string]any{"user_id": m.ID}, auth),
					http.StatusCreated, http.StatusNoContent, http.StatusOK, http.StatusConflict, http.StatusNotFound, http.StatusForbidden)
			case 1:
				judge("manager", "remove from the group", a.send(http.MethodDelete, "/api/me/managed-groups/"+me.managed+"/members/"+m.ID, nil, auth),
					http.StatusNoContent, http.StatusNotFound, http.StatusForbidden)
			case 2:
				judge("manager", "another company's group", a.post("/api/me/managed-groups/"+other.managed+"/members",
					map[string]any{"user_id": other.members[0].ID}, auth), http.StatusNotFound)
			case 3:
				judge("manager", "the Admin door", a.get("/api/admin/users", auth), http.StatusForbidden)
			}
		})
		// Members sign in, renew and look around, while their Admin works on them.
		run("member", seed+4, func(r *rand.Rand) {
			m := me.members[r.IntN(len(me.members))]
			w := a.post("/auth/login/password", map[string]any{"email": m.Email, "password": m.Password})
			judge("member", "sign in", w, http.StatusOK, http.StatusUnauthorized, http.StatusForbidden)
			if w.Code != http.StatusOK || jsonField(w, "status") != "authenticated" {
				return
			}
			ck := cookieNamed(w, centralCookie)
			keep(m.ID, ck)
			access := jsonField(w, "access_token")
			judge("member", "who am I", a.get("/api/me", bearer(access)), http.StatusOK, http.StatusUnauthorized, http.StatusForbidden)
			// The storm's Admins may give one of the member's groups users:read,
			// so the list may open — but only ever on their own company.
			lw := a.get("/api/admin/users", bearer(access))
			judge("member", "the Admin door", lw, http.StatusOK, http.StatusForbidden, http.StatusUnauthorized)
			if lw.Code == http.StatusOK {
				for _, x := range other.members {
					if strings.Contains(lw.Body.String(), x.ID) {
						note("SECURITY: a member's user list shows another company's member")
					}
				}
			}
			rw := a.post("/auth/central/refresh", nil, withCookie(ck))
			judge("member", "renew", rw, http.StatusOK, http.StatusUnauthorized, http.StatusForbidden)
			if rw.Code == http.StatusOK {
				keep(m.ID, cookieNamed(rw, centralCookie))
			}
		})
		// The API client takes tokens while its secrets change.
		run("application", seed+5, func(r *rand.Rand) {
			form := url.Values{"grant_type": {"client_credentials"}, "resource": {"product:" + me.product.Key}}
			judge("application", "a token", a.post("/oauth/token", form, basic(me.appID, me.appSecret)), http.StatusOK)
			judge("application", "another company's product", a.post("/oauth/token",
				url.Values{"grant_type": {"client_credentials"}, "resource": {"product:" + other.product.Key}}, basic(me.appID, me.appSecret)),
				http.StatusBadRequest)
		})
	}
	wg.Wait()
	for _, b := range bad {
		t.Error(b)
	}
	t.Logf("%d requests in the storm", sent)

	// Nobody deactivated keeps a session that works — whatever raced what.
	for _, s := range world {
		for _, m := range s.members {
			var active bool
			a.scalar(&active, `SELECT is_active FROM tbl_users WHERE id = $1`, m.ID)
			if active {
				continue
			}
			for _, ck := range cookies[m.ID] {
				if w := a.post("/auth/central/refresh", nil, withCookie(ck)); w.Code == http.StatusOK {
					t.Errorf("SECURITY: %s is deactivated, but a session of theirs still renews", m.Email)
					break
				}
			}
		}
	}
	// Every company keeps its rules.
	for _, s := range world {
		if n := a.count(`SELECT count(*) FROM tbl_user_groups ug JOIN tbl_users u ON u.id = ug.user_id
		                 WHERE ug.group_id = $1 AND u.is_active`, s.co.AdminsID); n < 1 {
			t.Errorf("SECURITY: a company was left with no active Admin")
		}
		if n := a.count(`SELECT count(*) FROM tbl_api_client_secrets WHERE api_client_id = $1 AND revoked_at IS NULL`, s.appID); n > 2 {
			t.Errorf("an API client holds %d live secrets", n)
		}
		if n := a.count(`SELECT count(*) FROM (SELECT lower(email) FROM tbl_invitations WHERE client_id = $1 AND status = 'PENDING'
		                 GROUP BY lower(email) HAVING count(*) > 1) x`, s.co.ID); n != 0 {
			t.Errorf("%d addresses hold more than one pending invitation", n)
		}
		var listed []struct {
			ID          string `json:"id"`
			MemberCount int    `json:"member_count"`
		}
		decodeInto(t, a.get("/api/admin/groups", bearer(s.admin.Access)), &listed)
		for _, g := range listed {
			actual := a.count(`SELECT count(*) FROM tbl_user_groups ug JOIN tbl_users u ON u.id = ug.user_id
			                   WHERE ug.group_id = $1 AND u.deleted_at IS NULL`, g.ID)
			if actual != g.MemberCount {
				t.Errorf("group %s lists %d members but has %d", g.ID, g.MemberCount, actual)
			}
		}
	}
	for what, q := range map[string]string{
		"a membership across companies": `SELECT count(*) FROM tbl_user_groups ug JOIN tbl_users u ON u.id = ug.user_id
		                                  JOIN tbl_groups g ON g.id = ug.group_id WHERE u.client_id <> g.client_id`,
		"a manager across companies": `SELECT count(*) FROM tbl_group_managers gm JOIN tbl_users u ON u.id = gm.user_id
		                               JOIN tbl_groups g ON g.id = gm.group_id WHERE u.client_id <> g.client_id`,
		"a manager of a system group": `SELECT count(*) FROM tbl_group_managers gm JOIN tbl_groups g ON g.id = gm.group_id
		                                WHERE g.system_key IS NOT NULL`,
		"an audit row naming another company's actor": `SELECT count(*) FROM tbl_audit_logs l JOIN tbl_users u ON u.id = l.actor_user_id
		                                                 WHERE u.client_id <> l.client_id`,
	} {
		if n := a.count(q); n != 0 {
			t.Errorf("SECURITY: %d rows of %s", n, what)
		}
	}
}
