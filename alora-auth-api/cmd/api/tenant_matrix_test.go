package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// Every company against every other. Each company's Admin — and the Owner,
// through each company's door — aims every route that takes an id at the ids of
// every other company: users, groups, members, managers, invitations, sessions,
// API clients and their secrets, login policies, SSO connections and products.
// Every attempt is refused as if the thing did not exist, and afterwards every
// company's rows are exactly as they were.

// tenant is one company with one of everything a route can name.
type tenant struct {
	name             string
	co               company
	admin, target    member
	manager          member
	as               session // the Admin's session; empty for a suspended company
	sessionID        string  // the target's session
	group, managed   string
	invitation       string
	client, secretID string
	exclusive        product // a product only this company subscribes to
	policy, sso      string
	suspended        bool
}

func (a *app) newTenant(owner session, co company, name string, shared product, suspended bool) tenant {
	a.t.Helper()
	admin, other, target, manager := a.newAdmin(co), a.newAdmin(co), a.newMember(co, ""), a.newMember(co, "")
	tn := tenant{name: name, co: co, admin: admin, target: target, manager: manager, suspended: suspended}
	as := a.login(admin)
	ts := a.login(target)
	tn.sessionID = sessionID(a.t, ts.Access)
	tn.group = a.newGroup(co, "sessions:read")
	a.join(target, tn.group)
	tn.managed = a.newGroup(co)
	a.makeManager(tn.managed, manager, other)
	a.join(target, tn.managed)
	email, _ := a.invite(as, tn.group)
	var invitations []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	decodeInto(a.t, a.get("/api/admin/invitations", bearer(as.Access)), &invitations)
	for _, i := range invitations {
		if i.Email == email {
			tn.invitation = i.ID
		}
	}
	tn.exclusive = a.newProduct("Viewer")
	a.subscribe(co, tn.exclusive)
	a.acceptAPIClients(tn.exclusive, true)
	a.subscribe(co, shared)
	a.grant(target, shared, "Viewer")
	c := a.newAPIClient(as, "Matrix "+randSuffix(a.t))
	tn.client = c.ID
	sec, code := a.newSecret(as, c.ID, nil)
	if code != http.StatusCreated {
		a.t.Fatalf("%s secret: %d", name, code)
	}
	tn.secretID = sec.ID
	// Priorities are unique per company, and the platform company outlives a
	// run: take the next free one.
	var priority int
	a.scalar(&priority, `SELECT coalesce(max(priority), 0) + 1 FROM tbl_login_policies WHERE client_id = $1`, co.ID)
	res := a.ownerCall(owner, http.MethodPost, "/api/owner/companies/"+co.ID+"/login-policies", co.ID,
		map[string]any{"name": "Matrix " + randSuffix(a.t), "allow_password": true, "allow_google": false, "priority": priority})
	expect(a.t, res, http.StatusCreated, name+" policy")
	tn.policy = jsonField(res, "id")
	res = a.ownerCall(owner, http.MethodPost, "/api/owner/companies/"+co.ID+"/sso-connections", co.ID,
		map[string]any{"name": "Matrix " + randSuffix(a.t), "issuer": "https://sso.invalid", "client_id": "matrix-" + randSuffix(a.t),
			"client_secret": "s", "is_active": true})
	expect(a.t, res, http.StatusCreated, name+" SSO connection")
	tn.sso = jsonField(res, "id")
	if suspended {
		expect(a.t, a.ownerCall(owner, http.MethodPatch, "/api/owner/companies/"+co.ID, co.ID, map[string]any{"is_active": false}),
			http.StatusOK, "suspend "+name)
	} else {
		tn.as = as
	}
	return tn
}

// fingerprint is a digest of every row a company owns — every table with a
// client_id, and the company itself — except its audit trail, which is written
// asynchronously: table by table, so a change names where it happened. Equal
// fingerprints mean nothing of the company changed.
func (a *app) fingerprint(companyID string) map[string]string {
	a.t.Helper()
	ctx := context.Background()
	rows, err := a.pool.Query(ctx, `SELECT table_name FROM information_schema.columns
	                                WHERE table_schema = 'public' AND column_name = 'client_id'
	                                  AND table_name LIKE 'tbl\_%' AND table_name <> 'tbl_audit_logs'
	                                ORDER BY table_name`)
	if err != nil {
		a.t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			a.t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	out := map[string]string{}
	for _, tbl := range tables {
		var digest string
		a.scalar(&digest, fmt.Sprintf(`SELECT coalesce(md5(string_agg(x::text, ',' ORDER BY x::text)), '-')
		                              FROM %s x WHERE x.client_id = $1`, tbl), companyID)
		out[tbl] = digest
	}
	var self string
	a.scalar(&self, `SELECT md5(x::text) FROM tbl_clients x WHERE x.id = $1`, companyID)
	out["tbl_clients (the company)"] = self
	return out
}

// changedTables lists the tables whose rows differ between two fingerprints.
func changedTables(before, after map[string]string) []string {
	var out []string
	for tbl, d := range after {
		if before[tbl] != d {
			out = append(out, tbl)
		}
	}
	sort.Strings(out)
	return out
}

// attempt is one request aimed across companies, and what must answer it.
type attempt struct {
	what   string
	method string
	path   string
	body   any
	want   int // 404 for a foreign id in the path; 400 for one in the body; 409 for a product the company lacks
}

// adminAttempts is everything A's Admin can aim at B through /api/admin.
func adminAttempts(A, B tenant) []attempt {
	email := "matrix-" + randSuffixN(8) + "@acme.test"
	return []attempt{
		{"read B's user", "GET", "/api/admin/users/" + B.target.ID, nil, 404},
		{"deactivate B's user", "PATCH", "/api/admin/users/" + B.target.ID, map[string]any{"is_active": false}, 404},
		{"give B's user scopes", "PUT", "/api/admin/users/" + B.target.ID + "/scopes", map[string]any{"scopes": []string{"sessions:read"}}, 404},
		{"reset B's user", "POST", "/api/admin/users/" + B.target.ID + "/password-reset", nil, 404},
		{"revoke B's invitation", "DELETE", "/api/admin/invitations/" + B.invitation, nil, 404},
		{"invite into B's group", "POST", "/api/admin/invitations", map[string]any{"email": email, "group_ids": []string{B.group}}, 400},
		{"read B's group", "GET", "/api/admin/groups/" + B.group, nil, 404},
		{"rename B's group", "PATCH", "/api/admin/groups/" + B.group, map[string]any{"name": "Hijacked", "description": ""}, 404},
		{"delete B's group", "DELETE", "/api/admin/groups/" + B.group, nil, 404},
		{"re-scope B's group", "PUT", "/api/admin/groups/" + B.group + "/scopes", map[string]any{"scopes": []string{"users:edit"}}, 404},
		{"put A's user in B's group", "POST", "/api/admin/groups/" + B.group + "/members", map[string]any{"user_id": A.target.ID}, 404},
		{"pull B's user into A's group", "POST", "/api/admin/groups/" + A.group + "/members", map[string]any{"user_id": B.target.ID}, 404},
		{"pull B's user in by address", "POST", "/api/admin/groups/" + A.group + "/members", map[string]any{"email": B.target.Email}, 404},
		{"remove B's member", "DELETE", "/api/admin/groups/" + B.group + "/members/" + B.target.ID, nil, 404},
		{"remove B's user from A's group", "DELETE", "/api/admin/groups/" + A.group + "/members/" + B.target.ID, nil, 404},
		{"appoint in B's group", "POST", "/api/admin/groups/" + B.group + "/managers", map[string]any{"user_id": A.target.ID}, 404},
		{"appoint B's user in A's group", "POST", "/api/admin/groups/" + A.group + "/managers", map[string]any{"user_id": B.target.ID}, 404},
		{"appoint B's user by address", "POST", "/api/admin/groups/" + A.group + "/managers", map[string]any{"email": B.target.Email}, 404},
		{"dismiss B's manager", "DELETE", "/api/admin/groups/" + B.managed + "/managers/" + B.manager.ID, nil, 404},
		{"revoke B's session", "DELETE", "/api/admin/sessions/" + B.sessionID, nil, 404},
		{"read B's API client", "GET", "/api/admin/api-clients/" + B.client, nil, 404},
		{"switch off B's API client", "PATCH", "/api/admin/api-clients/" + B.client, map[string]any{"name": "Hijacked", "is_active": false}, 404},
		{"delete B's API client", "DELETE", "/api/admin/api-clients/" + B.client, nil, 404},
		{"re-scope B's API client", "PUT", "/api/admin/api-clients/" + B.client + "/scopes", map[string]any{"scopes": []string{"api:edit"}}, 404},
		{"empty B's API client's products", "PUT", "/api/admin/api-clients/" + B.client + "/products", map[string]any{"product_ids": []string{}}, 404},
		{"make B's API client a secret", "POST", "/api/admin/api-clients/" + B.client + "/secrets", map[string]any{}, 404},
		{"revoke B's secret", "DELETE", "/api/admin/api-clients/" + B.client + "/secrets/" + B.secretID, nil, 404},
		{"revoke B's secret through A's client", "DELETE", "/api/admin/api-clients/" + A.client + "/secrets/" + B.secretID, nil, 404},
		{"put B's product on A's client", "PUT", "/api/admin/api-clients/" + A.client + "/products", map[string]any{"product_ids": []string{B.exclusive.ID}}, 400},
	}
}

// ownerAttempts is everything the Owner, acting on A, can aim at B's ids.
func ownerAttempts(A, B tenant) []attempt {
	base := "/api/owner/companies/" + A.co.ID
	email := "matrix-" + randSuffixN(8) + "@acme.test"
	return []attempt{
		{"read B's user", "GET", base + "/users/" + B.target.ID, nil, 404},
		{"deactivate B's user", "PATCH", base + "/users/" + B.target.ID, map[string]any{"is_active": false}, 404},
		{"give B's user scopes", "PUT", base + "/users/" + B.target.ID + "/scopes", map[string]any{"scopes": []string{"users:edit"}}, 404},
		{"reset B's user", "POST", base + "/users/" + B.target.ID + "/password-reset", nil, 404},
		{"give B's user A's policy", "PUT", base + "/users/" + B.target.ID + "/login-policy", map[string]any{"policy_id": A.policy}, 404},
		{"give A's user B's policy", "PUT", base + "/users/" + A.target.ID + "/login-policy", map[string]any{"policy_id": B.policy}, 400},
		{"grant B's user a product", "PUT", base + "/users/" + B.target.ID + "/grants/" + A.exclusive.ID, map[string]any{"role_name": "Viewer"}, 404},
		{"grant A's user B's product", "PUT", base + "/users/" + A.target.ID + "/grants/" + B.exclusive.ID, map[string]any{"role_name": "Viewer"}, 409},
		{"revoke B's user's grant", "DELETE", base + "/users/" + B.target.ID + "/grants/" + B.exclusive.ID, nil, 404},
		{"revoke B's invitation", "DELETE", base + "/invitations/" + B.invitation, nil, 404},
		{"invite into B's group", "POST", base + "/invitations", map[string]any{"email": email, "group_ids": []string{B.group}}, 400},
		{"read B's group", "GET", base + "/groups/" + B.group, nil, 404},
		{"rename B's group", "PATCH", base + "/groups/" + B.group, map[string]any{"name": "Hijacked", "description": ""}, 404},
		{"delete B's group", "DELETE", base + "/groups/" + B.group, nil, 404},
		{"re-scope B's group", "PUT", base + "/groups/" + B.group + "/scopes", map[string]any{"scopes": []string{"users:edit"}}, 404},
		{"give B's group products", "PUT", base + "/groups/" + B.group + "/product-grants",
			map[string]any{"product_grants": []any{map[string]any{"product_id": A.exclusive.ID, "role_name": "Viewer"}}}, 404},
		{"give A's group B's product", "PUT", base + "/groups/" + A.group + "/product-grants",
			map[string]any{"product_grants": []any{map[string]any{"product_id": B.exclusive.ID, "role_name": "Viewer"}}}, 400},
		{"give B's group A's policy", "PUT", base + "/groups/" + B.group + "/login-policy", map[string]any{"policy_id": A.policy}, 404},
		{"give A's group B's policy", "PUT", base + "/groups/" + A.group + "/login-policy", map[string]any{"policy_id": B.policy}, 400},
		{"put A's user in B's group", "POST", base + "/groups/" + B.group + "/members", map[string]any{"user_id": A.target.ID}, 404},
		{"pull B's user into A's group", "POST", base + "/groups/" + A.group + "/members", map[string]any{"user_id": B.target.ID}, 404},
		{"remove B's member", "DELETE", base + "/groups/" + B.group + "/members/" + B.target.ID, nil, 404},
		{"appoint in B's group", "POST", base + "/groups/" + B.group + "/managers", map[string]any{"user_id": A.target.ID}, 404},
		{"appoint B's user in A's group", "POST", base + "/groups/" + A.group + "/managers", map[string]any{"user_id": B.target.ID}, 404},
		{"dismiss B's manager", "DELETE", base + "/groups/" + B.managed + "/managers/" + B.manager.ID, nil, 404},
		{"edit B's policy", "PATCH", base + "/login-policies/" + B.policy,
			map[string]any{"name": "Hijacked", "allow_password": false, "allow_google": true, "priority": 11}, 404},
		{"delete B's policy", "DELETE", base + "/login-policies/" + B.policy, nil, 404},
		{"make B's policy the default", "PUT", base + "/login-policies/" + B.policy + "/default", nil, 404},
		{"a policy on B's connection", "POST", base + "/login-policies",
			map[string]any{"name": "Cross " + randSuffixN(6), "allow_password": false, "allow_google": false, "sso_connection_id": B.sso, "priority": 12}, 400},
		{"edit B's connection", "PATCH", base + "/sso-connections/" + B.sso,
			map[string]any{"name": "Hijacked", "issuer": "https://evil.invalid", "client_id": "x", "is_active": true}, 404},
		{"claim domains on B's connection", "PUT", base + "/sso-connections/" + B.sso + "/domains", map[string]any{"domains": []string{"evil.test"}}, 404},
		{"test B's connection", "POST", base + "/sso-connections/" + B.sso + "/test", nil, 404},
		{"read B's API client", "GET", base + "/api-clients/" + B.client, nil, 404},
		{"switch off B's API client", "PATCH", base + "/api-clients/" + B.client, map[string]any{"name": "Hijacked", "is_active": false}, 404},
		{"delete B's API client", "DELETE", base + "/api-clients/" + B.client, nil, 404},
		{"re-scope B's API client", "PUT", base + "/api-clients/" + B.client + "/scopes", map[string]any{"scopes": []string{"api:edit"}}, 404},
		{"empty B's API client's products", "PUT", base + "/api-clients/" + B.client + "/products", map[string]any{"product_ids": []string{}}, 404},
		{"make B's API client a secret", "POST", base + "/api-clients/" + B.client + "/secrets", map[string]any{}, 404},
		{"revoke B's secret", "DELETE", base + "/api-clients/" + B.client + "/secrets/" + B.secretID, nil, 404},
		{"revoke B's secret through A's client", "DELETE", base + "/api-clients/" + A.client + "/secrets/" + B.secretID, nil, 404},
		{"put B's product on A's client", "PUT", base + "/api-clients/" + A.client + "/products", map[string]any{"product_ids": []string{B.exclusive.ID}}, 400},
	}
}

func TestEveryCompanyIsSealedFromEveryOther(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	owner := a.login(a.newOwner())
	shared := a.newProduct("Viewer")
	var world []tenant
	for i := 1; i <= 4; i++ {
		world = append(world, a.newTenant(owner, a.newCompany(), fmt.Sprintf("company %d", i), shared, false))
	}
	world = append(world, a.newTenant(owner, a.platform(), "the platform company", shared, false))
	world = append(world, a.newTenant(owner, a.newCompany(), "a suspended company", shared, true))

	// Positive controls: every Admin reaches their own company's things, so a
	// refusal below is the boundary, not a broken route.
	for _, A := range world {
		if A.suspended {
			continue
		}
		for _, path := range []string{"/api/admin/users/" + A.target.ID, "/api/admin/groups/" + A.group, "/api/admin/api-clients/" + A.client} {
			expect(t, a.get(path, bearer(A.as.Access)), http.StatusOK, A.name+" reads its own "+path)
		}
		expect(t, a.ownerCall(owner, http.MethodGet, "/api/owner/companies/"+A.co.ID+"/groups/"+A.group, "", nil), http.StatusOK,
			"the Owner reads "+A.name+"'s group through its door")
	}

	// Every session the loop uses exists before the snapshot: a sign-in writes
	// session rows, and those would read as a change.
	managers := map[string]session{}
	for _, tn := range world {
		if !tn.suspended {
			managers[tn.co.ID] = a.login(tn.manager)
		}
	}
	before := map[string]map[string]string{}
	for _, tn := range world {
		before[tn.co.ID] = a.fingerprint(tn.co.ID)
	}

	sent := 0
	var wrong []string
	judge := func(who string, at attempt, w *httptest.ResponseRecorder) {
		sent++
		if w.Code != at.want {
			wrong = append(wrong, fmt.Sprintf("%s: %s (%s %s): %d %s, want %d", who, at.what, at.method, at.path, w.Code, clip(w.Body.String()), at.want))
		}
	}
	for _, A := range world {
		for _, B := range world {
			if A.co.ID == B.co.ID {
				continue
			}
			if !A.suspended {
				for _, at := range adminAttempts(A, B) {
					judge(A.name+"'s Admin → "+B.name, at, a.send(at.method, at.path, at.body, bearer(A.as.Access)))
				}
				// A's group manager has no door onto B's groups.
				ms := managers[A.co.ID]
				for _, at := range []attempt{
					{"read B's managed group", "GET", "/api/me/managed-groups/" + B.managed, nil, 404},
					{"add to B's managed group", "POST", "/api/me/managed-groups/" + B.managed + "/members", map[string]any{"user_id": A.target.ID}, 404},
					{"remove from B's managed group", "DELETE", "/api/me/managed-groups/" + B.managed + "/members/" + B.target.ID, nil, 404},
					{"add B's user to A's managed group", "POST", "/api/me/managed-groups/" + A.managed + "/members", map[string]any{"user_id": B.target.ID}, 404},
				} {
					judge(A.name+"'s manager → "+B.name, at, a.send(at.method, at.path, at.body, bearer(ms.Access)))
				}
			}
			for _, at := range ownerAttempts(A, B) {
				judge("the Owner in "+A.name+" → "+B.name, at, a.ownerCall(owner, at.method, at.path, A.co.ID, at.body))
			}
		}
	}
	for _, w := range wrong {
		t.Error(w)
	}

	// Lists show a company its own things and nobody else's.
	for _, A := range world {
		if A.suspended {
			continue
		}
		for _, path := range []string{"/api/admin/users", "/api/admin/users?search=" + "acme.test", "/api/admin/groups",
			"/api/admin/invitations", "/api/admin/sessions", "/api/admin/api-clients", "/api/admin/products"} {
			body := a.get(path, bearer(A.as.Access)).Body.String()
			for _, B := range world {
				if B.co.ID == A.co.ID {
					continue
				}
				for _, leak := range []string{B.target.ID, B.target.Email, B.admin.Email, B.group, B.client, B.exclusive.ID, B.invitation} {
					if strings.Contains(body, leak) {
						t.Errorf("SECURITY: %s's %s shows %s's %q", A.name, path, B.name, leak)
					}
				}
			}
		}
		for _, B := range world {
			if B.co.ID == A.co.ID {
				continue
			}
			body := a.get("/api/admin/users?search="+B.target.Email, bearer(A.as.Access)).Body.String()
			if strings.Contains(body, B.target.ID) {
				t.Errorf("SECURITY: %s found %s's user by searching", A.name, B.name)
			}
		}
	}

	for _, tn := range world {
		if changed := changedTables(before[tn.co.ID], a.fingerprint(tn.co.ID)); len(changed) > 0 {
			t.Errorf("SECURITY: %s's rows changed while other companies aimed at them: %v", tn.name, changed)
		}
	}
	t.Logf("%d cross-company requests across %d companies", sent, len(world))
}

// ensure the fingerprint notices a change, so an unchanged one means something.
func TestTheCompanyFingerprintSeesEveryChange(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	g := a.newGroup(co)
	m := a.newMember(co, "")
	prints := []map[string]string{a.fingerprint(co.ID)}
	for _, change := range []func(){
		func() { a.join(m, g) },
		func() { a.exec(`UPDATE tbl_groups SET name = name || '!' WHERE id = $1`, g) },
		func() { a.exec(`UPDATE tbl_users SET is_active = false WHERE id = $1`, m.ID) },
		func() { a.exec(`UPDATE tbl_clients SET name = name || '!' WHERE id = $1`, co.ID) },
		func() { a.login(a.newMember(co, "")) },
	} {
		change()
		prints = append(prints, a.fingerprint(co.ID))
	}
	for i := 1; i < len(prints); i++ {
		if len(changedTables(prints[i-1], prints[i])) == 0 {
			t.Errorf("change %d left the fingerprint unchanged", i)
		}
	}
}
