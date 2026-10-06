package main

// API clients: applications' identities. A company's people manage them with
// api-clients:read / api-clients:edit, the Owner through the Owner console. An
// API client holds where its credential may be used (application scopes), the
// products it may get a token for — only products the company subscribes to
// and the Owner lets accept API clients — and its secrets: shown once, stored as
// hashes, at most two live.

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
)

// acceptAPIClients lets API clients get tokens for a product, as the Owner does.
func (a *app) acceptAPIClients(p product, on bool) {
	a.t.Helper()
	a.exec(`UPDATE tbl_products SET accepts_api_clients = $2 WHERE id = $1`, p.ID, on)
}

// apiClient is an API client as its routes render it.
type apiClient struct {
	ID          string   `json:"id"`
	CompanyID   string   `json:"company_id"`
	CompanyName string   `json:"company_name"`
	Name        string   `json:"name"`
	IsActive    bool     `json:"is_active"`
	Scopes      []string `json:"scopes"`
	LiveSecrets int      `json:"live_secrets"`
	Products    []struct {
		ProductID  string `json:"product_id"`
		ProductKey string `json:"product_key"`
		Usable     bool   `json:"usable"`
	} `json:"products"`
	ProductChoices []struct {
		ProductID string `json:"product_id"`
	} `json:"product_choices"`
	Secrets []struct {
		ID        string     `json:"id"`
		Prefix    string     `json:"prefix"`
		IsLive    bool       `json:"is_live"`
		ExpiresAt *time.Time `json:"expires_at"`
	} `json:"secrets"`
}

// newAPIClient creates an API client through the admin door.
func (a *app) newAPIClient(s session, name string) apiClient {
	a.t.Helper()
	w := a.post("/api/admin/api-clients", map[string]any{"name": name}, bearer(s.Access))
	expect(a.t, w, http.StatusCreated, "create API client "+name)
	var out apiClient
	decodeInto(a.t, w, &out)
	return out
}

func (a *app) apiClientDetail(s session, id string) apiClient {
	a.t.Helper()
	w := a.get("/api/admin/api-clients/"+id, bearer(s.Access))
	expect(a.t, w, http.StatusOK, "API client detail")
	var out apiClient
	decodeInto(a.t, w, &out)
	return out
}

type newSecret struct {
	ID           string `json:"id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Prefix       string `json:"prefix"`
	IsLive       bool   `json:"is_live"`
}

func (a *app) newSecret(s session, id string, body any) (newSecret, int) {
	a.t.Helper()
	w := a.post("/api/admin/api-clients/"+id+"/secrets", body, bearer(s.Access))
	var out newSecret
	if w.Code == http.StatusCreated {
		decodeInto(a.t, w, &out)
		if w.Header().Get("Cache-Control") != "no-store" {
			a.t.Errorf("a new secret's response may be cached: %q", w.Header().Get("Cache-Control"))
		}
	}
	return out, w.Code
}

// Both doors create, read and change the same API clients; the Owner console
// needs its target echo on every write; and the Owner alone sees every
// company's.
func TestAPIClientsThroughBothDoors(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	admin := a.newAdmin(co)
	s := a.login(admin)

	mine := a.newAPIClient(s, "Nightly sync")
	if !strings.HasPrefix(mine.ID, "aci_") || mine.CompanyID != co.ID || mine.CompanyName != co.Name || !mine.IsActive ||
		len(mine.Scopes) != 0 || len(mine.Products) != 0 || mine.LiveSecrets != 0 {
		t.Errorf("a new API client = %+v", mine)
	}

	owner := a.login(a.newOwner())
	base := "/api/owner/companies/" + co.ID + "/api-clients"
	for name, cid := range map[string]string{"no header": "", "another company": other.ID} {
		if w := a.ownerCall(owner, http.MethodPost, base, cid, map[string]any{"name": "Echo " + name}); w.Code != http.StatusBadRequest {
			t.Errorf("SECURITY: an Owner write with %s: %d", name, w.Code)
		}
	}
	w := a.ownerCall(owner, http.MethodPost, base, co.ID, map[string]any{"name": "Warehouse"})
	expect(t, w, http.StatusCreated, "the Owner creating one")
	theirs := jsonField(w, "id")
	w = a.ownerCall(owner, http.MethodGet, base+"/"+mine.ID, "", nil)
	expect(t, w, http.StatusOK, "the Owner reading the Admin's")
	w = a.ownerCall(owner, http.MethodPut, base+"/"+mine.ID+"/scopes", co.ID, map[string]any{"scopes": []string{"api:read"}})
	expect(t, w, http.StatusOK, "the Owner scoping the Admin's")

	// Who made each is recorded: a user of the company, or an Owner.
	if a.count(`SELECT count(*) FROM tbl_api_clients WHERE id = $1 AND created_by_user_id = $2 AND created_by_owner_id IS NULL`,
		mine.ID, admin.ID) != 1 ||
		a.count(`SELECT count(*) FROM tbl_api_clients WHERE id = $1 AND created_by_owner_id IS NOT NULL AND created_by_user_id IS NULL`,
			theirs) != 1 {
		t.Error("an API client's creator is not recorded")
	}

	// The Admin sees both; the Owner's page lists every company's.
	var list []apiClient
	decodeInto(t, a.get("/api/admin/api-clients", bearer(s.Access)), &list)
	if len(list) != 2 {
		t.Errorf("the company's list = %+v", list)
	}
	a.newAPIClient(a.login(a.newAdmin(other)), "Elsewhere")
	decodeInto(t, a.ownerCall(owner, http.MethodGet, "/api/owner/api-clients", "", nil), &list)
	companies := map[string]int{}
	for _, c := range list {
		companies[c.CompanyID]++
	}
	if companies[co.ID] != 2 || companies[other.ID] != 1 {
		t.Errorf("the Owner's list covers %v", companies)
	}
	if w := a.get("/api/owner/api-clients", bearer(s.Access)); w.Code != http.StatusForbidden {
		t.Errorf("SECURITY: an Admin listed every company's API clients: %d", w.Code)
	}
}

// An API client exists only in its own company: every route, through either
// door, answers another company's id as if it did not exist.
func TestAPIClientsStayInTheirCompany(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	c := a.newAPIClient(a.login(a.newAdmin(co)), "Theirs")
	sec, _ := a.newSecret(a.login(a.newAdmin(co)), c.ID, nil)
	intruder := a.login(a.newAdmin(other))

	path := "/api/admin/api-clients/" + c.ID
	for _, r := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, path, nil},
		{http.MethodPatch, path, map[string]any{"name": "Mine now", "is_active": false}},
		{http.MethodDelete, path, nil},
		{http.MethodPut, path + "/scopes", map[string]any{"scopes": []string{"api:edit"}}},
		{http.MethodPut, path + "/products", map[string]any{"product_ids": []string{}}},
		{http.MethodPost, path + "/secrets", map[string]any{}},
		{http.MethodDelete, path + "/secrets/" + sec.ID, nil},
	} {
		if w := a.send(r.method, r.path, r.body, bearer(intruder.Access)); w.Code != http.StatusNotFound {
			t.Errorf("SECURITY: %s %s from another company: %d %s", r.method, r.path, w.Code, w.Body.String())
		}
	}
	// And under another company's path in the Owner console.
	owner := a.login(a.newOwner())
	w := a.ownerCall(owner, http.MethodGet, "/api/owner/companies/"+other.ID+"/api-clients/"+c.ID, "", nil)
	expect(t, w, http.StatusNotFound, "an API client under another company's path")

	var name string
	var active bool
	a.scalar(&name, `SELECT name FROM tbl_api_clients WHERE id = $1`, c.ID)
	a.scalar(&active, `SELECT revoked_at IS NULL FROM tbl_api_client_secrets WHERE id = $1`, sec.ID)
	if name != "Theirs" || !active {
		t.Fatal("SECURITY: another company changed an API client")
	}
}

// Read looks, Edit changes: api-clients:read opens the list and the detail and
// nothing else.
func TestAPIClientsNeedTheirScope(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	c := a.newAPIClient(a.login(a.newAdmin(co)), "Sync")
	reader := a.newMember(co, "")
	a.join(reader, a.newGroup(co, shared.ScopeAPIClientsRead))
	rs := a.login(reader)
	expect(t, a.get("/api/admin/api-clients", bearer(rs.Access)), http.StatusOK, "list with read")
	expect(t, a.get("/api/admin/api-clients/"+c.ID, bearer(rs.Access)), http.StatusOK, "detail with read")
	for _, r := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/admin/api-clients", map[string]any{"name": "Mine"}},
		{http.MethodPatch, "/api/admin/api-clients/" + c.ID, map[string]any{"name": "x", "is_active": false}},
		{http.MethodDelete, "/api/admin/api-clients/" + c.ID, nil},
		{http.MethodPut, "/api/admin/api-clients/" + c.ID + "/scopes", map[string]any{"scopes": []string{"mcp:tools"}}},
		{http.MethodPost, "/api/admin/api-clients/" + c.ID + "/secrets", map[string]any{}},
	} {
		if w := a.send(r.method, r.path, r.body, bearer(rs.Access)); !refusedByGuard(w) {
			t.Errorf("SECURITY: api-clients:read reached %s %s: %d", r.method, r.path, w.Code)
		}
	}
	editor := a.newMember(co, "")
	a.join(editor, a.newGroup(co, shared.ScopeAPIClientsEdit))
	es := a.login(editor)
	expect(t, a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/scopes", map[string]any{"scopes": []string{"mcp:tools"}},
		bearer(es.Access)), http.StatusOK, "scopes with edit")
	if _, code := a.newSecret(es, c.ID, nil); code != http.StatusCreated {
		t.Errorf("a secret with edit: %d", code)
	}
}

// A secret is shown once and stored as its hash; at most two are live, so one
// rotates without downtime; revoking stamps, and an expired secret is not live.
func TestAPIClientSecrets(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	c := a.newAPIClient(s, "Rotating")

	first, code := a.newSecret(s, c.ID, nil)
	if code != http.StatusCreated || first.ClientID != c.ID || !strings.HasPrefix(first.ClientSecret, "acc_") ||
		first.Prefix != first.ClientSecret[:12] || !first.IsLive || len(first.ClientSecret) < 40 {
		t.Fatalf("a new secret = %+v (%d)", first, code)
	}
	var hash string
	a.scalar(&hash, `SELECT secret_hash FROM tbl_api_client_secrets WHERE id = $1`, first.ID)
	if hash != tokens.HashToken(first.ClientSecret) {
		t.Error("the secret is not stored as its SHA-256")
	}
	if a.count(`SELECT count(*) FROM tbl_api_client_secrets WHERE secret_hash = $1 OR prefix = $1`, first.ClientSecret) != 0 {
		t.Error("SECURITY: the secret's value is stored")
	}
	// Never again in any read.
	w := a.get("/api/admin/api-clients/"+c.ID, bearer(s.Access))
	if strings.Contains(w.Body.String(), first.ClientSecret) || strings.Contains(w.Body.String(), hash) {
		t.Fatal("SECURITY: the detail shows a secret or its hash")
	}
	d := a.apiClientDetail(s, c.ID)
	if len(d.Secrets) != 1 || d.Secrets[0].Prefix != first.Prefix || !d.Secrets[0].IsLive || d.LiveSecrets != 1 {
		t.Errorf("secrets = %+v", d.Secrets)
	}

	// Two may be live; a third waits for one to go.
	second, code := a.newSecret(s, c.ID, map[string]any{"expires_in_days": 30})
	if code != http.StatusCreated || second.ClientSecret == first.ClientSecret {
		t.Fatalf("the second secret: %d", code)
	}
	if _, code := a.newSecret(s, c.ID, nil); code != http.StatusConflict {
		t.Errorf("a third live secret: %d, want 409", code)
	}
	expect(t, a.send(http.MethodDelete, "/api/admin/api-clients/"+c.ID+"/secrets/"+first.ID, nil, bearer(s.Access)),
		http.StatusNoContent, "revoke the first")
	expect(t, a.send(http.MethodDelete, "/api/admin/api-clients/"+c.ID+"/secrets/"+first.ID, nil, bearer(s.Access)),
		http.StatusNotFound, "revoke it again")
	expect(t, a.send(http.MethodDelete, "/api/admin/api-clients/"+c.ID+"/secrets/"+noSuchID, nil, bearer(s.Access)),
		http.StatusNotFound, "revoke an unknown secret")
	if a.count(`SELECT count(*) FROM tbl_api_client_secrets WHERE id = $1 AND revoked_at IS NOT NULL`, first.ID) != 1 {
		t.Error("a revoked secret is not kept, stamped")
	}
	if _, code := a.newSecret(s, c.ID, nil); code != http.StatusCreated {
		t.Fatalf("a secret after a revocation: %d", code)
	}

	// The second lives thirty days; once expired it is not live, and no longer
	// counts against the two.
	d = a.apiClientDetail(s, c.ID)
	for _, x := range d.Secrets {
		if x.ID == second.ID && (x.ExpiresAt == nil || x.ExpiresAt.Sub(time.Now()) < 29*24*time.Hour) {
			t.Errorf("the second secret expires %v", x.ExpiresAt)
		}
	}
	a.exec(`UPDATE tbl_api_client_secrets SET expires_at = now() - interval '1 minute' WHERE id = $1`, second.ID)
	d = a.apiClientDetail(s, c.ID)
	if d.LiveSecrets != 1 {
		t.Errorf("live secrets with one expired = %d", d.LiveSecrets)
	}
	if _, code := a.newSecret(s, c.ID, nil); code != http.StatusCreated {
		t.Errorf("a secret beside an expired one: %d", code)
	}
	for _, days := range []int{0, 731} {
		if _, code := a.newSecret(s, c.ID, map[string]any{"expires_in_days": days}); code != http.StatusBadRequest {
			t.Errorf("expires_in_days %d: %d", days, code)
		}
	}
}

// An API client's product list: only products the company subscribes to and
// the Owner lets accept API clients can be added; one already there may stay
// when that changes, and shows as not usable.
func TestAPIClientProducts(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	s := a.login(a.newAdmin(co))
	c := a.newAPIClient(s, "Reporting")
	crm, hr, unsubscribed, elsewhere := a.newProduct(), a.newProduct(), a.newProduct(), a.newProduct()
	a.subscribe(co, crm)
	a.subscribe(co, hr)
	a.subscribe(other, elsewhere)
	for _, p := range []product{hr, unsubscribed, elsewhere} {
		a.acceptAPIClients(p, true)
	}
	set := func(ids ...string) (*apiClient, int) {
		t.Helper()
		w := a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/products", map[string]any{"product_ids": ids}, bearer(s.Access))
		if w.Code != http.StatusOK {
			return nil, w.Code
		}
		var out apiClient
		decodeInto(t, w, &out)
		return &out, w.Code
	}

	// What could go on the list: HR only.
	d := a.apiClientDetail(s, c.ID)
	if len(d.ProductChoices) != 1 || d.ProductChoices[0].ProductID != hr.ID {
		t.Errorf("product choices = %+v", d.ProductChoices)
	}
	for name, id := range map[string]string{
		"a product that does not accept API clients":  crm.ID,
		"a product the company does not subscribe to": unsubscribed.ID,
		"another company's subscription":              elsewhere.ID,
		"a product that does not exist":               noSuchID,
	} {
		if _, code := set(id); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
	if _, code := set("not-a-uuid"); code != http.StatusBadRequest {
		t.Errorf("a malformed id: %d", code)
	}
	out, code := set(hr.ID, hr.ID)
	if code != http.StatusOK || len(out.Products) != 1 || out.Products[0].ProductID != hr.ID || !out.Products[0].Usable {
		t.Fatalf("set HR: %d %+v", code, out)
	}

	// The Owner switches HR off: the entry stays, not usable, and may be kept —
	// but not added anew once removed.
	a.acceptAPIClients(hr, false)
	d = a.apiClientDetail(s, c.ID)
	if len(d.Products) != 1 || d.Products[0].Usable || len(d.ProductChoices) != 0 {
		t.Errorf("after the switch: products %+v, choices %+v", d.Products, d.ProductChoices)
	}
	if _, code := set(hr.ID); code != http.StatusOK {
		t.Errorf("keeping an entry that is no longer usable: %d", code)
	}
	a.acceptAPIClients(crm, true)
	if out, code := set(hr.ID, crm.ID); code != http.StatusOK || len(out.Products) != 2 {
		t.Errorf("adding CRM beside HR: %d", code)
	}
	if out, code := set(); code != http.StatusOK || len(out.Products) != 0 {
		t.Errorf("emptying the list: %d", code)
	}
	if _, code := set(hr.ID); code != http.StatusBadRequest {
		t.Errorf("re-adding HR once it no longer accepts API clients: %d", code)
	}
	// A subscription switched off takes the product out of the choices too.
	a.exec(`UPDATE tbl_client_products SET is_active = false WHERE client_id = $1 AND product_id = $2`, co.ID, crm.ID)
	if _, code := set(crm.ID); code != http.StatusBadRequest {
		t.Errorf("adding a product whose subscription is off: %d", code)
	}
}

// Only application scopes: a person's scope is not one, an edit scope brings its
// read scope, and the list comes back sorted.
func TestAPIClientScopes(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	c := a.newAPIClient(s, "Agent")
	put := func(scopes ...string) (int, []string) {
		t.Helper()
		w := a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/scopes", map[string]any{"scopes": scopes}, bearer(s.Access))
		var out struct {
			Scopes []string `json:"scopes"`
		}
		if w.Code == http.StatusOK {
			decodeInto(t, w, &out)
		}
		return w.Code, out.Scopes
	}
	for _, bad := range [][]string{{"users:read"}, {"owner"}, {"api:everything"}, {""}, {"apps:read"}} {
		if code, _ := put(bad...); code != http.StatusBadRequest {
			t.Errorf("scopes %v: %d, want 400", bad, code)
		}
	}
	if code, got := put("mcp:tools", "grpc:edit", "api:edit"); code != http.StatusOK ||
		!slices.Equal(got, []string{"api:edit", "api:read", "grpc:edit", "grpc:read", "mcp:tools"}) {
		t.Errorf("put = %d %v", code, got)
	}
	if d := a.apiClientDetail(s, c.ID); !slices.Equal(d.Scopes, []string{"api:edit", "api:read", "grpc:edit", "grpc:read", "mcp:tools"}) {
		t.Errorf("stored = %v", d.Scopes)
	}
	if code, got := put(); code != http.StatusOK || len(got) != 0 {
		t.Errorf("clearing: %d %v", code, got)
	}
}

// Names are unique within a company, whatever their case; renaming and
// switching off work; deleting takes everything with it and leaves a record.
func TestAPIClientLifecycle(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	s := a.login(a.newAdmin(co))
	c := a.newAPIClient(s, "Exporter")
	expect(t, a.post("/api/admin/api-clients", map[string]any{"name": "EXPORTER"}, bearer(s.Access)), http.StatusConflict, "a taken name")
	a.newAPIClient(a.login(a.newAdmin(other)), "Exporter") // another company's is its own
	b := a.newAPIClient(s, "Importer")
	expect(t, a.send(http.MethodPatch, "/api/admin/api-clients/"+b.ID, map[string]any{"name": "exporter", "is_active": true}, bearer(s.Access)),
		http.StatusConflict, "renaming onto a taken name")
	expect(t, a.send(http.MethodPatch, "/api/admin/api-clients/"+b.ID, map[string]any{"name": "Importer"}, bearer(s.Access)),
		http.StatusBadRequest, "a change without is_active")

	w := a.send(http.MethodPatch, "/api/admin/api-clients/"+c.ID, map[string]any{"name": "Exporter v2", "description": "Nightly", "is_active": false}, bearer(s.Access))
	expect(t, w, http.StatusOK, "switch off")
	var got apiClient
	decodeInto(t, w, &got)
	if got.Name != "Exporter v2" || got.IsActive {
		t.Errorf("after the change: %+v", got)
	}

	p := a.newProduct()
	a.subscribe(co, p)
	a.acceptAPIClients(p, true)
	expect(t, a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/products", map[string]any{"product_ids": []string{p.ID}}, bearer(s.Access)),
		http.StatusOK, "products")
	expect(t, a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/scopes", map[string]any{"scopes": []string{"api:read"}}, bearer(s.Access)),
		http.StatusOK, "scopes")
	if _, code := a.newSecret(s, c.ID, nil); code != http.StatusCreated {
		t.Fatalf("secret: %d", code)
	}
	expect(t, a.send(http.MethodDelete, "/api/admin/api-clients/"+c.ID, nil, bearer(s.Access)), http.StatusNoContent, "delete")
	expect(t, a.get("/api/admin/api-clients/"+c.ID, bearer(s.Access)), http.StatusNotFound, "after the delete")
	for _, table := range []string{"tbl_api_client_scopes", "tbl_api_client_products", "tbl_api_client_secrets"} {
		if n := a.count(`SELECT count(*) FROM `+table+` WHERE api_client_id = $1`, c.ID); n != 0 {
			t.Errorf("%d rows of %s outlived their API client", n, table)
		}
	}
	// The subscription it named is untouched.
	if a.count(`SELECT count(*) FROM tbl_client_products WHERE client_id = $1 AND product_id = $2`, co.ID, p.ID) != 1 {
		t.Error("deleting an API client took a subscription with it")
	}
}

// Every change is in the trail, with what changed — never a secret's value.
func TestAPIClientChangesAreAudited(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	c := a.newAPIClient(s, "Audited")
	sec, _ := a.newSecret(s, c.ID, nil)
	expect(t, a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/scopes", map[string]any{"scopes": []string{"grpc:read"}}, bearer(s.Access)),
		http.StatusOK, "scopes")
	expect(t, a.send(http.MethodDelete, "/api/admin/api-clients/"+c.ID+"/secrets/"+sec.ID, nil, bearer(s.Access)),
		http.StatusNoContent, "revoke")

	waitFor := func(event string, want ...string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			var meta string
			err := a.pool.QueryRow(t.Context(), `SELECT coalesce(event_metadata::text, '') FROM tbl_audit_logs
			        WHERE client_id = $1 AND event_type = $2 AND event_metadata->>'api_client_id' = $3
			        ORDER BY created_at DESC LIMIT 1`, co.ID, event, c.ID).Scan(&meta)
			if err == nil {
				for _, w := range want {
					if !strings.Contains(meta, w) {
						t.Errorf("%s metadata %s lacks %q", event, meta, w)
					}
				}
				if strings.Contains(meta, sec.ClientSecret) {
					t.Errorf("SECURITY: %s recorded a secret's value", event)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("no %s in the trail: %v", event, err)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitFor("api_client.created", `"name": "Audited"`)
	waitFor("api_client.secret_created", sec.Prefix)
	waitFor("api_client.scopes_set", "grpc:read")
	waitFor("api_client.secret_revoked", sec.ID, sec.Prefix)
}

// Whether a product accepts API clients is the Owner's switch: off for a new
// product, kept when a change leaves it out.
func TestTheOwnerSwitchesProductsToAcceptAPIClients(t *testing.T) {
	a := newApp(t)
	owner := a.login(a.newOwner())
	p := a.newProduct()
	path := "/api/owner/products/" + p.ID
	accepts := func() bool {
		t.Helper()
		var on bool
		a.scalar(&on, `SELECT accepts_api_clients FROM tbl_products WHERE id = $1`, p.ID)
		return on
	}
	if accepts() {
		t.Fatal("a new product accepts API clients")
	}
	body := func(extra map[string]any) map[string]any {
		b := map[string]any{"name": "Product", "is_active": true}
		for k, v := range extra {
			b[k] = v
		}
		return b
	}
	w := a.send(http.MethodPatch, path, body(map[string]any{"accepts_api_clients": true}), bearer(owner.Access))
	expect(t, w, http.StatusOK, "switch on")
	if decode(t, w)["accepts_api_clients"] != true || !accepts() {
		t.Errorf("switched on: %s", w.Body.String())
	}
	expect(t, a.send(http.MethodPatch, path, body(nil), bearer(owner.Access)), http.StatusOK, "a change leaving it out")
	if !accepts() {
		t.Error("a change that left the switch out turned it off")
	}
	expect(t, a.send(http.MethodPatch, path, body(map[string]any{"accepts_api_clients": false}), bearer(owner.Access)), http.StatusOK, "switch off")
	if accepts() {
		t.Error("the switch did not turn off")
	}
	// Only the Owner: a company Admin has no such route.
	s := a.login(a.newAdmin(a.newCompany()))
	if w := a.send(http.MethodPatch, path, body(map[string]any{"accepts_api_clients": true}), bearer(s.Access)); w.Code != http.StatusForbidden {
		t.Errorf("SECURITY: an Admin reached the product switch: %d", w.Code)
	}
}
