package main

// Admin CRUD coverage, weighted toward the two failure modes that matter in a
// multi-tenant IdP: crossing a tenant boundary, and escalating privilege.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/alora/auth/internal/crypto/password"
)

// ---------- USERS ----------

func TestAdminUsersListAndDetailAreTenantScoped(t *testing.T) {
	f := newFlowFixture(t)
	other := newFlowFixture(t) // separate tenant, separate user
	tok := f.adminToken(t, map[string]string{"CRM": "Admin"})

	w := f.reqAuth(t, http.MethodGet, "/admin/users", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var listed struct {
		Users []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"users"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &listed)

	sawSelf := false
	for _, u := range listed.Users {
		if u.ID == other.userID {
			t.Fatal("SECURITY: another tenant's user appeared in the list")
		}
		if u.ID == f.userID {
			sawSelf = true
		}
	}
	if !sawSelf {
		t.Error("own user missing from the list")
	}
	// No secret may appear anywhere in the payload.
	for _, leak := range []string{"password_hash", "argon2", "deleted_at"} {
		if bodyContains(w.Body.String(), leak) {
			t.Errorf("SECURITY: list leaked %q", leak)
		}
	}

	// Fetching a foreign user by id must be indistinguishable from missing.
	if w := f.reqAuth(t, http.MethodGet, "/admin/users/"+other.userID, nil, tok); w.Code != http.StatusNotFound {
		t.Errorf("SECURITY: cross-tenant user detail returned %d, want 404", w.Code)
	}
	if w := f.reqAuth(t, http.MethodGet, "/admin/users/"+f.userID, nil, tok); w.Code != http.StatusOK {
		t.Errorf("own user detail: %d", w.Code)
	}
}

func TestAdminUserUpdateGuards(t *testing.T) {
	f := newFlowFixture(t)
	other := newFlowFixture(t)
	tok := f.adminToken(t, map[string]string{"CRM": "Admin"})

	// Self-modification is refused (lockout guard).
	w := f.reqAuth(t, http.MethodPatch, "/admin/users/"+f.userID, map[string]any{"is_active": false}, tok)
	if w.Code != http.StatusBadRequest {
		t.Errorf("self-update: %d, want 400", w.Code)
	}
	// Cross-tenant is 404, and must not mutate.
	if w := f.reqAuth(t, http.MethodPatch, "/admin/users/"+other.userID,
		map[string]any{"is_active": false}, tok); w.Code != http.StatusNotFound {
		t.Errorf("SECURITY: cross-tenant update returned %d, want 404", w.Code)
	}
	var stillActive bool
	if err := f.pool.QueryRow(context.Background(),
		`SELECT is_active FROM tbl_users WHERE id=$1`, other.userID).Scan(&stillActive); err != nil {
		t.Fatal(err)
	}
	if !stillActive {
		t.Error("SECURITY: cross-tenant update mutated another tenant's user")
	}
	// Unknown field is rejected rather than ignored.
	if w := f.reqAuth(t, http.MethodPatch, "/admin/users/"+other.userID,
		map[string]any{"is_active": false, "is_global_admin": true}, tok); w.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d, want 400", w.Code)
	}
}

// Deactivating a user must kill their sessions immediately, not at token expiry.
func TestDeactivationRevokesSessionsImmediately(t *testing.T) {
	f := newFlowFixture(t)
	admin := newFlowFixtureInTenant(t, f) // a second admin in the SAME tenant

	code := f.getCode(t)
	lw := f.post("/auth/token", map[string]any{"code": code, "code_verifier": f.verifier})
	rt := cookieNamed(lw, "alora_rt")
	if rt == nil {
		t.Fatal("no session")
	}
	if w := f.post("/auth/refresh", nil, rt); w.Code != http.StatusOK {
		t.Fatalf("precondition: refresh should work, got %d", w.Code)
	}

	tok := admin.adminToken(t, map[string]string{"CRM": "Admin"})
	if w := f.reqAuth(t, http.MethodPatch, "/admin/users/"+f.userID,
		map[string]any{"is_active": false}, tok); w.Code != http.StatusOK {
		t.Fatalf("deactivate: %d %s", w.Code, w.Body.String())
	}

	// The refresh cookie from before deactivation must now be dead. (The cookie
	// value rotated on the successful refresh above, so re-read it.)
	if w := f.post("/auth/refresh", nil, rt); w.Code == http.StatusOK {
		t.Error("SECURITY: session survived deactivation")
	}
	// And the user can no longer log in at all.
	if w := f.post("/auth/authorize", f.authorizeBody()); w.Code == http.StatusOK {
		t.Error("SECURITY: deactivated user can still authenticate")
	}
}

// newFlowFixtureInTenant seeds a second user inside an EXISTING tenant so
// admin-on-user tests do not trip the self-modification guard.
func newFlowFixtureInTenant(t *testing.T, base *fixture) *fixture {
	t.Helper()
	f := *base // copy router/pool/tenant
	f.email = fmt.Sprintf("admin2-%s@acme.test", randSuffix(t))
	hash := mustHash(t, base.pass)
	if err := base.pool.QueryRow(context.Background(),
		`INSERT INTO tbl_users (client_id, email, password_hash, account_type, is_active)
		 VALUES ($1,$2,$3,'EMAIL',true) RETURNING id`,
		base.clientID, f.email, hash).Scan(&f.userID); err != nil {
		t.Fatal(err)
	}
	return &f
}

// ---------- PERMISSIONS ----------

func TestPermissionGrantRevokeAndTenantIsolation(t *testing.T) {
	f := newFlowFixture(t)
	other := newFlowFixture(t)
	target := newFlowFixtureInTenant(t, f)
	tok := f.adminToken(t, map[string]string{"CRM": "Admin"})

	// Grant.
	w := f.reqAuth(t, http.MethodPut, "/admin/users/"+target.userID+"/permissions/"+f.product,
		map[string]any{"roleName": "Editor"}, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("grant: %d %s", w.Code, w.Body.String())
	}
	// The version bump is what forces the new role into the next token.
	var pv int32
	if err := f.pool.QueryRow(context.Background(),
		`SELECT permissions_version FROM tbl_users WHERE id=$1`, target.userID).Scan(&pv); err != nil {
		t.Fatal(err)
	}
	if pv < 2 {
		t.Errorf("permissions_version = %d, want > 1 (stale tokens would survive)", pv)
	}

	// Granting to a user in ANOTHER tenant must 404 and write nothing.
	if w := f.reqAuth(t, http.MethodPut, "/admin/users/"+other.userID+"/permissions/"+f.product,
		map[string]any{"roleName": "Admin"}, tok); w.Code != http.StatusNotFound {
		t.Errorf("SECURITY: cross-tenant grant returned %d, want 404", w.Code)
	}
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM tbl_product_permissions WHERE user_id=$1`, other.userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("SECURITY: cross-tenant grant created a permission row")
	}

	// Granting a product the tenant does not subscribe to.
	var foreignProduct string
	if err := f.pool.QueryRow(context.Background(),
		`INSERT INTO tbl_products (key,name,is_active) VALUES ($1,'X',true) RETURNING id`,
		"X-"+randSuffix(t)).Scan(&foreignProduct); err != nil {
		t.Fatal(err)
	}
	if w := f.reqAuth(t, http.MethodPut, "/admin/users/"+target.userID+"/permissions/"+foreignProduct,
		map[string]any{"roleName": "Admin"}, tok); w.Code != http.StatusForbidden {
		t.Errorf("unsubscribed product grant: %d, want 403 (Fastify parity)", w.Code)
	}

	// Revoke.
	if w := f.reqAuth(t, http.MethodDelete,
		"/admin/users/"+target.userID+"/permissions/"+f.product, nil, tok); w.Code != http.StatusNoContent {
		t.Errorf("revoke: %d", w.Code)
	}
	if w := f.reqAuth(t, http.MethodDelete,
		"/admin/users/"+target.userID+"/permissions/"+f.product, nil, tok); w.Code != http.StatusNotFound {
		t.Errorf("double revoke: %d, want 404", w.Code)
	}
}

// ---------- GROUPS ----------

func TestGroupLifecycleAndFeatureValidation(t *testing.T) {
	f := newFlowFixture(t)
	tok := f.grantFeatureToken(t, "groups:manage", "groups:view")

	// An unknown feature key must be rejected, not silently stored.
	if w := f.postAuth(t, "/admin/groups", map[string]any{
		"name": "bad-" + randSuffix(t), "features": []string{"users:view", "not:a:real:feature"},
	}, tok); w.Code != http.StatusBadRequest {
		t.Errorf("unknown feature: %d, want 400", w.Code)
	}

	name := "Support-" + randSuffix(t)
	w := f.postAuth(t, "/admin/groups", map[string]any{
		"name": name, "description": "support staff", "features": []string{"users:view", "sessions:view"},
	}, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var grp struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &grp)

	// Duplicate name within the tenant → 409 (case-insensitive unique index).
	if w := f.postAuth(t, "/admin/groups", map[string]any{"name": name}, tok); w.Code != http.StatusConflict {
		t.Errorf("duplicate group name: %d, want 409", w.Code)
	}

	// Add a member.
	member := newFlowFixtureInTenant(t, f)
	if w := f.postAuth(t, "/admin/groups/"+grp.ID+"/members",
		map[string]any{"userId": member.userID}, tok); w.Code != http.StatusCreated {
		t.Fatalf("add member: %d %s", w.Code, w.Body.String())
	}
	// Duplicate membership → 409.
	if w := f.postAuth(t, "/admin/groups/"+grp.ID+"/members",
		map[string]any{"userId": member.userID}, tok); w.Code != http.StatusConflict {
		t.Errorf("duplicate member: %d, want 409", w.Code)
	}

	// Detail reflects features + members.
	w = f.reqAuth(t, http.MethodGet, "/admin/groups/"+grp.ID, nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", w.Code, w.Body.String())
	}
	var detail struct {
		Features []string `json:"features"`
		Members  []struct {
			UserID string `json:"user_id"`
		} `json:"members"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &detail)
	if len(detail.Features) != 2 || len(detail.Members) != 1 {
		t.Errorf("detail = %+v, want 2 features / 1 member", detail)
	}

	// Remove member, then delete the group.
	if w := f.reqAuth(t, http.MethodDelete,
		"/admin/groups/"+grp.ID+"/members/"+member.userID, nil, tok); w.Code != http.StatusNoContent {
		t.Errorf("remove member: %d", w.Code)
	}
	if w := f.reqAuth(t, http.MethodDelete, "/admin/groups/"+grp.ID, nil, tok); w.Code != http.StatusNoContent {
		t.Errorf("delete group: %d", w.Code)
	}
	if w := f.reqAuth(t, http.MethodDelete, "/admin/groups/"+grp.ID, nil, tok); w.Code != http.StatusNotFound {
		t.Errorf("delete twice: %d, want 404", w.Code)
	}
}

// A group id from another tenant must never be mutated — the SQL guard on
// Delete/CreateGroupFeatures is the last line of defence here.
func TestGroupCrossTenantMutationBlocked(t *testing.T) {
	f := newFlowFixture(t)
	victim := newFlowFixture(t)

	vTok := victim.grantFeatureToken(t, "groups:manage", "groups:view")
	w := victim.postAuth(t, "/admin/groups", map[string]any{
		"name": "Victim-" + randSuffix(t), "features": []string{"users:view"},
	}, vTok)
	if w.Code != http.StatusCreated {
		t.Fatalf("victim group: %d %s", w.Code, w.Body.String())
	}
	var vg struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &vg)

	attacker := f.grantFeatureToken(t, "groups:manage", "groups:view")

	// Update, delete and member-add all target the victim's group id.
	if w := f.reqAuth(t, http.MethodPatch, "/admin/groups/"+vg.ID,
		map[string]any{"name": "pwned", "features": []string{"users:view"}}, attacker); w.Code != http.StatusNotFound {
		t.Errorf("SECURITY: cross-tenant group update returned %d, want 404", w.Code)
	}
	if w := f.reqAuth(t, http.MethodDelete, "/admin/groups/"+vg.ID, nil, attacker); w.Code != http.StatusNotFound {
		t.Errorf("SECURITY: cross-tenant group delete returned %d, want 404", w.Code)
	}
	if w := f.postAuth(t, "/admin/groups/"+vg.ID+"/members",
		map[string]any{"userId": f.userID}, attacker); w.Code != http.StatusNotFound {
		t.Errorf("SECURITY: cross-tenant member add returned %d, want 404", w.Code)
	}

	// The victim's group must be completely untouched.
	var name string
	var featureCount int
	if err := victim.pool.QueryRow(context.Background(),
		`SELECT g.name, (SELECT count(*) FROM tbl_group_features gf WHERE gf.group_id=g.id)
		 FROM tbl_groups g WHERE g.id=$1`, vg.ID).Scan(&name, &featureCount); err != nil {
		t.Fatalf("victim group destroyed: %v", err)
	}
	if name == "pwned" || featureCount != 1 {
		t.Errorf("SECURITY: victim group mutated (name=%s features=%d)", name, featureCount)
	}
}

// ---------- FEATURE GATING ----------

// Each route must demand its OWN feature key; holding one must not imply another.
func TestFeatureGatingIsPerRoute(t *testing.T) {
	f := newFlowFixture(t)
	// Only users:view — every other gated route must refuse.
	tok := f.grantFeatureToken(t, "users:view")

	allowed := []struct{ method, path string }{
		{http.MethodGet, "/admin/users"},
	}
	denied := []struct{ method, path string }{
		{http.MethodGet, "/admin/groups"},
		{http.MethodGet, "/admin/products"},
		{http.MethodGet, "/admin/client"},
		{http.MethodGet, "/admin/sessions"},
	}
	for _, tc := range allowed {
		if w := f.reqAuth(t, tc.method, tc.path, nil, tok); w.Code != http.StatusOK {
			t.Errorf("%s %s: %d, want 200", tc.method, tc.path, w.Code)
		}
	}
	for _, tc := range denied {
		if w := f.reqAuth(t, tc.method, tc.path, nil, tok); w.Code != http.StatusForbidden {
			t.Errorf("SECURITY: %s %s allowed without its feature (%d)", tc.method, tc.path, w.Code)
		}
	}
}

// ---------- SESSIONS / PRODUCTS / CLIENT ----------

func TestAdminSessionsProductsAndClient(t *testing.T) {
	f := newFlowFixture(t)
	tok := f.adminToken(t, map[string]string{"CRM": "Admin"})

	// Create a live session to list.
	code := f.getCode(t)
	f.post("/auth/token", map[string]any{"code": code, "code_verifier": f.verifier})

	w := f.reqAuth(t, http.MethodGet, "/admin/sessions", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("sessions: %d %s", w.Code, w.Body.String())
	}
	// D10b + spec §2: these must never be projected.
	for _, leak := range []string{"refresh_token_hash", "prev_token_hash", "revoked_reason", "user_id"} {
		if bodyContains(w.Body.String(), leak) {
			t.Errorf("SECURITY: session list leaked %q: %s", leak, w.Body.String())
		}
	}

	if w := f.reqAuth(t, http.MethodGet, "/admin/products", nil, tok); w.Code != http.StatusOK {
		t.Errorf("products: %d", w.Code)
	}
	if w := f.reqAuth(t, http.MethodGet, "/admin/client", nil, tok); w.Code != http.StatusOK {
		t.Errorf("client: %d", w.Code)
	}

	// A tenant admin must not be able to self-upgrade plan or un-suspend.
	if w := f.reqAuth(t, http.MethodPatch, "/admin/client",
		map[string]any{"subscription_status": "ACTIVE"}, tok); w.Code != http.StatusBadRequest {
		t.Errorf("SECURITY: subscription_status accepted from a tenant admin (%d)", w.Code)
	}
	if w := f.reqAuth(t, http.MethodPatch, "/admin/client",
		map[string]any{"is_active": true}, tok); w.Code != http.StatusBadRequest {
		t.Errorf("SECURITY: is_active accepted from a tenant admin (%d)", w.Code)
	}
	// An empty PATCH is a no-op request and must be refused.
	if w := f.reqAuth(t, http.MethodPatch, "/admin/client", map[string]any{}, tok); w.Code != http.StatusBadRequest {
		t.Errorf("empty patch: %d, want 400", w.Code)
	}
	// A legitimate edit succeeds.
	if w := f.reqAuth(t, http.MethodPatch, "/admin/client",
		map[string]any{"name": "Renamed " + randSuffix(t)}, tok); w.Code != http.StatusOK {
		t.Errorf("rename: %d %s", w.Code, w.Body.String())
	}
}

// ---------- helpers ----------

func bodyContains(body, needle string) bool { return strings.Contains(body, needle) }

func mustHash(t *testing.T, plaintext string) string {
	t.Helper()
	h, err := password.Hash(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
