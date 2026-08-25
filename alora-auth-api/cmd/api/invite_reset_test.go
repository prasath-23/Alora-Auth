package main

// Coverage for invitation onboarding and admin-issued password resets, including
// the tenant-isolation and single-use guarantees each flow depends on.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alora/auth/internal/crypto/jwtkeys"
)

// adminToken mints a token for the seeded user with a product "Admin" role, which
// satisfies RequireAdmin via the roles-map VALUE check.
func (f *fixture) adminToken(t *testing.T, roles map[string]string) string {
	t.Helper()
	var pv int32
	if err := f.pool.QueryRow(context.Background(),
		`SELECT permissions_version FROM tbl_users WHERE id=$1`, f.userID).Scan(&pv); err != nil {
		t.Fatal(err)
	}
	tok, err := jwtkeys.Sign(f.userID, map[string]any{
		"client_id": f.clientID, "email": f.email, "roles": roles,
		"pv": int(pv), "is_global_admin": false,
	}, 15*time.Minute, []string{"alora-auth-api"})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *fixture) postAuth(t *testing.T, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	return f.reqAuth(t, http.MethodPost, path, body, token)
}

func (f *fixture) reqAuth(t *testing.T, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = strings.NewReader(string(b))
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, req)
	return w
}

// ---------- INVITATIONS ----------

func TestInvitationFullLifecycle(t *testing.T) {
	f := newFlowFixture(t)
	tok := f.adminToken(t, map[string]string{"CRM": "Admin"})
	invitee := fmt.Sprintf("newhire-%s@acme.test", randSuffix(t))

	// Create.
	w := f.postAuth(t, "/admin/invitations", map[string]any{
		"email":    invitee,
		"products": []map[string]any{{"product_id": f.product, "role_name": "Viewer"}},
	}, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		ID        string `json:"id"`
		InviteURL string `json:"invite_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.InviteURL == "" {
		t.Fatal("invite_url missing (D10a: needed when SMTP is unconfigured)")
	}
	// Only the HASH may be stored — never the raw token.
	rawToken := created.InviteURL[strings.LastIndex(created.InviteURL, "=")+1:]
	var stored string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT token_hash FROM tbl_invitations WHERE id=$1`, created.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == rawToken {
		t.Fatal("SECURITY: raw invite token stored in the database")
	}

	// Public preview.
	w = f.reqAuth(t, http.MethodGet, "/auth/accept-invitation/lookup?token="+rawToken, nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("lookup: %d %s", w.Code, w.Body.String())
	}
	var preview struct {
		Email    string `json:"email"`
		Products []struct {
			Role string `json:"role_name"`
		} `json:"products"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &preview)
	if preview.Email != invitee {
		t.Errorf("preview email = %q, want %q", preview.Email, invitee)
	}
	if len(preview.Products) != 1 || preview.Products[0].Role != "Viewer" {
		t.Errorf("preview products = %+v, want one Viewer grant", preview.Products)
	}

	// Accept.
	if w := f.post("/auth/accept-invitation", map[string]any{
		"token": rawToken, "password": "a-brand-new-password",
	}); w.Code != http.StatusNoContent {
		t.Fatalf("accept: %d %s", w.Code, w.Body.String())
	}

	// The account exists, in the right tenant, with the invited grant applied.
	var gotClient, gotRole string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT u.client_id, pp.role_name FROM tbl_users u
		 JOIN tbl_product_permissions pp ON pp.user_id = u.id
		 WHERE lower(u.email)=$1`, strings.ToLower(invitee)).Scan(&gotClient, &gotRole); err != nil {
		t.Fatalf("created user/grant not found: %v", err)
	}
	if gotClient != f.clientID || gotRole != "Viewer" {
		t.Errorf("client=%s role=%s, want %s/Viewer", gotClient, gotRole, f.clientID)
	}

	// Single-use: the token must not work twice.
	if w := f.post("/auth/accept-invitation", map[string]any{
		"token": rawToken, "password": "another-password",
	}); w.Code == http.StatusNoContent {
		t.Error("SECURITY: invitation token was redeemable twice")
	}
}

func TestInvitationRequiresAdminAndIsTenantScoped(t *testing.T) {
	f := newFlowFixture(t)

	// A non-admin role must not be able to invite.
	viewer := f.adminToken(t, map[string]string{"CRM": "Viewer"})
	if w := f.postAuth(t, "/admin/invitations",
		map[string]any{"email": "x@acme.test"}, viewer); w.Code != http.StatusForbidden {
		t.Errorf("viewer create: %d, want 403", w.Code)
	}
	// Unauthenticated.
	if w := f.post("/admin/invitations", map[string]any{"email": "x@acme.test"}); w.Code != http.StatusUnauthorized {
		t.Errorf("anon create: %d, want 401", w.Code)
	}

	// An admin of ANOTHER tenant must not revoke this tenant's invitation.
	tok := f.adminToken(t, map[string]string{"CRM": "Admin"})
	w := f.postAuth(t, "/admin/invitations",
		map[string]any{"email": fmt.Sprintf("v-%s@acme.test", randSuffix(t))}, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	other := newFlowFixture(t) // a separate tenant + admin
	otherTok := other.adminToken(t, map[string]string{"CRM": "Admin"})
	if w := other.reqAuth(t, http.MethodDelete, "/admin/invitations/"+created.ID, nil, otherTok); w.Code != http.StatusNotFound {
		t.Errorf("SECURITY: cross-tenant revoke returned %d, want 404", w.Code)
	}
	// Still pending for its real owner.
	var status string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT status FROM tbl_invitations WHERE id=$1`, created.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" {
		t.Errorf("SECURITY: cross-tenant revoke mutated the invitation (status=%s)", status)
	}

	// The owner can revoke it.
	if w := f.reqAuth(t, http.MethodDelete, "/admin/invitations/"+created.ID, nil, tok); w.Code != http.StatusNoContent {
		t.Errorf("owner revoke: %d, want 204", w.Code)
	}
	// A revoked invite must no longer be listed as pending, nor be acceptable.
	if w := f.reqAuth(t, http.MethodDelete, "/admin/invitations/"+created.ID, nil, tok); w.Code != http.StatusNotFound {
		t.Errorf("double revoke: %d, want 404", w.Code)
	}
}

func TestInvitationRejectsDuplicateAndExistingUser(t *testing.T) {
	f := newFlowFixture(t)
	tok := f.adminToken(t, map[string]string{"CRM": "Admin"})

	// Inviting an address that is already an active member.
	if w := f.postAuth(t, "/admin/invitations", map[string]any{"email": f.email}, tok); w.Code != http.StatusConflict {
		t.Errorf("existing user: %d, want 409 (%s)", w.Code, w.Body.String())
	}

	// Two live invites for the same address must not coexist.
	dup := fmt.Sprintf("dup-%s@acme.test", randSuffix(t))
	if w := f.postAuth(t, "/admin/invitations", map[string]any{"email": dup}, tok); w.Code != http.StatusCreated {
		t.Fatalf("first invite: %d %s", w.Code, w.Body.String())
	}
	if w := f.postAuth(t, "/admin/invitations", map[string]any{"email": dup}, tok); w.Code != http.StatusConflict {
		t.Errorf("duplicate invite: %d, want 409", w.Code)
	}
}

func TestInvitationLookupAndAcceptRejectBadTokens(t *testing.T) {
	f := newFlowFixture(t)
	for _, tc := range []struct{ name, token string }{
		{"unknown", strings.Repeat("f", 64)},
		{"empty", ""},
	} {
		t.Run("lookup/"+tc.name, func(t *testing.T) {
			w := f.reqAuth(t, http.MethodGet, "/auth/accept-invitation/lookup?token="+tc.token, nil, "")
			if w.Code != http.StatusBadRequest {
				t.Errorf("status %d, want 400", w.Code)
			}
		})
		t.Run("accept/"+tc.name, func(t *testing.T) {
			w := f.post("/auth/accept-invitation", map[string]any{"token": tc.token, "password": "long-enough-password"})
			if w.Code == http.StatusNoContent {
				t.Error("SECURITY: bad token accepted")
			}
		})
	}
	// Weak password must be refused by validation.
	if w := f.post("/auth/accept-invitation", map[string]any{
		"token": strings.Repeat("a", 64), "password": "short",
	}); w.Code != http.StatusBadRequest {
		t.Errorf("weak password: %d, want 400", w.Code)
	}
}

// An invite issued before the tenant was suspended must stop working.
func TestInvitationBlockedForInactiveTenant(t *testing.T) {
	f := newFlowFixture(t)
	tok := f.adminToken(t, map[string]string{"CRM": "Admin"})
	w := f.postAuth(t, "/admin/invitations",
		map[string]any{"email": fmt.Sprintf("late-%s@acme.test", randSuffix(t))}, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		InviteURL string `json:"invite_url"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	raw := created.InviteURL[strings.LastIndex(created.InviteURL, "=")+1:]

	if _, err := f.pool.Exec(context.Background(),
		`UPDATE tbl_clients SET is_active=false WHERE id=$1`, f.clientID); err != nil {
		t.Fatal(err)
	}
	if w := f.reqAuth(t, http.MethodGet, "/auth/accept-invitation/lookup?token="+raw, nil, ""); w.Code == http.StatusOK {
		t.Error("SECURITY: suspended tenant still previews invitations")
	}
}

// ---------- PASSWORD RESET ----------

func TestPasswordResetFullLifecycle(t *testing.T) {
	f := newFlowFixture(t)
	// passwords:reset is granted through a group, exercising RequireFeature.
	tok := f.grantFeatureToken(t, "passwords:reset")

	w := f.postAuth(t, "/admin/users/"+f.userID+"/password-reset", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("issue: %d %s", w.Code, w.Body.String())
	}
	var issued struct {
		ResetURL string `json:"reset_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil || issued.ResetURL == "" {
		t.Fatalf("no reset_url in %s", w.Body.String())
	}
	raw := issued.ResetURL[strings.LastIndex(issued.ResetURL, "=")+1:]

	// Give the user a live session, which the reset must destroy.
	code := f.getCode(t)
	lw := f.post("/auth/token", map[string]any{"code": code, "code_verifier": f.verifier})
	rt := cookieNamed(lw, "alora_rt")
	if rt == nil {
		t.Fatal("no session cookie")
	}

	newPass := "a-completely-new-password"
	if w := f.post("/auth/reset-password", map[string]any{"token": raw, "new_password": newPass}); w.Code != http.StatusNoContent {
		t.Fatalf("consume: %d %s", w.Code, w.Body.String())
	}

	// Old password dead, new password works.
	old := f.authorizeBody()
	if w := f.post("/auth/authorize", old); w.Code != http.StatusUnauthorized {
		t.Errorf("old password still works: %d", w.Code)
	}
	f.pass = newPass
	if w := f.post("/auth/authorize", f.authorizeBody()); w.Code != http.StatusOK {
		t.Errorf("new password rejected: %d %s", w.Code, w.Body.String())
	}

	// Every prior session must be revoked (LOGOUT_ALL).
	if w := f.post("/auth/refresh", nil, rt); w.Code != http.StatusUnauthorized {
		t.Errorf("SECURITY: session survived a password reset: %d", w.Code)
	}

	// Single-use.
	if w := f.post("/auth/reset-password", map[string]any{"token": raw, "new_password": "yet-another-password"}); w.Code == http.StatusNoContent {
		t.Error("SECURITY: reset token was redeemable twice")
	}
}

// grantFeatureToken creates a group carrying the given feature keys, adds the
// seeded user to it, and returns a token with NO product roles — so
// authorization can only succeed through the group-membership path.
//
// Note that view and manage are deliberately distinct keys (matching the Fastify
// contract): holding groups:manage does NOT imply groups:view, so a caller that
// needs both must be granted both, exactly as the admin UI does.
func (f *fixture) grantFeatureToken(t *testing.T, featureKeys ...string) string {
	t.Helper()
	ctx := context.Background()
	var groupID string
	if err := f.pool.QueryRow(ctx,
		`INSERT INTO tbl_groups (client_id, name) VALUES ($1,$2) RETURNING id`,
		f.clientID, "grp-"+randSuffix(t)).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	for _, k := range featureKeys {
		if _, err := f.pool.Exec(ctx,
			`INSERT INTO tbl_group_features (group_id, feature_key) VALUES ($1,$2)`, groupID, k); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO tbl_user_groups (user_id, group_id, client_id) VALUES ($1,$2,$3)`,
		f.userID, groupID, f.clientID); err != nil {
		t.Fatal(err)
	}
	return f.adminToken(t, map[string]string{})
}

func TestPasswordResetRequiresFeatureAndTenantScope(t *testing.T) {
	f := newFlowFixture(t)

	// No feature, no product role → 403.
	plain := f.adminToken(t, map[string]string{})
	if w := f.postAuth(t, "/admin/users/"+f.userID+"/password-reset", nil, plain); w.Code != http.StatusForbidden {
		t.Errorf("no feature: %d, want 403", w.Code)
	}
	// Unauthenticated → 401.
	if w := f.post("/admin/users/"+f.userID+"/password-reset", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("anon: %d, want 401", w.Code)
	}

	// Cross-tenant: a properly-entitled admin must not reset another tenant's user.
	other := newFlowFixture(t)
	otherTok := other.grantFeatureToken(t, "passwords:reset")
	if w := other.postAuth(t, "/admin/users/"+f.userID+"/password-reset", nil, otherTok); w.Code != http.StatusNotFound {
		t.Errorf("SECURITY: cross-tenant reset returned %d, want 404", w.Code)
	}
}

func TestPasswordResetRejectsBadTokensUniformly(t *testing.T) {
	f := newFlowFixture(t)
	var bodies []string
	for _, tok := range []string{strings.Repeat("z", 43), "short"} {
		w := f.post("/auth/reset-password", map[string]any{"token": tok, "new_password": "a-valid-long-password"})
		if w.Code != http.StatusBadRequest {
			t.Errorf("token %q: %d, want 400", tok, w.Code)
		}
		bodies = append(bodies, w.Body.String())
	}
	// Unknown vs malformed must be indistinguishable (no token oracle).
	if len(bodies) == 2 && !sameErrorMessage(bodies[0], bodies[1]) {
		t.Errorf("SECURITY: reset token oracle — %q vs %q", bodies[0], bodies[1])
	}
}

// A reset link issued before deactivation must not revive the account.
func TestPasswordResetBlockedForDeactivatedUser(t *testing.T) {
	f := newFlowFixture(t)
	tok := f.grantFeatureToken(t, "passwords:reset")
	w := f.postAuth(t, "/admin/users/"+f.userID+"/password-reset", nil, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("issue: %d %s", w.Code, w.Body.String())
	}
	var issued struct {
		ResetURL string `json:"reset_url"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &issued)
	raw := issued.ResetURL[strings.LastIndex(issued.ResetURL, "=")+1:]

	if _, err := f.pool.Exec(context.Background(),
		`UPDATE tbl_users SET is_active=false WHERE id=$1`, f.userID); err != nil {
		t.Fatal(err)
	}
	if w := f.post("/auth/reset-password", map[string]any{"token": raw, "new_password": "new-password-here"}); w.Code == http.StatusNoContent {
		t.Error("SECURITY: reset succeeded for a deactivated user")
	}
}
