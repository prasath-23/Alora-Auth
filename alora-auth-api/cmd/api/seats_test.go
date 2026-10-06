package main

// Seat limits: a company's max_seats caps its active members, and a product
// subscription's seat_limit caps the people who may open that product. Both are
// enforced in the same transaction as the change that would exceed them, so a
// race cannot oversubscribe either.

import (
	"context"
	"net/http"
	"testing"

	"github.com/alora/auth/internal/database/services/groups"
	"github.com/alora/auth/internal/database/services/productpermissions"
	"github.com/alora/auth/internal/exceptions"
)

// A company's max_seats caps its ACTIVE members. Accepting an invitation or
// reactivating a member past the cap is refused with 409; a NULL cap is
// unlimited; a freed seat (deactivation) can be refilled.
func TestCompanySeatLimitIsEnforced(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.newAdmin(co) // one active member
	s := a.login(admin)

	a.exec(`UPDATE tbl_clients SET max_seats = 1 WHERE id = $1`, co.ID)

	// Inviting only stages intent; accepting is what would exceed the cap.
	email, tok := a.invite(s)
	expect(t, a.post("/auth/accept-invitation", map[string]any{"token": tok, "password": testPassword}),
		http.StatusConflict, "accept past the seat cap")
	// The failed accept rolled back: the invitation is still pending.
	if n := a.count(`SELECT count(*) FROM tbl_users WHERE client_id = $1 AND email = $2`, co.ID, email); n != 0 {
		t.Fatal("a user was created despite the seat cap")
	}

	// Raising the cap lets the very same invitation through.
	a.exec(`UPDATE tbl_clients SET max_seats = 2 WHERE id = $1`, co.ID)
	expect(t, a.post("/auth/accept-invitation", map[string]any{"token": tok, "password": testPassword}),
		http.StatusNoContent, "accept once the cap is raised")
	var newcomer string
	a.scalar(&newcomer, `SELECT id FROM tbl_users WHERE client_id = $1 AND email = $2`, co.ID, email)

	// At capacity again (admin + newcomer = 2, cap 2). Free a seat, fill it with a
	// third person, then reactivating the newcomer would be a third active member.
	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+newcomer, map[string]any{"is_active": false}, bearer(s.Access)),
		http.StatusOK, "deactivate the newcomer")
	_, tok2 := a.invite(s)
	expect(t, a.post("/auth/accept-invitation", map[string]any{"token": tok2, "password": testPassword}),
		http.StatusNoContent, "a third person fills the freed seat")
	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+newcomer, map[string]any{"is_active": true}, bearer(s.Access)),
		http.StatusConflict, "reactivating past the cap")

	// A NULL cap is unlimited: the same reactivation now succeeds.
	a.exec(`UPDATE tbl_clients SET max_seats = NULL WHERE id = $1`, co.ID)
	expect(t, a.send(http.MethodPatch, "/api/admin/users/"+newcomer, map[string]any{"is_active": true}, bearer(s.Access)),
		http.StatusOK, "reactivation allowed when uncapped")
}

// A product subscription's seat_limit caps the DISTINCT people who may open it.
// Joining a group that grants the product consumes a seat; past the cap the join
// is refused (409), and raising the cap lets it through. The common path, end to
// end through the Admin door.
func TestProductSeatLimitBlocksGroupJoin(t *testing.T) {
	a := newApp(t)
	co := a.newCompany()
	admin := a.newAdmin(co)
	s := a.login(admin)
	p := a.newProduct("Viewer")
	a.subscribe(co, p)
	a.exec(`UPDATE tbl_client_products SET seat_limit = 1 WHERE client_id = $1 AND product_id = $2`, co.ID, p.ID)
	g := a.newGroup(co)
	a.grantGroup(co, g, p, "Viewer")
	u1 := a.newMember(co, "")
	u2 := a.newMember(co, "")

	expect(t, a.post("/api/admin/groups/"+g+"/members", map[string]any{"user_id": u1.ID}, bearer(s.Access)),
		http.StatusCreated, "first member joins")
	expect(t, a.post("/api/admin/groups/"+g+"/members", map[string]any{"user_id": u2.ID}, bearer(s.Access)),
		http.StatusConflict, "second member would exceed the product seat limit")
	// A failed join leaves no membership behind (the whole statement rolled back).
	if n := a.count(`SELECT count(*) FROM tbl_user_groups WHERE group_id = $1 AND user_id = $2`, g, u2.ID); n != 0 {
		t.Fatal("a membership survived the seat-limit refusal")
	}

	a.exec(`UPDATE tbl_client_products SET seat_limit = 2 WHERE client_id = $1 AND product_id = $2`, co.ID, p.ID)
	expect(t, a.post("/api/admin/groups/"+g+"/members", map[string]any{"user_id": u2.ID}, bearer(s.Access)),
		http.StatusCreated, "second member joins once the cap is raised")
}

// The direct-grant and group-product-grant paths enforce seat_limit too. Checked
// at the service layer (direct grants and group product grants are the Owner's),
// asserting the database refuses the overflow with the seat-limit SQLSTATE.
func TestProductSeatLimitBlocksDirectAndGroupGrant(t *testing.T) {
	a := newApp(t)
	ctx := context.Background()
	co := a.newCompany()
	p := a.newProduct("Viewer")
	a.subscribe(co, p)
	a.exec(`UPDATE tbl_client_products SET seat_limit = 1 WHERE client_id = $1 AND product_id = $2`, co.ID, p.ID)
	u1 := a.newMember(co, "")
	u2 := a.newMember(co, "")
	pp := productpermissions.NewProductPermissionDbService(a.owner)

	// Direct grant: first fills the single seat, second is refused.
	if err := pp.Upsert(ctx, u1.ID, co.ID, p.ID, "Viewer", u1.ID); err != nil {
		t.Fatalf("first direct grant: %v", err)
	}
	if err := pp.Upsert(ctx, u2.ID, co.ID, p.ID, "Viewer", u2.ID); !exceptions.IsSeatLimit(err) {
		t.Fatalf("second direct grant should hit the seat limit, got %v", err)
	}
	// Re-granting the SAME user who already holds a seat is not a new seat.
	if err := pp.Upsert(ctx, u1.ID, co.ID, p.ID, "Viewer", u1.ID); err != nil {
		t.Fatalf("re-granting an existing holder should be free: %v", err)
	}

	// Group product grant: a product attached to a 2-member group grants it to
	// both at once, exceeding a cap of 1.
	a.exec(`DELETE FROM tbl_product_permissions WHERE client_id = $1 AND product_id = $2`, co.ID, p.ID)
	g := a.newGroup(co)
	a.join(u1, g)
	a.join(u2, g)
	if _, err := groups.NewGroupDbService(a.owner).SetProductGrants(ctx, g, co.ID,
		[]groups.ProductGrant{{ProductID: p.ID, RoleName: "Viewer"}}, ""); !exceptions.IsSeatLimit(err) {
		t.Fatalf("granting a product to a 2-member group at cap 1 should hit the seat limit, got %v", err)
	}
}
