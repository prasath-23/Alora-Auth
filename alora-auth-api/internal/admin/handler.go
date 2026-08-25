// Package admin serves the tenant-administration surface: users, groups,
// permissions, sessions, products and client settings.
//
// EVERY handler scopes its queries by the client_id from the CALLER'S VERIFIED
// TOKEN. No handler accepts a tenant identifier from a path, query or body — that
// is the single rule that makes cross-tenant access impossible at this layer,
// backed by composite foreign keys at the database layer.
package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/alora/auth/internal/middleware"
	"github.com/alora/auth/internal/platform/audit"
	"github.com/alora/auth/internal/platform/database"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Handler struct {
	pool  *pgxpool.Pool
	q     *sqlc.Queries
	audit *audit.Logger
}

func New(pool *pgxpool.Pool, q *sqlc.Queries, a *audit.Logger) *Handler {
	return &Handler{pool: pool, q: q, audit: a}
}

func (h *Handler) logEvent(c *gin.Context, u *middleware.AuthUser, event string) {
	reqID := httpx.RequestIDFrom(c)
	h.audit.Log(audit.Entry{
		ClientID: u.ClientID, ActorUserID: &u.UserID, EventType: event, RequestID: &reqID,
	})
}

// ---------- USERS ----------

// ListUsers handles GET /admin/users.
//
// Wire contract mirrors Fastify exactly: query is ?cursor=<userId>&take=<n>&search=,
// and the response is {users:[...], nextCursor:<userId|null>}. The cursor is an
// opaque user id to the client; internally it resolves to a (created_at, id)
// keyset position, which is stable under concurrent inserts in a way OFFSET is not.
func (h *Handler) ListUsers(c *gin.Context) {
	u := middleware.UserFrom(c)
	ctx := c.Request.Context()

	take := 25 // Fastify default
	if v := c.Query("take"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			httpx.FailWith(c, http.StatusBadRequest, "Invalid request")
			return
		}
		take = n
	}

	params := sqlc.ListUsersParams{
		ClientID: u.ClientID,
		Search:   database.TextOrNull(c.Query("search")),
		Take:     int32(take + 1), // peek one row ahead to detect a next page
	}
	if cursor := c.Query("cursor"); cursor != "" {
		// Tenant-scoped resolve: a cursor belonging to another tenant simply does
		// not resolve, rather than revealing a position in their list.
		createdAt, err := h.q.UserCursorPosition(ctx, sqlc.UserCursorPositionParams{
			PUserid: cursor, PClientid: u.ClientID,
		})
		if err != nil {
			httpx.FailWith(c, http.StatusBadRequest, "Invalid request")
			return
		}
		params.CursorCreated = createdAt
		params.CursorID = database.Text(cursor)
	}

	rows, err := h.q.ListUsers(ctx, params)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	hasNext := len(rows) > take
	if hasNext {
		rows = rows[:take]
	}

	// Group memberships for the whole page in ONE query rather than N+1.
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	groupsByUser := map[string][]gin.H{}
	if len(ids) > 0 {
		gs, err := h.q.ListUserGroups(ctx, sqlc.ListUserGroupsParams{
			ClientID: u.ClientID, UserIds: ids,
		})
		if err != nil {
			httpx.Fail(c, err)
			return
		}
		for _, g := range gs {
			groupsByUser[g.UserID] = append(groupsByUser[g.UserID],
				gin.H{"id": g.GroupID, "name": g.GroupName})
		}
	}

	items := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		g := groupsByUser[r.ID]
		if g == nil {
			g = []gin.H{} // never emit JSON null for a collection
		}
		// password_hash and deleted_at are not projected by the query at all.
		items = append(items, gin.H{
			"id": r.ID, "email": r.Email, "is_active": r.IsActive,
			"account_type": string(r.AccountType),
			"created_at":   database.TimePtr(r.CreatedAt), "groups": g,
		})
	}

	var nextCursor any // null, not "", when there is no further page
	if hasNext && len(rows) > 0 {
		nextCursor = rows[len(rows)-1].ID
	}
	c.JSON(http.StatusOK, gin.H{"users": items, "nextCursor": nextCursor})
}

// GetUser handles GET /admin/users/:id.
//
// Composed from three focused reads rather than one wide join. The previous
// single query LEFT JOINed permissions and groups together, producing a cartesian
// product the handler then had to de-duplicate — a correctness hazard accepted
// for one round trip. Three small calls cannot double-count.
func (h *Handler) GetUser(c *gin.Context) {
	u := middleware.UserFrom(c)
	ctx := c.Request.Context()
	targetID := c.Param("id")

	user, err := h.q.GetUserTenantScoped(ctx, sqlc.GetUserTenantScopedParams{
		PUserid: targetID, PClientid: u.ClientID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.Fail(c, httpx.ErrNotFound) // unknown and cross-tenant are identical
			return
		}
		httpx.Fail(c, err)
		return
	}

	roles, err := h.q.ListUserProductRoles(ctx, sqlc.ListUserProductRolesParams{
		PUserid: targetID, PClientid: u.ClientID,
	})
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	groups, err := h.q.ListUserGroups(ctx, sqlc.ListUserGroupsParams{
		ClientID: u.ClientID, UserIds: []string{targetID},
	})
	if err != nil {
		httpx.Fail(c, err)
		return
	}

	perms := make([]gin.H, 0, len(roles))
	for _, r := range roles {
		perms = append(perms, gin.H{
			"product_id": r.ProductID, "product_key": r.ProductKey,
			"product_name": r.ProductName, "role_name": r.RoleName,
			"valid_until": database.TimePtr(r.ValidUntil),
		})
	}
	grps := make([]gin.H, 0, len(groups))
	for _, g := range groups {
		grps = append(grps, gin.H{
			"id": g.GroupID, "name": g.GroupName,
			"assigned_at": database.TimePtr(g.AssignedAt),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"id": user.ID, "email": user.Email, "account_type": user.AccountType,
		"is_active": user.IsActive, "is_global_admin": user.IsGlobalAdmin,
		"created_at": database.TimePtr(user.CreatedAt), "updated_at": database.TimePtr(user.UpdatedAt),
		"permissions": perms, "groups": grps,
	})
}

type updateUserRequest struct {
	IsActive *bool `json:"is_active" validate:"required"`
}

// UpdateUser handles PATCH /admin/users/:id (activate / deactivate).
func (h *Handler) UpdateUser(c *gin.Context) {
	u := middleware.UserFrom(c)
	targetID := c.Param("id")

	// Self-lockout guard: an admin disabling their own account could strand the
	// tenant with no way back in.
	if targetID == u.UserID {
		httpx.FailWith(c, http.StatusBadRequest, "Cannot modify your own account")
		return
	}

	var req updateUserRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}

	n, err := h.q.SetUserActive(c.Request.Context(), sqlc.SetUserActiveParams{
		PUserid: targetID, PClientid: u.ClientID, PIsactive: *req.IsActive,
	})
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	if n == 0 {
		httpx.Fail(c, httpx.ErrNotFound)
		return
	}

	// Deactivation must take effect immediately, not when the access token
	// expires: bumping permissions_version invalidates it on the next request,
	// and revoking sessions kills the refresh chain.
	if !*req.IsActive {
		ctx := c.Request.Context()
		if err := h.q.BumpPermissionsVersion(ctx, sqlc.BumpPermissionsVersionParams{
			PUserid: targetID, PClientid: u.ClientID,
		}); err != nil {
			httpx.Fail(c, err)
			return
		}
		if _, err := h.q.RevokeAllUserSessions(ctx, sqlc.RevokeAllUserSessionsParams{
			UserID: targetID, Reason: sqlc.SessionRevokedReasonADMIN,
		}); err != nil {
			httpx.Fail(c, err)
			return
		}
	}
	h.logEvent(c, u, "user.updated")
	c.JSON(http.StatusOK, gin.H{"id": targetID, "is_active": *req.IsActive})
}

// ---------- PERMISSIONS ----------

// ListPermissions handles GET /admin/users/:id/permissions.
func (h *Handler) ListPermissions(c *gin.Context) {
	u := middleware.UserFrom(c)
	rows, err := h.q.ListUserProductRoles(c.Request.Context(),
		sqlc.ListUserProductRolesParams{PUserid: c.Param("id"), PClientid: u.ClientID})
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	items := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		items = append(items, gin.H{
			"product_id": r.ProductID, "product_key": r.ProductKey,
			"product_name": r.ProductName, "role_name": r.RoleName,
		})
	}
	// Bare array — matches the Fastify response shape the SPA parses.
	c.JSON(http.StatusOK, items)
}

// grantRequest mirrors the Fastify contract exactly: productId travels in the
// PATH, and the body carries only camelCase `roleName`. Unknown fields are
// rejected, so any drift here is a hard 400 for the existing UI.
type grantRequest struct {
	RoleName string `json:"roleName" validate:"required,max=64"`
}

// GrantPermission handles PUT /admin/users/:id/permissions/:productId.
func (h *Handler) GrantPermission(c *gin.Context) {
	u := middleware.UserFrom(c)
	targetID := c.Param("id")

	productID := c.Param("productId")

	var req grantRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	ctx := c.Request.Context()

	// Confirm the target belongs to the caller's tenant BEFORE writing: the
	// upsert alone would happily create a grant row for a foreign user id.
	if _, err := h.q.GetUserTenantScoped(ctx, sqlc.GetUserTenantScopedParams{
		PUserid: targetID, PClientid: u.ClientID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.Fail(c, httpx.ErrNotFound)
			return
		}
		httpx.Fail(c, err)
		return
	}
	// The tenant must actually subscribe to the product being granted.
	if _, err := h.q.ActiveSubscriptionId(ctx, sqlc.ActiveSubscriptionIdParams{
		PClientid: u.ClientID, PProductid: productID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// 403 (not 400) — matches the Fastify status for an unsubscribed product.
			httpx.FailWith(c, http.StatusForbidden, "Tenant is not subscribed to this product")
			return
		}
		httpx.Fail(c, err)
		return
	}

	if err := h.q.UpsertProductPermission(ctx, sqlc.UpsertProductPermissionParams{
		PUserid: targetID, PClientid: u.ClientID, PProductid: productID,
		PRolename: req.RoleName, PGrantedby: u.UserID,
	}); err != nil {
		httpx.Fail(c, err)
		return
	}
	// Roles live inside the JWT, so a grant only takes effect once the token is
	// re-minted — the version bump forces that on the next request.
	if err := h.q.BumpPermissionsVersion(ctx, sqlc.BumpPermissionsVersionParams{
		PUserid: targetID, PClientid: u.ClientID,
	}); err != nil {
		httpx.Fail(c, err)
		return
	}
	h.logEvent(c, u, "permission.granted")
	c.JSON(http.StatusOK, gin.H{"user_id": targetID, "product_id": productID, "role_name": req.RoleName})
}

// RevokePermission handles DELETE /admin/users/:id/permissions/:productId.
func (h *Handler) RevokePermission(c *gin.Context) {
	u := middleware.UserFrom(c)
	targetID := c.Param("id")
	ctx := c.Request.Context()

	n, err := h.q.DeleteProductPermission(ctx, sqlc.DeleteProductPermissionParams{
		PUserid: targetID, PClientid: u.ClientID, PProductid: c.Param("productId"),
	})
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	if n == 0 {
		httpx.Fail(c, httpx.ErrNotFound)
		return
	}
	if err := h.q.BumpPermissionsVersion(ctx, sqlc.BumpPermissionsVersionParams{
		PUserid: targetID, PClientid: u.ClientID,
	}); err != nil {
		httpx.Fail(c, err)
		return
	}
	h.logEvent(c, u, "permission.revoked")
	c.Status(http.StatusNoContent)
}

// ---------- SESSIONS ----------

// ListSessions handles GET /admin/sessions.
func (h *Handler) ListSessions(c *gin.Context) {
	u := middleware.UserFrom(c)
	rows, err := h.q.ListActiveSessions(c.Request.Context(), u.ClientID)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	items := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		// The query projects no token hashes, no revoked_reason and no user_id
		// (Decision D10b).
		items = append(items, gin.H{
			"id": r.ID, "device_label": r.DeviceLabel.String, "ip_address": r.IpAddress.String,
			"last_seen_at": database.TimePtr(r.LastSeenAt), "created_at": database.TimePtr(r.CreatedAt),
		})
	}
	c.JSON(http.StatusOK, items) // bare array (Fastify shape)
}

// RevokeSession handles DELETE /admin/sessions/:id.
func (h *Handler) RevokeSession(c *gin.Context) {
	u := middleware.UserFrom(c)
	n, err := h.q.RevokeSession(c.Request.Context(), sqlc.RevokeSessionParams{
		SessionID: c.Param("id"), ClientID: u.ClientID, Reason: sqlc.SessionRevokedReasonADMIN,
	})
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	if n == 0 {
		httpx.Fail(c, httpx.ErrNotFound)
		return
	}
	h.logEvent(c, u, "session.revoked")
	c.Status(http.StatusNoContent)
}

// ---------- PRODUCTS / CLIENT ----------

// ListProducts handles GET /admin/products (the tenant's subscriptions).
func (h *Handler) ListProducts(c *gin.Context) {
	u := middleware.UserFrom(c)
	rows, err := h.q.ListClientProducts(c.Request.Context(), u.ClientID)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	// Field-for-field parity with Fastify: `id` is the SUBSCRIPTION id (not the
	// product id), and nullable columns render as JSON null rather than "" / 0 so
	// the UI can distinguish "unset" from "zero".
	items := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		var seatLimit any
		if r.SeatLimit.Valid {
			seatLimit = r.SeatLimit.Int32
		}
		items = append(items, gin.H{
			"id":          r.ID,
			"product_id":  r.ProductID,
			"key":         r.ProductKey,
			"name":        r.ProductName,
			"description": nullableString(r.ProductDescription),
			"base_url":    nullableString(r.ProductBaseUrl),
			"is_active":   r.IsActive,
			"seat_limit":  seatLimit,
			"starts_at":   database.TimePtr(r.StartsAt),
			"ends_at":     database.TimePtr(r.EndsAt),
		})
	}
	c.JSON(http.StatusOK, items) // bare array (Fastify shape)
}

// GetClient handles GET /admin/client.
func (h *Handler) GetClient(c *gin.Context) {
	u := middleware.UserFrom(c)
	row, err := h.q.GetClientById(c.Request.Context(), u.ClientID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.Fail(c, httpx.ErrNotFound)
			return
		}
		httpx.Fail(c, err)
		return
	}
	providers := make([]string, 0, len(row.AllowedIdpProviders))
	for _, p := range row.AllowedIdpProviders {
		providers = append(providers, string(p))
	}
	// Field names mirror Fastify exactly. In particular the UI reads
	// `domain_verified_at` (a nullable TIMESTAMP), not a boolean — emitting a
	// bool here would render as "verified on: true".
	var maxSeats any
	if row.MaxSeats.Valid {
		maxSeats = row.MaxSeats.Int32
	}
	c.JSON(http.StatusOK, gin.H{
		"id":                    row.ID,
		"name":                  row.Name,
		"domain":                nullableString(row.Domain),
		"domain_verified_at":    database.TimePtr(row.DomainVerifiedAt),
		"require_mfa":           row.RequireMfa,
		"allowed_idp_providers": providers,
		"subscription_status":   string(row.SubscriptionStatus),
		"max_seats":             maxSeats,
		"is_active":             row.IsActive,
		"created_at":            database.TimePtr(row.CreatedAt),
		"updated_at":            database.TimePtr(row.UpdatedAt),
	})
}

type updateClientRequest struct {
	Name       *string `json:"name" validate:"omitempty,min=1,max=200"`
	RequireMFA *bool   `json:"require_mfa"`
}

// UpdateClient handles PATCH /admin/client.
//
// Only presentation/policy fields are editable. subscription_status, is_active
// and domain_verified_at are deliberately NOT settable here: a tenant admin must
// not be able to self-upgrade their plan, un-suspend their own organisation, or
// self-verify a domain (which would grant CORS trust).
func (h *Handler) UpdateClient(c *gin.Context) {
	u := middleware.UserFrom(c)
	var req updateClientRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	if req.Name == nil && req.RequireMFA == nil {
		httpx.FailWith(c, http.StatusBadRequest, "Invalid request") // empty PATCH
		return
	}

	ctx := c.Request.Context()
	cur, err := h.q.GetClientById(ctx, u.ClientID)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	params := sqlc.UpdateClientParams{
		ClientID: cur.ID, Name: cur.Name, RequireMfa: cur.RequireMfa,
		AllowedIdpProviders: cur.AllowedIdpProviders, DomainVerifiedAt: cur.DomainVerifiedAt,
		SubscriptionStatus: cur.SubscriptionStatus, MaxSeats: cur.MaxSeats, IsActive: cur.IsActive,
	}
	if req.Name != nil {
		params.Name = *req.Name
	}
	if req.RequireMFA != nil {
		params.RequireMfa = *req.RequireMFA
	}
	if _, err := h.q.UpdateClient(ctx, params); err != nil {
		httpx.Fail(c, err)
		return
	}
	h.logEvent(c, u, "client.updated")
	c.JSON(http.StatusOK, gin.H{"id": params.ClientID, "name": params.Name, "require_mfa": params.RequireMfa})
}

// ---------- helpers ----------

// nullableString renders a NULL text column as JSON null rather than "", so the
// UI can distinguish "no domain set" from "empty domain".
func nullableString(t pgtype.Text) any {
	if !t.Valid {
		return nil
	}
	return t.String
}

func values(m map[string]gin.H) []gin.H {
	out := make([]gin.H, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// rawFeatures decodes the aggregated feature-key array from a view column.
//
// The parameter is `any` because sqlc cannot infer a concrete type through the
// jsonb_agg expression in vw_GroupListItem / vw_GroupDetailRow, so it generates
// interface{}. Both forms pgx may produce are handled, and anything unexpected
// degrades to an empty list rather than a 500 — a group whose features cannot be
// read should still render.
func rawFeatures(v any) []string {
	if v == nil {
		return []string{}
	}
	var raw []byte
	switch t := v.(type) {
	case []byte:
		raw = t
	case string:
		raw = []byte(t)
	default:
		// pgx decodes jsonb into a Go value (e.g. []interface{}) when the target is
		// interface{}, so neither branch above fires. Re-marshal and decode: the
		// round trip costs nothing at these sizes and keeps one decode path.
		b, err := json.Marshal(t)
		if err != nil {
			return []string{}
		}
		raw = b
	}
	var out []string
	if len(raw) == 0 || json.Unmarshal(raw, &out) != nil {
		return []string{}
	}
	return out
}
