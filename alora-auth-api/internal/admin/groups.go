package admin

import (
	"errors"
	"net/http"

	"github.com/alora/auth/internal/middleware"
	"github.com/alora/auth/internal/platform/database"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

// ListGroups handles GET /admin/groups.
func (h *Handler) ListGroups(c *gin.Context) {
	u := middleware.UserFrom(c)
	rows, err := h.q.ListGroups(c.Request.Context(), u.ClientID)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	items := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		items = append(items, gin.H{
			"id": r.ID, "name": r.Name, "description": r.Description.String,
			"features": rawFeatures(r.Features), "member_count": r.MemberCount,
			"created_at": database.TimePtr(r.CreatedAt),
		})
	}
	c.JSON(http.StatusOK, items) // bare array (Fastify shape)
}

// GetGroup handles GET /admin/groups/:id.
func (h *Handler) GetGroup(c *gin.Context) {
	u := middleware.UserFrom(c)
	rows, err := h.q.GetGroupDetail(c.Request.Context(), sqlc.GetGroupDetailParams{
		PGroupid: c.Param("id"), PClientid: u.ClientID,
	})
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	if len(rows) == 0 {
		httpx.Fail(c, httpx.ErrNotFound)
		return
	}
	head := rows[0]
	// One row per member; a group with no members still yields a single row with
	// NULL member columns.
	members := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		if r.UserID.Valid {
			members = append(members, gin.H{
				"user_id": r.UserID.String, "email": r.UserEmail.String,
				"assigned_at": database.TimePtr(r.AssignedAt),
			})
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"id": head.ID, "name": head.Name, "description": head.Description.String,
		"features": rawFeatures(head.Features), "members": members,
		"created_at": database.TimePtr(head.CreatedAt),
	})
}

type groupRequest struct {
	Name        string   `json:"name" validate:"required,min=1,max=100"`
	Description string   `json:"description" validate:"omitempty,max=500"`
	Features    []string `json:"features" validate:"omitempty,dive,required"`
}

// validateFeatures rejects any key outside the closed registry, so a typo cannot
// silently create an unreachable grant and an attacker cannot invent a key that
// some future route might honour.
func validateFeatures(keys []string) ([]string, error) {
	seen := make(map[string]struct{}, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if _, ok := middleware.AdminFeatures[k]; !ok {
			return nil, httpx.NewAPIError(http.StatusBadRequest, "Unknown feature key: "+k, nil)
		}
		if _, dup := seen[k]; dup {
			continue // de-dupe; the unique index would otherwise abort the tx
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out, nil
}

// CreateGroup handles POST /admin/groups.
func (h *Handler) CreateGroup(c *gin.Context) {
	u := middleware.UserFrom(c)
	var req groupRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	features, err := validateFeatures(req.Features)
	if err != nil {
		httpx.Fail(c, err)
		return
	}

	ctx := c.Request.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := h.q.WithTx(tx)

	grp, err := qtx.CreateGroup(ctx, sqlc.CreateGroupParams{
		ClientID: u.ClientID, Name: req.Name, Description: database.TextOrNull(req.Description),
	})
	if err != nil {
		if httpx.IsUniqueViolation(err) {
			httpx.FailWith(c, http.StatusConflict, "A group with this name already exists")
			return
		}
		httpx.Fail(c, err)
		return
	}
	if _, err := qtx.SetGroupFeatures(ctx, sqlc.SetGroupFeaturesParams{
		GroupID: grp.ID, ClientID: u.ClientID, FeatureKeys: features,
	}); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.Fail(c, err)
		return
	}
	h.logEvent(c, u, "group.created")
	c.JSON(http.StatusCreated, gin.H{"id": grp.ID, "name": grp.Name, "features": features})
}

// UpdateGroup handles PATCH /admin/groups/:id. Features are replaced wholesale
// (delete-then-insert inside one transaction) so the request body is the
// complete desired state rather than a diff the client must compute.
func (h *Handler) UpdateGroup(c *gin.Context) {
	u := middleware.UserFrom(c)
	groupID := c.Param("id")

	var req groupRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	features, err := validateFeatures(req.Features)
	if err != nil {
		httpx.Fail(c, err)
		return
	}

	ctx := c.Request.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := h.q.WithTx(tx)

	if _, err := qtx.UpdateGroup(ctx, sqlc.UpdateGroupParams{
		GroupID: groupID, ClientID: u.ClientID, Name: req.Name,
		Description: database.TextOrNull(req.Description),
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.Fail(c, httpx.ErrNotFound)
			return
		}
		if httpx.IsUniqueViolation(err) {
			httpx.FailWith(c, http.StatusConflict, "A group with this name already exists")
			return
		}
		httpx.Fail(c, err)
		return
	}
	// One call: stp_SetGroupFeatures owns the delete-then-insert and re-derives
	// tenant ownership itself, so a mis-routed group id cannot touch another
	// tenant's rows even if this handler's checks were bypassed.
	if _, err := qtx.SetGroupFeatures(ctx, sqlc.SetGroupFeaturesParams{
		GroupID: groupID, ClientID: u.ClientID, FeatureKeys: features,
	}); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.Fail(c, err)
		return
	}
	h.logEvent(c, u, "group.updated")
	c.JSON(http.StatusOK, gin.H{"id": groupID, "name": req.Name, "features": features})
}

// DeleteGroup handles DELETE /admin/groups/:id. Memberships and feature rows
// cascade at the database level.
func (h *Handler) DeleteGroup(c *gin.Context) {
	u := middleware.UserFrom(c)
	n, err := h.q.DeleteGroup(c.Request.Context(), sqlc.DeleteGroupParams{
		PGroupid: c.Param("id"), PClientid: u.ClientID,
	})
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	if n == 0 {
		httpx.Fail(c, httpx.ErrNotFound)
		return
	}
	h.logEvent(c, u, "group.deleted")
	c.Status(http.StatusNoContent)
}

// memberRequest mirrors Fastify: EITHER userId or email (camelCase). Email is
// accepted because groups:manage does not imply users:view — a group manager may
// legitimately know a colleague's address without being able to list users.
type memberRequest struct {
	UserID string `json:"userId" validate:"omitempty,uuid4"`
	Email  string `json:"email" validate:"omitempty,email,max=254"`
}

// AddMember handles POST /admin/groups/:id/members.
func (h *Handler) AddMember(c *gin.Context) {
	u := middleware.UserFrom(c)
	groupID := c.Param("id")

	var req memberRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	if req.UserID == "" && req.Email == "" {
		httpx.FailWith(c, http.StatusBadRequest, "Provide userId or email")
		return
	}
	ctx := c.Request.Context()

	// Both the group AND the user must belong to the caller's tenant. The
	// composite FK on tbl_user_groups would also reject a mismatch, but failing
	// here produces a clean 404 instead of a constraint-violation 500.
	if _, err := h.q.GetGroupTenantScoped(ctx, sqlc.GetGroupTenantScopedParams{
		PGroupid: groupID, PClientid: u.ClientID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.Fail(c, httpx.ErrNotFound)
			return
		}
		httpx.Fail(c, err)
		return
	}
	// Resolve the target to a concrete id, whichever identifier was supplied.
	// Both lookups are tenant-scoped, so an id or address from another
	// organisation reports not-found rather than being added.
	targetID := req.UserID
	if targetID != "" {
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
	} else {
		row, err := h.q.UserIdByEmail(ctx, sqlc.UserIdByEmailParams{
			PClientid: u.ClientID, PEmail: httpx.NormalizeEmail(req.Email),
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				httpx.Fail(c, httpx.ErrNotFound)
				return
			}
			httpx.Fail(c, err)
			return
		}
		targetID = row
	}

	if err := h.q.AddGroupMember(ctx, sqlc.AddGroupMemberParams{
		UserID: targetID, GroupID: groupID, ClientID: u.ClientID,
		AssignedBy: database.Text(u.UserID),
	}); err != nil {
		if httpx.IsUniqueViolation(err) {
			httpx.FailWith(c, http.StatusConflict, "User is already a member of this group")
			return
		}
		httpx.Fail(c, err)
		return
	}
	// Group membership can confer features, so cached tokens must be refreshed.
	if err := h.q.BumpPermissionsVersion(ctx, sqlc.BumpPermissionsVersionParams{
		PUserid: targetID, PClientid: u.ClientID,
	}); err != nil {
		httpx.Fail(c, err)
		return
	}
	h.logEvent(c, u, "group.member_added")
	c.JSON(http.StatusCreated, gin.H{"group_id": groupID, "user_id": targetID})
}

// RemoveMember handles DELETE /admin/groups/:id/members/:userId.
func (h *Handler) RemoveMember(c *gin.Context) {
	u := middleware.UserFrom(c)
	targetID := c.Param("userId")

	// Scoped by (user_id, group_id, client_id) so a foreign group id removes
	// nothing.
	n, err := h.q.RemoveGroupMember(c.Request.Context(), sqlc.RemoveGroupMemberParams{
		PUserid: targetID, PGroupid: c.Param("id"), PClientid: u.ClientID,
	})
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	if n == 0 {
		httpx.Fail(c, httpx.ErrNotFound)
		return
	}
	if err := h.q.BumpPermissionsVersion(c.Request.Context(),
		sqlc.BumpPermissionsVersionParams{PUserid: targetID, PClientid: u.ClientID}); err != nil {
		httpx.Fail(c, err)
		return
	}
	h.logEvent(c, u, "group.member_removed")
	c.Status(http.StatusNoContent)
}

// MyFeatures handles GET /admin/me/features — the effective feature keys for the
// caller, used by the UI to decide what to render.
func (h *Handler) MyFeatures(c *gin.Context) {
	u := middleware.UserFrom(c)
	// A global admin — or anyone holding the "Admin" role in ANY product —
	// implicitly holds every feature. Ranging the roles map's VALUES mirrors the
	// RBAC precedence used by RequireAdmin.
	isAdmin := u.IsGlobalAdmin
	if !isAdmin {
		for _, role := range u.Roles {
			if role == "Admin" {
				isAdmin = true
				break
			}
		}
	}
	if isAdmin {
		out := make([]string, 0, len(middleware.AdminFeatures))
		for k := range middleware.AdminFeatures {
			out = append(out, k)
		}
		c.JSON(http.StatusOK, gin.H{"features": out, "is_global_admin": u.IsGlobalAdmin})
		return
	}
	rows, err := h.q.ListUserFeatures(c.Request.Context(), sqlc.ListUserFeaturesParams{
		PClientid: u.ClientID, PUserid: u.UserID,
	})
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	keys := make([]string, 0, len(rows))
	for _, k := range rows {
		if k.Valid {
			keys = append(keys, k.String)
		}
	}
	c.JSON(http.StatusOK, gin.H{"features": keys, "is_global_admin": false})
}
