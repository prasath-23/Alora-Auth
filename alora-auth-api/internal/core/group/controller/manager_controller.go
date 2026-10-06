package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/group/models"
	"github.com/alora/auth/internal/core/group/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/alora/auth/internal/middlewares"
	"github.com/gin-gonic/gin"
)

// ManagerController appoints and dismisses group managers through the company
// doors: a company's groups:edit holders on their own company, the Owner on
// any.
type ManagerController struct {
	svc   service.ManagerService
	scope shared.ScopeResolver
}

// NewManagerController builds the controller for the routes scope resolves.
func NewManagerController(svc service.ManagerService, scope shared.ScopeResolver) *ManagerController {
	return &ManagerController{svc: svc, scope: scope}
}

// userParam is the user id from the path: :userId on the admin routes, :uid
// under the Owner console's company and on the manager's door.
func userParam(c *gin.Context) string {
	if id := c.Param("uid"); id != "" {
		return id
	}
	return c.Param("userId")
}

// Appoint handles POST /api/admin/groups/:id/managers.
//
//	@Summary		Appoint a group manager
//	@Description	Makes someone — by EITHER `user_id` or `email` — a manager of the group: they may add and remove its members, and nothing else, without `groups:edit`. Needs `groups:edit` and every scope the group gives (a manager can hand the group out), and the person may have no more reach than you: the scopes they hold plus those of the groups they already manage. You can't appoint yourself, and the Admins group never has managers. The Owner console appoints at /api/owner/companies/{cid}/groups/{gid}/managers, bound by neither scope rule.
//	@Tags			groups
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"Group id"	example(1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d)
//	@Param			request	body		models.AppointManagerRequest	true	"User id or email address"
//	@Success		201		{object}	models.AppointmentResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Neither user_id nor email, a malformed body, or yourself"
//	@Failure		401		{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks groups:edit, lacks one of the group's scopes, or the person has more reach"
//	@Failure		404		{object}	exceptions.ErrorResponse	"No such group or user in this company"
//	@Failure		409		{object}	exceptions.ErrorResponse	"The Admins group, or they already manage it"
//	@Router			/api/admin/groups/{id}/managers [post]
func (h *ManagerController) Appoint(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.AppointManagerRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	a, err := h.svc.Appoint(c.Request.Context(), scope, groupParam(c), req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.NewAppointmentResponse(a))
}

// Dismiss handles DELETE /api/admin/groups/:id/managers/:userId.
//
//	@Summary		Dismiss a group manager
//	@Description	Ends an appointment. Needs `groups:edit` and every scope the group gives, and the manager may have no more reach than you. The Owner console dismisses at /api/owner/companies/{cid}/groups/{gid}/managers/{uid}.
//	@Tags			groups
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id		path	string	true	"Group id"	example(1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d)
//	@Param			userId	path	string	true	"User id"	example(4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d)
//	@Success		204				"Dismissed"
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks groups:edit, lacks one of the group's scopes, or the manager has more reach"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such group, user or appointment in this company"
//	@Router			/api/admin/groups/{id}/managers/{userId} [delete]
func (h *ManagerController) Dismiss(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.Dismiss(c.Request.Context(), scope, groupParam(c), userParam(c)); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ManagedGroupController is a manager's own door, /api/me/managed-groups: the
// groups they run, always in their own company. It has no scope resolver on
// purpose — what it may touch is decided group by group, by the database, on
// every call.
type ManagedGroupController struct {
	svc service.ManagerService
}

// NewManagedGroupController builds the manager's door.
func NewManagedGroupController(svc service.ManagerService) *ManagedGroupController {
	return &ManagedGroupController{svc: svc}
}

// List handles GET /api/me/managed-groups.
//
//	@Summary		The groups I manage
//	@Description	Every group the caller manages, with what it gives and how many members it has. Empty for anyone who manages none; needs no scope.
//	@Tags			me
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{array}		models.GroupListItemResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Router			/api/me/managed-groups [get]
func (h *ManagedGroupController) List(c *gin.Context) {
	groups, err := h.svc.Managed(c.Request.Context(), middlewares.ActorFrom(c))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewGroupListResponse(groups))
}

// Get handles GET /api/me/managed-groups/:gid.
//
//	@Summary		A group I manage
//	@Description	One group the caller manages: its members, its managers, what it gives and the sign-in policy it carries — adding someone can put them under that policy. A group the caller does not manage is not found.
//	@Tags			me
//	@Security		BearerAuth
//	@Produce		json
//	@Param			gid	path		string	true	"Group id"	example(1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d)
//	@Success		200	{object}	models.GroupDetailResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		404	{object}	exceptions.ErrorResponse	"Not a group you manage"
//	@Router			/api/me/managed-groups/{gid} [get]
func (h *ManagedGroupController) Get(c *gin.Context) {
	group, err := h.svc.ManagedGroup(c.Request.Context(), middlewares.ActorFrom(c), c.Param("gid"))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewGroupDetailResponse(group))
}

// AddMember handles POST /api/me/managed-groups/:gid/members.
//
//	@Summary		Add a member to a group I manage
//	@Description	Identify the person by EITHER `user_id` or `email`. They must have no more reach than you — the scopes you hold plus those of the groups you manage — and may not be one of the group's managers, you included. Budgeted per account.
//	@Tags			me
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			gid		path		string					true	"Group id"	example(1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d)
//	@Param			request	body		models.AddMemberRequest	true	"User id or email address"
//	@Success		201		{object}	models.AddMemberResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Neither user_id nor email, or a malformed body"
//	@Failure		401		{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403		{object}	exceptions.ErrorResponse	"One of the group's managers, or someone with more reach"
//	@Failure		404		{object}	exceptions.ErrorResponse	"Not a group you manage, or no such user"
//	@Failure		409		{object}	exceptions.ErrorResponse	"Already a member"
//	@Failure		429		{object}	exceptions.ErrorResponse	"Too many changes; see Retry-After"
//	@Router			/api/me/managed-groups/{gid}/members [post]
func (h *ManagedGroupController) AddMember(c *gin.Context) {
	var req models.AddMemberRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	m, err := h.svc.AddMember(c.Request.Context(), middlewares.ActorFrom(c), c.Param("gid"), req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.NewAddMemberResponse(m))
}

// RemoveMember handles DELETE /api/me/managed-groups/:gid/members/:uid.
//
//	@Summary		Remove a member from a group I manage
//	@Description	The member must have no more reach than you and may not be one of the group's managers, you included. Budgeted per account.
//	@Tags			me
//	@Security		BearerAuth
//	@Produce		json
//	@Param			gid	path	string	true	"Group id"	example(1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d)
//	@Param			uid	path	string	true	"User id"	example(4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d)
//	@Success		204			"Removed"
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"One of the group's managers, or someone with more reach"
//	@Failure		404	{object}	exceptions.ErrorResponse	"Not a group you manage, or not a member"
//	@Failure		429	{object}	exceptions.ErrorResponse	"Too many changes; see Retry-After"
//	@Router			/api/me/managed-groups/{gid}/members/{uid} [delete]
func (h *ManagedGroupController) RemoveMember(c *gin.Context) {
	if err := h.svc.RemoveMember(c.Request.Context(), middlewares.ActorFrom(c), c.Param("gid"), userParam(c)); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
