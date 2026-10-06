package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/group/models"
	"github.com/alora/auth/internal/core/group/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// MemberController serves group memberships: a company's Admins manage their
// own company's, and the Owner any company's.
type MemberController struct {
	svc   service.MemberService
	scope shared.ScopeResolver
}

// NewMemberController builds the controller for the routes scope resolves.
func NewMemberController(svc service.MemberService, scope shared.ScopeResolver) *MemberController {
	return &MemberController{svc: svc, scope: scope}
}

// Add handles POST /api/admin/groups/:id/members.
//
//	@Summary		Add a member to a group
//	@Description	Identify the user by EITHER `user_id` or `email`. Both the group and the user must belong to the company. Adding someone to the Admins group makes them an Admin at once.
//	@Tags			groups
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Group id"	example(1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d)
//	@Param			request	body		models.AddMemberRequest	true	"User id or email address"
//	@Success		201		{object}	models.AddMemberResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Neither user_id nor email supplied, or a malformed body"
//	@Failure		401		{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks groups:edit, lacks one of the group's scopes, or the person has more access"
//	@Failure		404		{object}	exceptions.ErrorResponse	"No such group or user in this company"
//	@Failure		409		{object}	exceptions.ErrorResponse	"User is already a member of this group"
//	@Router			/api/admin/groups/{id}/members [post]
func (h *MemberController) Add(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.AddMemberRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	m, err := h.svc.Add(c.Request.Context(), scope, groupParam(c), req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.NewAddMemberResponse(m))
}

// Remove handles DELETE /api/admin/groups/:id/members/:userId.
//
//	@Summary		Remove a member from a group
//	@Description	Scoped by user, group and company together. The company's last active Admin cannot be removed from the Admins group.
//	@Tags			groups
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id		path	string	true	"Group id"	example(1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d)
//	@Param			userId	path	string	true	"User id"	example(4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d)
//	@Success		204				"Removed"
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks groups:edit, lacks one of the group's scopes, or the person has more access"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such membership in this company"
//	@Failure		409	{object}	exceptions.ErrorResponse	"The last active Admin"
//	@Router			/api/admin/groups/{id}/members/{userId} [delete]
func (h *MemberController) Remove(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.Remove(c.Request.Context(), scope, groupParam(c), userParam(c)); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
