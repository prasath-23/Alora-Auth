// Package controller serves a company's groups and their memberships.
package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/group/models"
	"github.com/alora/auth/internal/core/group/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// GroupController serves the groups. It is wired twice: on /api/admin, where
// each route needs its groups scope, and on the Owner console. Which products a
// group opens is decided only on the Owner console.
type GroupController struct {
	svc   service.GroupService
	scope shared.ScopeResolver
}

// NewGroupController builds the controller for the routes scope resolves.
func NewGroupController(svc service.GroupService, scope shared.ScopeResolver) *GroupController {
	return &GroupController{svc: svc, scope: scope}
}

// groupParam is the group id from the path: :id on the admin routes, :gid under
// the Owner console's company.
func groupParam(c *gin.Context) string {
	if id := c.Param("gid"); id != "" {
		return id
	}
	return c.Param("id")
}

// List handles GET /api/admin/groups.
//
//	@Summary		List groups
//	@Description	Every group in the company with what it gives — App Central scopes and product roles — its login policy, and how many members it has. The Admins group (`system_key` ADMINS) is always present and holds every scope. Needs `groups:read`.
//	@Tags			groups
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{array}		models.GroupListItemResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks groups:read"
//	@Router			/api/admin/groups [get]
func (h *GroupController) List(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	groups, err := h.svc.List(c.Request.Context(), scope)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewGroupListResponse(groups))
}

// Get handles GET /api/admin/groups/:id.
//
//	@Summary		Get a group
//	@Description	One group with what it grants and its members. A group with no members returns an empty `members` array, never null.
//	@Tags			groups
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id	path		string	true	"Group id"	example(1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d)
//	@Success		200	{object}	models.GroupDetailResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks groups:read"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such group in this company"
//	@Router			/api/admin/groups/{id} [get]
func (h *GroupController) Get(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	group, err := h.svc.Get(c.Request.Context(), scope, groupParam(c))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewGroupDetailResponse(group))
}

// Create handles POST /api/admin/groups and POST /api/owner/companies/:cid/groups.
//
//	@Summary		Create a group
//	@Description	Creates a group with the App Central scopes it gives, in one transaction. Needs `groups:edit`, and you can only give scopes you hold yourself (the Owner excepted). An edit scope brings its read scope. Product grants are the Owner's alone: each must name a product the company subscribes to and a role in its catalogue.
//	@Tags			groups
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		models.CreateGroupRequest	true	"The group"
//	@Success		201		{object}	models.GroupResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body, an unknown scope, or an unusable product grant"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks groups:edit, lacks a scope they tried to give, or is not the Owner and gave products"
//	@Failure		409		{object}	exceptions.ErrorResponse	"A group with this name already exists"
//	@Router			/api/admin/groups [post]
func (h *GroupController) Create(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.CreateGroupRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	group, err := h.svc.Create(c.Request.Context(), scope, req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.NewGroupResponse(group))
}

// Update handles PATCH /api/admin/groups/:id and PATCH /api/owner/companies/:cid/groups/:gid.
//
//	@Summary		Rename a group
//	@Description	Needs `groups:edit`. The Admins group cannot be renamed.
//	@Tags			groups
//	@Security		BearerAuth
//	@Accept			json
//	@Param			id		path	string						true	"Group id"
//	@Param			request	body	models.UpdateGroupRequest	true	"Name and description"
//	@Success		204								"Updated"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks groups:edit"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such group in this company"
//	@Failure		409	{object}	exceptions.ErrorResponse	"The name is taken, or this is the Admins group"
//	@Router			/api/admin/groups/{id} [patch]
func (h *GroupController) Update(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.UpdateGroupRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.Update(c.Request.Context(), scope, groupParam(c), req.Name, req.Description); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// SetScopes handles PUT /api/admin/groups/:id/scopes and PUT /api/owner/companies/:cid/groups/:gid/scopes.
//
//	@Summary		Set the scopes a group gives
//	@Description	The COMPLETE set of App Central scopes: any scope omitted is taken away, and an edit scope brings its read scope. Needs `groups:edit`, and you can only give or take away scopes you hold yourself (the Owner excepted). The Admins group holds every scope and takes none. Every member's next request sees the change.
//	@Tags			groups
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Group id"
//	@Param			request	body		models.SetGroupScopesRequest	true	"The complete set of scopes"
//	@Success		200		{object}	models.GroupScopesResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body or an unknown scope"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks groups:edit, or lacks a scope they tried to give or take"
//	@Failure		404		{object}	exceptions.ErrorResponse	"No such group in this company"
//	@Failure		409		{object}	exceptions.ErrorResponse	"This is the Admins group"
//	@Router			/api/admin/groups/{id}/scopes [put]
func (h *GroupController) SetScopes(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.SetGroupScopesRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	scopes, err := h.svc.SetScopes(c.Request.Context(), scope, groupParam(c), req.Scopes)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewGroupScopesResponse(scopes))
}

// SetProductGrants handles PUT /api/owner/companies/:cid/groups/:gid/product-grants.
//
//	@Summary		Set the product roles a group confers
//	@Description	The COMPLETE set: one role per product, and any product omitted loses the grant. Every member's products see the change at their next refresh, or at once through introspection.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Param			cid						path	string							true	"Company id"
//	@Param			gid						path	string							true	"Group id"
//	@Param			X-Alora-Target-Company	header	string							true	"Must repeat the company id"
//	@Param			request					body	models.SetProductGrantsRequest	true	"Product grants"
//	@Success		204										"Set"
//	@Failure		400	{object}	exceptions.ErrorResponse	"A product the company does not subscribe to, or a role outside its catalogue"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such group in this company"
//	@Router			/api/owner/companies/{cid}/groups/{gid}/product-grants [put]
func (h *GroupController) SetProductGrants(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.SetProductGrantsRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.SetProductGrants(c.Request.Context(), scope, groupParam(c), req.Grants()); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Delete handles DELETE /api/admin/groups/:id and DELETE /api/owner/companies/:cid/groups/:gid.
//
//	@Summary		Delete a group
//	@Description	Memberships and grants cascade; members lose what the group gave. Needs `groups:edit`, and deleting takes the group's scopes away from its members, so you must hold all of them (the Owner excepted). A group that gives products is the Owner's to delete. The Admins group cannot be deleted.
//	@Tags			groups
//	@Security		BearerAuth
//	@Param			id	path	string	true	"Group id"
//	@Success		204						"Deleted"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks groups:edit or one of the group's scopes, or the group gives products"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such group in this company"
//	@Failure		409	{object}	exceptions.ErrorResponse	"This is the Admins group"
//	@Router			/api/admin/groups/{id} [delete]
func (h *GroupController) Delete(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.Delete(c.Request.Context(), scope, groupParam(c)); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
