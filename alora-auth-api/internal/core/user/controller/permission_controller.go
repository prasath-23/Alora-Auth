package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/user/models"
	"github.com/alora/auth/internal/core/user/service"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// PermissionController serves direct product grants. It is wired onto the Owner
// console: which products a user may use is the Owner's decision.
type PermissionController struct {
	svc   service.PermissionService
	scope shared.ScopeResolver
}

// NewPermissionController builds the controller for the routes scope resolves.
func NewPermissionController(svc service.PermissionService, scope shared.ScopeResolver) *PermissionController {
	return &PermissionController{svc: svc, scope: scope}
}

// Grant handles PUT /api/owner/companies/:cid/users/:uid/grants/:pid.
//
//	@Summary		Grant a user a product role directly
//	@Description	Creates or replaces the user's direct role in one product. Most access is better granted through a group; a direct grant is for the exception. The company must subscribe to the product and the role must be in the product's catalogue.
//	@Description
//	@Description	Products see the change at their next refresh, or at once if they introspect.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			cid						path	string				true	"Company id"
//	@Param			uid						path	string				true	"User id"
//	@Param			pid						path	string				true	"Product id"
//	@Param			X-Alora-Target-Company	header	string				true	"Must repeat the company id"
//	@Param			request					body	models.GrantRequest	true	"The role"
//	@Success		204										"Granted"
//	@Failure		400	{object}	exceptions.ErrorResponse	"Malformed body, or no such role in the product"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such user in this company"
//	@Failure		409	{object}	exceptions.ErrorResponse	"The company does not subscribe to the product"
//	@Router			/api/owner/companies/{cid}/users/{uid}/grants/{pid} [put]
func (h *PermissionController) Grant(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.GrantRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if _, err := h.svc.Grant(c.Request.Context(), scope, c.Param("uid"), c.Param("pid"), req.RoleName); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Revoke handles DELETE /api/owner/companies/:cid/users/:uid/grants/:pid.
//
//	@Summary		Remove a user's direct product role
//	@Description	Access the user holds through a group is not affected.
//	@Tags			owner
//	@Security		BearerAuth
//	@Param			cid						path	string	true	"Company id"
//	@Param			uid						path	string	true	"User id"
//	@Param			pid						path	string	true	"Product id"
//	@Param			X-Alora-Target-Company	header	string	true	"Must repeat the company id"
//	@Success		204								"Removed"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such direct grant in this company"
//	@Router			/api/owner/companies/{cid}/users/{uid}/grants/{pid} [delete]
func (h *PermissionController) Revoke(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.Revoke(c.Request.Context(), scope, c.Param("uid"), c.Param("pid")); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
