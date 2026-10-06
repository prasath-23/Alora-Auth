// Package controller serves a company's own record and its product
// subscriptions.
package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/tenant/models"
	"github.com/alora/auth/internal/core/tenant/service"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// ClientController serves /api/admin/client.
type ClientController struct {
	svc   service.ClientService
	scope shared.ScopeResolver
}

// NewClientController builds the controller for the routes scope resolves.
func NewClientController(svc service.ClientService, scope shared.ScopeResolver) *ClientController {
	return &ClientController{svc: svc, scope: scope}
}

// Get handles GET /api/admin/client.
//
//	@Summary		Get the company record
//	@Description	The organisation of the caller: its name, domain, plan and standing.
//	@Tags			tenant
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{object}	models.ClientDetailResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks company:read"
//	@Router			/api/admin/client [get]
func (h *ClientController) Get(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	client, err := h.svc.Get(c.Request.Context(), scope)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewClientDetailResponse(client))
}

// Update handles PATCH /api/admin/client.
//
//	@Summary		Rename the company
//	@Description	The name is all an Admin may change. The plan, the company's standing and its domain are the Owner's to set: an Admin must not be able to un-suspend their own company or verify a domain for it.
//	@Tags			tenant
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		models.UpdateClientRequest	true	"The new name"
//	@Success		200		{object}	models.ClientDetailResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Unknown field, or a name outside 1-200 characters"
//	@Failure		401		{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks company:edit"
//	@Router			/api/admin/client [patch]
func (h *ClientController) Update(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.UpdateClientRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	client, err := h.svc.Rename(c.Request.Context(), scope, req.Name)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewClientDetailResponse(client))
}
