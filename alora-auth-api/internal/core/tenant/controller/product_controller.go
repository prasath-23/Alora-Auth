package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/tenant/models"
	"github.com/alora/auth/internal/core/tenant/service"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// ProductController serves /api/admin/products.
type ProductController struct {
	svc   service.ProductService
	scope shared.ScopeResolver
}

// NewProductController builds the controller for the routes scope resolves.
func NewProductController(svc service.ProductService, scope shared.ScopeResolver) *ProductController {
	return &ProductController{svc: svc, scope: scope}
}

// List handles GET /api/admin/products (the company's subscriptions).
//
//	@Summary		List product subscriptions
//	@Description	The products the company subscribes to. `id` is the SUBSCRIPTION id; the product itself is `product_id`.
//	@Tags			tenant
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{array}		models.ProductListItemResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks products:read"
//	@Router			/api/admin/products [get]
func (h *ProductController) List(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	subs, err := h.svc.List(c.Request.Context(), scope)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewProductListResponse(subs))
}
