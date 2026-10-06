// Package controller serves API clients: applications' identities and their
// secrets.
package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/apiclient/models"
	"github.com/alora/auth/internal/core/apiclient/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/alora/auth/internal/middlewares"
	"github.com/gin-gonic/gin"
)

// APIClientController serves the API clients of one company. It is wired
// twice: on /api/admin, where each route needs its api-clients scope, and on
// the Owner console, for any company.
type APIClientController struct {
	svc   service.APIClientService
	scope shared.ScopeResolver
}

// NewAPIClientController builds the controller for the routes scope resolves.
func NewAPIClientController(svc service.APIClientService, scope shared.ScopeResolver) *APIClientController {
	return &APIClientController{svc: svc, scope: scope}
}

// apiClientParam is the API client id from the path: :id on the admin routes,
// :aid under the Owner console's company.
func apiClientParam(c *gin.Context) string {
	if id := c.Param("aid"); id != "" {
		return id
	}
	return c.Param("id")
}

// List handles GET /api/admin/api-clients.
//
//	@Summary		List API clients
//	@Description	Every API client of the company: what each may get a token for (`products`), where that token may be used (`scopes`) and how many live secrets it has. Never a secret. Needs `api-clients:read`.
//	@Tags			api-clients
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{array}		models.APIClientResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks api-clients:read"
//	@Router			/api/admin/api-clients [get]
func (h *APIClientController) List(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	list, err := h.svc.List(c.Request.Context(), scope)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewAPIClientListResponse(list))
}

// ListAll handles GET /api/owner/api-clients.
//
//	@Summary		List every company's API clients
//	@Description	Every API client of every company, by company and then by name, each naming its company. For the Owner's Client credentials page.
//	@Tags			owner
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{array}		models.APIClientResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller is not an Owner, or signed in too long ago"
//	@Router			/api/owner/api-clients [get]
func (h *APIClientController) ListAll(c *gin.Context) {
	list, err := h.svc.ListAll(c.Request.Context(), middlewares.ActorFrom(c))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewAPIClientListResponse(list))
}

// Get handles GET /api/admin/api-clients/:id.
//
//	@Summary		Get an API client
//	@Description	One API client with its secrets — each told apart by its prefix, never its value — and `product_choices`: the products that could go on its list (live subscriptions to products that accept API clients). Needs `api-clients:read`.
//	@Tags			api-clients
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id	path		string	true	"API client id (its client_id)"
//	@Success		200	{object}	models.APIClientDetailResponse
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks api-clients:read"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such API client in this company"
//	@Router			/api/admin/api-clients/{id} [get]
func (h *APIClientController) Get(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	d, err := h.svc.Get(c.Request.Context(), scope, apiClientParam(c))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewAPIClientDetailResponse(d))
}

// Create handles POST /api/admin/api-clients.
//
//	@Summary		Create an API client
//	@Description	An application's identity. It starts with no scopes, no products and no secret, so it can do nothing until each is chosen. Its `id` is its OAuth `client_id`. Needs `api-clients:edit`.
//	@Tags			api-clients
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		models.CreateAPIClientRequest	true	"Its name"
//	@Success		201		{object}	models.APIClientResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks api-clients:edit"
//	@Failure		409		{object}	exceptions.ErrorResponse	"An API client with this name already exists"
//	@Router			/api/admin/api-clients [post]
func (h *APIClientController) Create(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.CreateAPIClientRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	a, err := h.svc.Create(c.Request.Context(), scope, req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.NewAPIClientResponse(a))
}

// Update handles PATCH /api/admin/api-clients/:id.
//
//	@Summary		Change an API client
//	@Description	Its complete settable state. Switched off (`is_active` false), it gets no token, whatever its secrets. Needs `api-clients:edit`.
//	@Tags			api-clients
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"API client id"
//	@Param			request	body		models.UpdateAPIClientRequest	true	"Name, description and whether it is on"
//	@Success		200		{object}	models.APIClientResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks api-clients:edit"
//	@Failure		404		{object}	exceptions.ErrorResponse	"No such API client in this company"
//	@Failure		409		{object}	exceptions.ErrorResponse	"An API client with this name already exists"
//	@Router			/api/admin/api-clients/{id} [patch]
func (h *APIClientController) Update(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.UpdateAPIClientRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	a, err := h.svc.Update(c.Request.Context(), scope, apiClientParam(c), req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewAPIClientResponse(a))
}

// Delete handles DELETE /api/admin/api-clients/:id.
//
//	@Summary		Delete an API client
//	@Description	Its scopes, products and secrets go with it, and it gets no token again. The audit trail keeps what it was. Needs `api-clients:edit`.
//	@Tags			api-clients
//	@Security		BearerAuth
//	@Param			id	path	string	true	"API client id"
//	@Success		204						"Deleted"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks api-clients:edit"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such API client in this company"
//	@Router			/api/admin/api-clients/{id} [delete]
func (h *APIClientController) Delete(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.Delete(c.Request.Context(), scope, apiClientParam(c)); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// SetScopes handles PUT /api/admin/api-clients/:id/scopes.
//
//	@Summary		Set where an API client's credential may be used
//	@Description	The COMPLETE set of application scopes: `api:read` / `api:edit` (a product's REST API), `grpc:read` / `grpc:edit` (its gRPC services) and `mcp:tools` (its MCP tools). Any scope omitted is taken away, and an edit scope brings its read scope. Its product tokens carry these, or fewer. Needs `api-clients:edit`.
//	@Tags			api-clients
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"API client id"
//	@Param			request	body		models.SetAPIClientScopesRequest	true	"The complete set of scopes"
//	@Success		200		{object}	models.APIClientScopesResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body, or a scope that is not an application scope"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks api-clients:edit"
//	@Failure		404		{object}	exceptions.ErrorResponse	"No such API client in this company"
//	@Router			/api/admin/api-clients/{id}/scopes [put]
func (h *APIClientController) SetScopes(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.SetAPIClientScopesRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	scopes, err := h.svc.SetScopes(c.Request.Context(), scope, apiClientParam(c), req.Scopes)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewAPIClientScopesResponse(scopes))
}

// SetProducts handles PUT /api/admin/api-clients/:id/products.
//
//	@Summary		Set the products an API client may get a token for
//	@Description	The COMPLETE list: any product omitted is taken off. A product added must be one the company subscribes to, and one the Owner has let accept API clients; a product already on the list may stay, and earns no token while it is not usable. Needs `api-clients:edit`.
//	@Tags			api-clients
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"API client id"
//	@Param			request	body		models.SetAPIClientProductsRequest	true	"The complete list of product ids"
//	@Success		200		{object}	models.APIClientProductsResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body, or a product that cannot be added"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks api-clients:edit"
//	@Failure		404		{object}	exceptions.ErrorResponse	"No such API client in this company"
//	@Router			/api/admin/api-clients/{id}/products [put]
func (h *APIClientController) SetProducts(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.SetAPIClientProductsRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	products, err := h.svc.SetProducts(c.Request.Context(), scope, apiClientParam(c), req.ProductIDs)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewAPIClientProductsResponse(products))
}

// CreateSecret handles POST /api/admin/api-clients/:id/secrets.
//
//	@Summary		Make an API client a secret
//	@Description	Returns the secret's value THIS ONCE: App Central keeps only its hash. At most two secrets are live at a time, so a client rotates without downtime — make a second, deploy it, then revoke the first. The body is optional; `expires_in_days` limits the secret's life. Needs `api-clients:edit`.
//	@Tags			api-clients
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"API client id"
//	@Param			request	body		models.CreateAPIClientSecretRequest	false	"Optional lifetime"
//	@Success		201		{object}	models.IssuedSecretResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks api-clients:edit"
//	@Failure		404		{object}	exceptions.ErrorResponse	"No such API client in this company"
//	@Failure		409		{object}	exceptions.ErrorResponse	"It already has two live secrets"
//	@Router			/api/admin/api-clients/{id}/secrets [post]
func (h *APIClientController) CreateSecret(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.CreateAPIClientSecretRequest
	if c.Request.ContentLength != 0 { // the body is optional
		if err := shared.BindJSON(c, &req); err != nil {
			exceptions.Fail(c, err)
			return
		}
	}
	s, err := h.svc.CreateSecret(c.Request.Context(), scope, apiClientParam(c), req.Lifetime())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, models.NewIssuedSecretResponse(s))
}

// RevokeSecret handles DELETE /api/admin/api-clients/:id/secrets/:sid.
//
//	@Summary		Revoke an API client's secret
//	@Description	It stops working at once. The secret is kept, revoked, so the record says it existed. Needs `api-clients:edit`.
//	@Tags			api-clients
//	@Security		BearerAuth
//	@Param			id	path	string	true	"API client id"
//	@Param			sid	path	string	true	"Secret id"
//	@Success		204						"Revoked"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks api-clients:edit"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such live secret of this API client"
//	@Router			/api/admin/api-clients/{id}/secrets/{sid} [delete]
func (h *APIClientController) RevokeSecret(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.RevokeSecret(c.Request.Context(), scope, apiClientParam(c), c.Param("sid")); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
