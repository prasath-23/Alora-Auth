// Package controller serves the Owner console: companies, subscriptions and
// product registrations, and the one place a scope for ANOTHER company is built.
package controller

import (
	"context"
	"net/http"

	"github.com/alora/auth/internal/core/owner/models"
	"github.com/alora/auth/internal/core/owner/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/alora/auth/internal/middlewares"
	"github.com/gin-gonic/gin"
)

// TargetHeader must repeat, on every write under /api/owner/companies/:cid, the
// company named in the path. A console acting on the wrong company — a stale
// tab, a crafted link, a mistyped id — is refused rather than obeyed, because
// the Owner's rights reach every company and a slip would land somewhere real.
const TargetHeader = "X-Alora-Target-Company"

var (
	errNotOwner       = exceptions.NewAPIError(http.StatusForbidden, "Forbidden", nil)
	errTargetMismatch = exceptions.NewAPIError(http.StatusBadRequest, "The "+TargetHeader+" header must repeat the company id", nil)
)

// companyChecker is what OwnerScopeFrom needs of the service.
type companyChecker interface {
	CompanyExists(ctx context.Context, clientID string) (bool, error)
}

// OwnerScopeFrom builds the scope of an Owner acting on the company named in the
// path. It is the ONLY way a scope for a company other than the caller's own
// comes to exist, and an architecture test keeps every other package from
// calling it.
func OwnerScopeFrom(c *gin.Context, companies companyChecker, cid string) (shared.Scope, error) {
	actor := middlewares.ActorFrom(c)
	if !actor.IsOwner {
		return shared.Scope{}, errNotOwner
	}
	switch c.Request.Method {
	case http.MethodGet, http.MethodHead:
	default:
		if c.GetHeader(TargetHeader) != cid {
			return shared.Scope{}, errTargetMismatch
		}
	}
	ok, err := companies.CompanyExists(c.Request.Context(), cid)
	if err != nil {
		return shared.Scope{}, err
	}
	if !ok {
		return shared.Scope{}, exceptions.ErrNotFound
	}
	return shared.Scope{ClientID: cid, Actor: actor, ByOwner: true}, nil
}

// OwnerController serves /api/owner.
type OwnerController struct{ svc service.OwnerService }

// NewOwnerController builds the controller.
func NewOwnerController(svc service.OwnerService) *OwnerController { return &OwnerController{svc: svc} }

// CompanyScope resolves the company of an /api/owner/companies/:cid route. It is
// the resolver every feature controller mounted there is built with.
func (h *OwnerController) CompanyScope(c *gin.Context) (shared.Scope, error) {
	return OwnerScopeFrom(c, h.svc, c.Param("cid"))
}

// ListCompanies handles GET /api/owner/companies.
//
//	@Summary		List companies
//	@Description	Every company, with its standing and member count. The platform company (`is_platform`) is the Owners' own.
//	@Tags			owner
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{array}		models.CompanyResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller is not an Owner, or signed in more than twelve hours ago"
//	@Router			/api/owner/companies [get]
func (h *OwnerController) ListCompanies(c *gin.Context) {
	cs, err := h.svc.ListCompanies(c.Request.Context())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewCompanyListResponse(cs))
}

// CreateCompany handles POST /api/owner/companies.
//
//	@Summary		Create a company
//	@Description	Creates the company together with its Admins group and its default login policy (password and Google), in one statement. Invite its first Admin into the Admins group next.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		models.CreateCompanyRequest	true	"The company"
//	@Success		201		{object}	models.CompanyResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller is not an Owner, or signed in too long ago"
//	@Router			/api/owner/companies [post]
func (h *OwnerController) CreateCompany(c *gin.Context) {
	var req models.CreateCompanyRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	co, err := h.svc.CreateCompany(c.Request.Context(), middlewares.ActorFrom(c), req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.NewCompanyResponse(co))
}

// GetCompany handles GET /api/owner/companies/:cid.
//
//	@Summary		Get a company
//	@Tags			owner
//	@Security		BearerAuth
//	@Produce		json
//	@Param			cid	path		string	true	"Company id"
//	@Success		200	{object}	models.CompanyResponse
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such company"
//	@Router			/api/owner/companies/{cid} [get]
func (h *OwnerController) GetCompany(c *gin.Context) {
	scope, err := h.CompanyScope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	co, err := h.svc.GetCompany(c.Request.Context(), scope)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewCompanyResponse(co))
}

// UpdateCompany handles PATCH /api/owner/companies/:cid.
//
//	@Summary		Update a company
//	@Description	Send only what changes. `is_active: false` suspends the company: nobody in it can sign in, its App Central sessions stop working at once, and its products' logins stop renewing. The platform company cannot be suspended.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			cid						path		string						true	"Company id"
//	@Param			X-Alora-Target-Company	header		string						true	"Must repeat the company id"
//	@Param			request					body		models.UpdateCompanyRequest	true	"The changes"
//	@Success		200						{object}	models.CompanyResponse
//	@Failure		400						{object}	exceptions.ErrorResponse	"Malformed body, or the target header does not match"
//	@Failure		404						{object}	exceptions.ErrorResponse	"No such company"
//	@Failure		409						{object}	exceptions.ErrorResponse	"The platform company cannot be suspended"
//	@Router			/api/owner/companies/{cid} [patch]
func (h *OwnerController) UpdateCompany(c *gin.Context) {
	scope, err := h.CompanyScope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.UpdateCompanyRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	co, err := h.svc.UpdateCompany(c.Request.Context(), scope, req.Changes())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewCompanyResponse(co))
}

// SetDomain handles PUT /api/owner/companies/:cid/domain.
//
//	@Summary		Set a company's email domain
//	@Description	A verified domain is unique across companies. It is how the login page recognises the company's addresses, and what lets its SSO connections claim the domain.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			cid						path		string					true	"Company id"
//	@Param			X-Alora-Target-Company	header		string					true	"Must repeat the company id"
//	@Param			request					body		models.SetDomainRequest	true	"The domain, or null"
//	@Success		200						{object}	models.CompanyResponse
//	@Failure		409						{object}	exceptions.ErrorResponse	"Another company verified this domain"
//	@Router			/api/owner/companies/{cid}/domain [put]
func (h *OwnerController) SetDomain(c *gin.Context) {
	scope, err := h.CompanyScope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.SetDomainRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	co, err := h.svc.SetDomain(c.Request.Context(), scope, req.Domain, req.Verified)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewCompanyResponse(co))
}

// ListSubscriptions handles GET /api/owner/companies/:cid/subscriptions.
//
//	@Summary		List a company's subscriptions
//	@Tags			owner
//	@Security		BearerAuth
//	@Produce		json
//	@Param			cid	path		string	true	"Company id"
//	@Success		200	{array}		models.SubscriptionResponse
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such company"
//	@Router			/api/owner/companies/{cid}/subscriptions [get]
func (h *OwnerController) ListSubscriptions(c *gin.Context) {
	scope, err := h.CompanyScope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	ss, err := h.svc.ListSubscriptions(c.Request.Context(), scope)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewSubscriptionListResponse(ss))
}

// SetSubscription handles PUT /api/owner/companies/:cid/subscriptions/:pid.
//
//	@Summary		Subscribe a company to a product, or change it
//	@Description	A subscription is switched off, never deleted. Switching it off ends the company's access to the product: App Central stops offering it and every product login ends at its next refresh.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Param			cid						path	string						true	"Company id"
//	@Param			pid						path	string						true	"Product id"
//	@Param			X-Alora-Target-Company	header	string						true	"Must repeat the company id"
//	@Param			request					body	models.SubscriptionRequest	true	"The subscription"
//	@Success		204										"Set"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such company or product"
//	@Router			/api/owner/companies/{cid}/subscriptions/{pid} [put]
func (h *OwnerController) SetSubscription(c *gin.Context) {
	scope, err := h.CompanyScope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.SubscriptionRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.SetSubscription(c.Request.Context(), scope, c.Param("pid"), req.Input()); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ListProducts handles GET /api/owner/products.
//
//	@Summary		List products
//	@Description	Every product App Central signs people in to, with its registration: redirect URIs, initiate_login_uri, role catalogue, and whether a client secret is set.
//	@Tags			owner
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{array}		models.ProductResponse
//	@Router			/api/owner/products [get]
func (h *OwnerController) ListProducts(c *gin.Context) {
	ps, err := h.svc.ListProducts(c.Request.Context())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewProductListResponse(ps))
}

// GetProduct handles GET /api/owner/products/:pid.
//
//	@Summary		Get a product
//	@Tags			owner
//	@Security		BearerAuth
//	@Produce		json
//	@Param			pid	path		string	true	"Product id"
//	@Success		200	{object}	models.ProductResponse
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such product"
//	@Router			/api/owner/products/{pid} [get]
func (h *OwnerController) GetProduct(c *gin.Context) {
	p, err := h.svc.GetProduct(c.Request.Context(), c.Param("pid"))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewProductResponse(p))
}

// CreateProduct handles POST /api/owner/products.
//
//	@Summary		Register a product
//	@Description	The key is permanent: every token for the product carries the audience `product:<key>`. Then set its redirect URIs and roles, and issue its client secret.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		models.CreateProductRequest	true	"The product"
//	@Success		201		{object}	models.ProductResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body, a bad key or URL"
//	@Failure		409		{object}	exceptions.ErrorResponse	"The key is taken"
//	@Router			/api/owner/products [post]
func (h *OwnerController) CreateProduct(c *gin.Context) {
	var req models.CreateProductRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	p, err := h.svc.CreateProduct(c.Request.Context(), middlewares.ActorFrom(c), req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.NewProductResponse(p))
}

// UpdateProduct handles PATCH /api/owner/products/:pid.
//
//	@Summary		Update a product
//	@Description	The complete settable state, the key excepted. An inactive product signs nobody in and renews no login. `accepts_api_clients` lets companies' API clients get tokens for the product (off until switched on); leave it out to keep it as it is.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			pid		path		string						true	"Product id"
//	@Param			request	body		models.UpdateProductRequest	true	"The product"
//	@Success		200		{object}	models.ProductResponse
//	@Failure		404		{object}	exceptions.ErrorResponse	"No such product"
//	@Router			/api/owner/products/{pid} [patch]
func (h *OwnerController) UpdateProduct(c *gin.Context) {
	var req models.UpdateProductRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	p, err := h.svc.UpdateProduct(c.Request.Context(), middlewares.ActorFrom(c), c.Param("pid"), req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewProductResponse(p))
}

// SetRedirectURIs handles PUT /api/owner/products/:pid/redirect-uris.
//
//	@Summary		Set a product's redirect URIs
//	@Description	The COMPLETE list. An authorization code is delivered only to one of these, matched byte for byte — no prefixes, no wildcards.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Param			pid		path	string						true	"Product id"
//	@Param			request	body	models.RedirectURIsRequest	true	"The redirect URIs"
//	@Success		204								"Set"
//	@Failure		400	{object}	exceptions.ErrorResponse	"A URI that is not absolute https, or carries a fragment"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such product"
//	@Router			/api/owner/products/{pid}/redirect-uris [put]
func (h *OwnerController) SetRedirectURIs(c *gin.Context) {
	var req models.RedirectURIsRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.SetRedirectURIs(c.Request.Context(), middlewares.ActorFrom(c), c.Param("pid"), req.RedirectURIs); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// SetRoles handles PUT /api/owner/products/:pid/roles.
//
//	@Summary		Set a product's role catalogue
//	@Description	The COMPLETE catalogue. Grants may name only these roles, and a role still granted cannot be removed.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Param			pid		path	string				true	"Product id"
//	@Param			request	body	models.RolesRequest	true	"The roles"
//	@Success		204							"Set"
//	@Failure		400	{object}	exceptions.ErrorResponse	"A malformed role name"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such product"
//	@Failure		409	{object}	exceptions.ErrorResponse	"A role being removed is still granted"
//	@Router			/api/owner/products/{pid}/roles [put]
func (h *OwnerController) SetRoles(c *gin.Context) {
	var req models.RolesRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.SetRoles(c.Request.Context(), middlewares.ActorFrom(c), c.Param("pid"), req.Roles); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// RotateSecret handles POST /api/owner/products/:pid/client-secret.
//
//	@Summary		Issue a product's client secret
//	@Description	A new secret, shown in this response only and stored as a hash. The previous one stops working at once, so deploy this one to the product's backend straight away.
//	@Tags			owner
//	@Security		BearerAuth
//	@Produce		json
//	@Param			pid	path		string	true	"Product id"
//	@Success		200	{object}	models.SecretResponse
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such product"
//	@Router			/api/owner/products/{pid}/client-secret [post]
func (h *OwnerController) RotateSecret(c *gin.Context) {
	sec, err := h.svc.RotateSecret(c.Request.Context(), middlewares.ActorFrom(c), c.Param("pid"))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, models.NewSecretResponse(sec))
}
