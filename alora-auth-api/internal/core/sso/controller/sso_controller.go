// Package controller serves SSO-connection administration. It is wired onto the
// Owner console only.
package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/sso/models"
	"github.com/alora/auth/internal/core/sso/service"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// SSOController serves /api/owner/companies/:cid/sso-connections.
type SSOController struct {
	svc   service.SSOService
	scope shared.ScopeResolver
}

// NewSSOController builds the controller for the routes scope resolves.
func NewSSOController(svc service.SSOService, scope shared.ScopeResolver) *SSOController {
	return &SSOController{svc: svc, scope: scope}
}

// List handles GET /api/owner/companies/:cid/sso-connections.
//
//	@Summary		List a company's SSO connections
//	@Description	Each with its domains and whether a secret is set. Secrets are never returned.
//	@Tags			owner
//	@Security		BearerAuth
//	@Produce		json
//	@Param			cid	path		string	true	"Company id"
//	@Success		200	{array}		models.ConnectionResponse
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller is not an Owner, or signed in too long ago"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such company"
//	@Router			/api/owner/companies/{cid}/sso-connections [get]
func (h *SSOController) List(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	cs, err := h.svc.List(c.Request.Context(), scope)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewConnectionListResponse(cs))
}

// Create handles POST /api/owner/companies/:cid/sso-connections.
//
//	@Summary		Register an SSO connection
//	@Description	An OpenID Connect provider of the company's (Okta, Entra ID, Google Workspace, ...). Register App Central's callback there as the redirect URI. The client secret is sealed on arrival and never returned. A connection signs people in only once domains are set on it and a login policy names it.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			cid						path		string						true	"Company id"
//	@Param			X-Alora-Target-Company	header		string						true	"Must repeat the company id"
//	@Param			request					body		models.ConnectionRequest	true	"The connection"
//	@Success		201						{object}	models.ConnectionResponse
//	@Failure		400						{object}	exceptions.ErrorResponse	"Malformed body, or an issuer that is not an absolute https URL"
//	@Failure		409						{object}	exceptions.ErrorResponse	"The name, or the issuer and client id, is taken"
//	@Failure		503						{object}	exceptions.ErrorResponse	"No key configured to seal the secret"
//	@Router			/api/owner/companies/{cid}/sso-connections [post]
func (h *SSOController) Create(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.ConnectionRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	conn, err := h.svc.Create(c.Request.Context(), scope, req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.NewConnectionResponse(conn))
}

// Update handles PATCH /api/owner/companies/:cid/sso-connections/:sid.
//
//	@Summary		Update an SSO connection
//	@Description	The complete desired state. Leave client_secret out to keep the stored one.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			cid						path		string						true	"Company id"
//	@Param			sid						path		string						true	"Connection id"
//	@Param			X-Alora-Target-Company	header		string						true	"Must repeat the company id"
//	@Param			request					body		models.ConnectionRequest	true	"The connection"
//	@Success		200						{object}	models.ConnectionResponse
//	@Failure		404						{object}	exceptions.ErrorResponse	"No such connection in this company"
//	@Router			/api/owner/companies/{cid}/sso-connections/{sid} [patch]
func (h *SSOController) Update(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.ConnectionRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	conn, err := h.svc.Update(c.Request.Context(), scope, c.Param("sid"), req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewConnectionResponse(conn))
}

// SetDomains handles PUT /api/owner/companies/:cid/sso-connections/:sid/domains.
//
//	@Summary		Set the email domains a connection signs in
//	@Description	The COMPLETE set. A domain can be on one connection only, and never on one whose company is not the domain's verified owner. The login page offers the connection for these domains, and a first SSO sign-in links an account only at one of them.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Param			cid						path	string					true	"Company id"
//	@Param			sid						path	string					true	"Connection id"
//	@Param			X-Alora-Target-Company	header	string					true	"Must repeat the company id"
//	@Param			request					body	models.DomainsRequest	true	"The domains"
//	@Success		204										"Set"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such connection in this company"
//	@Failure		409	{object}	exceptions.ErrorResponse	"A domain is on another connection, or is another company's"
//	@Router			/api/owner/companies/{cid}/sso-connections/{sid}/domains [put]
func (h *SSOController) SetDomains(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.DomainsRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.SetDomains(c.Request.Context(), scope, c.Param("sid"), req.Domains); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Test handles POST /api/owner/companies/:cid/sso-connections/:sid/test.
//
//	@Summary		Test an SSO connection
//	@Description	Fetches the provider's discovery document through the same guarded client sign-in uses, and checks it names the configured issuer.
//	@Tags			owner
//	@Security		BearerAuth
//	@Produce		json
//	@Param			cid						path		string	true	"Company id"
//	@Param			sid						path		string	true	"Connection id"
//	@Param			X-Alora-Target-Company	header		string	true	"Must repeat the company id"
//	@Success		200						{object}	models.TestResponse
//	@Failure		404						{object}	exceptions.ErrorResponse	"No such connection in this company"
//	@Failure		502						{object}	exceptions.ErrorResponse	"The provider could not be used"
//	@Router			/api/owner/companies/{cid}/sso-connections/{sid}/test [post]
func (h *SSOController) Test(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	res, err := h.svc.Test(c.Request.Context(), scope, c.Param("sid"))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewTestResponse(res))
}
