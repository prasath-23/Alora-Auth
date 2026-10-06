// Package controller serves a company's session administration.
package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/session/models"
	"github.com/alora/auth/internal/core/session/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// SessionController serves GET and DELETE /api/admin/sessions.
type SessionController struct {
	svc   service.SessionService
	scope shared.ScopeResolver
}

// NewSessionController builds the controller for the routes scope resolves.
func NewSessionController(svc service.SessionService, scope shared.ScopeResolver) *SessionController {
	return &SessionController{svc: svc, scope: scope}
}

// List handles GET /api/admin/sessions.
//
//	@Summary		List live sessions
//	@Description	Every live sign-in in the company of the caller: App Central sessions (kind CENTRAL) and the product logins opened under them (kind PRODUCT, with the product's key). Most recently used first. Each names its user by address; no token hashes and no user ids are projected, and the device label is display-only, never used for a security decision.
//	@Tags			sessions
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{array}		models.SessionListItemResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks sessions:read"
//	@Router			/api/admin/sessions [get]
func (h *SessionController) List(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	sessions, err := h.svc.ListActive(c.Request.Context(), scope)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewSessionListResponse(sessions))
}

// Revoke handles DELETE /api/admin/sessions/:id.
//
//	@Summary		Revoke a session
//	@Description	Ends one sign-in. Revoking an App Central session also ends every product login opened under it; revoking a product login ends only that. The next refresh of anything revoked fails, and App Central's own access tokens for the session stop working at once.
//	@Description
//	@Description	A product's access token already issued stays valid until it expires (at most fifteen minutes) unless the product introspects it. Scoped to the company of the caller: a session id from another organisation reports 404.
//	@Tags			sessions
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id	path	string	true	"Session id"	example(7e8f9a0b-1c2d-3e4f-5a6b-7c8d9e0f1a2b)
//	@Success		204			"Revoked"
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks sessions:edit"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such live session in this company"
//	@Router			/api/admin/sessions/{id} [delete]
func (h *SessionController) Revoke(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.RevokeByAdmin(c.Request.Context(), scope, c.Param("id")); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
