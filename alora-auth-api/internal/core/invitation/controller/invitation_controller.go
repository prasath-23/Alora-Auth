// Package controller serves invitation issuing (Admins and the Owner) and
// redemption (public).
package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/invitation/models"
	"github.com/alora/auth/internal/core/invitation/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// InvitationController serves the invitation routes. The issuing routes are
// wired twice — /api/admin and the Owner console — with the scope of each.
type InvitationController struct {
	svc   service.InvitationService
	scope shared.ScopeResolver
}

// NewInvitationController builds the controller for the routes scope resolves.
// The public redemption routes use no scope.
func NewInvitationController(svc service.InvitationService, scope shared.ScopeResolver) *InvitationController {
	return &InvitationController{svc: svc, scope: scope}
}

// Create handles POST /api/admin/invitations.
//
//	@Summary		Invite a user
//	@Description	Issues an invitation into the company, naming the groups the new account joins — which is what gives it access (and, for the Admins group, makes it an Admin). There is no company field: it comes from the route.
//	@Description
//	@Description	Refused if the address already belongs to a live member, or already has a live invitation. `invite_url` is returned so the link can be shared by hand when SMTP is not configured; email delivery is best-effort and off the response path.
//	@Tags			invitations
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		models.CreateInvitationRequest	true	"Address to invite, and the groups to join"
//	@Success		201		{object}	models.CreateInvitationResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body, or a group of another company"
//	@Failure		401		{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks invitations:edit, or lacks a scope one of the groups gives"
//	@Failure		409		{object}	exceptions.ErrorResponse	"Address already belongs to a user, or already has a live invitation"
//	@Router			/api/admin/invitations [post]
func (h *InvitationController) Create(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.CreateInvitationRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	created, err := h.svc.Create(c.Request.Context(), scope, req.Email, req.GroupIDs)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.NewCreateInvitationResponse(created))
}

// List handles GET /api/admin/invitations.
//
//	@Summary		List invitations
//	@Description	Every invitation of the company, in any status. Token hashes are never projected, and the invite link is not recoverable here — an invitation whose link was lost must be revoked and re-issued.
//	@Tags			invitations
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{array}		models.InvitationListItemResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks invitations:read"
//	@Router			/api/admin/invitations [get]
func (h *InvitationController) List(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	items, err := h.svc.List(c.Request.Context(), scope)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewInvitationListResponse(items))
}

// Revoke handles DELETE /api/admin/invitations/:id.
//
//	@Summary		Revoke an invitation
//	@Description	Cancels a PENDING invitation so its link stops working. An id from another organisation affects no rows and reports 404.
//	@Tags			invitations
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id	path	string	true	"Invitation id"	example(8c1d2e3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f)
//	@Success		204			"Revoked"
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks invitations:edit"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No pending invitation with that id in this company"
//	@Router			/api/admin/invitations/{id} [delete]
func (h *InvitationController) Revoke(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	id := c.Param("iid")
	if id == "" {
		id = c.Param("id")
	}
	if err := h.svc.Revoke(c.Request.Context(), scope, id); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Lookup handles GET /auth/accept-invitation/lookup?token=... (public).
//
//	@Summary		Preview an invitation
//	@Description	The invite landing page for a visitor holding the raw token: the address, the company, the groups it joins, and how the invitee will sign in (per the login policy they will have). Unauthenticated. Unknown, expired and already-used tokens all return the same 400; limited to 20 attempts per 15 minutes.
//	@Tags			invitations
//	@Produce		json
//	@Param			token	query		string	true	"Raw invitation token from the invite link"
//	@Success		200		{object}	models.InvitationPreviewResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Invitation not found, expired, or already used"
//	@Failure		429		{object}	exceptions.ErrorResponse	"Rate limited"
//	@Router			/auth/accept-invitation/lookup [get]
func (h *InvitationController) Lookup(c *gin.Context) {
	token := c.Query("token")
	if token == "" || len(token) > 256 {
		exceptions.FailWith(c, http.StatusBadRequest, "Invitation not found, expired, or already used")
		return
	}
	preview, err := h.svc.Lookup(c.Request.Context(), token)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, models.NewInvitationPreviewResponse(preview))
}

// Accept handles POST /auth/accept-invitation (public).
//
//	@Summary		Accept an invitation with a password
//	@Description	Creates the account, adds it to the invitation's groups and consumes the invitation. Refused when the invitee's login policy does not allow passwords. Answers 204 with no body; sign in afterwards at App Central.
//	@Tags			invitations
//	@Accept			json
//	@Produce		json
//	@Param			request	body	models.AcceptInvitationRequest	true	"Invitation token and the password to set"
//	@Success		204				"Account created"
//	@Failure		400		{object}	exceptions.ErrorResponse	"Invitation not found, expired or used, passwords not allowed, or the password fails policy"
//	@Failure		429		{object}	exceptions.ErrorResponse	"Rate limited"
//	@Router			/auth/accept-invitation [post]
func (h *InvitationController) Accept(c *gin.Context) {
	var req models.AcceptInvitationRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.Accept(c.Request.Context(), req.Token, req.Password); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// AcceptFederated handles POST /auth/accept-invitation/federated (public).
//
//	@Summary		Accept an invitation without a password
//	@Description	Creates an account with no password, for an invitee who will sign in with Google or their company's SSO, adds it to the invitation's groups and consumes the invitation. The external identity is linked at the first sign-in. Refused when the invitee's login policy allows neither.
//	@Tags			invitations
//	@Accept			json
//	@Produce		json
//	@Param			request	body	models.AcceptFederatedRequest	true	"Invitation token"
//	@Success		204				"Account created; sign in with Google or SSO"
//	@Failure		400		{object}	exceptions.ErrorResponse	"Invitation not found, expired or used, or neither Google nor SSO allowed"
//	@Failure		409		{object}	exceptions.ErrorResponse	"An account with this address already exists"
//	@Failure		429		{object}	exceptions.ErrorResponse	"Rate limited"
//	@Router			/auth/accept-invitation/federated [post]
func (h *InvitationController) AcceptFederated(c *gin.Context) {
	var req models.AcceptFederatedRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.AcceptFederated(c.Request.Context(), req.Token); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
