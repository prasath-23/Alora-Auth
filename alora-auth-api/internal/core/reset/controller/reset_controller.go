// Package controller serves password-reset issuing (admin) and redemption
// (public).
package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/reset/models"
	"github.com/alora/auth/internal/core/reset/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// ResetController serves the reset issuing routes (on /api/admin and the Owner
// console) and the public /auth/reset-password.
type ResetController struct {
	svc   service.ResetService
	scope shared.ScopeResolver
}

// NewResetController builds the controller for the routes scope resolves.
func NewResetController(svc service.ResetService, scope shared.ScopeResolver) *ResetController {
	return &ResetController{svc: svc, scope: scope}
}

// Issue handles POST /api/admin/users/:id/password-reset.
//
//	@Summary		Issue a password reset for a user
//	@Description	Mints a reset link for a user in the company. Needs `users:edit`. A reset is an account-takeover primitive, so nobody may reset someone with more access than they have (the Owner excepted).
//	@Description
//	@Description	Any token already outstanding for that user is deleted first, so exactly one link is ever live. The link is emailed; only outside production, with no mail configured, is reset_url returned instead. Production without mail answers 503.
//	@Tags			passwords
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id	path		string	true	"User id"	example(4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d)
//	@Success		200	{object}	models.IssueResetResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks users:edit, or the target has more access than the caller"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such user in this company"
//	@Failure		503	{object}	exceptions.ErrorResponse	"Production with no mail configured"
//	@Router			/api/admin/users/{id}/password-reset [post]
func (h *ResetController) Issue(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	userID := c.Param("uid")
	if userID == "" {
		userID = c.Param("id")
	}
	issued, err := h.svc.Issue(c.Request.Context(), scope, userID)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, models.NewIssueResetResponse(issued))
}

// Consume handles POST /auth/reset-password (public).
//
//	@Summary		Reset a password with a token
//	@Description	Sets a new password and consumes the reset token. Unauthenticated.
//	@Description
//	@Description	The field is `new_password`, not `password` — the invite-accept body uses that one, and unknown fields are rejected. Validation failures and unknown tokens collapse to the same 400 message, so a malformed body cannot be distinguished from a token that does not exist.
//	@Description
//	@Description	Every session of that user ends on success — at App Central and in every product: a reset performed because of a suspected compromise must not leave the attacker's sessions alive.
//	@Tags			passwords
//	@Accept			json
//	@Produce		json
//	@Param			request	body	models.ResetPasswordRequest	true	"Reset token and the new password"
//	@Success		204				"Password changed; all sessions revoked"
//	@Failure		400		{object}	exceptions.ErrorResponse	"Invalid or expired reset token"
//	@Failure		429		{object}	exceptions.ErrorResponse	"Rate limited"
//	@Router			/auth/reset-password [post]
func (h *ResetController) Consume(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := shared.BindJSON(c, &req); err != nil {
		// Collapsed to the same generic message so validation failures cannot be
		// used to distinguish a real token from a malformed one.
		exceptions.FailWith(c, http.StatusBadRequest, "Invalid or expired reset token")
		return
	}
	if err := h.svc.Consume(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
