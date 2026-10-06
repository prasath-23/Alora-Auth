package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/user/models"
	"github.com/alora/auth/internal/core/user/service"
	"github.com/alora/auth/internal/exceptions"
	"github.com/alora/auth/internal/middlewares"
	"github.com/gin-gonic/gin"
)

// MeController serves /api/me: the caller's own account at App Central.
type MeController struct{ svc service.MeService }

// NewMeController builds the controller.
func NewMeController(svc service.MeService) *MeController { return &MeController{svc: svc} }

// Me handles GET /api/me.
//
//	@Summary		Your account
//	@Description	Who the caller is, in which company, whether they are an Admin or an Owner, and which admin feature keys they hold (an Admin holds all). App Central uses it to decide what to show; every route re-checks its own guard server-side.
//	@Tags			me
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{object}	models.MeResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Router			/api/me [get]
func (h *MeController) Me(c *gin.Context) {
	me, err := h.svc.Me(c.Request.Context(), middlewares.ActorFrom(c))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewMeResponse(me))
}

// Apps handles GET /api/me/apps.
//
//	@Summary		Your apps
//	@Description	The products the caller may use right now — a role through a group or granted directly, a live subscription, an active product — each with the caller's roles in it and a `launch_url` that starts the product's own sign-in.
//	@Tags			me
//	@Security		BearerAuth
//	@Produce		json
//	@Success		200	{array}		models.AppResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Router			/api/me/apps [get]
func (h *MeController) Apps(c *gin.Context) {
	apps, err := h.svc.Apps(c.Request.Context(), middlewares.ActorFrom(c))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewAppListResponse(apps))
}

// ChangePassword handles POST /api/me/change-password.
//
//	@Summary		Change your own password
//	@Description	The current password is re-verified even though the caller holds a valid token: that re-authentication is what stops a stolen token from becoming permanent account takeover. A wrong one is 403, not 401 — the token was fine, and a client that refreshes on 401 must not re-send the guess — and each account gets five attempts per fifteen minutes, however many addresses they come from. On success every session of the account ends — this one too — so the caller signs in again.
//	@Tags			me
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			request	body	models.ChangePasswordRequest	true	"Current and new password"
//	@Success		204				"Password changed; every session ended"
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body, or the account has no password"
//	@Failure		401		{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403		{object}	exceptions.ErrorResponse	"The current password is incorrect"
//	@Failure		429		{object}	exceptions.ErrorResponse	"Too many attempts for this account"
//	@Router			/api/me/change-password [post]
func (h *MeController) ChangePassword(c *gin.Context) {
	actor := middlewares.ActorFrom(c)
	var req models.ChangePasswordRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.ChangePassword(c.Request.Context(), actor, req.CurrentPassword, req.NewPassword); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
