package admin

import (
	"errors"
	"net/http"

	"github.com/alora/auth/internal/crypto/password"
	"github.com/alora/auth/internal/middleware"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,min=1,max=512"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=512"`
}

// ChangePassword handles POST /admin/me/change-password.
//
// Requires the CURRENT password even though the caller already holds a valid
// token: that re-authentication is what stops a stolen access token from being
// escalated into permanent account takeover.
func (h *Handler) ChangePassword(c *gin.Context) {
	u := middleware.UserFrom(c)

	var req changePasswordRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	ctx := c.Request.Context()

	user, err := h.q.GetUserById(ctx, u.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.Fail(c, httpx.ErrUnauthorized)
			return
		}
		httpx.Fail(c, err)
		return
	}
	// OAUTH_ONLY accounts have no password to change.
	if !user.PasswordHash.Valid {
		httpx.FailWith(c, http.StatusBadRequest, "Password change is not supported for OAuth-only accounts")
		return
	}
	if !password.Verify(req.CurrentPassword, user.PasswordHash.String) {
		httpx.FailWith(c, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	hash, err := password.Hash(req.NewPassword)
	if err != nil {
		httpx.FailWith(c, http.StatusBadRequest, "Invalid request")
		return
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := h.q.WithTx(tx)

	if err := qtx.SetUserPassword(ctx, sqlc.SetUserPasswordParams{
		UserID: u.UserID, ClientID: u.ClientID, PasswordHash: hash,
	}); err != nil {
		httpx.Fail(c, err)
		return
	}
	// Every OTHER session must die: if the password was changed because of a
	// suspected compromise, leaving the attacker's refresh tokens alive would
	// defeat the point. The caller simply re-authenticates.
	if _, err := qtx.RevokeAllUserSessions(ctx, sqlc.RevokeAllUserSessionsParams{
		UserID: u.UserID, Reason: sqlc.SessionRevokedReasonLOGOUTALL,
	}); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := qtx.BumpPermissionsVersion(ctx, sqlc.BumpPermissionsVersionParams{
		PUserid: u.UserID, PClientid: u.ClientID,
	}); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.Fail(c, err)
		return
	}

	h.logEvent(c, u, "password.changed")
	c.Status(http.StatusNoContent)
}
