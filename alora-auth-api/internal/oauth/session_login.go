package oauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/alora/auth/internal/crypto/password"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

// AuthenticatePassword verifies credentials and returns the user id.
//
// This is the ADMIN-PORTAL login path: it skips the authorization-code leg
// because the portal is first-party and has no redirect to protect. It keeps
// every other control — the same opaque error, the same dummy-hash timing
// equalisation, and the same account-state checks.
func (s *Service) AuthenticatePassword(ctx context.Context, email, plaintext string) (string, error) {
	user, err := s.q.GetUserCredentialByEmail(ctx, httpx.NormalizeEmail(email))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	storedHash := password.DummyHash()
	found := err == nil
	if found && user.PasswordHash.Valid {
		storedHash = user.PasswordHash.String
	}
	ok := password.Verify(plaintext, storedHash)
	if !found || !user.PasswordHash.Valid || !ok {
		return "", httpx.ErrInvalidCredentials
	}
	return user.ID, nil
}

type sessionLoginRequest struct {
	Email    string `json:"email" validate:"required,email,max=320"`
	Password string `json:"password" validate:"required,min=1,max=512"`
}

// SessionLogin handles POST /auth/session — direct login for the admin portal.
func (h *Handler) SessionLogin(c *gin.Context) {
	var req sessionLoginRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	ctx := c.Request.Context()

	userID, err := h.svc.AuthenticatePassword(ctx, req.Email, req.Password)
	if err != nil {
		httpx.Fail(c, err)
		return
	}

	// No product key: this token's audience is the auth API itself, so it cannot
	// be replayed against a product backend.
	accessToken, identity, err := h.authSvc.MintAccessToken(ctx, userID, "")
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	issued, err := h.sessions.Create(ctx, identity.UserID, identity.ClientID, metaFrom(c))
	if err != nil {
		httpx.Fail(c, err)
		return
	}

	h.jar.SetRefresh(c, issued.RawToken, h.sessions.RefreshTTL())
	h.jar.SetAccess(c, accessToken)

	// Body is exactly these three fields — no user object, no roles echo.
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   h.authSvc.AccessTokenTTLSeconds(),
	})
}
