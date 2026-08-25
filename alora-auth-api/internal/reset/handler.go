package reset

import (
	"net/http"

	"github.com/alora/auth/internal/mailer"
	"github.com/alora/auth/internal/middleware"
	"github.com/alora/auth/internal/platform/audit"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc   *Service
	mail  *mailer.Mailer
	audit *audit.Logger
}

func NewHandler(svc *Service, mail *mailer.Mailer, a *audit.Logger) *Handler {
	return &Handler{svc: svc, mail: mail, audit: a}
}

// Issue handles POST /admin/users/:id/password-reset (admin, feature-gated).
func (h *Handler) Issue(c *gin.Context) {
	u := middleware.UserFrom(c)
	issued, err := h.svc.Issue(c.Request.Context(), c.Param("id"), u.ClientID, u.UserID)
	if err != nil {
		httpx.Fail(c, err)
		return
	}

	if h.mail.Enabled() {
		// Logger captured before the goroutine: *gin.Context is pooled and reused
		// once the handler returns.
		log := httpx.LoggerFrom(c)
		to, url, exp := issued.Email, issued.ResetURL, issued.ExpiresAt
		go func() {
			defer func() {
				if r := recover(); r != nil && log != nil {
					log.Error("reset email panicked", "recover", r)
				}
			}()
			if err := h.mail.SendPasswordReset(to, url, exp); err != nil && log != nil {
				log.Error("reset email failed", "err", err)
			}
		}()
	}

	h.audit.Log(audit.Entry{
		ClientID: u.ClientID, ActorUserID: &u.UserID, EventType: "password.reset_issued",
		RequestID: ptr(httpx.RequestIDFrom(c)),
	})

	body := gin.H{"expires_at": issued.ExpiresAt}
	// The link is surfaced ONLY when email is unavailable, so a configured
	// deployment never returns an account-takeover primitive in an API response.
	if !h.mail.Enabled() {
		body["reset_url"] = issued.ResetURL
	}
	c.JSON(http.StatusOK, body)
}

// Field names mirror the Fastify contract EXACTLY: the reset body uses
// `new_password` (not `password`, which the invite-accept body uses). Because
// unknown fields are rejected, a mismatch here is a hard 400 for the existing UI.
type consumeRequest struct {
	Token       string `json:"token" validate:"required,min=1,max=256"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=512"`
}

// Consume handles POST /auth/reset-password (public).
func (h *Handler) Consume(c *gin.Context) {
	var req consumeRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		// Collapsed to the same generic message so validation failures cannot be
		// used to distinguish a real token from a malformed one.
		httpx.FailWith(c, http.StatusBadRequest, "Invalid or expired reset token")
		return
	}
	if err := h.svc.Consume(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		httpx.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func ptr(s string) *string { return &s }
