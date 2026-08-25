package invitation

import (
	"net/http"
	"time"

	"github.com/alora/auth/internal/mailer"
	"github.com/alora/auth/internal/middleware"
	"github.com/alora/auth/internal/platform/audit"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc   *Service
	mail  *mailer.Mailer
	audit *audit.Logger
	q     *sqlc.Queries
}

func NewHandler(svc *Service, mail *mailer.Mailer, a *audit.Logger, q *sqlc.Queries) *Handler {
	return &Handler{svc: svc, mail: mail, audit: a, q: q}
}

type createRequest struct {
	Email    string `json:"email" validate:"required,email,max=320"`
	Products []struct {
		ProductID string `json:"product_id" validate:"required,uuid4"`
		RoleName  string `json:"role_name" validate:"required,max=64"`
	} `json:"products" validate:"omitempty,dive"`
}

// Create handles POST /admin/invitations.
func (h *Handler) Create(c *gin.Context) {
	u := middleware.UserFrom(c)
	var req createRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}

	grants := make([]ProductGrant, 0, len(req.Products))
	for _, p := range req.Products {
		grants = append(grants, ProductGrant{ProductID: p.ProductID, RoleName: p.RoleName})
	}

	// clientID comes from the TOKEN, never the body.
	created, err := h.svc.Create(c.Request.Context(), u.ClientID, u.UserID, req.Email, grants)
	if err != nil {
		httpx.Fail(c, err)
		return
	}

	// Email is best-effort and must never fail the request: when SMTP is not
	// configured the caller shares invite_url manually instead.
	if h.mail.Enabled() {
		clientName, _ := h.q.ClientNameById(c.Request.Context(), u.ClientID)
		// Detached goroutine: SMTP latency must not be on the response path, and a
		// mail outage must not turn a successful invite into a 500. Arguments are
		// passed by value so nothing races with the handler returning.
		// The logger is captured HERE, not inside the goroutine: Gin pools and
		// reuses *gin.Context after the handler returns, so touching c from a
		// detached goroutine is a use-after-free race.
		log := httpx.LoggerFrom(c)
		go func(to, url, name string, exp time.Time) {
			defer func() {
				if r := recover(); r != nil && log != nil {
					log.Error("invite email panicked", "recover", r)
				}
			}()
			if err := h.mail.SendInvitation(to, url, name, exp); err != nil && log != nil {
				log.Error("invite email failed", "err", err)
			}
		}(created.Email, created.InviteURL, clientName, created.ExpiresAt)
	}

	h.audit.Log(audit.Entry{
		ClientID: u.ClientID, ActorUserID: &u.UserID, EventType: "invitation.created",
		RequestID: ptr(httpx.RequestIDFrom(c)),
	})

	c.JSON(http.StatusCreated, gin.H{
		"id": created.ID, "email": created.Email,
		"expires_at": created.ExpiresAt,
		// Returned deliberately (Decision D10a) so an admin can share the link
		// when email delivery is unavailable. The raw token is never persisted.
		"invite_url": created.InviteURL,
	})
}

// List handles GET /admin/invitations.
func (h *Handler) List(c *gin.Context) {
	u := middleware.UserFrom(c)
	items, err := h.svc.List(c.Request.Context(), u.ClientID)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, items) // bare array (Fastify shape)
}

// Revoke handles DELETE /admin/invitations/:id.
func (h *Handler) Revoke(c *gin.Context) {
	u := middleware.UserFrom(c)
	if err := h.svc.Revoke(c.Request.Context(), c.Param("id"), u.ClientID, u.UserID); err != nil {
		httpx.Fail(c, err)
		return
	}
	h.audit.Log(audit.Entry{
		ClientID: u.ClientID, ActorUserID: &u.UserID, EventType: "invitation.revoked",
		RequestID: ptr(httpx.RequestIDFrom(c)),
	})
	c.Status(http.StatusNoContent)
}

// Lookup handles GET /auth/accept-invitation/lookup?token=... (public).
func (h *Handler) Lookup(c *gin.Context) {
	token := c.Query("token")
	if token == "" || len(token) > 256 {
		httpx.FailWith(c, http.StatusBadRequest, "Invitation not found, expired, or already used")
		return
	}
	preview, err := h.svc.Lookup(c.Request.Context(), token)
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, preview)
}

type acceptRequest struct {
	Token    string `json:"token" validate:"required,max=256"`
	Password string `json:"password" validate:"required,min=8,max=512"`
}

// Accept handles POST /auth/accept-invitation (public).
func (h *Handler) Accept(c *gin.Context) {
	var req acceptRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := h.svc.Accept(c.Request.Context(), req.Token, req.Password); err != nil {
		httpx.Fail(c, err)
		return
	}
	// 204 with no body: nothing about the created account is echoed back to an
	// unauthenticated caller.
	c.Status(http.StatusNoContent)
}

func ptr(s string) *string { return &s }

type acceptGoogleRequest struct {
	Token string `json:"token" validate:"required,min=10,max=256"`
}

// AcceptGoogle handles POST /auth/accept-invitation/google (public) — redeems an
// invitation into an OAUTH_ONLY account with no password.
func (h *Handler) AcceptGoogle(c *gin.Context) {
	var req acceptGoogleRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	if err := h.svc.AcceptGoogle(c.Request.Context(), req.Token); err != nil {
		httpx.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
