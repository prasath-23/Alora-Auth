package oauth

import (
	"net/http"
	"strings"

	"github.com/alora/auth/internal/auth"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/alora/auth/internal/session"
	"github.com/gin-gonic/gin"
)

// Handler serves the two login legs plus refresh/logout.
type Handler struct {
	svc      *Service
	authSvc  *auth.Service
	sessions *session.Service
	jar      *httpx.CookieJar
}

func NewHandler(svc *Service, authSvc *auth.Service, sessions *session.Service, jar *httpx.CookieJar) *Handler {
	return &Handler{svc: svc, authSvc: authSvc, sessions: sessions, jar: jar}
}

// authorizeRequest — binding tags enforce presence/shape before any DB work.
// This is a DTO, deliberately separate from any sqlc row type: the wire contract
// and the storage schema must be free to diverge.
type authorizeRequest struct {
	Email               string `json:"email" validate:"required,email,max=320"`
	Password            string `json:"password" validate:"required,min=1,max=512"`
	ProductID           string `json:"product_id" validate:"required,uuid4"`
	RedirectURL         string `json:"redirect_url" validate:"required,url,max=2048"`
	CodeChallenge       string `json:"code_challenge" validate:"required,min=43,max=128"`
	CodeChallengeMethod string `json:"code_challenge_method" validate:"omitempty,oneof=S256"`
	State               string `json:"state" validate:"omitempty,max=512"`
}

// Authorize handles POST /auth/authorize.
func (h *Handler) Authorize(c *gin.Context) {
	var req authorizeRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	code, err := h.svc.Authorize(c.Request.Context(), AuthorizeInput{
		Email:               req.Email,
		Password:            req.Password,
		ProductID:           req.ProductID,
		RedirectURL:         req.RedirectURL,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		State:               req.State,
	})
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	// Only the code is returned — never a token on the credential leg.
	c.JSON(http.StatusOK, gin.H{"code": code})
}

type tokenRequest struct {
	Code         string `json:"code" validate:"required,max=256"`
	CodeVerifier string `json:"code_verifier" validate:"required,min=43,max=128"`
	RedirectURL  string `json:"redirect_url" validate:"omitempty,url,max=2048"`
}

// Token handles POST /auth/token: code + verifier → access token (+ cookies).
func (h *Handler) Token(c *gin.Context) {
	var req tokenRequest
	if err := httpx.BindJSON(c, &req); err != nil {
		httpx.Fail(c, err)
		return
	}
	ctx := c.Request.Context()

	redeemed, err := h.svc.Redeem(ctx, req.Code, req.CodeVerifier, req.RedirectURL)
	if err != nil {
		httpx.Fail(c, err)
		return
	}

	// The product key scopes the token's audience so a token minted for product A
	// cannot be replayed against product B.
	productKey, err := h.svc.ProductKey(ctx, redeemed.ProductID)
	if err != nil {
		httpx.Fail(c, err)
		return
	}

	// Minting re-reads identity from the DB WITH a liveness guard, so an account
	// deactivated during the 2-minute code window is refused here.
	accessToken, identity, err := h.authSvc.MintAccessToken(ctx, redeemed.UserID, productKey)
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

	body := gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   h.authSvc.AccessTokenTTLSeconds(),
	}
	if redeemed.State != "" {
		body["state"] = redeemed.State // RFC 6749 §4.1.2 echo
	}
	c.JSON(http.StatusOK, body)
}

// Refresh handles POST /auth/refresh — the rotation endpoint.
func (h *Handler) Refresh(c *gin.Context) {
	raw, err := c.Cookie(httpx.CookieRefresh)
	// Length bounds before any hashing: rejects absurd input cheaply and keeps a
	// malformed cookie from reaching the database at all.
	if err != nil || len(raw) < 32 || len(raw) > 256 {
		h.clearAuthCookies(c)
		httpx.Fail(c, httpx.ErrSessionInvalid)
		return
	}

	issued, userID, err := h.sessions.Rotate(c.Request.Context(), raw, metaFrom(c))
	if err != nil {
		// A benign concurrent rotation must NOT clear the cookie: the winning
		// request's token is still valid and the client should simply retry.
		if err == httpx.ErrRotationRace {
			httpx.Fail(c, err)
			return
		}
		h.clearAuthCookies(c)
		httpx.Fail(c, err)
		return
	}

	accessToken, _, err := h.authSvc.MintAccessToken(c.Request.Context(), userID, "")
	if err != nil {
		h.clearAuthCookies(c)
		httpx.Fail(c, err)
		return
	}

	h.jar.SetRefresh(c, issued.RawToken, h.sessions.RefreshTTL())
	h.jar.SetAccess(c, accessToken)
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   h.authSvc.AccessTokenTTLSeconds(),
	})
}

// Logout handles POST /auth/logout. Always 204: revealing whether the presented
// token existed would leak session state to an unauthenticated caller.
func (h *Handler) Logout(c *gin.Context) {
	if raw, err := c.Cookie(httpx.CookieRefresh); err == nil && len(raw) <= 256 && raw != "" {
		if err := h.sessions.Revoke(c.Request.Context(), raw); err != nil {
			httpx.Fail(c, err)
			return
		}
	}
	h.clearAuthCookies(c)
	c.Status(http.StatusNoContent)
}

func (h *Handler) clearAuthCookies(c *gin.Context) {
	h.jar.ClearRefresh(c)
	h.jar.ClearAccess(c)
}

// metaFrom captures the request fingerprint. ClientIP() is only trustworthy
// because SetTrustedProxies is an explicit allowlist; with Gin's default
// trust-all a client could spoof this via X-Forwarded-For.
func metaFrom(c *gin.Context) session.Meta {
	ua := c.Request.UserAgent()
	if len(ua) > 512 {
		ua = ua[:512] // bound what an untrusted header can store
	}
	return session.Meta{IP: c.ClientIP(), UserAgent: ua, DeviceLabel: deviceLabel(ua)}
}

// deviceLabel renders a coarse, human-readable label for the sessions UI. It is
// display-only and never used for any security decision.
func deviceLabel(ua string) string {
	switch {
	case ua == "":
		return "Unknown device"
	case strings.Contains(ua, "Edg/"):
		return "Edge"
	case strings.Contains(ua, "Chrome/"):
		return "Chrome"
	case strings.Contains(ua, "Firefox/"):
		return "Firefox"
	case strings.Contains(ua, "Safari/"):
		return "Safari"
	default:
		return "Unknown device"
	}
}
