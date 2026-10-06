// Package controller publishes App Central's OpenID Provider metadata and its
// token-verification keys.
package controller

import (
	"net/http"

	"github.com/alora/auth/internal/core/auth/models"
	"github.com/alora/auth/internal/core/auth/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// WellKnownController serves /.well-known/*.
type WellKnownController struct{ svc service.AuthService }

// NewWellKnownController builds the controller.
func NewWellKnownController(svc service.AuthService) *WellKnownController {
	return &WellKnownController{svc: svc}
}

// JWKS publishes the PUBLIC verification keys so product backends can validate
// tokens offline. Public by design — it contains no private material.
//
//	@Summary		Public signing keys (JWKS)
//	@Description	The RS256 public keys every token is signed with, including any key being retired during a rotation. Products verify their access tokens and ID tokens offline against these. Cached for five minutes, so a rotated key propagates quickly without every verifier hitting this endpoint on every request.
//	@Tags			standards
//	@Produce		json
//	@Success		200	{object}	models.JWKSResponse
//	@Failure		500	{object}	exceptions.ErrorResponse
//	@Router			/.well-known/jwks.json [get]
func (h *WellKnownController) JWKS(c *gin.Context) {
	body, err := h.svc.JWKS()
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Header("Cache-Control", "public, max-age=300, must-revalidate")
	shared.AddVary(c.Writer.Header(), "Accept-Encoding")
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}

// Discovery publishes the OpenID Provider metadata.
//
//	@Summary		OpenID Provider metadata
//	@Description	Where a product finds everything else: the authorize, token, revocation and introspection endpoints, the JWKS, and exactly what is supported — the code flow with S256 PKCE, client_secret_basic, RS256.
//	@Tags			standards
//	@Produce		json
//	@Success		200	{object}	models.DiscoveryResponse
//	@Router			/.well-known/openid-configuration [get]
func (h *WellKnownController) Discovery(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=300, must-revalidate")
	c.JSON(http.StatusOK, models.NewDiscoveryResponse(h.svc.Discovery()))
}
