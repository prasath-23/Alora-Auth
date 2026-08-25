package auth

import (
	"net/http"

	"github.com/alora/auth/internal/crypto/jwtkeys"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

// JWKS publishes the PUBLIC verification keys so product backends can validate
// tokens offline. Public by design — it contains no private material.
//
// Cached for 5 minutes: long enough to spare the endpoint from every downstream
// verifier, short enough that a rotated key propagates quickly.
func JWKS(c *gin.Context) {
	body, err := jwtkeys.JWKS()
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	c.Header("Cache-Control", "public, max-age=300, must-revalidate")
	c.Header("Vary", "Accept-Encoding")
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}
