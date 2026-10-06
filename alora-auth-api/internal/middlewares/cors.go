package middlewares

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// WellKnownCORS lets any origin READ the published discovery document and keys,
// and nothing else. A product's frontend, a gateway or a library may fetch them
// from a browser; they are public by definition and carry no credentials.
//
// Every other route answers no CORS at all. App Central's own pages and its API
// share one origin, so they never need it, and a product's backend talks to the
// token endpoint server to server, where CORS does not apply. Without a
// credentialed CORS policy there is no origin list to get wrong.
func WellKnownCORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/.well-known/") {
			c.Next()
			return
		}
		h := c.Writer.Header()
		// "*" — and deliberately never Allow-Credentials, so no browser will ever
		// send cookies with such a request or expose a credentialed response.
		h.Set("Access-Control-Allow-Origin", "*")
		// The published documents are read cross-origin, which the
		// Cross-Origin-Resource-Policy set on every response would otherwise block
		// for a no-cors fetch.
		h.Set("Cross-Origin-Resource-Policy", "cross-origin")
		if c.Request.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			h.Set("Access-Control-Max-Age", "86400")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
