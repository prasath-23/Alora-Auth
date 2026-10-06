package middlewares

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// ErrCrossSite is the refusal of a state-changing request a browser sent from
// another site.
var ErrCrossSite = exceptions.NewAPIError(http.StatusForbidden, "Cross-site request refused", nil)

// SameOriginOnly refuses a cookie-bearing, state-changing request unless the
// browser says it came from App Central's own origin.
//
// The session cookie is SameSite=Lax, which already keeps it off a cross-site
// POST, and every JSON endpoint refuses a body that is not application/json,
// which a cross-site form cannot send. This is the third, independent layer,
// and the one that also covers a same-SITE attacker: a sibling subdomain is
// "same-site", so SameSite does not stop it, but it is not same-origin.
//
// The Fetch Metadata header decides when present (every current browser sends
// it). Otherwise the Origin header must name one of the allowed origins. A
// request with neither did not come from a browser, and a non-browser client
// carries no ambient cookies to abuse, so it passes.
func SameOriginOnly(allowedOrigins ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if u, err := url.Parse(o); err == nil && u.Host != "" {
			allowed[strings.ToLower(u.Scheme+"://"+u.Host)] = true
		}
	}
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		if site := c.GetHeader("Sec-Fetch-Site"); site != "" {
			// "none" is a navigation the user started themselves (the address bar,
			// a bookmark) and never a POST another page made.
			if site == "same-origin" || site == "none" {
				c.Next()
				return
			}
			exceptions.Fail(c, ErrCrossSite)
			return
		}
		if origin := c.GetHeader("Origin"); origin != "" {
			if !allowed[strings.ToLower(origin)] {
				exceptions.Fail(c, ErrCrossSite)
				return
			}
		}
		c.Next()
	}
}
