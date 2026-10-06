package middlewares

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders is the helmet equivalent. This is a JSON API that never renders
// HTML, so the policy is maximally restrictive: a locked-down CSP costs nothing
// and neutralizes any reflected content that somehow reaches a browser.
//
// HSTS is emitted only in production (SPEC §7, D14). A browser honours it only
// over TLS, and a development or staging host served over TLS — a *.alora.test
// proxy, say — would otherwise be pinned to https, subdomains included, for a
// year.
func SecurityHeaders(isProd bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()

		// Nothing may be loaded, framed, or connected to by a document from this
		// origin. frame-ancestors 'none' is the modern anti-clickjacking control.
		h.Set("Content-Security-Policy",
			"default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

		h.Set("X-Content-Type-Options", "nosniff") // no MIME sniffing
		h.Set("X-Frame-Options", "DENY")           // legacy clickjacking guard
		h.Set("Referrer-Policy", "no-referrer")    // never leak tokens in URLs via Referer
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		h.Set("Origin-Agent-Cluster", "?1")

		if isProd {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		c.Next()
	}
}

// BodyLimit caps the request body at maxBytes (64 KiB). Applied before any
// decoding so an oversized payload is rejected without being buffered — this is
// the first line of defense against memory-exhaustion on unauthenticated routes.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
