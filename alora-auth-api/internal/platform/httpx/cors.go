package httpx

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// OriginVerifier reports whether an origin hostname belongs to an ACTIVE tenant
// with a VERIFIED domain. Implemented over the clients repo; declared as an
// interface here so httpx never imports a feature or the generated db package.
type OriginVerifier interface {
	IsVerifiedActiveDomain(ctx context.Context, host string) (bool, error)
}

const originCacheTTL = 60 * time.Second

type cacheEntry struct {
	allowed bool
	expires time.Time
}

// CORS validates the Origin header against the tenant table, and FAILS CLOSED:
// an unknown origin, a DB error, or a malformed header all result in no CORS
// headers being emitted, so the browser blocks the response.
//
// Credentials are allowed, therefore the allow-origin header is ALWAYS the exact
// echoed origin — never "*". (A wildcard with credentials is rejected by browsers
// anyway, and would be a catastrophic misconfiguration if it were not.)
type CORS struct {
	verifier OriginVerifier
	isProd   bool
	mu       sync.RWMutex
	cache    map[string]cacheEntry
}

func NewCORS(v OriginVerifier, isProd bool) *CORS {
	return &CORS{verifier: v, isProd: isProd, cache: make(map[string]cacheEntry)}
}

func (x *CORS) allowed(ctx context.Context, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()

	// Local development origins. Gated on !isProd so a production deployment can
	// never be reached from a localhost page.
	if !x.isProd {
		if host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".alora.test") {
			return true
		}
	}
	// Everything else must be https — an http origin cannot be a legitimate tenant.
	if u.Scheme != "https" {
		return false
	}

	x.mu.RLock()
	e, ok := x.cache[host]
	x.mu.RUnlock()
	if ok && time.Now().Before(e.expires) {
		return e.allowed
	}

	ok2, err := x.verifier.IsVerifiedActiveDomain(ctx, host)
	if err != nil {
		return false // fail closed; do NOT cache a transient DB failure
	}
	x.mu.Lock()
	x.cache[host] = cacheEntry{allowed: ok2, expires: time.Now().Add(originCacheTTL)}
	x.mu.Unlock()
	return ok2
}

func (x *CORS) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		// No Origin = same-origin or a non-browser client (curl, server-to-server).
		// CORS is a browser control; there is nothing to decide here.
		if origin == "" {
			c.Next()
			return
		}

		if !x.allowed(c.Request.Context(), origin) {
			// Emit no CORS headers. A preflight must not be answered 2xx, or the
			// browser would treat the denial as success.
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Next()
			return
		}

		h := c.Writer.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		// Vary is mandatory: without it a shared cache could serve one tenant's
		// allow-origin header to another tenant's request.
		h.Add("Vary", "Origin")

		if c.Request.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET,POST,PATCH,PUT,DELETE,OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
			h.Set("Access-Control-Max-Age", "600")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
