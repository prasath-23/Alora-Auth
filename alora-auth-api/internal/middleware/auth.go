// Package middleware holds the authentication and authorization chain applied to
// protected routes: authenticate → requireFresh → requireAdmin/requireFeature.
package middleware

import (
	"context"
	"strings"

	"github.com/alora/auth/internal/crypto/jwtkeys"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

const ctxUser = "alora.user"

// AuthUser is the verified identity extracted from a JWT. Every field comes from
// a SIGNED token, so it is trustworthy for authorization decisions EXCEPT for
// staleness — which is what RequireFresh re-checks against the database.
type AuthUser struct {
	UserID        string
	ClientID      string
	Email         string
	Roles         map[string]string // product_key → role_name
	PermVersion   int
	IsGlobalAdmin bool
}

// UserFrom returns the authenticated user, or nil if the route is unauthenticated.
func UserFrom(c *gin.Context) *AuthUser {
	if v, ok := c.Get(ctxUser); ok {
		if u, ok := v.(*AuthUser); ok {
			return u
		}
	}
	return nil
}

// Authenticate verifies a Bearer token and loads the identity onto the context.
//
// The token is read ONLY from the Authorization header, never from the alora_at
// cookie: accepting an ambient cookie as proof of identity would reintroduce
// CSRF on every admin route, which the SameSite=Lax + Bearer design exists to
// prevent (there is no CSRF token in this system).
func Authenticate(apiAudience string) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.GetHeader("Authorization")
		scheme, token, ok := strings.Cut(raw, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
			httpx.Fail(c, httpx.ErrUnauthorized)
			return
		}

		tok, err := jwtkeys.Verify(token, apiAudience)
		if err != nil {
			// Never echo the verifier's reason: it distinguishes "expired" from
			// "bad signature" from "unknown kid", which aids forgery attempts.
			httpx.Fail(c, httpx.ErrUnauthorized)
			return
		}

		u := &AuthUser{UserID: tok.Subject(), Roles: map[string]string{}}
		if v, ok := tok.Get("client_id"); ok {
			u.ClientID, _ = v.(string)
		}
		if v, ok := tok.Get("email"); ok {
			u.Email, _ = v.(string)
		}
		if v, ok := tok.Get("is_global_admin"); ok {
			u.IsGlobalAdmin, _ = v.(bool)
		}
		if v, ok := tok.Get("pv"); ok {
			u.PermVersion = toInt(v)
		}
		if v, ok := tok.Get("roles"); ok {
			if m, ok := v.(map[string]any); ok {
				for k, rv := range m {
					if s, ok := rv.(string); ok {
						u.Roles[k] = s
					}
				}
			}
		}
		// A token without a tenant cannot be scoped to anything; refuse it rather
		// than let a handler run an unscoped query.
		if u.UserID == "" || u.ClientID == "" {
			httpx.Fail(c, httpx.ErrUnauthorized)
			return
		}

		c.Set(ctxUser, u)
		c.Next()
	}
}

// toInt normalizes a JSON number claim. encoding/json yields float64, jwx may
// yield json.Number or int64 depending on the decoder — all three must work, or
// the freshness comparison silently fails and every request 401s.
func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case interface{ Int64() (int64, error) }: // json.Number
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	}
	return 0
}

// Freshness is the per-request staleness probe backing RequireFresh.
type Freshness struct {
	PermissionsVersion int
	IsActive           bool
	Deleted            bool
	Found              bool
}

// FreshnessChecker is implemented by the users repo.
type FreshnessChecker interface {
	Freshness(ctx context.Context, userID string) (Freshness, error)
}

// RequireFresh re-validates the token's claims against the database on EVERY
// request: one indexed read is the price of instant revocation.
//
// A JWT is valid for 15 minutes, so without this check a deactivated, deleted, or
// demoted user would keep full access until natural expiry. Comparing pv to the
// stored permissions_version is what makes a permission change take effect
// immediately without forcing a global logout.
func RequireFresh(fc FreshnessChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := UserFrom(c)
		if u == nil {
			httpx.Fail(c, httpx.ErrUnauthorized)
			return
		}
		f, err := fc.Freshness(c.Request.Context(), u.UserID)
		if err != nil {
			httpx.Fail(c, err)
			return
		}
		if !f.Found || !f.IsActive || f.Deleted || f.PermissionsVersion != u.PermVersion {
			httpx.Fail(c, httpx.ErrUnauthorized)
			return
		}
		c.Next()
	}
}

// RequireAdmin enforces the top two tiers of the RBAC precedence chain:
// is_global_admin, then any product role whose VALUE is "Admin".
//
// It ranges over the roles map's VALUES, not its keys: the map is
// product_key → role_name, so a user is an admin when they hold the "Admin" role
// in ANY product, regardless of which product that is.
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		u := UserFrom(c)
		if u == nil {
			httpx.Fail(c, httpx.ErrUnauthorized)
			return
		}
		if u.IsGlobalAdmin {
			c.Next()
			return
		}
		for _, role := range u.Roles {
			if role == "Admin" {
				c.Next()
				return
			}
		}
		httpx.Fail(c, httpx.ErrForbidden)
	}
}

// AdminFeatures is the closed registry of grantable feature keys. A closed set
// means a typo in a route definition fails loudly at startup rather than
// silently granting or denying access at runtime.
var AdminFeatures = map[string]struct{}{
	"users:view": {}, "users:add": {}, "users:edit": {}, "users:deactivate": {},
	"passwords:reset": {}, "products:view": {}, "sessions:view": {}, "sessions:revoke": {},
	"groups:view": {}, "groups:manage": {}, "client:view": {}, "client:edit": {},
}

// FeatureChecker is implemented by the RBAC repo.
type FeatureChecker interface {
	// HasGroupFeature must verify the GROUP's own client_id matches clientID —
	// checking only membership would let a cross-tenant group grant access.
	HasGroupFeature(ctx context.Context, featureKey, clientID, userID string) (bool, error)
}

// RequireFeature enforces the third RBAC tier: group-granted feature keys.
// Admins short-circuit, matching the documented precedence
// (is_global_admin > product "Admin" role > group membership).
func RequireFeature(fc FeatureChecker, key string) gin.HandlerFunc {
	if _, ok := AdminFeatures[key]; !ok {
		panic("middleware: unknown feature key " + key) // startup-time typo guard
	}
	return func(c *gin.Context) {
		u := UserFrom(c)
		if u == nil {
			httpx.Fail(c, httpx.ErrUnauthorized)
			return
		}
		if u.IsGlobalAdmin {
			c.Next()
			return
		}
		for _, role := range u.Roles {
			if role == "Admin" {
				c.Next()
				return
			}
		}
		ok, err := fc.HasGroupFeature(c.Request.Context(), key, u.ClientID, u.UserID)
		if err != nil {
			httpx.Fail(c, err)
			return
		}
		if !ok {
			httpx.Fail(c, httpx.ErrForbidden)
			return
		}
		c.Next()
	}
}
