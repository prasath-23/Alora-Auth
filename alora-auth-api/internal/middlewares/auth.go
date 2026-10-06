// Package middlewares holds the HTTP interceptors that run around every handler:
// request ids and the request logger, error rendering, panic recovery, security
// headers, CORS, CSRF, rate limiting, and the authentication and authorization
// chain applied to protected routes:
// Authenticate → RequireFresh → RequireScope / RequireOwner.
package middlewares

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/jwtkeys"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

const (
	ctxPrincipal = "alora.principal"
	ctxActor     = "alora.actor"
)

// Principal is the identity a verified App Central token claims. Every field
// comes from a SIGNED token, so it is who the caller is; what they may do is
// decided by RequireFresh, from the database, on every request.
type Principal struct {
	UserID    string
	ClientID  string
	Email     string
	SessionID string
	// AdminVersion and PermVersion are the access versions the token was minted
	// at. They decide nothing; they only tell RequireFresh when the token's own
	// description of the caller's access (its scope and products) is stale.
	AdminVersion int64
	PermVersion  int64
}

// TokenStaleHeader is set on a response to a request whose token describes
// access the caller no longer has — or lacks access they now have. The request
// itself was decided on the caller's CURRENT access, read from the database;
// the header tells the SPA to fetch a fresh token and re-render.
const TokenStaleHeader = "X-Alora-Token-Stale"

// ErrReauthRequired is the refusal of an Owner whose sign-in is too old for the
// Owner console. It is a 403, not a 401: refreshing the session does not change
// when its user signed in, so only signing in again helps.
var ErrReauthRequired = exceptions.NewAPIError(http.StatusForbidden, "Recent sign-in required", nil)

// Authenticate verifies a Bearer token issued for audience and puts its identity
// on the context.
//
// The token is read ONLY from the Authorization header, never from a cookie:
// accepting an ambient cookie as proof of identity would reintroduce CSRF on
// every route behind it. The audience is what keeps the planes apart: a product
// token (audience product:<key>) is refused here however valid its signature.
func Authenticate(audience string) gin.HandlerFunc {
	if audience == "" {
		panic("middlewares: Authenticate needs an audience") // startup-time guard
	}
	return func(c *gin.Context) {
		scheme, token, ok := strings.Cut(c.GetHeader("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
			exceptions.Fail(c, exceptions.ErrUnauthorized)
			return
		}
		tok, err := jwtkeys.VerifyAccess(token, audience)
		if err != nil {
			// Never echo the verifier's reason: it distinguishes "expired" from
			// "bad signature" from "unknown kid", which aids forgery attempts.
			exceptions.Fail(c, exceptions.ErrUnauthorized)
			return
		}
		p := &Principal{UserID: tok.Subject()}
		p.ClientID = stringClaim(tok.Get("tenant_id"))
		p.Email = stringClaim(tok.Get("email"))
		p.SessionID = stringClaim(tok.Get("sid"))
		p.AdminVersion = intClaim(tok.Get("av"))
		p.PermVersion = intClaim(tok.Get("pv"))
		// A token without a company or a session cannot be scoped or checked for
		// revocation; refuse it rather than let a handler run unscoped.
		if p.UserID == "" || p.ClientID == "" || p.SessionID == "" {
			exceptions.Fail(c, exceptions.ErrUnauthorized)
			return
		}
		c.Set(ctxPrincipal, p)
		c.Next()
	}
}

func stringClaim(v any, ok bool) string {
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// intClaim reads a numeric claim, which JSON decodes as float64 (SPEC §8 #10);
// -1 when absent, so a token without it is never taken for current.
func intClaim(v any, ok bool) int64 {
	if !ok {
		return -1
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	default:
		return -1
	}
}

// CallerLoader decides, from the database, whether a token's session still
// stands and what its user may do. Implemented by the auth service, which owns
// the rule.
type CallerLoader interface {
	// LoadCaller returns the caller when the session is a live App Central login
	// of that user in that company, and exceptions.ErrUnauthorized when it is not.
	LoadCaller(ctx context.Context, userID, clientID, sessionID string) (shared.Actor, error)
}

// RequireFresh re-checks the token's session against the database on EVERY
// request, so a revoked session, a deactivated user or a suspended company loses
// access immediately rather than when the token expires. It also loads, fresh,
// the caller's scopes and whether they are an Owner: those rights are never read
// from the token. When the token's own snapshot of them is out of date, the
// response carries TokenStaleHeader.
func RequireFresh(loader CallerLoader) gin.HandlerFunc {
	return func(c *gin.Context) {
		p := principalFrom(c)
		if p == nil {
			exceptions.Fail(c, exceptions.ErrUnauthorized)
			return
		}
		actor, err := loader.LoadCaller(c.Request.Context(), p.UserID, p.ClientID, p.SessionID)
		if err != nil {
			exceptions.Fail(c, err)
			return
		}
		actor.RequestID = RequestIDFrom(c)
		if p.AdminVersion != int64(actor.AdminVersion) || p.PermVersion != int64(actor.PermVersion) {
			c.Header(TokenStaleHeader, "1")
		}
		c.Set(ctxActor, &actor)
		c.Next()
	}
}

func principalFrom(c *gin.Context) *Principal {
	if v, ok := c.Get(ctxPrincipal); ok {
		if p, ok := v.(*Principal); ok {
			return p
		}
	}
	return nil
}

func actorFrom(c *gin.Context) *shared.Actor {
	if v, ok := c.Get(ctxActor); ok {
		if a, ok := v.(*shared.Actor); ok {
			return a
		}
	}
	return nil
}

// ActorFrom is the authenticated caller as the service layer sees it. It panics
// when no caller is on the context: that is a route wired outside the
// authenticated groups, and the recovered panic is a fail-closed 500 -- never a
// zero-value Actor querying with an empty company.
func ActorFrom(c *gin.Context) shared.Actor {
	a := actorFrom(c)
	if a == nil {
		panic("middlewares: ActorFrom on a route without RequireFresh")
	}
	return *a
}

// TenantScope is the caller acting on their own company: the scope of every
// /api/admin route.
func TenantScope(c *gin.Context) (shared.Scope, error) {
	return shared.TenantScope(ActorFrom(c)), nil
}

// RequireScope admits a caller who holds the App Central scope, as the database
// grants it on this request (through a group, the Admins group, or an extra).
// An unknown scope panics when the route is wired, so a typo fails at startup
// instead of silently locking or opening the route.
func RequireScope(scope string) gin.HandlerFunc {
	if !shared.IsGrantable(scope) {
		panic("middlewares: unknown scope " + scope) // startup-time typo guard
	}
	return func(c *gin.Context) {
		a := actorFrom(c)
		if a == nil {
			exceptions.Fail(c, exceptions.ErrUnauthorized)
			return
		}
		if !a.Can(scope) {
			exceptions.Fail(c, exceptions.ErrForbidden)
			return
		}
		c.Next()
	}
}

// RequireOwner admits a platform Owner who signed in within maxAge. The Owner
// console can change how anyone in any company signs in, so a session that has
// merely been kept alive by refreshes is not enough: its sign-in must be recent.
func RequireOwner(maxAge time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		a := actorFrom(c)
		if a == nil {
			exceptions.Fail(c, exceptions.ErrUnauthorized)
			return
		}
		if !a.IsOwner {
			exceptions.Fail(c, exceptions.ErrForbidden)
			return
		}
		if a.AuthenticatedAt.IsZero() || time.Since(a.AuthenticatedAt) > maxAge {
			exceptions.Fail(c, ErrReauthRequired)
			return
		}
		c.Next()
	}
}
