package shared

import (
	"time"

	"github.com/gin-gonic/gin"
)

// Actor is the authenticated caller as a service sees it: the identity from the
// verified App Central token, the rights the database granted it on THIS
// request, and the request id that correlates its audit rows. Controllers build
// it with middlewares.ActorFrom, so no service ever reads *gin.Context.
type Actor struct {
	UserID    string
	ClientID  string // the caller's own company
	Email     string
	SessionID string // the central session family the token belongs to
	// Scopes: the App Central scopes the database grants the caller on THIS
	// request — never read from the token, so a change takes effect at once.
	Scopes ScopeSet
	// InAdmins: a member of the company's Admins group, which holds every scope.
	// For display; what the caller may do is decided by Scopes.
	InAdmins bool
	// IsOwner: a platform Owner, likewise read on every request.
	IsOwner bool
	// AuthenticatedAt is when the caller last proved who they are (the session's
	// sign-in, not its latest refresh). The Owner console requires it be recent.
	AuthenticatedAt time.Time
	// AdminVersion and PermVersion are the caller's current versions of their App
	// Central access and their product access. A token minted at other versions
	// describes access the caller no longer has.
	AdminVersion int32
	PermVersion  int32
	RequestID    string
}

// Can reports whether the caller holds an App Central scope.
func (a Actor) Can(scope string) bool { return a.Scopes.Has(scope) }

// Scope is who is acting, on which company. Every company-scoped service method
// takes one, and scopes every query by ClientID.
//
// An Admin's scope is always their own company. Only the Owner console builds a
// scope for another company, and only from a company id the Owner named in the
// path (see owner/controller).
type Scope struct {
	ClientID string // the company acted on
	Actor    Actor
	ByOwner  bool // an Owner acting through the Owner console
}

// TenantScope is the actor acting on their own company.
func TenantScope(a Actor) Scope { return Scope{ClientID: a.ClientID, Actor: a} }

// CanGive reports whether the actor may give — or take away — every one of
// scopes (rule 1): the Owner always; anyone else only scopes they hold
// themselves. It covers a group's scopes, a person's extras, adding someone to a
// group and inviting someone into one, so nobody can raise their own access or
// hand out more than they have.
func (s Scope) CanGive(scopes []string) bool {
	return s.ByOwner || s.Actor.Scopes.Covers(scopes)
}

// CanManage reports whether the actor may act on a person who holds
// targetScopes (rule 2): deactivate them, reset their password, change their
// extras or their groups. The Owner always may; nobody else may act on an
// Owner; anyone else only on people with no more access than themselves, so a
// helper can never lock out the people who gave them their access.
func (s Scope) CanManage(targetScopes []string, targetIsOwner bool) bool {
	switch {
	case s.ByOwner:
		return true
	case targetIsOwner:
		return false
	default:
		return s.Actor.Scopes.Covers(targetScopes)
	}
}

// ScopeResolver builds the scope a request acts in. The same controller serves a
// company's Admins (who act on their own company) and the Owner console (which
// names the company in the path), and is wired with the resolver for each: the
// company a request may act on is decided by the route it came in on, never by
// the handler.
type ScopeResolver func(c *gin.Context) (Scope, error)
