package shared

import (
	"sort"
	"strconv"
	"strings"
)

// App Central scopes: what a person may do in App Central. Each feature has a
// read scope and, where it can be changed, an edit scope. Edit includes Read:
// giving an edit scope always gives its read scope too, and a token lists both.
//
// The closed catalogue also lives in the database (tbl_scopes, kind PERSON),
// which every grant references, so an unknown scope cannot even be stored. This
// registry must list exactly the same scopes; cmd/api's schema tests hold the
// two in step.
const (
	ScopeApps            = "apps:read" // everyone signed in: the product list
	ScopeUsersRead       = "users:read"
	ScopeUsersEdit       = "users:edit"
	ScopeGroupsRead      = "groups:read"
	ScopeGroupsEdit      = "groups:edit"
	ScopeInvitationsRead = "invitations:read"
	ScopeInvitationsEdit = "invitations:edit"
	ScopeSessionsRead    = "sessions:read"
	ScopeSessionsEdit    = "sessions:edit"
	ScopeProductsRead    = "products:read"
	ScopeCompanyRead     = "company:read"
	ScopeCompanyEdit     = "company:edit"
	ScopeAPIClientsRead  = "api-clients:read"
	ScopeAPIClientsEdit  = "api-clients:edit"
	ScopeOwner           = "owner" // a platform Owner: provisioned, never given
)

// Application scopes: where an API client's credential may be used. They are
// given to API clients only, never to people, and edit includes read here too.
// The catalogue lists them as well (tbl_scopes, kind CLIENT).
const (
	ScopeAPIRead  = "api:read"  // read through a product's REST API
	ScopeAPIEdit  = "api:edit"  // change data through it
	ScopeGRPCRead = "grpc:read" // read through a product's gRPC services
	ScopeGRPCEdit = "grpc:edit" // change data through them
	ScopeMCPTools = "mcp:tools" // use a product's MCP tools
)

// ClientScopes is every application scope, in display order.
func ClientScopes() []string {
	return []string{ScopeAPIRead, ScopeAPIEdit, ScopeGRPCRead, ScopeGRPCEdit, ScopeMCPTools}
}

// clientScopes maps each application scope to the read scope it implies.
var clientScopes = map[string]string{
	ScopeAPIRead: "", ScopeAPIEdit: ScopeAPIRead,
	ScopeGRPCRead: "", ScopeGRPCEdit: ScopeGRPCRead,
	ScopeMCPTools: "",
}

// Feature is one row of the access table: a feature's read scope and, where it
// can be changed, its edit scope.
type Feature struct {
	Key  string
	Read string
	Edit string // "" for a read-only feature
}

// Features lists the App Central features in display order.
var Features = []Feature{
	{Key: "users", Read: ScopeUsersRead, Edit: ScopeUsersEdit},
	{Key: "groups", Read: ScopeGroupsRead, Edit: ScopeGroupsEdit},
	{Key: "invitations", Read: ScopeInvitationsRead, Edit: ScopeInvitationsEdit},
	{Key: "sessions", Read: ScopeSessionsRead, Edit: ScopeSessionsEdit},
	{Key: "products", Read: ScopeProductsRead},
	{Key: "company", Read: ScopeCompanyRead, Edit: ScopeCompanyEdit},
	{Key: "api-clients", Read: ScopeAPIClientsRead, Edit: ScopeAPIClientsEdit},
}

// GrantableScopes is every scope a group or an extra can give, in display
// order. apps:read (everyone holds it) and owner (provisioned, never given) are
// not among them.
func GrantableScopes() []string {
	out := make([]string, 0, 2*len(Features))
	for _, f := range Features {
		out = append(out, f.Read)
		if f.Edit != "" {
			out = append(out, f.Edit)
		}
	}
	return out
}

var grantable = func() map[string]string {
	m := map[string]string{} // scope -> the read scope it implies ("" for a read scope)
	for _, f := range Features {
		m[f.Read] = ""
		if f.Edit != "" {
			m[f.Edit] = f.Read
		}
	}
	return m
}()

// IsGrantable reports whether s is a scope a group or an extra can give.
func IsGrantable(s string) bool {
	_, ok := grantable[s]
	return ok
}

// UnknownScopeError names a requested scope that no group or extra can give —
// including the empty string.
type UnknownScopeError struct{ Scope string }

func (e UnknownScopeError) Error() string { return "Unknown scope " + strconv.Quote(e.Scope) }

// NormalizeScopes validates a requested set of a person's scopes and completes
// it: every edit scope brings its read scope. It returns the scopes sorted and
// without duplicates, or an UnknownScopeError for the first scope that is not
// grantable.
func NormalizeScopes(in []string) ([]string, error) { return normalize(in, grantable) }

// NormalizeClientScopes does the same for an API client's scopes.
func NormalizeClientScopes(in []string) ([]string, error) { return normalize(in, clientScopes) }

func normalize(in []string, known map[string]string) ([]string, error) {
	set := NewScopeSet()
	for _, s := range in {
		s = strings.TrimSpace(s)
		read, ok := known[s]
		if !ok {
			return nil, UnknownScopeError{Scope: s}
		}
		set[s] = struct{}{}
		if read != "" {
			set[read] = struct{}{}
		}
	}
	return set.Sorted(), nil
}

// ScopeSet is a set of scopes.
type ScopeSet map[string]struct{}

// NewScopeSet builds a set.
func NewScopeSet(scopes ...string) ScopeSet {
	s := make(ScopeSet, len(scopes))
	for _, v := range scopes {
		s[v] = struct{}{}
	}
	return s
}

// Has reports whether the set holds scope.
func (s ScopeSet) Has(scope string) bool {
	_, ok := s[scope]
	return ok
}

// Covers reports whether the set holds every one of scopes.
func (s ScopeSet) Covers(scopes []string) bool {
	for _, v := range scopes {
		if !s.Has(v) {
			return false
		}
	}
	return true
}

// Sorted lists the set's scopes in order; never nil.
func (s ScopeSet) Sorted() []string {
	out := make([]string, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// TokenScopes is the scope list a login token carries, in order: apps:read
// (everyone signed in), the App Central scopes held, and owner for a platform
// Owner.
func TokenScopes(held ScopeSet, isOwner bool) []string {
	out := []string{ScopeApps}
	out = append(out, held.Sorted()...)
	if isOwner {
		out = append(out, ScopeOwner)
	}
	return out
}

// Changed is what moving from before to after gives or takes away: every scope
// in one set and not the other.
func Changed(before, after []string) []string {
	b, a := NewScopeSet(before...), NewScopeSet(after...)
	diff := NewScopeSet()
	for v := range b {
		if !a.Has(v) {
			diff[v] = struct{}{}
		}
	}
	for v := range a {
		if !b.Has(v) {
			diff[v] = struct{}{}
		}
	}
	return diff.Sorted()
}
