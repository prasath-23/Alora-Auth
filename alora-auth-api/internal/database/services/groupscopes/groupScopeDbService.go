// Package groupscopes is the table service for tbl_group_scopes: the App
// Central scopes each group gives its members.
package groupscopes

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/sqlc"
)

// Outcomes of Set other than a count.
const (
	NotFound    int32 = -1 // no such group in this tenant
	SystemGroup int32 = -3 // a system group, which holds every scope already
)

// GroupScopeDbService is the CRUD surface of tbl_group_scopes.
type GroupScopeDbService struct{ q *sqlc.Queries }

// NewGroupScopeDbService binds the service to a context: the pool or a
// transaction.
func NewGroupScopeDbService(c contexts.Querier) *GroupScopeDbService {
	return &GroupScopeDbService{q: c.Queries()}
}

// Set replaces a group's scopes wholesale and bumps every member's
// admin_version, in one statement. It returns the number of scopes the group
// now gives, or NotFound / SystemGroup. An unknown scope is a foreign-key
// violation.
func (s *GroupScopeDbService) Set(ctx context.Context, groupID, clientID string, scopes []string) (int32, error) {
	if scopes == nil {
		scopes = []string{}
	}
	return s.q.SetGroupScopes(ctx, sqlc.SetGroupScopesParams{GroupID: groupID, ClientID: clientID, Scopes: scopes})
}
