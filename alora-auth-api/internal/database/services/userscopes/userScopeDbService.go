// Package userscopes is the table service for tbl_user_scopes: the extra App
// Central scopes given to one person, on top of their groups'.
package userscopes

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// NotFound is Set's outcome for a user who is not a live member of the tenant.
const NotFound int32 = -1

// UserScopeDbService is the CRUD surface of tbl_user_scopes.
type UserScopeDbService struct{ q *sqlc.Queries }

// NewUserScopeDbService binds the service to a context: the pool or a
// transaction.
func NewUserScopeDbService(c contexts.Querier) *UserScopeDbService {
	return &UserScopeDbService{q: c.Queries()}
}

// Set replaces a person's extras wholesale and bumps their admin_version, in one
// statement. New extras are attributed to grantedByUserID or grantedByOwnerID
// (at most one set); kept ones keep their attribution. It returns the number of
// extras now held, or NotFound.
func (s *UserScopeDbService) Set(ctx context.Context, userID, clientID string, scopes []string,
	grantedByUserID, grantedByOwnerID string) (int32, error) {
	if scopes == nil {
		scopes = []string{}
	}
	return s.q.SetUserScopes(ctx, sqlc.SetUserScopesParams{
		UserID: userID, ClientID: clientID, Scopes: scopes,
		GrantedByUserID:  services.TextOrNull(grantedByUserID),
		GrantedByOwnerID: services.TextOrNull(grantedByOwnerID),
	})
}
