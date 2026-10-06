// Package apiclientscopes is the table service for tbl_api_client_scopes: where
// each API client's credential may be used.
package apiclientscopes

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/sqlc"
)

// NotFound is the outcome of Set for an API client not in the company.
const NotFound int32 = -1

// APIClientScopeDbService is the CRUD surface of tbl_api_client_scopes.
type APIClientScopeDbService struct{ q *sqlc.Queries }

// NewAPIClientScopeDbService binds the service to a context: the pool or a
// transaction.
func NewAPIClientScopeDbService(c contexts.Querier) *APIClientScopeDbService {
	return &APIClientScopeDbService{q: c.Queries()}
}

// Set replaces an API client's scopes wholesale and returns how many it now
// holds, or NotFound. An unknown scope, or a person's scope, is a foreign-key
// violation.
func (s *APIClientScopeDbService) Set(ctx context.Context, apiClientID, clientID string, scopes []string) (int32, error) {
	if scopes == nil {
		scopes = []string{}
	}
	return s.q.SetApiClientScopes(ctx, sqlc.SetApiClientScopesParams{ApiClientID: apiClientID, ClientID: clientID, Scopes: scopes})
}
