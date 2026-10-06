// Package customs reads tbl_scopes, the closed scope catalogue. The table is
// reference data the build writes; the application only reads it.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/sqlc"
)

// ScopeDbCustoms is the query surface of tbl_scopes.
type ScopeDbCustoms struct{ q *sqlc.Queries }

// NewScopeDbCustoms binds the queries to a context: the pool or a transaction.
func NewScopeDbCustoms(c contexts.Querier) *ScopeDbCustoms { return &ScopeDbCustoms{q: c.Queries()} }

// List returns the whole catalogue in display order.
func (s *ScopeDbCustoms) List(ctx context.Context) ([]models.Scope, error) {
	rows, err := s.q.ListScopes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]models.Scope, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.Scope{
			Scope: r.Scope, Kind: r.Kind, Feature: r.Feature, Level: r.Level,
			Description: r.Description, SortOrder: r.SortOrder,
		})
	}
	return out, nil
}
