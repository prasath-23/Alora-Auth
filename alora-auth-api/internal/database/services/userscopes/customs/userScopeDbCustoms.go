// Package customs holds the queries over a person's effective App Central
// scopes: every scope they hold, and where each comes from.
package customs

import (
	"context"
	"sort"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// UserScopeDbCustoms is the custom query surface over vw_EffectiveScope.
type UserScopeDbCustoms struct{ q *sqlc.Queries }

// NewUserScopeDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewUserScopeDbCustoms(c contexts.Querier) *UserScopeDbCustoms {
	return &UserScopeDbCustoms{q: c.Queries()}
}

// ListForUser lists every scope the user holds in the tenant, one row per
// source: each group, and their extras.
func (s *UserScopeDbCustoms) ListForUser(ctx context.Context, clientID, userID string) ([]models.EffectiveScope, error) {
	rows, err := s.q.ListUserScopes(ctx, sqlc.ListUserScopesParams{ClientID: clientID, UserID: userID})
	if err != nil {
		return nil, err
	}
	out := make([]models.EffectiveScope, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.EffectiveScope{
			UserID: r.UserID, ClientID: r.ClientID, Scope: r.Scope, Source: r.Source,
			GroupID: services.StringPtr(r.GroupID), GroupName: services.StringPtr(r.GroupName),
		})
	}
	return out, nil
}

// Reach is rule 2's measure of a person, sorted: the scopes they hold plus the
// scopes of every group they manage, since a manager can hand those out. It
// never grants anything — what a person may do is EffectiveScopes — it decides
// who may act on whom.
func (s *UserScopeDbCustoms) Reach(ctx context.Context, clientID, userID string) ([]string, error) {
	return s.q.ListScopeReach(ctx, sqlc.ListScopeReachParams{ClientID: clientID, UserID: userID})
}

// EffectiveScopes is the distinct set of scopes the user holds in the tenant,
// sorted: what rule 1 compares, and what a person may do.
func (s *UserScopeDbCustoms) EffectiveScopes(ctx context.Context, clientID, userID string) ([]string, error) {
	rows, err := s.ListForUser(ctx, clientID, userID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if !seen[r.Scope] {
			seen[r.Scope] = true
			out = append(out, r.Scope)
		}
	}
	sort.Strings(out)
	return out, nil
}
