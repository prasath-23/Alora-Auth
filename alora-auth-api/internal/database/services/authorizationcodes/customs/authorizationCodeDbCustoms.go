// Package customs holds the tbl_authorization_codes queries beyond CRUD: the
// atomic single-use claim, the lookup that tells a replay from an unknown code,
// and the sweep.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/authorizationcodes"
	"github.com/alora/auth/internal/database/sqlc"
)

// AuthorizationCodeDbCustoms is the custom query surface of
// tbl_authorization_codes.
type AuthorizationCodeDbCustoms struct{ q *sqlc.Queries }

// NewAuthorizationCodeDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewAuthorizationCodeDbCustoms(c contexts.Querier) *AuthorizationCodeDbCustoms {
	return &AuthorizationCodeDbCustoms{q: c.Queries()}
}

// Claim consumes an unused, unexpired code in one atomic UPDATE ... RETURNING, so
// two concurrent redemptions cannot both succeed: the second yields no rows.
func (s *AuthorizationCodeDbCustoms) Claim(ctx context.Context, codeHash string) (models.AuthorizationCode, error) {
	row, err := s.q.ClaimAuthorizationCode(ctx, codeHash)
	if err != nil {
		return models.AuthorizationCode{}, err
	}
	return authorizationcodes.FromRow(row), nil
}

// ByHash reads a code whether or not it is spent: after a failed claim it tells a
// replay from a code that never existed.
func (s *AuthorizationCodeDbCustoms) ByHash(ctx context.Context, codeHash string) (models.AuthorizationCode, error) {
	row, err := s.q.GetAuthorizationCodeByHash(ctx, codeHash)
	if err != nil {
		return models.AuthorizationCode{}, err
	}
	return authorizationcodes.FromRow(row), nil
}

// CleanupExpired deletes codes past their expiry (with a margin, so a replay just
// after expiry is still recognised) and reports how many.
func (s *AuthorizationCodeDbCustoms) CleanupExpired(ctx context.Context) (int32, error) {
	return s.q.CleanupExpiredAuthCodes(ctx)
}
