// Package customs holds the tbl_password_reset_tokens queries beyond CRUD: the
// locking read that makes redemption single-use.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// PasswordResetTokenTxCustoms holds the queries that take row locks. It can only
// be built from a transaction, so a FOR UPDATE read outside one is a compile
// error rather than a lock silently released the moment the statement ends.
type PasswordResetTokenTxCustoms struct{ q *sqlc.Queries }

// NewPasswordResetTokenTxCustoms binds the locking queries to a transaction.
func NewPasswordResetTokenTxCustoms(tx *contexts.TxContext) *PasswordResetTokenTxCustoms {
	return &PasswordResetTokenTxCustoms{q: tx.Queries()}
}

// ValidForUpdate locks an unused, unexpired token by hash and reads its owner's
// state. The used_at guard is re-evaluated under the lock, so a concurrent second
// redemption finds no row.
func (s *PasswordResetTokenTxCustoms) ValidForUpdate(ctx context.Context, tokenHash string) (models.ValidResetToken, error) {
	r, err := s.q.GetValidResetToken(ctx, tokenHash)
	if err != nil {
		return models.ValidResetToken{}, err
	}
	return models.ValidResetToken{
		ID: r.ID, UserID: r.UserID, ClientID: r.ClientID, TokenHash: r.TokenHash, Email: r.Email,
		IsActive: r.IsActive, DeletedAt: services.TimePtr(r.DeletedAt),
	}, nil
}
