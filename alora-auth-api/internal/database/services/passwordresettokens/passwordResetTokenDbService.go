// Package passwordresettokens is the table service for tbl_password_reset_tokens.
// The locking read that redeems a token lives in customs.
package passwordresettokens

import (
	"context"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// PasswordResetTokenDbService is the CRUD surface of tbl_password_reset_tokens.
type PasswordResetTokenDbService struct{ q *sqlc.Queries }

// NewPasswordResetTokenDbService binds the service to a context: the pool or a
// transaction.
func NewPasswordResetTokenDbService(c contexts.Querier) *PasswordResetTokenDbService {
	return &PasswordResetTokenDbService{q: c.Queries()}
}

// Create stores a reset token's hash. The raw token is never stored.
func (s *PasswordResetTokenDbService) Create(ctx context.Context, userID, clientID, tokenHash string, expiresAt time.Time, createdBy string) (models.PasswordResetToken, error) {
	row, err := s.q.CreateResetToken(ctx, sqlc.CreateResetTokenParams{
		PUserid: userID, PClientid: clientID, PTokenhash: tokenHash,
		PExpiresat: services.Timestamptz(expiresAt), PCreatedby: createdBy,
	})
	if err != nil {
		return models.PasswordResetToken{}, err
	}
	return models.PasswordResetToken{
		ID: row.ID, UserID: row.UserID, ClientID: row.ClientID, TokenHash: row.TokenHash,
		ExpiresAt: services.TimePtr(row.ExpiresAt), UsedAt: services.TimePtr(row.UsedAt),
		CreatedBy: row.CreatedBy, CreatedAt: services.TimePtr(row.CreatedAt),
	}, nil
}

// DeleteUnused removes every outstanding token of a user, so a re-issued reset
// leaves exactly one live link.
func (s *PasswordResetTokenDbService) DeleteUnused(ctx context.Context, userID string) error {
	return s.q.DeleteUnusedResetTokens(ctx, userID)
}

// MarkUsed burns a token.
func (s *PasswordResetTokenDbService) MarkUsed(ctx context.Context, tokenID string) error {
	return s.q.MarkResetTokenUsed(ctx, tokenID)
}
