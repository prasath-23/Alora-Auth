// Package reset implements admin-issued password resets: an admin mints a
// one-time token for a user, the user redeems it to set a new password.
//
// Only the SHA-256 hash of the token is stored, and redemption is single-use.
package reset

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/alora/auth/internal/crypto/password"
	"github.com/alora/auth/internal/crypto/tokens"
	"github.com/alora/auth/internal/platform/database"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ResetTTL is deliberately short — a reset token is a full account takeover
// primitive, so its window is measured in minutes, not days like an invite.
const ResetTTL = 60 * time.Minute

type Service struct {
	pool        *pgxpool.Pool
	q           *sqlc.Queries
	frontendURL string
}

func NewService(pool *pgxpool.Pool, q *sqlc.Queries, frontendURL string) *Service {
	return &Service{pool: pool, q: q, frontendURL: frontendURL}
}

type Issued struct {
	Email     string
	RawToken  string
	ResetURL  string
	ExpiresAt time.Time
}

// Issue mints a reset token for a user in the CALLER's tenant.
//
// Any previously outstanding token for that user is deleted first, so exactly
// one reset link is ever live: otherwise an admin re-issuing a reset would leave
// the earlier link (possibly already leaked) still redeemable.
func (s *Service) Issue(ctx context.Context, userID, clientID, issuedBy string) (Issued, error) {
	user, err := s.q.GetUserTenantScoped(ctx, sqlc.GetUserTenantScopedParams{PUserid: userID, PClientid: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Issued{}, httpx.ErrNotFound // wrong tenant is indistinguishable from missing
	}
	if err != nil {
		return Issued{}, err
	}

	raw, err := tokens.GenerateOpaque()
	if err != nil {
		return Issued{}, err
	}
	expires := time.Now().Add(ResetTTL)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Issued{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := s.q.WithTx(tx)

	if err := qtx.DeleteUnusedResetTokens(ctx, userID); err != nil {
		return Issued{}, err
	}
	if _, err := qtx.CreateResetToken(ctx, sqlc.CreateResetTokenParams{
		PUserid: userID, PClientid: clientID, PTokenhash: tokens.HashToken(raw),
		PExpiresat: database.Timestamptz(expires), PCreatedby: issuedBy,
	}); err != nil {
		return Issued{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Issued{}, err
	}

	return Issued{
		Email: user.Email, RawToken: raw,
		ResetURL:  strings.TrimRight(s.frontendURL, "/") + "/reset-password?token=" + raw,
		ExpiresAt: expires,
	}, nil
}

// Consume redeems a reset token and sets the new password.
//
// Runs in one transaction: the token row is locked with FOR UPDATE and its
// `used_at IS NULL` guard is re-evaluated under that lock, so two concurrent
// redemptions of a leaked token serialise and the second finds no row. The
// password write and the burn therefore cannot diverge.
//
// Every failure returns ONE generic message: distinguishing "unknown token" from
// "expired" from "deactivated user" would turn this public endpoint into an
// oracle for valid tokens and account states.
func (s *Service) Consume(ctx context.Context, rawToken, newPassword string) error {
	const generic = "Invalid or expired reset token"

	if newPassword == "" {
		return httpx.NewAPIError(400, generic, nil)
	}
	hash, err := password.Hash(newPassword)
	if err != nil {
		return httpx.NewAPIError(400, generic, err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := s.q.WithTx(tx)

	row, err := qtx.GetValidResetToken(ctx, tokens.HashToken(rawToken))
	if errors.Is(err, pgx.ErrNoRows) {
		return httpx.NewAPIError(400, generic, nil)
	}
	if err != nil {
		return err
	}
	// A deprovisioned account must not be revivable through a stale reset link.
	if !row.IsActive || row.DeletedAt.Valid {
		return httpx.NewAPIError(400, generic, nil)
	}

	if err := qtx.SetUserPassword(ctx, sqlc.SetUserPasswordParams{
		UserID: row.UserID, ClientID: row.ClientID, PasswordHash: hash,
	}); err != nil {
		return err
	}
	if err := qtx.MarkResetTokenUsed(ctx, row.ID); err != nil {
		return err
	}

	// Changing a password must invalidate every existing session: if the reset
	// was triggered because the account was compromised, leaving the attacker's
	// refresh tokens alive would defeat the entire exercise.
	if _, err := qtx.RevokeAllUserSessions(ctx, sqlc.RevokeAllUserSessionsParams{
		UserID: row.UserID, Reason: sqlc.SessionRevokedReasonLOGOUTALL,
	}); err != nil {
		return err
	}
	// Bump permissions_version so already-issued ACCESS tokens (valid up to 15
	// more minutes) are rejected by the freshness check on their next request.
	if err := qtx.BumpPermissionsVersion(ctx, sqlc.BumpPermissionsVersionParams{
		PUserid: row.UserID, PClientid: row.ClientID,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
