// Package customs holds the tbl_invitations queries beyond CRUD: the lookups
// through vw_PendingInvitation (which carries every redeemability predicate), the
// list, the single-use claim, the policy the invitee will sign in under and the
// expiry sweep.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/services/invitations"
	"github.com/alora/auth/internal/database/sqlc"
)

// InvitationDbCustoms is the custom query surface of tbl_invitations.
type InvitationDbCustoms struct{ q *sqlc.Queries }

// NewInvitationDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewInvitationDbCustoms(c contexts.Querier) *InvitationDbCustoms {
	return &InvitationDbCustoms{q: c.Queries()}
}

// PendingByEmail finds a live invitation for an address within a company.
func (s *InvitationDbCustoms) PendingByEmail(ctx context.Context, clientID, email string) (models.PendingInvitation, error) {
	r, err := s.q.GetPendingInviteByEmail(ctx, sqlc.GetPendingInviteByEmailParams{PClientid: clientID, PEmail: email})
	if err != nil {
		return models.PendingInvitation{}, err
	}
	return pending(r), nil
}

// PendingByTokenHash finds a live invitation by the hash of its raw token.
func (s *InvitationDbCustoms) PendingByTokenHash(ctx context.Context, tokenHash string) (models.PendingInvitation, error) {
	r, err := s.q.GetPendingInvitation(ctx, tokenHash)
	if err != nil {
		return models.PendingInvitation{}, err
	}
	return pending(r), nil
}

// List lists a company's invitations in every status.
func (s *InvitationDbCustoms) List(ctx context.Context, clientID string) ([]models.InvitationListItem, error) {
	rows, err := s.q.ListInvitations(ctx, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.InvitationListItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.InvitationListItem{
			ID: r.ID, ClientID: r.ClientID, Email: r.Email, Status: models.InvitationStatus(r.Status),
			ExpiresAt: services.TimePtr(r.ExpiresAt), CreatedAt: services.TimePtr(r.CreatedAt),
		})
	}
	return out, nil
}

// Claim atomically consumes a PENDING, unexpired invitation. A second claim of
// the same token updates nothing and yields no rows.
func (s *InvitationDbCustoms) Claim(ctx context.Context, tokenHash string) (models.Invitation, error) {
	row, err := s.q.ClaimInvitation(ctx, sqlc.ClaimInvitationParams{TokenHash: tokenHash})
	if err != nil {
		return models.Invitation{}, err
	}
	return invitations.FromRow(row), nil
}

// LoginPolicy reads the policy an invitee will sign in under: the
// highest-priority policy among the invitation's groups, else the company
// default.
func (s *InvitationDbCustoms) LoginPolicy(ctx context.Context, invitationID, clientID string) (models.LoginPolicy, error) {
	r, err := s.q.GetInvitationLoginPolicy(ctx, sqlc.GetInvitationLoginPolicyParams{
		PInvitationid: invitationID, PClientid: clientID,
	})
	if err != nil {
		return models.LoginPolicy{}, err
	}
	return services.LoginPolicyFromRow(r), nil
}

// ExpireStale marks up to batch overdue invitations expired.
func (s *InvitationDbCustoms) ExpireStale(ctx context.Context, batch int32) error {
	return s.q.ExpireInvitations(ctx, batch)
}

func pending(r sqlc.VwPendinginvitation) models.PendingInvitation {
	return models.PendingInvitation{
		ID: r.ID, Email: r.Email, ClientID: r.ClientID,
		InvitedByUserID: services.StringPtr(r.InvitedByUserID), InvitedByOwnerID: services.StringPtr(r.InvitedByOwnerID),
		TokenHash: r.TokenHash, ExpiresAt: services.TimePtr(r.ExpiresAt), ClientName: r.ClientName,
	}
}
