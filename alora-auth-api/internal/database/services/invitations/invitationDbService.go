// Package invitations is the table service for tbl_invitations. The pending
// lookups, the list, the single-use claim, the policy an invitee will sign in
// under and the expiry sweep live in customs.
package invitations

import (
	"context"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// InvitationDbService is the CRUD surface of tbl_invitations.
type InvitationDbService struct{ q *sqlc.Queries }

// NewInvitationDbService binds the service to a context: the pool or a
// transaction.
func NewInvitationDbService(c contexts.Querier) *InvitationDbService {
	return &InvitationDbService{q: c.Queries()}
}

// NewInvitation is an invitation to issue. Exactly one inviter is set: a company
// Admin (InvitedByUserID) or a platform Owner (InvitedByOwnerID). Only the
// token's hash is stored.
type NewInvitation struct {
	Email            string
	ClientID         string
	InvitedByUserID  string
	InvitedByOwnerID string
	TokenHash        string
	ExpiresAt        time.Time
}

// Create inserts a PENDING invitation.
func (s *InvitationDbService) Create(ctx context.Context, n NewInvitation) (models.Invitation, error) {
	row, err := s.q.CreateInvitation(ctx, sqlc.CreateInvitationParams{
		Email: n.Email, ClientID: n.ClientID,
		InvitedByUserID: services.TextOrNull(n.InvitedByUserID), InvitedByOwnerID: services.TextOrNull(n.InvitedByOwnerID),
		TokenHash: n.TokenHash, ExpiresAt: services.Timestamptz(n.ExpiresAt),
	})
	if err != nil {
		return models.Invitation{}, err
	}
	return FromRow(row), nil
}

// Revoke cancels a PENDING invitation within a company and reports how many rows
// changed.
func (s *InvitationDbService) Revoke(ctx context.Context, invitationID, clientID, revokedBy string) (int32, error) {
	return s.q.RevokeInvitation(ctx, sqlc.RevokeInvitationParams{
		InvitationID: invitationID, ClientID: clientID, RevokedByUserID: services.TextOrNull(revokedBy),
	})
}

// SetAcceptedBy links a redeemed invitation to the account it created.
func (s *InvitationDbService) SetAcceptedBy(ctx context.Context, invitationID, userID string) error {
	return s.q.SetInvitationAcceptedBy(ctx, sqlc.SetInvitationAcceptedByParams{
		PInvitationid: invitationID, PAcceptedbyuserid: userID,
	})
}

// FromRow converts a tbl_invitations row. Exported for the customs queries, which
// return the same row type.
func FromRow(r sqlc.TblInvitation) models.Invitation {
	return models.Invitation{
		ID: r.ID, Email: r.Email, ClientID: r.ClientID,
		InvitedByUserID: services.StringPtr(r.InvitedByUserID), InvitedByOwnerID: services.StringPtr(r.InvitedByOwnerID),
		TokenHash: r.TokenHash, ExpiresAt: services.TimePtr(r.ExpiresAt),
		Status: models.InvitationStatus(r.Status), AcceptedAt: services.TimePtr(r.AcceptedAt),
		AcceptedByUserID: services.StringPtr(r.AcceptedByUserID), RevokedAt: services.TimePtr(r.RevokedAt),
		RevokedByUserID: services.StringPtr(r.RevokedByUserID),
		CreatedAt:       services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
	}
}
