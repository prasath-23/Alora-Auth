// Package invitationgroups is the table service for tbl_invitation_groups: the
// groups an invitation adds its user to on acceptance. The joined list lives in
// customs.
package invitationgroups

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/sqlc"
)

// InvitationGroupDbService is the (write-once) surface of tbl_invitation_groups.
type InvitationGroupDbService struct{ q *sqlc.Queries }

// NewInvitationGroupDbService binds the service to a context: the pool or a
// transaction.
func NewInvitationGroupDbService(c contexts.Querier) *InvitationGroupDbService {
	return &InvitationGroupDbService{q: c.Queries()}
}

// Create attaches a group to an invitation. A repeated group is a unique
// violation; a group of another company is a foreign-key violation.
func (s *InvitationGroupDbService) Create(ctx context.Context, invitationID, clientID, groupID string) error {
	return s.q.CreateInvitationGroup(ctx, sqlc.CreateInvitationGroupParams{
		PInvitationid: invitationID, PClientid: clientID, PGroupid: groupID,
	})
}
