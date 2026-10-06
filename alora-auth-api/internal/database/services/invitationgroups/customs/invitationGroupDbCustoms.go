// Package customs holds the tbl_invitation_groups queries beyond CRUD: an
// invitation's groups joined to their names.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/sqlc"
)

// InvitationGroupDbCustoms is the custom query surface of tbl_invitation_groups.
type InvitationGroupDbCustoms struct{ q *sqlc.Queries }

// NewInvitationGroupDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewInvitationGroupDbCustoms(c contexts.Querier) *InvitationGroupDbCustoms {
	return &InvitationGroupDbCustoms{q: c.Queries()}
}

// ListForInvitation lists the groups an invitation adds its user to.
func (s *InvitationGroupDbCustoms) ListForInvitation(ctx context.Context, invitationID string) ([]models.InvitationGroup, error) {
	rows, err := s.q.ListInvitationGroups(ctx, invitationID)
	if err != nil {
		return nil, err
	}
	out := make([]models.InvitationGroup, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.InvitationGroup{
			InvitationID: r.InvitationID, ClientID: r.ClientID, GroupID: r.GroupID, GroupName: r.GroupName,
		})
	}
	return out, nil
}
