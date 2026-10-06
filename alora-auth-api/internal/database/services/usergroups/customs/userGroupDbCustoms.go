// Package customs holds the tbl_user_groups queries beyond CRUD: memberships
// joined to their group names, for a batch of users at once.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// UserGroupDbCustoms is the custom query surface of tbl_user_groups.
type UserGroupDbCustoms struct{ q *sqlc.Queries }

// NewUserGroupDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewUserGroupDbCustoms(c contexts.Querier) *UserGroupDbCustoms {
	return &UserGroupDbCustoms{q: c.Queries()}
}

// ListForUsers lists the memberships of every given user within a company, in one
// query rather than one per user.
func (s *UserGroupDbCustoms) ListForUsers(ctx context.Context, clientID string, userIDs []string) ([]models.UserGroupMembership, error) {
	rows, err := s.q.ListUserGroups(ctx, sqlc.ListUserGroupsParams{ClientID: clientID, UserIds: userIDs})
	if err != nil {
		return nil, err
	}
	out := make([]models.UserGroupMembership, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.UserGroupMembership{
			UserID: r.UserID, ClientID: r.ClientID, GroupID: r.GroupID, GroupName: r.GroupName,
			SystemKey: services.StringPtr(r.SystemKey), AssignedAt: services.TimePtr(r.AssignedAt),
		})
	}
	return out, nil
}
