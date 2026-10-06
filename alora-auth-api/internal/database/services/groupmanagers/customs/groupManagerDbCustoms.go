// Package customs holds the tbl_group_managers lookups: a group's managers, and
// whether someone manages a group.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// GroupManagerDbCustoms is the custom query surface of tbl_group_managers.
type GroupManagerDbCustoms struct{ q *sqlc.Queries }

// NewGroupManagerDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewGroupManagerDbCustoms(c contexts.Querier) *GroupManagerDbCustoms {
	return &GroupManagerDbCustoms{q: c.Queries()}
}

// List lists a group's managers in a company, by address. A group of another
// company has none.
func (s *GroupManagerDbCustoms) List(ctx context.Context, groupID, clientID string) ([]models.GroupManager, error) {
	rows, err := s.q.ListGroupManagers(ctx, sqlc.ListGroupManagersParams{GroupID: groupID, ClientID: clientID})
	if err != nil {
		return nil, err
	}
	out := make([]models.GroupManager, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.GroupManager{
			GroupID: r.GroupID, ClientID: r.ClientID, UserID: r.UserID, Email: r.Email,
			AppointedAt: services.TimePtr(r.AppointedAt), AppointedByEmail: r.AppointedByEmail,
			AppointedByOwner: r.AppointedByOwner,
		})
	}
	return out, nil
}

// IsManager reports whether the user manages the group, in that company.
func (s *GroupManagerDbCustoms) IsManager(ctx context.Context, groupID, clientID, userID string) (bool, error) {
	return s.q.IsGroupManager(ctx, sqlc.IsGroupManagerParams{GroupID: groupID, ClientID: clientID, UserID: userID})
}
