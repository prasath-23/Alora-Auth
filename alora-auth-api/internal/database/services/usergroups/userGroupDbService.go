// Package usergroups is the table service for tbl_user_groups: group memberships.
// The joined membership list lives in customs.
package usergroups

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// LastAdmin is what Remove reports when the member is the company's last active
// Admin, whom the database refuses to remove.
const LastAdmin int32 = -2

// UserGroupDbService is the CRUD surface of tbl_user_groups.
type UserGroupDbService struct{ q *sqlc.Queries }

// NewUserGroupDbService binds the service to a context: the pool or a
// transaction.
func NewUserGroupDbService(c contexts.Querier) *UserGroupDbService {
	return &UserGroupDbService{q: c.Queries()}
}

// Add puts a user in a group. An existing membership is a unique violation; a
// user or group of another company is a foreign-key violation.
func (s *UserGroupDbService) Add(ctx context.Context, userID, groupID, clientID, assignedBy string) error {
	return s.q.AddGroupMember(ctx, sqlc.AddGroupMemberParams{
		UserID: userID, GroupID: groupID, ClientID: clientID, AssignedBy: services.TextOrNull(assignedBy),
	})
}

// Remove takes a user out of a group within a company and reports how many rows
// changed, or LastAdmin when the member is the Admins group's last active one.
func (s *UserGroupDbService) Remove(ctx context.Context, userID, groupID, clientID string) (int32, error) {
	return s.q.RemoveGroupMember(ctx, sqlc.RemoveGroupMemberParams{PUserid: userID, PGroupid: groupID, PClientid: clientID})
}
