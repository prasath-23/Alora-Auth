// Package groupmanagers is the table service for tbl_group_managers: who runs
// which group. A manager adds and removes the group's members and nothing else;
// the lookups live in customs.
package groupmanagers

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// What the routines report other than a count of rows changed.
const (
	// NoGroup: the group is not in the company — or, for AddMember and
	// RemoveMember, not one the caller manages (any more).
	NoGroup int32 = -1
	// SystemGroup: the Admins group, which never has managers.
	SystemGroup int32 = -2
	// NoAppointee: Appoint was given no live user of the company.
	NoAppointee int32 = -3
	// MemberIsManager: AddMember or RemoveMember was pointed at one of the
	// group's own managers, the caller included.
	MemberIsManager int32 = -3
	// NoMember: AddMember was given no live user of the company.
	NoMember int32 = -4
)

// GroupManagerDbService is the CRUD surface of tbl_group_managers, and the
// membership writes a manager makes.
type GroupManagerDbService struct{ q *sqlc.Queries }

// NewGroupManagerDbService binds the service to a context: the pool or a
// transaction.
func NewGroupManagerDbService(c contexts.Querier) *GroupManagerDbService {
	return &GroupManagerDbService{q: c.Queries()}
}

// Appoint makes a user a manager of a group, attributed to the user or the
// Owner who appointed them (exactly one of byUserID and byOwnerID). It reports
// 1 when appointed and 0 when they already manage it, or NoGroup, SystemGroup or
// NoAppointee; the appointee's admin_version is bumped in the same transaction.
func (s *GroupManagerDbService) Appoint(ctx context.Context, groupID, clientID, userID, byUserID, byOwnerID string) (int32, error) {
	return s.q.AddGroupManager(ctx, sqlc.AddGroupManagerParams{
		GroupID: groupID, ClientID: clientID, UserID: userID,
		ByUserID: services.TextOrNull(byUserID), ByOwnerID: services.TextOrNull(byOwnerID),
	})
}

// Dismiss ends an appointment, reporting 1 when dismissed, 0 when the user did
// not manage the group, or NoGroup. The former manager's admin_version is
// bumped in the same transaction.
func (s *GroupManagerDbService) Dismiss(ctx context.Context, groupID, clientID, userID string) (int32, error) {
	return s.q.RemoveGroupManager(ctx, sqlc.RemoveGroupManagerParams{GroupID: groupID, ClientID: clientID, UserID: userID})
}

// AddMember adds a member as the group's manager. The routine re-checks, at the
// moment of the change, that managerID still manages the group. It reports 1
// when added and 0 when already a member, or NoGroup, SystemGroup,
// MemberIsManager or NoMember; the member's versions are bumped in the same
// transaction.
func (s *GroupManagerDbService) AddMember(ctx context.Context, managerID, userID, groupID, clientID string) (int32, error) {
	return s.q.ManagerAddGroupMember(ctx, sqlc.ManagerAddGroupMemberParams{
		ManagerID: managerID, UserID: userID, GroupID: groupID, ClientID: clientID,
	})
}

// RemoveMember removes a member as the group's manager, with AddMember's
// re-check. It reports 1 when removed and 0 when they were not a member, or
// NoGroup, SystemGroup or MemberIsManager.
func (s *GroupManagerDbService) RemoveMember(ctx context.Context, managerID, userID, groupID, clientID string) (int32, error) {
	return s.q.ManagerRemoveGroupMember(ctx, sqlc.ManagerRemoveGroupMemberParams{
		ManagerID: managerID, UserID: userID, GroupID: groupID, ClientID: clientID,
	})
}
