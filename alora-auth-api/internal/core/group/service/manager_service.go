package service

import (
	"context"
	"errors"
	"net/http"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/group/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/services/groupmanagers"
	groupmanagercustoms "github.com/alora/auth/internal/database/services/groupmanagers/customs"
	groupcustoms "github.com/alora/auth/internal/database/services/groups/customs"
	usercustoms "github.com/alora/auth/internal/database/services/users/customs"
	userscopecustoms "github.com/alora/auth/internal/database/services/userscopes/customs"
	"github.com/alora/auth/internal/exceptions"
)

// ManagerService runs group managers: people who add and remove the members of
// one group, and nothing else, without holding groups:edit for the whole
// company.
//
// Appointing or dismissing a manager is done through a company door, by a
// groups:edit holder or the Owner, under the two scope rules. Rule 1 counts the
// whole group — a manager can hand it out, so appointing one is handing it out —
// and rule 2 measures the person appointed by their reach. Nobody appoints
// themselves, and the Admins group never has managers: whoever decides its
// members decides who is an Admin.
//
// A manager works through their own door, /api/me/managed-groups. It is not a
// scope and grants no scope: every call asks the database whether the caller
// manages that group, and the writes ask again inside the procedure, at the
// moment of the change. There, rule 2 measures both sides by reach — a manager
// counts as holding what their groups give — so they can take out anyone whose
// access comes from the groups they run, and never someone above that. Managers
// never decide their own or each other's membership.
type ManagerService interface {
	// Appoint makes the person named by id or email a manager of a group.
	Appoint(ctx context.Context, scope shared.Scope, groupID string, in models.MemberInput) (models.Appointment, error)
	// Dismiss ends an appointment.
	Dismiss(ctx context.Context, scope shared.Scope, groupID, userID string) error
	// Managed lists the groups the caller manages.
	Managed(ctx context.Context, actor shared.Actor) ([]models.GroupListItem, error)
	// ManagedGroup reads one group the caller manages, with its members and
	// managers and the sign-in policy it carries.
	ManagedGroup(ctx context.Context, actor shared.Actor, groupID string) (models.GroupDetail, error)
	// AddMember adds a member to a group the caller manages.
	AddMember(ctx context.Context, actor shared.Actor, groupID string, in models.MemberInput) (models.Membership, error)
	// RemoveMember removes a member from a group the caller manages.
	RemoveMember(ctx context.Context, actor shared.Actor, groupID, userID string) error
}

type managerService struct {
	db     *contexts.DbContext
	audit  auditservice.AuditService
	groups GroupService
}

// NewManagerService builds the group-manager service. groups reads a group's
// page, for the manager's door.
func NewManagerService(db *contexts.DbContext, audit auditservice.AuditService, groups GroupService) ManagerService {
	return &managerService{db: db, audit: audit, groups: groups}
}

var (
	errNamePerson   = exceptions.NewAPIError(http.StatusBadRequest, "Provide user_id or email", nil)
	errSelfAppoint  = exceptions.NewAPIError(http.StatusBadRequest, "You can't make yourself a group's manager", nil)
	errAdminsGroup  = exceptions.NewAPIError(http.StatusConflict, "The Admins group can't have managers", nil)
	errManagesIt    = exceptions.NewAPIError(http.StatusConflict, "This person already manages the group", nil)
	errAMember      = exceptions.NewAPIError(http.StatusConflict, "User is already a member of this group", nil)
	errManagersSelf = exceptions.NewAPIError(http.StatusForbidden,
		"A group's managers can't add or remove themselves or each other; an Admin does that", nil)
)

func (s *managerService) Appoint(ctx context.Context, scope shared.Scope, groupID string, in models.MemberInput) (models.Appointment, error) {
	if in.UserID == "" && in.Email == "" {
		return models.Appointment{}, errNamePerson
	}
	g, err := groupcustoms.NewGroupDbCustoms(s.db).Summary(ctx, groupID, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.Appointment{}, exceptions.ErrNotFound
	}
	if err != nil {
		return models.Appointment{}, err
	}
	if g.SystemKey != nil {
		return models.Appointment{}, errAdminsGroup
	}
	// Rule 1: a manager hands the group out, so appointing one takes every
	// scope it gives.
	if !scope.CanGive(g.Scopes) {
		return models.Appointment{}, exceptions.ErrCannotGive
	}
	userID, err := userFor(ctx, s.db, scope.ClientID, in)
	if err != nil {
		return models.Appointment{}, err
	}
	// Otherwise someone about to lose groups:edit could keep running the groups
	// they chose.
	if userID == scope.Actor.UserID {
		return models.Appointment{}, errSelfAppoint
	}
	if err := checkReach(ctx, s.db, scope, userID); err != nil {
		return models.Appointment{}, err
	}
	byUser, byOwner := scope.Actor.UserID, ""
	if scope.ByOwner {
		byUser, byOwner = "", scope.Actor.UserID
	}
	n, err := groupmanagers.NewGroupManagerDbService(s.db).Appoint(ctx, groupID, scope.ClientID, userID, byUser, byOwner)
	if err != nil {
		return models.Appointment{}, err
	}
	switch n {
	case groupmanagers.NoGroup, groupmanagers.NoAppointee:
		return models.Appointment{}, exceptions.ErrNotFound
	case groupmanagers.SystemGroup:
		return models.Appointment{}, errAdminsGroup
	case 0:
		return models.Appointment{}, errManagesIt
	}
	s.audit.RecordWith(scope, "group.manager_added", map[string]any{"group_id": groupID, "user_id": userID})
	return models.Appointment{GroupID: groupID, UserID: userID}, nil
}

func (s *managerService) Dismiss(ctx context.Context, scope shared.Scope, groupID, userID string) error {
	g, err := groupcustoms.NewGroupDbCustoms(s.db).Summary(ctx, groupID, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return exceptions.ErrNotFound
	}
	if err != nil {
		return err
	}
	// Rule 1, as for appointing: dismissing takes the group out of someone's
	// hands.
	if !scope.CanGive(g.Scopes) {
		return exceptions.ErrCannotGive
	}
	if err := checkReach(ctx, s.db, scope, userID); err != nil {
		return err
	}
	n, err := groupmanagers.NewGroupManagerDbService(s.db).Dismiss(ctx, groupID, scope.ClientID, userID)
	if err != nil {
		return err
	}
	if n != 1 {
		return exceptions.ErrNotFound
	}
	s.audit.RecordWith(scope, "group.manager_removed", map[string]any{"group_id": groupID, "user_id": userID})
	return nil
}

func (s *managerService) Managed(ctx context.Context, actor shared.Actor) ([]models.GroupListItem, error) {
	rows, err := groupcustoms.NewGroupDbCustoms(s.db).ManagedBy(ctx, actor.UserID, actor.ClientID)
	if err != nil {
		return nil, err
	}
	return listItems(rows), nil
}

func (s *managerService) ManagedGroup(ctx context.Context, actor shared.Actor, groupID string) (models.GroupDetail, error) {
	if err := s.mustManage(ctx, actor, groupID); err != nil {
		return models.GroupDetail{}, err
	}
	return s.groups.Get(ctx, shared.TenantScope(actor), groupID)
}

func (s *managerService) AddMember(ctx context.Context, actor shared.Actor, groupID string, in models.MemberInput) (models.Membership, error) {
	if in.UserID == "" && in.Email == "" {
		return models.Membership{}, errNamePerson
	}
	if err := s.mustManage(ctx, actor, groupID); err != nil {
		return models.Membership{}, err
	}
	userID, err := userFor(ctx, s.db, actor.ClientID, in)
	if err != nil {
		return models.Membership{}, err
	}
	if err := s.checkMember(ctx, actor, groupID, userID); err != nil {
		return models.Membership{}, err
	}
	n, err := groupmanagers.NewGroupManagerDbService(s.db).AddMember(ctx, actor.UserID, userID, groupID, actor.ClientID)
	if err != nil {
		return models.Membership{}, err
	}
	switch n {
	case groupmanagers.NoGroup, groupmanagers.NoMember:
		return models.Membership{}, exceptions.ErrNotFound
	case groupmanagers.SystemGroup:
		return models.Membership{}, errAdminsGroup
	case groupmanagers.MemberIsManager:
		return models.Membership{}, errManagersSelf
	case 0:
		return models.Membership{}, errAMember
	}
	s.audit.RecordWith(shared.TenantScope(actor), "group.member_added",
		map[string]any{"group_id": groupID, "user_id": userID, "by_manager": true})
	return models.Membership{GroupID: groupID, UserID: userID}, nil
}

func (s *managerService) RemoveMember(ctx context.Context, actor shared.Actor, groupID, userID string) error {
	if err := s.mustManage(ctx, actor, groupID); err != nil {
		return err
	}
	if err := s.checkMember(ctx, actor, groupID, userID); err != nil {
		return err
	}
	n, err := groupmanagers.NewGroupManagerDbService(s.db).RemoveMember(ctx, actor.UserID, userID, groupID, actor.ClientID)
	if err != nil {
		return err
	}
	switch n {
	case groupmanagers.NoGroup, 0:
		return exceptions.ErrNotFound
	case groupmanagers.SystemGroup:
		return errAdminsGroup
	case groupmanagers.MemberIsManager:
		return errManagersSelf
	}
	s.audit.RecordWith(shared.TenantScope(actor), "group.member_removed",
		map[string]any{"group_id": groupID, "user_id": userID, "by_manager": true})
	return nil
}

// mustManage is the manager door's gate: a group the caller does not manage —
// another company's, one they never ran, or one they were dismissed from — is
// simply not found.
func (s *managerService) mustManage(ctx context.Context, actor shared.Actor, groupID string) error {
	ok, err := groupmanagercustoms.NewGroupManagerDbCustoms(s.db).IsManager(ctx, groupID, actor.ClientID, actor.UserID)
	if err != nil {
		return err
	}
	if !ok {
		return exceptions.ErrNotFound
	}
	return nil
}

// checkMember is what a manager may do to one member: never to one of the
// group's managers, themselves included, and — rule 2 — only to someone whose
// reach their own reach covers. Nobody but an Owner acts on an Owner.
func (s *managerService) checkMember(ctx context.Context, actor shared.Actor, groupID, userID string) error {
	if userID == actor.UserID {
		return errManagersSelf
	}
	manages, err := groupmanagercustoms.NewGroupManagerDbCustoms(s.db).IsManager(ctx, groupID, actor.ClientID, userID)
	if err != nil {
		return err
	}
	if manages {
		return errManagersSelf
	}
	target, err := usercustoms.NewUserDbCustoms(s.db).TenantScoped(ctx, userID, actor.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return exceptions.ErrNotFound
	}
	if err != nil {
		return err
	}
	scopes := userscopecustoms.NewUserScopeDbCustoms(s.db)
	mine, err := scopes.Reach(ctx, actor.ClientID, actor.UserID)
	if err != nil {
		return err
	}
	theirs, err := scopes.Reach(ctx, actor.ClientID, userID)
	if err != nil {
		return err
	}
	if target.IsOwner || !shared.NewScopeSet(mine...).Covers(theirs) {
		return exceptions.ErrCannotManage
	}
	return nil
}
