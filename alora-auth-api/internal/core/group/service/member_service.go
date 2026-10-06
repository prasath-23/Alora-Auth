package service

import (
	"context"
	"errors"
	"net/http"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/group/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/database/contexts"
	groupcustoms "github.com/alora/auth/internal/database/services/groups/customs"
	"github.com/alora/auth/internal/database/services/usergroups"
	usercustoms "github.com/alora/auth/internal/database/services/users/customs"
	userscopecustoms "github.com/alora/auth/internal/database/services/userscopes/customs"
	"github.com/alora/auth/internal/exceptions"
)

// MemberService administers group memberships. Membership can confer product
// roles, so every change bumps the member's permissions_version — inside the
// same database statement as the change itself.
type MemberService interface {
	// Add puts a user, identified by id or email, into a group.
	Add(ctx context.Context, scope shared.Scope, groupID string, in models.MemberInput) (models.Membership, error)
	// Remove takes a user out of a group.
	Remove(ctx context.Context, scope shared.Scope, groupID, userID string) error
}

type memberService struct {
	db    *contexts.DbContext
	audit auditservice.AuditService
}

// NewMemberService builds the membership service.
func NewMemberService(db *contexts.DbContext, audit auditservice.AuditService) MemberService {
	return &memberService{db: db, audit: audit}
}

func (s *memberService) Add(ctx context.Context, scope shared.Scope, groupID string, in models.MemberInput) (models.Membership, error) {
	if in.UserID == "" && in.Email == "" {
		return models.Membership{}, exceptions.NewAPIError(http.StatusBadRequest, "Provide user_id or email", nil)
	}
	// Both the group AND the user must belong to the scope's company. The
	// composite FK on tbl_user_groups would also reject a mismatch, but failing
	// here produces a clean 404 instead of a constraint-violation 500.
	g, err := groupcustoms.NewGroupDbCustoms(s.db).Summary(ctx, groupID, scope.ClientID)
	if err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return models.Membership{}, exceptions.ErrNotFound
		}
		return models.Membership{}, err
	}
	// Rule 1: joining gives the group's scopes — the Admins group gives every
	// scope — so the actor must hold all of them.
	if !scope.CanGive(g.Scopes) {
		return models.Membership{}, exceptions.ErrCannotGive
	}
	userID, err := userFor(ctx, s.db, scope.ClientID, in)
	if err != nil {
		return models.Membership{}, err
	}
	if err := checkReach(ctx, s.db, scope, userID); err != nil {
		return models.Membership{}, err
	}
	// The procedure bumps the member's versions in the same statement.
	if err := usergroups.NewUserGroupDbService(s.db).Add(ctx, userID, groupID, scope.ClientID, scope.Actor.UserID); err != nil {
		if exceptions.IsUniqueViolation(err) {
			return models.Membership{}, exceptions.NewAPIError(http.StatusConflict, "User is already a member of this group", nil)
		}
		if exceptions.IsForeignKeyViolation(err) {
			// The group (or the user) was removed after it was checked above.
			return models.Membership{}, exceptions.ErrNotFound
		}
		return models.Membership{}, err
	}
	s.audit.RecordWith(scope, "group.member_added", map[string]any{"group_id": groupID, "user_id": userID})
	return models.Membership{GroupID: groupID, UserID: userID}, nil
}

// Remove is scoped by (user, group, company), so a group id of another company
// removes nothing. The database refuses to remove the last active member of the
// Admins group: a company with no Admin can only be rescued by an Owner.
func (s *memberService) Remove(ctx context.Context, scope shared.Scope, groupID, userID string) error {
	g, err := groupcustoms.NewGroupDbCustoms(s.db).Summary(ctx, groupID, scope.ClientID)
	if err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return exceptions.ErrNotFound
		}
		return err
	}
	// Rule 1: leaving takes the group's scopes away.
	if !scope.CanGive(g.Scopes) {
		return exceptions.ErrCannotGive
	}
	if err := checkReach(ctx, s.db, scope, userID); err != nil {
		return err
	}
	n, err := usergroups.NewUserGroupDbService(s.db).Remove(ctx, userID, groupID, scope.ClientID)
	if err != nil {
		return err
	}
	if n == usergroups.LastAdmin {
		return exceptions.NewAPIError(http.StatusConflict, "Cannot remove the company's last active Admin", nil)
	}
	if n == 0 {
		return exceptions.ErrNotFound
	}
	s.audit.RecordWith(scope, "group.member_removed", map[string]any{"group_id": groupID, "user_id": userID})
	return nil
}

// userFor resolves the person a request names — by id, else by email — to a
// live user of the company; anyone else is simply not found.
func userFor(ctx context.Context, db *contexts.DbContext, clientID string, in models.MemberInput) (string, error) {
	customs := usercustoms.NewUserDbCustoms(db)
	if in.UserID != "" {
		if _, err := customs.TenantScoped(ctx, in.UserID, clientID); err != nil {
			if errors.Is(err, exceptions.ErrNoRows) {
				return "", exceptions.ErrNotFound
			}
			return "", err
		}
		return in.UserID, nil
	}
	id, err := customs.IDByEmail(ctx, clientID, shared.NormalizeEmail(in.Email))
	if errors.Is(err, exceptions.ErrNoRows) {
		return "", exceptions.ErrNotFound
	}
	return id, err
}

// checkReach applies rule 2: the actor may only act on someone whose reach —
// the scopes they hold, plus those of the groups they manage — is no more than
// the actor's own. A user outside the company is simply not found.
func checkReach(ctx context.Context, db *contexts.DbContext, scope shared.Scope, userID string) error {
	target, err := usercustoms.NewUserDbCustoms(db).TenantScoped(ctx, userID, scope.ClientID)
	if err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return exceptions.ErrNotFound
		}
		return err
	}
	reach, err := userscopecustoms.NewUserScopeDbCustoms(db).Reach(ctx, scope.ClientID, userID)
	if err != nil {
		return err
	}
	if !scope.CanManage(reach, target.IsOwner) {
		return exceptions.ErrCannotManage
	}
	return nil
}
