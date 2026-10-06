// Package service owns company user administration — the user list and detail,
// activation, and direct product grants — and the caller's own account and
// apps.
//
// EVERY company-scoped method takes a shared.Scope and scopes its queries by
// its ClientID. An Admin's scope is their own company, from their verified
// token; only the Owner console builds a scope for another company. No method
// accepts a company from a request body — that is the single rule that makes
// crossing into another company impossible at this layer, backed by composite
// foreign keys at the database layer.
package service

import (
	"context"
	"errors"
	"net/http"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	policyservice "github.com/alora/auth/internal/core/policy/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/user/models"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/groups"
	groupcustoms "github.com/alora/auth/internal/database/services/groups/customs"
	permissioncustoms "github.com/alora/auth/internal/database/services/productpermissions/customs"
	"github.com/alora/auth/internal/database/services/sessions"
	usergroupcustoms "github.com/alora/auth/internal/database/services/usergroups/customs"
	"github.com/alora/auth/internal/database/services/users"
	usercustoms "github.com/alora/auth/internal/database/services/users/customs"
	"github.com/alora/auth/internal/database/services/userscopes"
	userscopecustoms "github.com/alora/auth/internal/database/services/userscopes/customs"
	"github.com/alora/auth/internal/exceptions"
)

// UserService administers the users of the scope's company.
type UserService interface {
	// List returns one keyset page of users.
	List(ctx context.Context, scope shared.Scope, q models.ListQuery) (models.UserPage, error)
	// Get returns one user with their access, groups and login policy.
	Get(ctx context.Context, scope shared.Scope, userID string) (models.UserDetail, error)
	// CheckModifiable rejects an attempt by the caller to modify their own
	// account. It needs no database, so it runs before the body is read.
	CheckModifiable(scope shared.Scope, userID string) error
	// SetActive activates or deactivates a user.
	SetActive(ctx context.Context, scope shared.Scope, userID string, active bool) (models.ActiveState, error)
	// SetExtraScopes replaces the App Central scopes given to the user alone, on
	// top of their groups'. It returns the complete set now held as extras.
	SetExtraScopes(ctx context.Context, scope shared.Scope, userID string, scopes []string) ([]string, error)
}

type userService struct {
	db     *contexts.DbContext
	audit  auditservice.AuditService
	policy policyservice.PolicyService
}

// NewUserService builds the user service.
func NewUserService(db *contexts.DbContext, audit auditservice.AuditService, policy policyservice.PolicyService) UserService {
	return &userService{db: db, audit: audit, policy: policy}
}

// List returns one keyset page. The cursor is an opaque user id to the client;
// internally it resolves to a (created_at, id) keyset position, which is stable
// under concurrent inserts in a way OFFSET is not.
func (s *userService) List(ctx context.Context, scope shared.Scope, q models.ListQuery) (models.UserPage, error) {
	customs := usercustoms.NewUserDbCustoms(s.db)
	page := usercustoms.ListQuery{
		ClientID: scope.ClientID,
		Search:   q.Search,
		Take:     int32(q.Take + 1), // peek one row ahead to detect a next page
	}
	if q.Cursor != "" {
		// Company-scoped resolve: a cursor belonging to another company simply
		// does not resolve, rather than revealing a position in their list.
		createdAt, err := customs.CursorPosition(ctx, q.Cursor, scope.ClientID)
		if err != nil {
			return models.UserPage{}, exceptions.NewAPIError(http.StatusBadRequest, "Invalid request", nil)
		}
		page.CursorCreated = createdAt
		page.CursorID = q.Cursor
	}

	rows, err := customs.ListPage(ctx, page)
	if err != nil {
		return models.UserPage{}, err
	}
	hasNext := len(rows) > q.Take
	if hasNext {
		rows = rows[:q.Take]
	}

	// Group memberships for the whole page in ONE query rather than N+1.
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	groupsByUser := map[string][]models.GroupRef{}
	if len(ids) > 0 {
		memberships, err := usergroupcustoms.NewUserGroupDbCustoms(s.db).ListForUsers(ctx, scope.ClientID, ids)
		if err != nil {
			return models.UserPage{}, err
		}
		for _, m := range memberships {
			groupsByUser[m.UserID] = append(groupsByUser[m.UserID], models.GroupRef{ID: m.GroupID, Name: m.GroupName, SystemKey: m.SystemKey})
		}
	}

	out := make([]models.UserListItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.UserListItem{
			ID: r.ID, Email: r.Email, IsActive: r.IsActive, IsAdmin: r.IsAdmin, IsOwner: r.IsOwner,
			AccountType: string(r.AccountType), CreatedAt: r.CreatedAt, Groups: groupsByUser[r.ID],
		})
	}

	var next *string // nil, not "", when there is no further page
	if hasNext && len(rows) > 0 {
		id := rows[len(rows)-1].ID
		next = &id
	}
	return models.UserPage{Users: out, NextCursor: next}, nil
}

// Get is composed from focused reads rather than one wide join: a single query
// LEFT JOINing grants, access and groups together produces a cartesian product
// that then has to be de-duplicated. Small calls cannot double-count.
func (s *userService) Get(ctx context.Context, scope shared.Scope, userID string) (models.UserDetail, error) {
	user, err := usercustoms.NewUserDbCustoms(s.db).TenantScoped(ctx, userID, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.UserDetail{}, exceptions.ErrNotFound // unknown and another company's are identical
	}
	if err != nil {
		return models.UserDetail{}, err
	}
	perms := permissioncustoms.NewProductPermissionDbCustoms(s.db)
	direct, err := perms.ListDirect(ctx, userID, scope.ClientID)
	if err != nil {
		return models.UserDetail{}, err
	}
	access, err := perms.EffectiveAccess(ctx, userID, scope.ClientID)
	if err != nil {
		return models.UserDetail{}, err
	}
	memberships, err := usergroupcustoms.NewUserGroupDbCustoms(s.db).ListForUsers(ctx, scope.ClientID, []string{userID})
	if err != nil {
		return models.UserDetail{}, err
	}
	d := models.UserDetail{
		ID: user.ID, Email: user.Email, AccountType: string(user.AccountType), IsActive: user.IsActive,
		IsAdmin: user.IsAdmin, IsOwner: user.IsOwner, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
		OwnPolicyID:  user.LoginPolicyID,
		DirectGrants: make([]models.Grant, 0, len(direct)),
		Access:       make([]models.Access, 0, len(access)),
		Groups:       make([]models.Membership, 0, len(memberships)),
	}
	for _, g := range direct {
		d.DirectGrants = append(d.DirectGrants, models.Grant{
			ProductID: g.ProductID, ProductKey: g.ProductKey, ProductName: g.ProductName,
			RoleName: g.RoleName, ValidUntil: g.ValidUntil,
		})
	}
	for _, a := range access {
		d.Access = append(d.Access, models.Access{
			ProductID: a.ProductID, ProductKey: a.ProductKey, ProductName: a.ProductName,
			RoleName: a.RoleName, Source: a.Source, GroupID: a.GroupID,
		})
	}
	for _, m := range memberships {
		d.Groups = append(d.Groups, models.Membership{ID: m.GroupID, Name: m.GroupName, SystemKey: m.SystemKey, AssignedAt: m.AssignedAt})
	}
	held, err := userscopecustoms.NewUserScopeDbCustoms(s.db).ListForUser(ctx, scope.ClientID, userID)
	if err != nil {
		return models.UserDetail{}, err
	}
	d.Scopes, d.ExtraScopes = scopeGrants(held)
	if d.Manages, err = managedGroups(ctx, s.db, userID, scope.ClientID); err != nil {
		return models.UserDetail{}, err
	}
	if p, err := s.policy.Resolve(ctx, userID, scope.ClientID); err == nil {
		d.Policy = &models.Policy{
			ID: p.PolicyID, Name: p.PolicyName, Source: p.Source, AllowPassword: p.AllowPassword,
			AllowGoogle: p.AllowGoogle, SSOConnectionID: p.SSOConnectionID,
		}
	} else if !errors.Is(err, exceptions.ErrNoRows) {
		return models.UserDetail{}, err
	}
	return d, nil
}

// CheckModifiable is the self-lockout guard: an admin disabling their own account
// could strand the company with no way back in.
func (s *userService) CheckModifiable(scope shared.Scope, userID string) error {
	if userID == scope.Actor.UserID {
		return exceptions.NewAPIError(http.StatusBadRequest, "Cannot modify your own account", nil)
	}
	return nil
}

// errLastAdmin is the refusal to leave a company with no active Admin.
var errLastAdmin = exceptions.NewAPIError(http.StatusConflict, "Cannot deactivate the company's last active Admin", nil)

// SetActive flips is_active. Deactivation must take effect immediately, not when
// a token expires: revoking every session ends App Central's access tokens at
// once (they are checked against their session on every request) and stops
// every product from refreshing, and bumping permissions_version makes product
// introspection report their tokens inactive.
func (s *userService) SetActive(ctx context.Context, scope shared.Scope, userID string, active bool) (models.ActiveState, error) {
	target, err := usercustoms.NewUserDbCustoms(s.db).TenantScoped(ctx, userID, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.ActiveState{}, exceptions.ErrNotFound
	}
	if err != nil {
		return models.ActiveState{}, err
	}
	// Rule 2 by reach: a group's manager counts as holding what the groups they
	// run give, so nobody below that can switch them off.
	reach, err := userscopecustoms.NewUserScopeDbCustoms(s.db).Reach(ctx, scope.ClientID, userID)
	if err != nil {
		return models.ActiveState{}, err
	}
	if !scope.CanManage(reach, target.IsOwner) {
		return models.ActiveState{}, exceptions.ErrCannotManage
	}
	if !active && target.IsAdmin && target.IsActive {
		last, err := s.isLastActiveAdmin(ctx, scope.ClientID, userID)
		if err != nil {
			return models.ActiveState{}, err
		}
		if last {
			return models.ActiveState{}, errLastAdmin
		}
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return models.ActiveState{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	userDb := users.NewUserDbService(tx)
	n, err := userDb.SetActive(ctx, userID, scope.ClientID, active)
	if err != nil {
		return models.ActiveState{}, err
	}
	if n == 0 {
		return models.ActiveState{}, exceptions.ErrNotFound
	}
	if !active {
		if err := userDb.BumpPermissionsVersion(ctx, userID, scope.ClientID); err != nil {
			return models.ActiveState{}, err
		}
		if _, err := sessions.NewSessionDbService(tx).RevokeAllForUser(ctx, userID, dbmodels.RevokeReasonAdmin); err != nil {
			return models.ActiveState{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return models.ActiveState{}, err
	}
	s.audit.Record(scope, "user.updated")
	return models.ActiveState{ID: userID, IsActive: active}, nil
}

// SetExtraScopes checks both scope rules before anything is written: the actor
// may only act on someone with no more access than they have (rule 2), and may
// only give or take away scopes they hold themselves (rule 1). Edit scopes bring
// their read scopes. Nobody changes their own extras: that is how an account
// locks itself out.
func (s *userService) SetExtraScopes(ctx context.Context, scope shared.Scope, userID string, in []string) ([]string, error) {
	want, err := shared.NormalizeScopes(in)
	if err != nil {
		return nil, exceptions.NewAPIError(http.StatusBadRequest, err.Error(), nil)
	}
	if err := s.CheckModifiable(scope, userID); err != nil {
		return nil, err
	}
	target, err := usercustoms.NewUserDbCustoms(s.db).TenantScoped(ctx, userID, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return nil, exceptions.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	scopes := userscopecustoms.NewUserScopeDbCustoms(s.db)
	held, err := scopes.ListForUser(ctx, scope.ClientID, userID)
	if err != nil {
		return nil, err
	}
	_, extras := scopeGrants(held)
	// Rule 2 by reach, as for deactivation.
	reach, err := scopes.Reach(ctx, scope.ClientID, userID)
	if err != nil {
		return nil, err
	}
	if !scope.CanManage(reach, target.IsOwner) {
		return nil, exceptions.ErrCannotManage
	}
	if !scope.CanGive(shared.Changed(extras, want)) {
		return nil, exceptions.ErrCannotGive
	}
	byUser, byOwner := scope.Actor.UserID, ""
	if scope.ByOwner {
		byUser, byOwner = "", scope.Actor.UserID
	}
	n, err := userscopes.NewUserScopeDbService(s.db).Set(ctx, userID, scope.ClientID, want, byUser, byOwner)
	if err != nil {
		if exceptions.IsForeignKeyViolation(err) {
			return nil, exceptions.NewAPIError(http.StatusBadRequest, "Unknown scope", nil)
		}
		return nil, err
	}
	if n == userscopes.NotFound {
		return nil, exceptions.ErrNotFound
	}
	s.audit.Record(scope, "user.scopes_set")
	return want, nil
}

// scopeGrants renders the rows of vw_EffectiveScope, and picks out the extras.
func scopeGrants(rows []dbmodels.EffectiveScope) ([]models.ScopeGrant, []string) {
	grants := make([]models.ScopeGrant, 0, len(rows))
	extras := []string{}
	for _, r := range rows {
		grants = append(grants, models.ScopeGrant{Scope: r.Scope, Source: r.Source, GroupID: r.GroupID, GroupName: r.GroupName})
		if r.Source == dbmodels.ScopeSourceExtra {
			extras = append(extras, r.Scope)
		}
	}
	return grants, extras
}

// isLastActiveAdmin reports whether userID is the only active member of the
// company's Admins group.
func (s *userService) isLastActiveAdmin(ctx context.Context, clientID, userID string) (bool, error) {
	gid, err := groups.NewGroupDbService(s.db).SystemGroupID(ctx, clientID, dbmodels.SystemGroupAdmins)
	if err != nil {
		return false, err
	}
	rows, err := groupcustoms.NewGroupDbCustoms(s.db).Detail(ctx, gid, clientID)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.UserID == nil || *r.UserID == userID {
			continue
		}
		u, err := usercustoms.NewUserDbCustoms(s.db).TenantScoped(ctx, *r.UserID, clientID)
		if err == nil && u.IsActive {
			return false, nil
		}
		if err != nil && !errors.Is(err, exceptions.ErrNoRows) {
			return false, err
		}
	}
	return true, nil
}
