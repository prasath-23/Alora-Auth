// Package service owns a company's groups: what each gives — App Central scopes
// and product roles — and who belongs to it. Every method scopes its queries by
// the scope's company.
//
// Anyone holding groups:edit may create groups and choose their scopes, under
// the two scope rules: they can only give or take away scopes they hold
// themselves, and only manage people with no more access than they have.
// Product grants remain the Owner's. The Admins group, which every company has
// from birth, holds every scope and can be neither renamed, re-scoped, deleted,
// nor emptied of its last active member.
package service

import (
	"context"
	"errors"
	"net/http"
	"strings"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/group/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	groupmanagercustoms "github.com/alora/auth/internal/database/services/groupmanagers/customs"
	"github.com/alora/auth/internal/database/services/groups"
	groupcustoms "github.com/alora/auth/internal/database/services/groups/customs"
	"github.com/alora/auth/internal/database/services/groupscopes"
	policycustoms "github.com/alora/auth/internal/database/services/loginpolicies/customs"
	"github.com/alora/auth/internal/exceptions"
)

// GroupService administers the groups of the scope's company.
type GroupService interface {
	// List returns every group with what it grants and its member count.
	List(ctx context.Context, scope shared.Scope) ([]models.GroupListItem, error)
	// Get returns one group with its members.
	Get(ctx context.Context, scope shared.Scope, groupID string) (models.GroupDetail, error)
	// Create creates a group with everything it grants, in one transaction.
	Create(ctx context.Context, scope shared.Scope, in models.GroupInput) (models.Group, error)
	// Update renames and re-describes a group.
	Update(ctx context.Context, scope shared.Scope, groupID, name, description string) error
	// SetScopes replaces the App Central scopes a group gives; it returns the
	// complete set now given.
	SetScopes(ctx context.Context, scope shared.Scope, groupID string, scopes []string) ([]string, error)
	// SetProductGrants replaces the product roles a group confers.
	SetProductGrants(ctx context.Context, scope shared.Scope, groupID string, grants []models.ProductGrant) error
	// Delete removes a group; memberships and grants cascade.
	Delete(ctx context.Context, scope shared.Scope, groupID string) error
}

type groupService struct {
	db    *contexts.DbContext
	audit auditservice.AuditService
}

// NewGroupService builds the group service.
func NewGroupService(db *contexts.DbContext, audit auditservice.AuditService) GroupService {
	return &groupService{db: db, audit: audit}
}

var (
	errNameTaken = exceptions.NewAPIError(http.StatusConflict, "A group with this name already exists", nil)
	errSystem    = exceptions.NewAPIError(http.StatusConflict,
		"The Admins group holds every scope; it cannot be renamed, re-scoped or deleted", nil)
	errBadGrant = exceptions.NewAPIError(http.StatusBadRequest,
		"Each product must be one the company subscribes to, and each role in that product's catalogue", nil)
	errOwnerProducts = exceptions.NewAPIError(http.StatusForbidden, "Only the Owner can give a group products", nil)
	errOwnerDelete   = exceptions.NewAPIError(http.StatusForbidden,
		"This group gives products; only the Owner can delete it", nil)
)

// normalize validates requested scopes and completes them (edit brings read).
func normalize(in []string) ([]string, error) {
	scopes, err := shared.NormalizeScopes(in)
	if err != nil {
		return nil, exceptions.NewAPIError(http.StatusBadRequest, err.Error(), nil)
	}
	return scopes, nil
}

func grants(gs []dbmodels.GroupProductGrant) []models.ProductGrant {
	out := make([]models.ProductGrant, 0, len(gs))
	for _, g := range gs {
		out = append(out, models.ProductGrant{ProductID: g.ProductID, ProductKey: g.ProductKey, RoleName: g.RoleName})
	}
	return out
}

func (s *groupService) List(ctx context.Context, scope shared.Scope) ([]models.GroupListItem, error) {
	rows, err := groupcustoms.NewGroupDbCustoms(s.db).List(ctx, scope.ClientID)
	if err != nil {
		return nil, err
	}
	return listItems(rows), nil
}

func listItems(rows []dbmodels.GroupListItem) []models.GroupListItem {
	out := make([]models.GroupListItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.GroupListItem{
			ID: r.ID, Name: r.Name, Description: deref(r.Description), SystemKey: r.SystemKey,
			LoginPolicyID: r.LoginPolicyID, Scopes: r.Scopes, ProductGrants: grants(r.ProductGrants),
			MemberCount: r.MemberCount, CreatedAt: r.CreatedAt,
		})
	}
	return out
}

func (s *groupService) Get(ctx context.Context, scope shared.Scope, groupID string) (models.GroupDetail, error) {
	rows, err := groupcustoms.NewGroupDbCustoms(s.db).Detail(ctx, groupID, scope.ClientID)
	if err != nil {
		return models.GroupDetail{}, err
	}
	if len(rows) == 0 {
		return models.GroupDetail{}, exceptions.ErrNotFound
	}
	head := rows[0]
	// One row per member; a group with no members still yields a single row with
	// NULL member columns.
	members := make([]models.Member, 0, len(rows))
	for _, r := range rows {
		if r.UserID != nil {
			members = append(members, models.Member{UserID: *r.UserID, Email: deref(r.UserEmail), AssignedAt: r.AssignedAt})
		}
	}
	appointed, err := groupmanagercustoms.NewGroupManagerDbCustoms(s.db).List(ctx, groupID, scope.ClientID)
	if err != nil {
		return models.GroupDetail{}, err
	}
	managers := make([]models.Manager, 0, len(appointed))
	for _, m := range appointed {
		managers = append(managers, models.Manager{
			UserID: m.UserID, Email: m.Email, AppointedAt: m.AppointedAt,
			AppointedByEmail: m.AppointedByEmail, AppointedByOwner: m.AppointedByOwner,
		})
	}
	// Adding someone to the group can put them under its sign-in policy, so
	// whoever manages its members is shown which one.
	var policyName *string
	if head.LoginPolicyID != nil {
		p, err := policycustoms.NewLoginPolicyDbCustoms(s.db).Get(ctx, *head.LoginPolicyID, scope.ClientID)
		switch {
		case err == nil:
			policyName = &p.Name
		case !errors.Is(err, exceptions.ErrNoRows):
			return models.GroupDetail{}, err
		}
	}
	return models.GroupDetail{
		GroupListItem: models.GroupListItem{
			ID: head.ID, Name: head.Name, Description: deref(head.Description), SystemKey: head.SystemKey,
			LoginPolicyID: head.LoginPolicyID, Scopes: head.Scopes, ProductGrants: grants(head.ProductGrants),
			MemberCount: int64(len(members)), CreatedAt: head.CreatedAt,
		},
		Members: members, Managers: managers, LoginPolicyName: policyName,
	}, nil
}

// Create creates the group and gives it its scopes (rule 1: only scopes the
// actor holds) and, for the Owner, its products, in one transaction.
func (s *groupService) Create(ctx context.Context, scope shared.Scope, in models.GroupInput) (models.Group, error) {
	scopes, err := normalize(in.Scopes)
	if err != nil {
		return models.Group{}, err
	}
	if !scope.CanGive(scopes) {
		return models.Group{}, exceptions.ErrCannotGive
	}
	pg := dedupeGrants(in.ProductGrants)
	if len(pg) > 0 && !scope.ByOwner {
		return models.Group{}, errOwnerProducts
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return models.Group{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	grp, err := groups.NewGroupDbService(tx).Create(ctx, scope.ClientID, strings.TrimSpace(in.Name), in.Description)
	if err != nil {
		if exceptions.IsUniqueViolation(err) {
			return models.Group{}, errNameTaken
		}
		return models.Group{}, err
	}
	if len(scopes) > 0 {
		if _, err := groupscopes.NewGroupScopeDbService(tx).Set(ctx, grp.ID, scope.ClientID, scopes); err != nil {
			return models.Group{}, err
		}
	}
	if len(pg) > 0 {
		if _, err := groups.NewGroupDbService(tx).SetProductGrants(ctx, grp.ID, scope.ClientID, pg, scope.Actor.UserID); err != nil {
			return models.Group{}, mapGrantError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return models.Group{}, err
	}
	s.audit.Record(scope, "group.created")
	out := models.Group{ID: grp.ID, Name: grp.Name, Scopes: scopes}
	for _, g := range pg {
		out.ProductGrants = append(out.ProductGrants, models.ProductGrant{ProductID: g.ProductID, RoleName: g.RoleName})
	}
	return out, nil
}

func (s *groupService) Update(ctx context.Context, scope shared.Scope, groupID, name, description string) error {
	g, err := groups.NewGroupDbService(s.db).GetTenantScoped(ctx, groupID, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return exceptions.ErrNotFound
	}
	if err != nil {
		return err
	}
	if g.SystemKey != nil {
		return errSystem
	}
	if _, err := groups.NewGroupDbService(s.db).Update(ctx, groupID, scope.ClientID, strings.TrimSpace(name), description); err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return exceptions.ErrNotFound
		}
		if exceptions.IsUniqueViolation(err) {
			return errNameTaken
		}
		return err
	}
	s.audit.Record(scope, "group.updated")
	return nil
}

// SetScopes replaces the group's scopes wholesale. Rule 1 applies to what the
// change gives AND what it takes away: the actor must hold every scope added or
// removed. The procedure bumps every member's admin_version in the same
// transaction.
func (s *groupService) SetScopes(ctx context.Context, scope shared.Scope, groupID string, in []string) ([]string, error) {
	scopes, err := normalize(in)
	if err != nil {
		return nil, err
	}
	g, err := groupcustoms.NewGroupDbCustoms(s.db).Summary(ctx, groupID, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return nil, exceptions.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if g.SystemKey != nil {
		return nil, errSystem
	}
	if !scope.CanGive(shared.Changed(g.Scopes, scopes)) {
		return nil, exceptions.ErrCannotGive
	}
	n, err := groupscopes.NewGroupScopeDbService(s.db).Set(ctx, groupID, scope.ClientID, scopes)
	if err != nil {
		if exceptions.IsForeignKeyViolation(err) {
			return nil, exceptions.NewAPIError(http.StatusBadRequest, "Unknown scope", nil)
		}
		return nil, err
	}
	switch n {
	case groupscopes.NotFound:
		return nil, exceptions.ErrNotFound
	case groupscopes.SystemGroup:
		return nil, errSystem
	}
	s.audit.Record(scope, "group.scopes_set")
	return scopes, nil
}

// SetProductGrants replaces the product roles wholesale. The procedure bumps
// every member's permissions_version in the same statement, so products see the
// change at their members' next refresh, or at once through introspection.
func (s *groupService) SetProductGrants(ctx context.Context, scope shared.Scope, groupID string, in []models.ProductGrant) error {
	if !scope.ByOwner {
		return errOwnerProducts // the route exists only in the Owner console; this is the belt to its braces
	}
	n, err := groups.NewGroupDbService(s.db).SetProductGrants(ctx, groupID, scope.ClientID, dedupeGrants(in), scope.Actor.UserID)
	if err != nil {
		return mapGrantError(err)
	}
	if n < 0 {
		return exceptions.ErrNotFound
	}
	s.audit.Record(scope, "group.product_grants_set")
	return nil
}

// Delete removes a group. Deleting takes its scopes away from every member, so
// rule 1 applies to all of them; a group that gives products is the Owner's to
// delete, since product access is theirs to decide.
func (s *groupService) Delete(ctx context.Context, scope shared.Scope, groupID string) error {
	g, err := groupcustoms.NewGroupDbCustoms(s.db).Summary(ctx, groupID, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return exceptions.ErrNotFound
	}
	if err != nil {
		return err
	}
	if g.SystemKey != nil {
		return errSystem
	}
	if len(g.ProductGrants) > 0 && !scope.ByOwner {
		return errOwnerDelete
	}
	if !scope.CanGive(g.Scopes) {
		return exceptions.ErrCannotGive
	}
	n, err := groups.NewGroupDbService(s.db).Delete(ctx, groupID, scope.ClientID)
	if err != nil {
		return err
	}
	if n == 0 {
		return exceptions.ErrNotFound
	}
	s.audit.Record(scope, "group.deleted")
	return nil
}

// dedupeGrants keeps one role per product: the primary key would otherwise abort
// the whole write on a repeated product.
func dedupeGrants(in []models.ProductGrant) []groups.ProductGrant {
	seen := map[string]bool{}
	out := make([]groups.ProductGrant, 0, len(in))
	for _, g := range in {
		if seen[g.ProductID] {
			continue
		}
		seen[g.ProductID] = true
		out = append(out, groups.ProductGrant{ProductID: g.ProductID, RoleName: g.RoleName})
	}
	return out
}

func mapGrantError(err error) error {
	if exceptions.IsForeignKeyViolation(err) {
		return errBadGrant
	}
	return err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
