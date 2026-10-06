// Package groups is the table service for tbl_groups and what a group grants: its
// product roles and its login policy. The list and the per-member detail, both
// read from views, live in customs.
package groups

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// GroupDbService is the CRUD surface of tbl_groups.
type GroupDbService struct{ q *sqlc.Queries }

// NewGroupDbService binds the service to a context: the pool or a transaction.
func NewGroupDbService(c contexts.Querier) *GroupDbService { return &GroupDbService{q: c.Queries()} }

// Create inserts a group. An empty description stores NULL. A name already taken
// in the company (case-insensitively) is a unique violation.
func (s *GroupDbService) Create(ctx context.Context, clientID, name, description string) (models.Group, error) {
	row, err := s.q.CreateGroup(ctx, sqlc.CreateGroupParams{
		ClientID: clientID, Name: name, Description: services.TextOrNull(description),
	})
	if err != nil {
		return models.Group{}, err
	}
	return fromRow(row), nil
}

// Update renames and re-describes a group within a company. A group outside the
// company, or a system group, yields no rows.
func (s *GroupDbService) Update(ctx context.Context, groupID, clientID, name, description string) (models.Group, error) {
	row, err := s.q.UpdateGroup(ctx, sqlc.UpdateGroupParams{
		GroupID: groupID, ClientID: clientID, Name: name, Description: services.TextOrNull(description),
	})
	if err != nil {
		return models.Group{}, err
	}
	return fromRow(row), nil
}

// Delete removes a group (memberships, features and grants cascade) and reports
// how many rows changed. A system group is never deleted.
func (s *GroupDbService) Delete(ctx context.Context, groupID, clientID string) (int32, error) {
	return s.q.DeleteGroup(ctx, sqlc.DeleteGroupParams{PGroupid: groupID, PClientid: clientID})
}

// GetTenantScoped reads one group within a company.
func (s *GroupDbService) GetTenantScoped(ctx context.Context, groupID, clientID string) (models.Group, error) {
	row, err := s.q.GetGroupTenantScoped(ctx, sqlc.GetGroupTenantScopedParams{PGroupid: groupID, PClientid: clientID})
	if err != nil {
		return models.Group{}, err
	}
	return fromRow(row), nil
}

// SystemGroupID resolves a company's system group (models.SystemGroupAdmins) to
// its id. A company always has one; no rows means no such company.
func (s *GroupDbService) SystemGroupID(ctx context.Context, clientID, systemKey string) (string, error) {
	return s.q.GetSystemGroupId(ctx, sqlc.GetSystemGroupIdParams{PClientid: clientID, PSystemkey: systemKey})
}

// ProductGrant is one product role a group confers.
type ProductGrant struct {
	ProductID string
	RoleName  string
}

// SetProductGrants replaces the product roles a group confers, wholesale, and
// bumps every member's permissions_version. It reports how many grants were
// written, or -1 when the group is not the company's. A product the company
// does not subscribe to, or a role outside the product's catalogue, is a
// foreign-key violation.
func (s *GroupDbService) SetProductGrants(ctx context.Context, groupID, clientID string, grants []ProductGrant, grantedBy string) (int32, error) {
	products := make([]string, 0, len(grants))
	roles := make([]string, 0, len(grants))
	for _, g := range grants {
		products = append(products, g.ProductID)
		roles = append(roles, g.RoleName)
	}
	return s.q.SetGroupProductGrants(ctx, sqlc.SetGroupProductGrantsParams{
		GroupID: groupID, ClientID: clientID, ProductIds: products, RoleNames: roles,
		GrantedBy: services.TextOrNull(grantedBy),
	})
}

// SetLoginPolicy sets the login policy a group's members sign in under, or with
// a nil policyID removes it. It reports how many groups changed: zero means no
// such group in the company. A policy of another company is a foreign-key
// violation.
func (s *GroupDbService) SetLoginPolicy(ctx context.Context, groupID, clientID string, policyID *string) (int32, error) {
	return s.q.SetGroupLoginPolicy(ctx, sqlc.SetGroupLoginPolicyParams{
		GroupID: groupID, ClientID: clientID, PolicyID: services.TextPtr(policyID),
	})
}

func fromRow(r sqlc.TblGroup) models.Group {
	return models.Group{
		ID: r.ID, ClientID: r.ClientID, Name: r.Name, Description: services.StringPtr(r.Description),
		SystemKey: services.StringPtr(r.SystemKey), LoginPolicyID: services.StringPtr(r.LoginPolicyID),
		CreatedAt: services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
	}
}
