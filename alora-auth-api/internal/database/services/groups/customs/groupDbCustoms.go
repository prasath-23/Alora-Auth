// Package customs holds the tbl_groups queries beyond CRUD: the list and the
// per-member detail, both read from views that aggregate what each group grants.
package customs

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// GroupDbCustoms is the custom query surface of tbl_groups.
type GroupDbCustoms struct{ q *sqlc.Queries }

// NewGroupDbCustoms binds the queries to a context: the pool or a transaction.
func NewGroupDbCustoms(c contexts.Querier) *GroupDbCustoms { return &GroupDbCustoms{q: c.Queries()} }

// List lists a company's groups with their scopes, product grants and member
// counts.
func (s *GroupDbCustoms) List(ctx context.Context, clientID string) ([]models.GroupListItem, error) {
	rows, err := s.q.ListGroups(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return listItems(rows), nil
}

// ManagedBy lists the groups a person manages in their company, as List shows
// them.
func (s *GroupDbCustoms) ManagedBy(ctx context.Context, userID, clientID string) ([]models.GroupListItem, error) {
	rows, err := s.q.ListManagedGroups(ctx, sqlc.ListManagedGroupsParams{UserID: userID, ClientID: clientID})
	if err != nil {
		return nil, err
	}
	return listItems(rows), nil
}

func listItems(rows []sqlc.VwGrouplistitem) []models.GroupListItem {
	out := make([]models.GroupListItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.GroupListItem{
			ID: r.ID, ClientID: r.ClientID, Name: r.Name, Description: services.StringPtr(r.Description),
			SystemKey: services.StringPtr(r.SystemKey), LoginPolicyID: services.StringPtr(r.LoginPolicyID),
			CreatedAt: services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
			Scopes: services.DecodeJSON[string](r.Scopes), ProductGrants: services.DecodeJSON[models.GroupProductGrant](r.ProductGrants),
			MemberCount: r.MemberCount,
		})
	}
	return out
}

// Detail reads a group within a company: one row per member, or one row with nil
// member fields for an empty group. A group outside the company yields none.
func (s *GroupDbCustoms) Detail(ctx context.Context, groupID, clientID string) ([]models.GroupDetailRow, error) {
	rows, err := s.q.GetGroupDetail(ctx, sqlc.GetGroupDetailParams{PGroupid: groupID, PClientid: clientID})
	if err != nil {
		return nil, err
	}
	out := make([]models.GroupDetailRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.GroupDetailRow{
			ID: r.ID, ClientID: r.ClientID, Name: r.Name, Description: services.StringPtr(r.Description),
			SystemKey: services.StringPtr(r.SystemKey), LoginPolicyID: services.StringPtr(r.LoginPolicyID),
			CreatedAt: services.TimePtr(r.CreatedAt),
			Scopes:    services.DecodeJSON[string](r.Scopes), ProductGrants: services.DecodeJSON[models.GroupProductGrant](r.ProductGrants),
			UserID: services.StringPtr(r.UserID), UserEmail: services.StringPtr(r.UserEmail),
			AssignedAt: services.TimePtr(r.AssignedAt),
		})
	}
	return out, nil
}

// Summary reads one group of a company — what it grants and whether it is a
// system group — without its members. ErrNoRows when the group is not the
// company's.
func (s *GroupDbCustoms) Summary(ctx context.Context, groupID, clientID string) (models.GroupDetailRow, error) {
	rows, err := s.Detail(ctx, groupID, clientID)
	if err != nil {
		return models.GroupDetailRow{}, err
	}
	if len(rows) == 0 {
		return models.GroupDetailRow{}, pgx.ErrNoRows
	}
	head := rows[0]
	head.UserID, head.UserEmail, head.AssignedAt = nil, nil, nil
	return head, nil
}
