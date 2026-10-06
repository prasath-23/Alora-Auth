// Package customs holds the product-access reads: a user's direct grants, and
// their effective access (direct grants plus group grants, counted only for live
// users, active companies and products, and live subscriptions).
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// ProductPermissionDbCustoms is the custom query surface of product access.
type ProductPermissionDbCustoms struct{ q *sqlc.Queries }

// NewProductPermissionDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewProductPermissionDbCustoms(c contexts.Querier) *ProductPermissionDbCustoms {
	return &ProductPermissionDbCustoms{q: c.Queries()}
}

// ListDirect lists a user's DIRECT product roles within a company.
func (s *ProductPermissionDbCustoms) ListDirect(ctx context.Context, userID, clientID string) ([]models.UserProductRole, error) {
	rows, err := s.q.ListUserProductRoles(ctx, sqlc.ListUserProductRolesParams{PUserid: userID, PClientid: clientID})
	if err != nil {
		return nil, err
	}
	out := make([]models.UserProductRole, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.UserProductRole{
			UserID: r.UserID, ClientID: r.ClientID, ProductID: r.ProductID, ProductKey: r.ProductKey,
			ProductName: r.ProductName, RoleName: r.RoleName, ValidUntil: services.TimePtr(r.ValidUntil),
		})
	}
	return out, nil
}

// EffectiveRoles lists the distinct roles a user may use in one product right
// now. An empty list means no access.
func (s *ProductPermissionDbCustoms) EffectiveRoles(ctx context.Context, userID, clientID, productID string) ([]string, error) {
	rows, err := s.q.ListEffectiveRoles(ctx, sqlc.ListEffectiveRolesParams{
		PUserid: userID, PClientid: clientID, PProductid: productID,
	})
	if err != nil {
		return nil, err
	}
	roles := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Valid {
			roles = append(roles, r.String)
		}
	}
	return roles, nil
}

// EffectiveAccess lists every role a user may use, in every product, with where
// each one comes from.
func (s *ProductPermissionDbCustoms) EffectiveAccess(ctx context.Context, userID, clientID string) ([]models.EffectiveProductRole, error) {
	rows, err := s.q.ListUserEffectiveAccess(ctx, sqlc.ListUserEffectiveAccessParams{PUserid: userID, PClientid: clientID})
	if err != nil {
		return nil, err
	}
	out := make([]models.EffectiveProductRole, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.EffectiveProductRole{
			UserID: r.UserID, ClientID: r.ClientID, ProductID: r.ProductID, ProductKey: r.ProductKey,
			ProductName: r.ProductName, RoleName: r.RoleName, Source: r.Source,
			GroupID: services.StringPtr(r.GroupID),
		})
	}
	return out, nil
}

// Apps lists the products a user may launch, each with every role they hold.
func (s *ProductPermissionDbCustoms) Apps(ctx context.Context, userID, clientID string) ([]models.UserApp, error) {
	rows, err := s.q.ListUserApps(ctx, sqlc.ListUserAppsParams{PUserid: userID, PClientid: clientID})
	if err != nil {
		return nil, err
	}
	out := make([]models.UserApp, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.UserApp{
			UserID: r.UserID, ClientID: r.ClientID, ProductID: r.ProductID, ProductKey: r.ProductKey,
			ProductName: r.ProductName, ProductDescription: services.StringPtr(r.ProductDescription),
			BaseURL: services.StringPtr(r.BaseUrl), InitiateLoginURI: services.StringPtr(r.InitiateLoginUri),
			Roles: r.Roles,
		})
	}
	return out, nil
}
