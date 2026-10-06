// Package productpermissions is the table service for tbl_product_permissions:
// the product roles granted to users directly. The direct and effective access
// reads live in customs.
package productpermissions

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/sqlc"
)

// ProductPermissionDbService is the CRUD surface of tbl_product_permissions.
type ProductPermissionDbService struct{ q *sqlc.Queries }

// NewProductPermissionDbService binds the service to a context: the pool or a
// transaction.
func NewProductPermissionDbService(c contexts.Querier) *ProductPermissionDbService {
	return &ProductPermissionDbService{q: c.Queries()}
}

// Upsert creates or replaces a user's role in one product. A role outside the
// product's catalogue, or a product the company does not subscribe to, is a
// foreign-key violation.
func (s *ProductPermissionDbService) Upsert(ctx context.Context, userID, clientID, productID, roleName, grantedBy string) error {
	return s.q.UpsertProductPermission(ctx, sqlc.UpsertProductPermissionParams{
		PUserid: userID, PClientid: clientID, PProductid: productID, PRolename: roleName, PGrantedby: grantedBy,
	})
}

// Delete removes a user's direct role in one product and reports how many rows
// changed.
func (s *ProductPermissionDbService) Delete(ctx context.Context, userID, clientID, productID string) (int32, error) {
	return s.q.DeleteProductPermission(ctx, sqlc.DeleteProductPermissionParams{
		PUserid: userID, PClientid: clientID, PProductid: productID,
	})
}
