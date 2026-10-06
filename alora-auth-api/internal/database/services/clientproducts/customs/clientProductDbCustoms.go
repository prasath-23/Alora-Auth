// Package customs holds the tbl_client_products queries beyond CRUD: a tenant's
// subscriptions joined to their products.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// ClientProductDbCustoms is the custom query surface of tbl_client_products.
type ClientProductDbCustoms struct{ q *sqlc.Queries }

// NewClientProductDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewClientProductDbCustoms(c contexts.Querier) *ClientProductDbCustoms {
	return &ClientProductDbCustoms{q: c.Queries()}
}

// ListForClient lists a tenant's subscriptions with their products.
func (s *ClientProductDbCustoms) ListForClient(ctx context.Context, clientID string) ([]models.ClientProductDetail, error) {
	rows, err := s.q.ListClientProducts(ctx, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.ClientProductDetail, 0, len(rows))
	for _, r := range rows {
		out = append(out, services.ClientProductDetailFromRow(r))
	}
	return out, nil
}
