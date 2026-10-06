// Package clientproducts is the table service for tbl_client_products: the
// companies' product subscriptions. The joined list lives in customs.
package clientproducts

import (
	"context"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// ClientProductDbService is the CRUD surface of tbl_client_products.
type ClientProductDbService struct{ q *sqlc.Queries }

// NewClientProductDbService binds the service to a context: the pool or a
// transaction.
func NewClientProductDbService(c contexts.Querier) *ClientProductDbService {
	return &ClientProductDbService{q: c.Queries()}
}

// ActiveSubscriptionID returns the company's live subscription to a product. No
// subscription yields no rows.
func (s *ClientProductDbService) ActiveSubscriptionID(ctx context.Context, clientID, productID string) (string, error) {
	return s.q.ActiveSubscriptionId(ctx, sqlc.ActiveSubscriptionIdParams{PClientid: clientID, PProductid: productID})
}

// Upsert creates a company's subscription to a product, or updates the one that
// exists. A subscription is switched off, never deleted. A nil seatLimit or
// endsAt stores NULL: unlimited seats, no end date.
func (s *ClientProductDbService) Upsert(ctx context.Context, clientID, productID string, active bool, seatLimit *int32, endsAt *time.Time) (models.ClientProduct, error) {
	r, err := s.q.UpsertSubscription(ctx, sqlc.UpsertSubscriptionParams{
		ClientID: clientID, ProductID: productID, IsActive: active,
		SeatLimit: services.Int4Ptr(seatLimit), EndsAt: services.TimestamptzPtr(endsAt),
	})
	if err != nil {
		return models.ClientProduct{}, err
	}
	return models.ClientProduct{
		ID: r.ID, ClientID: r.ClientID, ProductID: r.ProductID, IsActive: r.IsActive,
		SeatLimit: services.Int32Ptr(r.SeatLimit), StartsAt: services.TimePtr(r.StartsAt),
		EndsAt: services.TimePtr(r.EndsAt), CreatedAt: services.TimePtr(r.CreatedAt),
	}, nil
}
