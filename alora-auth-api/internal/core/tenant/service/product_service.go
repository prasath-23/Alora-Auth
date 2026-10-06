package service

import (
	"context"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/tenant/models"
	"github.com/alora/auth/internal/database/contexts"
	clientproductcustoms "github.com/alora/auth/internal/database/services/clientproducts/customs"
)

// ProductService reads the scope's company's product subscriptions.
type ProductService interface {
	// List returns every product the company subscribes to.
	List(ctx context.Context, scope shared.Scope) ([]models.Subscription, error)
}

type productService struct{ db *contexts.DbContext }

// NewProductService builds the product service.
func NewProductService(db *contexts.DbContext) ProductService {
	return &productService{db: db}
}

func (s *productService) List(ctx context.Context, scope shared.Scope) ([]models.Subscription, error) {
	rows, err := clientproductcustoms.NewClientProductDbCustoms(s.db).ListForClient(ctx, scope.ClientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.Subscription, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.Subscription{
			ID: r.ID, ProductID: r.ProductID, Key: r.ProductKey, Name: r.ProductName,
			Description: r.ProductDescription, BaseURL: r.ProductBaseURL, IsActive: r.IsActive,
			SeatLimit: r.SeatLimit, StartsAt: r.StartsAt, EndsAt: r.EndsAt,
		})
	}
	return out, nil
}
