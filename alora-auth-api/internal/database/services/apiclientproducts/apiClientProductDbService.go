// Package apiclientproducts is the table service for tbl_api_client_products:
// the products each API client may get a token for.
package apiclientproducts

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/sqlc"
)

// Outcomes of Set other than a count.
const (
	NotFound   int32 = -1 // no such API client in the company
	NotAllowed int32 = -2 // a product added is not a live subscription accepting API clients
)

// APIClientProductDbService is the CRUD surface of tbl_api_client_products.
type APIClientProductDbService struct{ q *sqlc.Queries }

// NewAPIClientProductDbService binds the service to a context: the pool or a
// transaction.
func NewAPIClientProductDbService(c contexts.Querier) *APIClientProductDbService {
	return &APIClientProductDbService{q: c.Queries()}
}

// Set replaces an API client's product list wholesale and returns how many
// products are on it, or NotFound / NotAllowed. A product already on the list
// may stay whatever has changed since; one added must be usable.
func (s *APIClientProductDbService) Set(ctx context.Context, apiClientID, clientID string, productIDs []string) (int32, error) {
	if productIDs == nil {
		productIDs = []string{}
	}
	return s.q.SetApiClientProducts(ctx, sqlc.SetApiClientProductsParams{
		ApiClientID: apiClientID, ClientID: clientID, ProductIds: productIDs,
	})
}
