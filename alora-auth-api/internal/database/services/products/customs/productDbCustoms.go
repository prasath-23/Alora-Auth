// Package customs holds the tbl_products queries beyond CRUD: the registration
// views (without and with the secret hash), the role catalogue, the redirect
// URIs and the exact-match redirect check.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// ProductDbCustoms is the custom query surface of tbl_products.
type ProductDbCustoms struct{ q *sqlc.Queries }

// NewProductDbCustoms binds the queries to a context: the pool or a transaction.
func NewProductDbCustoms(c contexts.Querier) *ProductDbCustoms {
	return &ProductDbCustoms{q: c.Queries()}
}

// Client reads one product's registration, without its secret hash.
func (s *ProductDbCustoms) Client(ctx context.Context, productID string) (models.ProductClient, error) {
	r, err := s.q.GetProductClient(ctx, productID)
	if err != nil {
		return models.ProductClient{}, err
	}
	return client(r), nil
}

// ListClients lists every product's registration, without secret hashes.
func (s *ProductDbCustoms) ListClients(ctx context.Context) ([]models.ProductClient, error) {
	rows, err := s.q.ListProducts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]models.ProductClient, 0, len(rows))
	for _, r := range rows {
		out = append(out, client(r))
	}
	return out, nil
}

// Credential reads what client authentication checks: the product's key, whether
// it is active, and its secret hash.
func (s *ProductDbCustoms) Credential(ctx context.Context, productID string) (models.ProductCredential, error) {
	r, err := s.q.GetProductClientCredential(ctx, productID)
	if err != nil {
		return models.ProductCredential{}, err
	}
	return models.ProductCredential{
		ID: r.ID, Key: r.Key, IsActive: r.IsActive, ClientSecretHash: services.StringPtr(r.ClientSecretHash),
	}, nil
}

// Roles lists a product's role catalogue.
func (s *ProductDbCustoms) Roles(ctx context.Context, productID string) ([]models.ProductRole, error) {
	rows, err := s.q.ListProductRoles(ctx, productID)
	if err != nil {
		return nil, err
	}
	out := make([]models.ProductRole, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.ProductRole{
			ProductID: r.ProductID, RoleName: r.RoleName,
			Description: services.StringPtr(r.Description), CreatedAt: services.TimePtr(r.CreatedAt),
		})
	}
	return out, nil
}

// RedirectURIs lists a product's registered redirect URIs.
func (s *ProductDbCustoms) RedirectURIs(ctx context.Context, productID string) ([]models.ProductRedirectURI, error) {
	rows, err := s.q.ListProductRedirectUris(ctx, productID)
	if err != nil {
		return nil, err
	}
	out := make([]models.ProductRedirectURI, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.ProductRedirectURI{
			ProductID: r.ProductID, RedirectURI: r.RedirectUri, CreatedAt: services.TimePtr(r.CreatedAt),
		})
	}
	return out, nil
}

// IsRedirectURIRegistered reports whether uri is, byte for byte, one of an
// ACTIVE product's registered redirect URIs.
func (s *ProductDbCustoms) IsRedirectURIRegistered(ctx context.Context, productID, uri string) (bool, error) {
	return s.q.IsRedirectUriRegistered(ctx, sqlc.IsRedirectUriRegisteredParams{PProductid: productID, PRedirecturi: uri})
}

func client(r sqlc.VwProductclient) models.ProductClient {
	return models.ProductClient{
		ID: r.ID, Key: r.Key, Name: r.Name,
		Description: services.StringPtr(r.Description), BaseURL: services.StringPtr(r.BaseUrl),
		InitiateLoginURI: services.StringPtr(r.InitiateLoginUri), IsActive: r.IsActive,
		AcceptsAPIClients: r.AcceptsApiClients, HasSecret: r.HasSecret,
		SecretRotatedAt: services.TimePtr(r.SecretRotatedAt),
		CreatedAt:       services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
	}
}
