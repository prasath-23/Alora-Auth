// Package products is the table service for tbl_products: the product catalogue
// and each product's registration as an OAuth client (its secret, redirect URIs
// and role catalogue). The view-backed reads live in customs.
package products

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// ProductDbService is the CRUD surface of tbl_products.
type ProductDbService struct{ q *sqlc.Queries }

// NewProductDbService binds the service to a context: the pool or a transaction.
func NewProductDbService(c contexts.Querier) *ProductDbService {
	return &ProductDbService{q: c.Queries()}
}

// ProductFields are a product's settable columns. An empty Description, BaseURL
// or InitiateLoginURI stores NULL. A nil AcceptsAPIClients is false for a new
// product and unchanged for an update.
type ProductFields struct {
	Name              string
	Description       string
	BaseURL           string
	InitiateLoginURI  string
	IsActive          bool
	AcceptsAPIClients *bool
}

// Create inserts a product under a unique key. The key is fixed for life: it is
// the suffix of the audience every token for the product carries.
func (s *ProductDbService) Create(ctx context.Context, key string, f ProductFields) (models.Product, error) {
	row, err := s.q.CreateProduct(ctx, sqlc.CreateProductParams{
		Key: key, Name: f.Name,
		Description: services.TextOrNull(f.Description), BaseUrl: services.TextOrNull(f.BaseURL),
		InitiateLoginUri: services.TextOrNull(f.InitiateLoginURI), IsActive: f.IsActive,
		AcceptsApiClients: f.AcceptsAPIClients != nil && *f.AcceptsAPIClients,
	})
	if err != nil {
		return models.Product{}, err
	}
	return fromRow(row), nil
}

// Update rewrites a product's settable columns. An unknown product yields no rows.
func (s *ProductDbService) Update(ctx context.Context, productID string, f ProductFields) (models.Product, error) {
	row, err := s.q.UpdateProduct(ctx, sqlc.UpdateProductParams{
		ProductID: productID, Name: f.Name,
		Description: services.TextOrNull(f.Description), BaseUrl: services.TextOrNull(f.BaseURL),
		InitiateLoginUri: services.TextOrNull(f.InitiateLoginURI), IsActive: f.IsActive,
		AcceptsApiClients: services.BoolPtr(f.AcceptsAPIClients),
	})
	if err != nil {
		return models.Product{}, err
	}
	return fromRow(row), nil
}

// GetByID reads one product; with activeOnly, an inactive product yields no rows.
func (s *ProductDbService) GetByID(ctx context.Context, productID string, activeOnly bool) (models.Product, error) {
	row, err := s.q.GetProductById(ctx, sqlc.GetProductByIdParams{PProductid: productID, PActiveonly: activeOnly})
	if err != nil {
		return models.Product{}, err
	}
	return fromRow(row), nil
}

// KeyByID reads a product's key, the suffix of its tokens' audience. An unknown
// product yields no rows.
func (s *ProductDbService) KeyByID(ctx context.Context, productID string) (string, error) {
	return s.q.ProductKeyById(ctx, productID)
}

// SetClientSecret stores the hash of a new client secret, replacing the old one,
// and reports how many products changed: zero means no such product.
func (s *ProductDbService) SetClientSecret(ctx context.Context, productID, secretHash string) (int32, error) {
	return s.q.SetProductClientSecret(ctx, sqlc.SetProductClientSecretParams{PProductid: productID, PSecrethash: secretHash})
}

// SetRedirectURIs replaces a product's registered redirect URIs wholesale and
// reports how many it now has.
func (s *ProductDbService) SetRedirectURIs(ctx context.Context, productID string, uris []string) (int32, error) {
	return s.q.SetProductRedirectUris(ctx, sqlc.SetProductRedirectUrisParams{ProductID: productID, RedirectUris: uris})
}

// SetRoles replaces a product's role catalogue and reports how many roles it now
// has. Removing a role that is still granted is a foreign-key violation: a grant
// never outlives the role it names.
func (s *ProductDbService) SetRoles(ctx context.Context, productID string, roles []string) (int32, error) {
	return s.q.SetProductRoles(ctx, sqlc.SetProductRolesParams{ProductID: productID, RoleNames: roles})
}

func fromRow(r sqlc.TblProduct) models.Product {
	return models.Product{
		ID: r.ID, Key: r.Key, Name: r.Name,
		Description: services.StringPtr(r.Description), BaseURL: services.StringPtr(r.BaseUrl),
		InitiateLoginURI: services.StringPtr(r.InitiateLoginUri),
		ClientSecretHash: services.StringPtr(r.ClientSecretHash),
		SecretRotatedAt:  services.TimePtr(r.SecretRotatedAt),
		IsActive:         r.IsActive, AcceptsAPIClients: r.AcceptsApiClients,
		CreatedAt: services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
	}
}
