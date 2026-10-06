// Package customs holds the tbl_api_clients reads beyond CRUD: the summaries
// vw_ApiClientSummary aggregates, the products a company may put on an API
// client's list, and what the token endpoint checks — the credentials of any
// OAuth client, and whether an API client may have a token for a product.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// APIClientDbCustoms is the custom query surface of tbl_api_clients.
type APIClientDbCustoms struct{ q *sqlc.Queries }

// NewAPIClientDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewAPIClientDbCustoms(c contexts.Querier) *APIClientDbCustoms {
	return &APIClientDbCustoms{q: c.Queries()}
}

// List lists a company's API clients, by name.
func (s *APIClientDbCustoms) List(ctx context.Context, clientID string) ([]models.APIClientSummary, error) {
	rows, err := s.q.ListApiClients(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return summaries(rows), nil
}

// ListAll lists every company's API clients, by company and then by name.
func (s *APIClientDbCustoms) ListAll(ctx context.Context) ([]models.APIClientSummary, error) {
	rows, err := s.q.ListAllApiClients(ctx)
	if err != nil {
		return nil, err
	}
	return summaries(rows), nil
}

// Get reads one API client of a company. Another company's yields no rows.
func (s *APIClientDbCustoms) Get(ctx context.Context, apiClientID, clientID string) (models.APIClientSummary, error) {
	r, err := s.q.GetApiClient(ctx, sqlc.GetApiClientParams{ApiClientID: apiClientID, ClientID: clientID})
	if err != nil {
		return models.APIClientSummary{}, err
	}
	return summary(r), nil
}

// ProductChoices lists the products a company may put on an API client's list:
// live subscriptions to active products that accept API clients.
func (s *APIClientDbCustoms) ProductChoices(ctx context.Context, clientID string) ([]models.ClientProductDetail, error) {
	rows, err := s.q.ListApiClientProductChoices(ctx, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.ClientProductDetail, 0, len(rows))
	for _, r := range rows {
		out = append(out, services.ClientProductDetailFromRow(r))
	}
	return out, nil
}

// OAuthCredentials reads the secrets a client id may authenticate with: a
// product's one, or an API client's live ones (at most two). None: no such
// client, or no usable secret.
func (s *APIClientDbCustoms) OAuthCredentials(ctx context.Context, oauthClientID string) ([]models.OAuthClientCredential, error) {
	rows, err := s.q.GetOAuthClientCredentials(ctx, oauthClientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.OAuthClientCredential, 0, len(rows))
	for _, r := range rows {
		c := models.OAuthClientCredential{
			Kind: r.Kind, OAuthClientID: r.OauthClientID, ProductKey: r.ProductKey,
			CompanyID: r.CompanyID, SecretID: r.SecretID, IsActive: r.IsActive,
		}
		if r.SecretHash.Valid {
			c.SecretHash = r.SecretHash.String
		}
		out = append(out, c)
	}
	return out, nil
}

// Grant reads whether an API client may have a token for a product on its list,
// by the product's key. A product unknown, or not on the list, yields no rows.
func (s *APIClientDbCustoms) Grant(ctx context.Context, apiClientID, productKey string) (models.APIClientGrant, error) {
	r, err := s.q.GetApiClientGrant(ctx, sqlc.GetApiClientGrantParams{ApiClientID: apiClientID, ProductKey: productKey})
	if err != nil {
		return models.APIClientGrant{}, err
	}
	scopes := r.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return models.APIClientGrant{
		APIClientID: r.ApiClientID, ClientID: r.ClientID, ProductID: r.ProductID, ProductKey: r.ProductKey,
		Usable: r.Usable, Scopes: scopes,
	}, nil
}

func summaries(rows []sqlc.VwApiclientsummary) []models.APIClientSummary {
	out := make([]models.APIClientSummary, 0, len(rows))
	for _, r := range rows {
		out = append(out, summary(r))
	}
	return out
}

func summary(r sqlc.VwApiclientsummary) models.APIClientSummary {
	return models.APIClientSummary{
		ID: r.ID, ClientID: r.ClientID, CompanyName: r.CompanyName, Name: r.Name,
		Description: services.StringPtr(r.Description), IsActive: r.IsActive,
		CreatedByUserID: services.StringPtr(r.CreatedByUserID), CreatedByOwnerID: services.StringPtr(r.CreatedByOwnerID),
		LastUsedAt: services.TimePtr(r.LastUsedAt), CreatedAt: services.TimePtr(r.CreatedAt),
		UpdatedAt: services.TimePtr(r.UpdatedAt), Scopes: services.DecodeJSON[string](r.Scopes),
		Products: services.DecodeJSON[models.APIClientProduct](r.Products), LiveSecrets: r.LiveSecrets,
	}
}
