// Package apiclients is the table service for tbl_api_clients: applications'
// identities. The view-backed reads live in customs.
package apiclients

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// APIClientDbService is the CRUD surface of tbl_api_clients.
type APIClientDbService struct{ q *sqlc.Queries }

// NewAPIClientDbService binds the service to a context: the pool or a
// transaction.
func NewAPIClientDbService(c contexts.Querier) *APIClientDbService {
	return &APIClientDbService{q: c.Queries()}
}

// Create inserts an API client in a company, created by a user of that company
// (byUserID) or by an Owner (byOwnerID) — exactly one of them. It starts with no
// scopes, no products and no secret. A name the company already uses is a
// unique violation.
func (s *APIClientDbService) Create(ctx context.Context, clientID, name, description, byUserID, byOwnerID string) (models.APIClient, error) {
	row, err := s.q.CreateApiClient(ctx, sqlc.CreateApiClientParams{
		ClientID: clientID, Name: name, Description: services.TextOrNull(description),
		CreatedByUserID: services.TextOrNull(byUserID), CreatedByOwnerID: services.TextOrNull(byOwnerID),
	})
	if err != nil {
		return models.APIClient{}, err
	}
	return fromRow(row), nil
}

// Update renames, re-describes or switches an API client on or off, within its
// company. Another company's API client yields no rows.
func (s *APIClientDbService) Update(ctx context.Context, apiClientID, clientID, name, description string, isActive bool) (models.APIClient, error) {
	row, err := s.q.UpdateApiClient(ctx, sqlc.UpdateApiClientParams{
		ApiClientID: apiClientID, ClientID: clientID, Name: name,
		Description: services.TextOrNull(description), IsActive: isActive,
	})
	if err != nil {
		return models.APIClient{}, err
	}
	return fromRow(row), nil
}

// Delete removes an API client with its scopes, products and secrets, within its
// company, and reports how many were removed: zero means no such client there.
func (s *APIClientDbService) Delete(ctx context.Context, apiClientID, clientID string) (int32, error) {
	return s.q.DeleteApiClient(ctx, sqlc.DeleteApiClientParams{ApiClientID: apiClientID, ClientID: clientID})
}

func fromRow(r sqlc.TblApiClient) models.APIClient {
	return models.APIClient{
		ID: r.ID, ClientID: r.ClientID, Name: r.Name, Description: services.StringPtr(r.Description),
		IsActive: r.IsActive, CreatedByUserID: services.StringPtr(r.CreatedByUserID),
		CreatedByOwnerID: services.StringPtr(r.CreatedByOwnerID), LastUsedAt: services.TimePtr(r.LastUsedAt),
		CreatedAt: services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
	}
}
