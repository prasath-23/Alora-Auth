// Package apiclientsecrets is the table service for tbl_api_client_secrets: the
// hashed secrets API clients authenticate with. The listing lives in customs.
package apiclientsecrets

import (
	"context"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// APIClientSecretDbService is the CRUD surface of tbl_api_client_secrets.
type APIClientSecretDbService struct{ q *sqlc.Queries }

// NewAPIClientSecretDbService binds the service to a context: the pool or a
// transaction.
func NewAPIClientSecretDbService(c contexts.Querier) *APIClientSecretDbService {
	return &APIClientSecretDbService{q: c.Queries()}
}

// NewSecret is a secret to store: its hash and prefix, never its plaintext.
type NewSecret struct {
	Hash      string
	Prefix    string
	ExpiresAt *time.Time // nil: never expires
	ByUserID  string     // a user of the company, or
	ByOwnerID string     // an Owner: exactly one
}

// Create adds a secret to an API client and returns it without its hash. It
// yields no rows when the API client is not the company's, or already has two
// live secrets.
func (s *APIClientSecretDbService) Create(ctx context.Context, apiClientID, clientID string, n NewSecret) (models.APIClientSecret, error) {
	row, err := s.q.CreateApiClientSecret(ctx, sqlc.CreateApiClientSecretParams{
		ApiClientID: apiClientID, ClientID: clientID, SecretHash: n.Hash, Prefix: n.Prefix,
		ExpiresAt:       services.TimestamptzPtr(n.ExpiresAt),
		CreatedByUserID: services.TextOrNull(n.ByUserID), CreatedByOwnerID: services.TextOrNull(n.ByOwnerID),
	})
	if err != nil {
		return models.APIClientSecret{}, err
	}
	return services.APIClientSecretFromRow(row), nil
}

// Revoke revokes one live secret of an API client of the company and reports how
// many were revoked: zero means no such live secret there.
func (s *APIClientSecretDbService) Revoke(ctx context.Context, secretID, apiClientID, clientID string) (int32, error) {
	return s.q.RevokeApiClientSecret(ctx, sqlc.RevokeApiClientSecretParams{
		SecretID: secretID, ApiClientID: apiClientID, ClientID: clientID,
	})
}

// Touch stamps when a secret, and its API client, last earned a token — at most
// once a minute each.
func (s *APIClientSecretDbService) Touch(ctx context.Context, secretID, apiClientID string) error {
	return s.q.TouchApiClientSecret(ctx, sqlc.TouchApiClientSecretParams{SecretID: secretID, ApiClientID: apiClientID})
}
