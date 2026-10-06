// Package customs holds the tbl_api_client_secrets reads: an API client's
// secrets, from vw_ApiClientSecret, which never carries a hash, and whether one
// is still live.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// APIClientSecretDbCustoms is the custom query surface of tbl_api_client_secrets.
type APIClientSecretDbCustoms struct{ q *sqlc.Queries }

// NewAPIClientSecretDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewAPIClientSecretDbCustoms(c contexts.Querier) *APIClientSecretDbCustoms {
	return &APIClientSecretDbCustoms{q: c.Queries()}
}

// List lists an API client's secrets, newest first. Another company's API client
// has none.
func (s *APIClientSecretDbCustoms) List(ctx context.Context, apiClientID, clientID string) ([]models.APIClientSecret, error) {
	rows, err := s.q.ListApiClientSecrets(ctx, sqlc.ListApiClientSecretsParams{ApiClientID: apiClientID, ClientID: clientID})
	if err != nil {
		return nil, err
	}
	out := make([]models.APIClientSecret, 0, len(rows))
	for _, r := range rows {
		out = append(out, services.APIClientSecretFromRow(r))
	}
	return out, nil
}

// IsLive reports whether a secret of an API client is still live: not revoked,
// not expired.
func (s *APIClientSecretDbCustoms) IsLive(ctx context.Context, secretID, apiClientID string) (bool, error) {
	return s.q.IsApiClientSecretLive(ctx, sqlc.IsApiClientSecretLiveParams{SecretID: secretID, ApiClientID: apiClientID})
}
