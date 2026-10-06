// Package customs holds the tbl_sso_connections queries beyond CRUD: the runtime
// read the SSO sign-in path uses, and the list the Owner console shows.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// SSOConnectionDbCustoms is the custom query surface of tbl_sso_connections.
type SSOConnectionDbCustoms struct{ q *sqlc.Queries }

// NewSSOConnectionDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewSSOConnectionDbCustoms(c contexts.Querier) *SSOConnectionDbCustoms {
	return &SSOConnectionDbCustoms{q: c.Queries()}
}

// Runtime reads what the SSO sign-in path needs about one connection, its
// encrypted secret and its domains included. It is never returned by any API.
func (s *SSOConnectionDbCustoms) Runtime(ctx context.Context, connectionID string) (models.SSOConnectionRuntime, error) {
	r, err := s.q.GetSsoConnection(ctx, connectionID)
	if err != nil {
		return models.SSOConnectionRuntime{}, err
	}
	return models.SSOConnectionRuntime{
		ID: r.ID, ClientID: r.ClientID, Name: r.Name, Issuer: r.Issuer, OIDCClientID: r.OidcClientID,
		ClientSecretCiphertext: r.ClientSecretCiphertext, SecretKeyID: services.StringPtr(r.SecretKeyID),
		Scopes: r.Scopes, TrustUnverifiedEmail: r.TrustUnverifiedEmail, IsActive: r.IsActive,
		Domains: nonNil(r.Domains),
	}, nil
}

// List lists a company's connections, without secrets.
func (s *SSOConnectionDbCustoms) List(ctx context.Context, clientID string) ([]models.SSOConnectionSummary, error) {
	rows, err := s.q.ListSsoConnections(ctx, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.SSOConnectionSummary, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.SSOConnectionSummary{
			ID: r.ID, ClientID: r.ClientID, Name: r.Name, Issuer: r.Issuer, OIDCClientID: r.OidcClientID,
			Scopes: r.Scopes, TrustUnverifiedEmail: r.TrustUnverifiedEmail, IsActive: r.IsActive,
			HasSecret: r.HasSecret, Domains: nonNil(r.Domains),
			CreatedAt: services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
		})
	}
	return out, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
