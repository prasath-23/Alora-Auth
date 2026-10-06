// Package ssoconnections is the table service for tbl_sso_connections and the
// email domains registered on each. The secret enters and leaves only as
// ciphertext: the key that opens it is the API's, never the database's. The
// runtime read and the list live in customs.
package ssoconnections

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// DomainsNotTheirs is what SetDomains reports when a domain is another company's
// verified domain.
const DomainsNotTheirs int32 = -2

// SSOConnectionDbService is the CRUD surface of tbl_sso_connections.
type SSOConnectionDbService struct{ q *sqlc.Queries }

// NewSSOConnectionDbService binds the service to a context: the pool or a
// transaction.
func NewSSOConnectionDbService(c contexts.Querier) *SSOConnectionDbService {
	return &SSOConnectionDbService{q: c.Queries()}
}

// ConnectionFields are a connection's settable columns. A nil SecretCiphertext
// keeps the stored secret on Update, and stores none on Create.
type ConnectionFields struct {
	Name                 string
	Issuer               string
	OIDCClientID         string
	SecretCiphertext     []byte
	SecretKeyID          string
	Scopes               string
	TrustUnverifiedEmail bool
	IsActive             bool
}

// Create inserts a connection under a caller-chosen id: the id is the associated
// data the secret was sealed with, so it must exist before the row does. An
// issuer and client id already registered is a unique violation.
func (s *SSOConnectionDbService) Create(ctx context.Context, connectionID, clientID string, f ConnectionFields) (models.SSOConnection, error) {
	row, err := s.q.CreateSsoConnection(ctx, sqlc.CreateSsoConnectionParams{
		ConnectionID: connectionID, ClientID: clientID, Name: f.Name, Issuer: f.Issuer,
		OidcClientID: f.OIDCClientID, SecretCiphertext: f.SecretCiphertext,
		SecretKeyID: services.TextOrNull(f.SecretKeyID), Scopes: f.Scopes,
		TrustUnverifiedEmail: f.TrustUnverifiedEmail, IsActive: f.IsActive,
	})
	if err != nil {
		return models.SSOConnection{}, err
	}
	return fromRow(row), nil
}

// Update rewrites a connection within a company. A connection outside the
// company yields no rows.
func (s *SSOConnectionDbService) Update(ctx context.Context, connectionID, clientID string, f ConnectionFields) (models.SSOConnection, error) {
	row, err := s.q.UpdateSsoConnection(ctx, sqlc.UpdateSsoConnectionParams{
		ConnectionID: connectionID, ClientID: clientID, Name: f.Name, Issuer: f.Issuer,
		OidcClientID: f.OIDCClientID, SecretCiphertext: f.SecretCiphertext,
		SecretKeyID: services.TextOrNull(f.SecretKeyID), Scopes: f.Scopes,
		TrustUnverifiedEmail: f.TrustUnverifiedEmail, IsActive: f.IsActive,
	})
	if err != nil {
		return models.SSOConnection{}, err
	}
	return fromRow(row), nil
}

// SetDomains replaces the email domains registered on a connection and reports
// how many it now has, -1 when the connection is not the company's, or
// DomainsNotTheirs. A domain already registered on another connection is a
// unique violation.
func (s *SSOConnectionDbService) SetDomains(ctx context.Context, connectionID, clientID string, domains []string) (int32, error) {
	return s.q.SetSsoConnectionDomains(ctx, sqlc.SetSsoConnectionDomainsParams{
		ConnectionID: connectionID, ClientID: clientID, Domains: domains,
	})
}

func fromRow(r sqlc.TblSsoConnection) models.SSOConnection {
	return models.SSOConnection{
		ID: r.ID, ClientID: r.ClientID, Name: r.Name, Issuer: r.Issuer, OIDCClientID: r.OidcClientID,
		ClientSecretCiphertext: r.ClientSecretCiphertext, SecretKeyID: services.StringPtr(r.SecretKeyID),
		Scopes: r.Scopes, TrustUnverifiedEmail: r.TrustUnverifiedEmail, IsActive: r.IsActive,
		CreatedAt: services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
	}
}
