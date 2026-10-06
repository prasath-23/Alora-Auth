// Package linkedidentities is the table service for tbl_linked_identities:
// external identities bound to local accounts. The owner lookups live in
// customs.
package linkedidentities

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// LinkedIdentityDbService is the CRUD surface of tbl_linked_identities.
type LinkedIdentityDbService struct{ q *sqlc.Queries }

// NewLinkedIdentityDbService binds the service to a context: the pool or a
// transaction.
func NewLinkedIdentityDbService(c contexts.Querier) *LinkedIdentityDbService {
	return &LinkedIdentityDbService{q: c.Queries()}
}

// NewLink is an external identity to bind. ConnectionID is set for an OIDC link
// and empty for a Google one.
type NewLink struct {
	UserID        string
	ClientID      string
	Provider      models.IdpProvider
	ConnectionID  string
	ProviderID    string // the provider's stable subject
	EmailVerified bool
	EmailAtLink   string
}

// Create binds a provider's stable subject to a local account. A subject already
// bound in that company, or an account already bound to that provider, is a
// unique violation.
func (s *LinkedIdentityDbService) Create(ctx context.Context, n NewLink) (models.LinkedIdentity, error) {
	row, err := s.q.CreateLinkedIdentity(ctx, sqlc.CreateLinkedIdentityParams{
		UserID: n.UserID, ClientID: n.ClientID, Provider: sqlc.IdpProvider(n.Provider),
		ConnectionID: services.TextOrNull(n.ConnectionID), ProviderID: n.ProviderID,
		EmailVerified: n.EmailVerified, EmailAtLink: services.TextOrNull(n.EmailAtLink),
	})
	if err != nil {
		return models.LinkedIdentity{}, err
	}
	return models.LinkedIdentity{
		ID: row.ID, UserID: row.UserID, ClientID: row.ClientID, Provider: models.IdpProvider(row.Provider),
		ConnectionID: services.StringPtr(row.ConnectionID), ProviderID: row.ProviderID,
		EmailVerified: row.EmailVerified, EmailAtLink: services.StringPtr(row.EmailAtLink),
		CreatedAt: services.TimePtr(row.CreatedAt),
	}, nil
}

// Delete unbinds a user's identity at a provider (and, for OIDC, at one
// connection) and reports how many rows changed.
func (s *LinkedIdentityDbService) Delete(ctx context.Context, userID, clientID string, provider models.IdpProvider, connectionID string) (int32, error) {
	return s.q.DeleteLinkedIdentity(ctx, sqlc.DeleteLinkedIdentityParams{
		UserID: userID, ClientID: clientID, Provider: sqlc.IdpProvider(provider),
		ConnectionID: services.TextOrNull(connectionID),
	})
}
