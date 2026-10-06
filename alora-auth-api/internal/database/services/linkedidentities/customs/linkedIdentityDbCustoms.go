// Package customs holds the tbl_linked_identities queries beyond CRUD: finding
// the accounts a provider's subject is linked to.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// LinkedIdentityDbCustoms is the custom query surface of tbl_linked_identities.
type LinkedIdentityDbCustoms struct{ q *sqlc.Queries }

// NewLinkedIdentityDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewLinkedIdentityDbCustoms(c contexts.Querier) *LinkedIdentityDbCustoms {
	return &LinkedIdentityDbCustoms{q: c.Queries()}
}

// GoogleOwners lists every live account a Google subject is linked to, at most
// one per company.
func (s *LinkedIdentityDbCustoms) GoogleOwners(ctx context.Context, subject string) ([]models.LinkedIdentityOwner, error) {
	rows, err := s.q.ListGoogleLinks(ctx, subject)
	if err != nil {
		return nil, err
	}
	out := make([]models.LinkedIdentityOwner, 0, len(rows))
	for _, r := range rows {
		out = append(out, owner(r))
	}
	return out, nil
}

// ByConnection finds the live account an SSO subject is linked to at one
// connection.
func (s *LinkedIdentityDbCustoms) ByConnection(ctx context.Context, connectionID, subject string) (models.LinkedIdentityOwner, error) {
	r, err := s.q.GetLinkedIdentityByConnection(ctx, sqlc.GetLinkedIdentityByConnectionParams{
		PConnectionid: connectionID, PSubject: subject,
	})
	if err != nil {
		return models.LinkedIdentityOwner{}, err
	}
	return owner(r), nil
}

func owner(r sqlc.VwLinkedidentityowner) models.LinkedIdentityOwner {
	return models.LinkedIdentityOwner{
		Provider: models.IdpProvider(r.Provider), ConnectionID: services.StringPtr(r.ConnectionID),
		ProviderID: r.ProviderID, UserID: r.UserID, ClientID: r.ClientID, Email: r.Email,
		AccountType: models.AccountType(r.AccountType), IsActive: r.IsActive,
	}
}
