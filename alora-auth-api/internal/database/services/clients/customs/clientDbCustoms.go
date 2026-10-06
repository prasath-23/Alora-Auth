// Package customs holds the tbl_clients queries beyond CRUD: resolving a verified
// domain to its company, and the Owner's company list.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// ClientDbCustoms is the custom query surface of tbl_clients.
type ClientDbCustoms struct{ q *sqlc.Queries }

// NewClientDbCustoms binds the queries to a context: the pool or a transaction.
func NewClientDbCustoms(c contexts.Querier) *ClientDbCustoms { return &ClientDbCustoms{q: c.Queries()} }

// IDByVerifiedDomain resolves a host to the ACTIVE company whose VERIFIED domain
// it is. Anything else yields no rows.
func (s *ClientDbCustoms) IDByVerifiedDomain(ctx context.Context, domain string) (string, error) {
	return s.q.ClientIdByVerifiedDomain(ctx, domain)
}

// ListCompanies lists every company with its live member count.
func (s *ClientDbCustoms) ListCompanies(ctx context.Context) ([]models.CompanyListItem, error) {
	rows, err := s.q.ListCompanies(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]models.CompanyListItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.CompanyListItem{
			Client: models.Client{
				ID: r.ID, Name: r.Name, Domain: services.StringPtr(r.Domain),
				DomainVerifiedAt:   services.TimePtr(r.DomainVerifiedAt),
				SubscriptionStatus: models.SubscriptionStatus(r.SubscriptionStatus),
				MaxSeats:           services.Int32Ptr(r.MaxSeats), IsActive: r.IsActive, IsPlatform: r.IsPlatform,
				CreatedAt: services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
			},
			UserCount: r.UserCount,
		})
	}
	return out, nil
}
