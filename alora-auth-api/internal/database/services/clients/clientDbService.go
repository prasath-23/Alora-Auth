// Package clients is the table service for tbl_clients: the companies. The
// domain lookup and the Owner's company list live in customs.
package clients

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// ClientDbService is the CRUD surface of tbl_clients.
type ClientDbService struct{ q *sqlc.Queries }

// NewClientDbService binds the service to a context: the pool or a transaction.
func NewClientDbService(c contexts.Querier) *ClientDbService { return &ClientDbService{q: c.Queries()} }

// NewClient is a company to create. An empty Domain stores NULL. A company is
// never created with a verified domain: verification is SetDomain.
type NewClient struct {
	Name               string
	Domain             string
	SubscriptionStatus models.SubscriptionStatus
	MaxSeats           *int32
	IsActive           bool
	IsPlatform         bool
}

// Create inserts a company. stp_CreateClient also creates its Admins group and
// its default login policy in the same statement, so no company ever exists
// without either.
func (s *ClientDbService) Create(ctx context.Context, n NewClient) (models.Client, error) {
	row, err := s.q.CreateClient(ctx, sqlc.CreateClientParams{
		Name:               n.Name,
		Domain:             services.TextOrNull(n.Domain),
		SubscriptionStatus: sqlc.SubscriptionStatus(n.SubscriptionStatus),
		MaxSeats:           services.Int4Ptr(n.MaxSeats),
		IsActive:           n.IsActive,
		IsPlatform:         n.IsPlatform,
	})
	if err != nil {
		return models.Client{}, err
	}
	return FromRow(row), nil
}

// GetByID reads one company.
func (s *ClientDbService) GetByID(ctx context.Context, clientID string) (models.Client, error) {
	row, err := s.q.GetClientById(ctx, clientID)
	if err != nil {
		return models.Client{}, err
	}
	return FromRow(row), nil
}

// Update writes every settable column of a company from c, keyed by c.ID. The
// domain itself is set with SetDomain.
func (s *ClientDbService) Update(ctx context.Context, c models.Client) (models.Client, error) {
	row, err := s.q.UpdateClient(ctx, sqlc.UpdateClientParams{
		ClientID:           c.ID,
		Name:               c.Name,
		DomainVerifiedAt:   services.TimestamptzPtr(c.DomainVerifiedAt),
		SubscriptionStatus: sqlc.SubscriptionStatus(c.SubscriptionStatus),
		MaxSeats:           services.Int4Ptr(c.MaxSeats),
		IsActive:           c.IsActive,
	})
	if err != nil {
		return models.Client{}, err
	}
	return FromRow(row), nil
}

// SetDomain sets or clears a company's email domain and whether it is verified.
// A nil domain clears it. A domain another company has verified is a unique
// violation.
func (s *ClientDbService) SetDomain(ctx context.Context, clientID string, domain *string, verified bool) (models.Client, error) {
	row, err := s.q.SetClientDomain(ctx, sqlc.SetClientDomainParams{
		ClientID: clientID, Domain: services.TextPtr(domain), Verified: verified,
	})
	if err != nil {
		return models.Client{}, err
	}
	return FromRow(row), nil
}

// NameByID reads a company's display name. An unknown company yields no rows.
func (s *ClientDbService) NameByID(ctx context.Context, clientID string) (string, error) {
	return s.q.ClientNameById(ctx, clientID)
}

// FromRow converts a tbl_clients row. Exported for customs.
func FromRow(r sqlc.TblClient) models.Client {
	return models.Client{
		ID: r.ID, Name: r.Name, Domain: services.StringPtr(r.Domain),
		DomainVerifiedAt:   services.TimePtr(r.DomainVerifiedAt),
		SubscriptionStatus: models.SubscriptionStatus(r.SubscriptionStatus),
		MaxSeats:           services.Int32Ptr(r.MaxSeats), IsActive: r.IsActive, IsPlatform: r.IsPlatform,
		CreatedAt: services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
	}
}
