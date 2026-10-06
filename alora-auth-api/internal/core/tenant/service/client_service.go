// Package service owns a company's own record and its product subscriptions, as
// the company's Admins see them. What the Owner may change beyond this lives in
// the owner feature.
package service

import (
	"context"
	"errors"
	"strings"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/tenant/models"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/clients"
	"github.com/alora/auth/internal/exceptions"
)

// ClientService reads and renames the scope's company.
type ClientService interface {
	// Get returns the company's record.
	Get(ctx context.Context, scope shared.Scope) (models.Client, error)
	// Rename changes the company's display name.
	Rename(ctx context.Context, scope shared.Scope, name string) (models.Client, error)
}

type clientService struct {
	db    *contexts.DbContext
	audit auditservice.AuditService
}

// NewClientService builds the client service.
func NewClientService(db *contexts.DbContext, audit auditservice.AuditService) ClientService {
	return &clientService{db: db, audit: audit}
}

func (s *clientService) Get(ctx context.Context, scope shared.Scope) (models.Client, error) {
	c, err := clients.NewClientDbService(s.db).GetByID(ctx, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.Client{}, exceptions.ErrNotFound
	}
	if err != nil {
		return models.Client{}, err
	}
	return ToClient(c), nil
}

// Rename is a read-modify-write of the whole row that changes only the name.
// Standing, plan, seats and domain verification are written back exactly as
// read: an Admin must not be able to un-suspend their own company or verify a
// domain for it.
func (s *clientService) Rename(ctx context.Context, scope shared.Scope, name string) (models.Client, error) {
	db := clients.NewClientDbService(s.db)
	cur, err := db.GetByID(ctx, scope.ClientID)
	if err != nil {
		return models.Client{}, err
	}
	cur.Name = strings.TrimSpace(name)
	out, err := db.Update(ctx, cur)
	if err != nil {
		return models.Client{}, err
	}
	s.audit.Record(scope, "client.updated")
	return ToClient(out), nil
}

// ToClient renders a company row.
func ToClient(c dbmodels.Client) models.Client {
	return models.Client{
		ID: c.ID, Name: c.Name, Domain: c.Domain, DomainVerifiedAt: c.DomainVerifiedAt,
		SubscriptionStatus: string(c.SubscriptionStatus), MaxSeats: c.MaxSeats, IsActive: c.IsActive,
		IsPlatform: c.IsPlatform, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}
