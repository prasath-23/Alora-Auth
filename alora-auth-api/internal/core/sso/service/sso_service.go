// Package service owns a company's SSO connections: the OIDC identity providers
// its people may sign in with, and the email domains each one signs in.
// Registering them is the Owner's; signing in through them is the login
// feature's.
//
// A connection's client secret is sealed (AES-256-GCM, bound to the
// connection's own id) the moment it arrives, and only the ciphertext is
// stored. It is never returned by any API.
package service

import (
	"context"
	"errors"
	"net/http"
	"strings"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/secretbox"
	"github.com/alora/auth/internal/core/sso/models"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/ssoconnections"
	ssocustoms "github.com/alora/auth/internal/database/services/ssoconnections/customs"
	"github.com/alora/auth/internal/exceptions"
	"github.com/alora/auth/internal/infrastructure"
	"github.com/google/uuid"
)

// SSOService administers the scope's company's SSO connections.
type SSOService interface {
	// List returns the company's connections, without secrets.
	List(ctx context.Context, scope shared.Scope) ([]models.Connection, error)
	// Create registers a connection.
	Create(ctx context.Context, scope shared.Scope, in models.ConnectionInput) (models.Connection, error)
	// Update rewrites a connection.
	Update(ctx context.Context, scope shared.Scope, connectionID string, in models.ConnectionInput) (models.Connection, error)
	// SetDomains replaces the email domains a connection signs in.
	SetDomains(ctx context.Context, scope shared.Scope, connectionID string, domains []string) error
	// Test fetches the provider's discovery document.
	Test(ctx context.Context, scope shared.Scope, connectionID string) (models.TestResult, error)
}

type ssoService struct {
	db     *contexts.DbContext
	audit  auditservice.AuditService
	box    *secretbox.Box
	oidc   *infrastructure.OIDC
	isProd bool
}

// NewSSOService builds the service.
func NewSSOService(db *contexts.DbContext, audit auditservice.AuditService, box *secretbox.Box, oidc *infrastructure.OIDC, isProd bool) SSOService {
	return &ssoService{db: db, audit: audit, box: box, oidc: oidc, isProd: isProd}
}

var (
	errNoKey       = exceptions.NewAPIError(http.StatusServiceUnavailable, "SSO secrets cannot be stored: SSO_SECRET_KEY is not configured", nil)
	errIssuer      = exceptions.NewAPIError(http.StatusBadRequest, "The issuer must be an absolute https URL", nil)
	errTaken       = exceptions.NewAPIError(http.StatusConflict, "A connection with this name, or this issuer and client id, already exists", nil)
	errDomainTaken = exceptions.NewAPIError(http.StatusConflict, "A domain is already registered on another connection", nil)
	errDomainOwned = exceptions.NewAPIError(http.StatusConflict, "A domain is another company's verified domain", nil)
)

func (s *ssoService) List(ctx context.Context, scope shared.Scope) ([]models.Connection, error) {
	rows, err := ssocustoms.NewSSOConnectionDbCustoms(s.db).List(ctx, scope.ClientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.Connection, 0, len(rows))
	for _, r := range rows {
		out = append(out, toConnection(r))
	}
	return out, nil
}

// checkIssuer accepts an absolute URL with no query or fragment — https only in
// production, because the provider's keys and tokens travel over it.
func (s *ssoService) checkIssuer(raw string) error {
	u, ok := shared.AbsoluteURL(raw)
	if !ok || strings.Contains(raw, "?") || (s.isProd && u.Scheme != "https") {
		return errIssuer
	}
	return nil
}

func (s *ssoService) fields(in models.ConnectionInput, connectionID string) (ssoconnections.ConnectionFields, error) {
	f := ssoconnections.ConnectionFields{
		Name: strings.TrimSpace(in.Name), Issuer: in.Issuer, OIDCClientID: in.OIDCClientID,
		Scopes: strings.Join(strings.Fields(in.Scopes), " "), TrustUnverifiedEmail: in.TrustUnverifiedEmail,
		IsActive: in.IsActive,
	}
	if f.Scopes == "" {
		f.Scopes = "openid email profile"
	}
	if in.ClientSecret != nil {
		if !s.box.Enabled() {
			return f, errNoKey
		}
		// Bound to the connection's own id, so the ciphertext opens only on its
		// own row.
		sealed, err := s.box.Seal([]byte(*in.ClientSecret), []byte(connectionID))
		if err != nil {
			return f, err
		}
		f.SecretCiphertext, f.SecretKeyID = sealed, s.box.KeyID()
	}
	return f, nil
}

func (s *ssoService) Create(ctx context.Context, scope shared.Scope, in models.ConnectionInput) (models.Connection, error) {
	if err := s.checkIssuer(in.Issuer); err != nil {
		return models.Connection{}, err
	}
	id := uuid.NewString()
	f, err := s.fields(in, id)
	if err != nil {
		return models.Connection{}, err
	}
	if _, err := ssoconnections.NewSSOConnectionDbService(s.db).Create(ctx, id, scope.ClientID, f); err != nil {
		if exceptions.IsUniqueViolation(err) {
			return models.Connection{}, errTaken
		}
		return models.Connection{}, err
	}
	s.audit.Record(scope, "sso_connection.created")
	return s.get(ctx, scope, id)
}

func (s *ssoService) Update(ctx context.Context, scope shared.Scope, connectionID string, in models.ConnectionInput) (models.Connection, error) {
	if err := s.checkIssuer(in.Issuer); err != nil {
		return models.Connection{}, err
	}
	f, err := s.fields(in, connectionID)
	if err != nil {
		return models.Connection{}, err
	}
	if _, err := ssoconnections.NewSSOConnectionDbService(s.db).Update(ctx, connectionID, scope.ClientID, f); err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return models.Connection{}, exceptions.ErrNotFound
		}
		if exceptions.IsUniqueViolation(err) {
			return models.Connection{}, errTaken
		}
		return models.Connection{}, err
	}
	s.audit.Record(scope, "sso_connection.updated")
	return s.get(ctx, scope, connectionID)
}

func (s *ssoService) SetDomains(ctx context.Context, scope shared.Scope, connectionID string, domains []string) error {
	clean := make([]string, 0, len(domains))
	for _, d := range domains {
		clean = append(clean, strings.ToLower(strings.TrimSpace(d)))
	}
	n, err := ssoconnections.NewSSOConnectionDbService(s.db).SetDomains(ctx, connectionID, scope.ClientID, clean)
	if exceptions.IsUniqueViolation(err) {
		return errDomainTaken
	}
	if err != nil {
		return err
	}
	switch n {
	case -1:
		return exceptions.ErrNotFound
	case ssoconnections.DomainsNotTheirs:
		return errDomainOwned
	}
	s.audit.Record(scope, "sso_connection.domains_set")
	return nil
}

// Test fetches the provider's discovery document through the same guarded
// client the sign-in uses, so what passes here is what sign-in will reach.
func (s *ssoService) Test(ctx context.Context, scope shared.Scope, connectionID string) (models.TestResult, error) {
	c, err := s.get(ctx, scope, connectionID)
	if err != nil {
		return models.TestResult{}, err
	}
	p, err := s.oidc.Discover(ctx, c.Issuer)
	if err != nil {
		return models.TestResult{}, exceptions.NewAPIError(http.StatusBadGateway, "The provider could not be used", err)
	}
	return models.TestResult{
		Issuer: p.Issuer, AuthorizationEndpoint: p.AuthorizationEndpoint, TokenEndpoint: p.TokenEndpoint, JWKSURI: p.JWKSURI,
	}, nil
}

func (s *ssoService) get(ctx context.Context, scope shared.Scope, connectionID string) (models.Connection, error) {
	rows, err := ssocustoms.NewSSOConnectionDbCustoms(s.db).List(ctx, scope.ClientID)
	if err != nil {
		return models.Connection{}, err
	}
	for _, r := range rows {
		if r.ID == connectionID {
			return toConnection(r), nil
		}
	}
	return models.Connection{}, exceptions.ErrNotFound
}

func toConnection(r dbmodels.SSOConnectionSummary) models.Connection {
	return models.Connection{
		ID: r.ID, Name: r.Name, Issuer: r.Issuer, OIDCClientID: r.OIDCClientID, Scopes: r.Scopes,
		TrustUnverifiedEmail: r.TrustUnverifiedEmail, IsActive: r.IsActive, HasSecret: r.HasSecret,
		Domains: r.Domains, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}
