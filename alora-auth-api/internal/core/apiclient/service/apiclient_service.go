// Package service administers API clients: applications' identities. An API
// client is given where its credential may be used (application scopes), the
// products it may get a token for, and its secrets — at most two live at a
// time, so it rotates without downtime. Only hashes are kept: a secret's value
// is shown once, when it is made.
package service

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alora/auth/internal/core/apiclient/models"
	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/apiclientproducts"
	"github.com/alora/auth/internal/database/services/apiclients"
	apiclientcustoms "github.com/alora/auth/internal/database/services/apiclients/customs"
	"github.com/alora/auth/internal/database/services/apiclientscopes"
	"github.com/alora/auth/internal/database/services/apiclientsecrets"
	apiclientsecretcustoms "github.com/alora/auth/internal/database/services/apiclientsecrets/customs"
	"github.com/alora/auth/internal/exceptions"
)

// SecretPrefix begins every API client secret, as "acs_" begins a product's: a
// secret found in a log or a repository says what it is.
const SecretPrefix = "acc_"

// shownPrefix is how much of a secret is kept in the clear to tell two apart:
// its prefix and 8 random characters, never enough to use.
const shownPrefix = len(SecretPrefix) + 8

// APIClientService administers API clients.
type APIClientService interface {
	// List lists the company's API clients.
	List(ctx context.Context, scope shared.Scope) ([]models.APIClient, error)
	// ListAll lists every company's API clients, for the Owner.
	ListAll(ctx context.Context, actor shared.Actor) ([]models.APIClient, error)
	// Get reads one API client with its secrets and the products it could be
	// given.
	Get(ctx context.Context, scope shared.Scope, id string) (models.Detail, error)
	// Create creates an API client holding nothing: no scopes, no products, no
	// secret.
	Create(ctx context.Context, scope shared.Scope, in models.Input) (models.APIClient, error)
	// Update renames, re-describes, or switches an API client on or off.
	Update(ctx context.Context, scope shared.Scope, id string, in models.Input) (models.APIClient, error)
	// Delete deletes an API client and everything it holds.
	Delete(ctx context.Context, scope shared.Scope, id string) error
	// SetScopes replaces where the API client's credential may be used.
	SetScopes(ctx context.Context, scope shared.Scope, id string, scopes []string) ([]string, error)
	// SetProducts replaces the products the API client may get a token for.
	SetProducts(ctx context.Context, scope shared.Scope, id string, productIDs []string) ([]models.Product, error)
	// CreateSecret makes the API client a new secret, shown this once.
	CreateSecret(ctx context.Context, scope shared.Scope, id string, lifetime *time.Duration) (models.NewSecret, error)
	// RevokeSecret revokes one of the API client's secrets.
	RevokeSecret(ctx context.Context, scope shared.Scope, id, secretID string) error
}

type apiClientService struct {
	db    *contexts.DbContext
	audit auditservice.AuditService
}

// NewAPIClientService builds the service.
func NewAPIClientService(db *contexts.DbContext, audit auditservice.AuditService) APIClientService {
	return &apiClientService{db: db, audit: audit}
}

var (
	errNameTaken = exceptions.NewAPIError(http.StatusConflict, "An API client with this name already exists", nil)
	errProducts  = exceptions.NewAPIError(http.StatusBadRequest,
		"Each product added must be one the company subscribes to, and one that accepts API clients", nil)
	errTwoSecrets = exceptions.NewAPIError(http.StatusConflict,
		"This API client already has two live secrets: revoke one first", nil)
)

// by attributes a write to whoever acts: a user of the company, or the Owner.
func by(scope shared.Scope) (userID, ownerID string) {
	if scope.ByOwner {
		return "", scope.Actor.UserID
	}
	return scope.Actor.UserID, ""
}

func (s *apiClientService) List(ctx context.Context, scope shared.Scope) ([]models.APIClient, error) {
	rows, err := apiclientcustoms.NewAPIClientDbCustoms(s.db).List(ctx, scope.ClientID)
	if err != nil {
		return nil, err
	}
	return clients(rows), nil
}

// ListAll is the Owner's alone. The route is the Owner console's; this check is
// the belt to its braces.
func (s *apiClientService) ListAll(ctx context.Context, actor shared.Actor) ([]models.APIClient, error) {
	if !actor.IsOwner {
		return nil, exceptions.ErrForbidden
	}
	rows, err := apiclientcustoms.NewAPIClientDbCustoms(s.db).ListAll(ctx)
	if err != nil {
		return nil, err
	}
	return clients(rows), nil
}

func (s *apiClientService) Get(ctx context.Context, scope shared.Scope, id string) (models.Detail, error) {
	a, err := s.summary(ctx, scope, id)
	if err != nil {
		return models.Detail{}, err
	}
	secrets, err := apiclientsecretcustoms.NewAPIClientSecretDbCustoms(s.db).List(ctx, id, scope.ClientID)
	if err != nil {
		return models.Detail{}, err
	}
	choices, err := apiclientcustoms.NewAPIClientDbCustoms(s.db).ProductChoices(ctx, scope.ClientID)
	if err != nil {
		return models.Detail{}, err
	}
	d := models.Detail{APIClient: a, Secrets: make([]models.Secret, 0, len(secrets)), Choices: make([]models.Product, 0, len(choices))}
	for _, x := range secrets {
		d.Secrets = append(d.Secrets, secret(x))
	}
	for _, c := range choices {
		d.Choices = append(d.Choices, models.Product{ID: c.ProductID, Key: c.ProductKey, Name: c.ProductName, Usable: true})
	}
	return d, nil
}

// summary reads one API client of the scope's company: another company's is
// not found.
func (s *apiClientService) summary(ctx context.Context, scope shared.Scope, id string) (models.APIClient, error) {
	r, err := apiclientcustoms.NewAPIClientDbCustoms(s.db).Get(ctx, id, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.APIClient{}, exceptions.ErrNotFound
	}
	if err != nil {
		return models.APIClient{}, err
	}
	return client(r), nil
}

func (s *apiClientService) Create(ctx context.Context, scope shared.Scope, in models.Input) (models.APIClient, error) {
	byUser, byOwner := by(scope)
	row, err := apiclients.NewAPIClientDbService(s.db).Create(ctx, scope.ClientID,
		strings.TrimSpace(in.Name), strings.TrimSpace(in.Description), byUser, byOwner)
	if err != nil {
		if exceptions.IsUniqueViolation(err) {
			return models.APIClient{}, errNameTaken
		}
		return models.APIClient{}, err
	}
	s.audit.RecordWith(scope, "api_client.created", map[string]any{"api_client_id": row.ID, "name": row.Name})
	return s.summary(ctx, scope, row.ID)
}

func (s *apiClientService) Update(ctx context.Context, scope shared.Scope, id string, in models.Input) (models.APIClient, error) {
	row, err := apiclients.NewAPIClientDbService(s.db).Update(ctx, id, scope.ClientID,
		strings.TrimSpace(in.Name), strings.TrimSpace(in.Description), in.IsActive)
	if err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return models.APIClient{}, exceptions.ErrNotFound
		}
		if exceptions.IsUniqueViolation(err) {
			return models.APIClient{}, errNameTaken
		}
		return models.APIClient{}, err
	}
	s.audit.RecordWith(scope, "api_client.updated", map[string]any{
		"api_client_id": id, "name": row.Name, "is_active": row.IsActive,
	})
	return s.summary(ctx, scope, id)
}

func (s *apiClientService) Delete(ctx context.Context, scope shared.Scope, id string) error {
	a, err := s.summary(ctx, scope, id) // what it was, for the trail
	if err != nil {
		return err
	}
	n, err := apiclients.NewAPIClientDbService(s.db).Delete(ctx, id, scope.ClientID)
	if err != nil {
		return err
	}
	if n == 0 {
		return exceptions.ErrNotFound
	}
	s.audit.RecordWith(scope, "api_client.deleted", map[string]any{"api_client_id": id, "name": a.Name})
	return nil
}

// SetScopes replaces the scopes wholesale; an edit scope brings its read scope.
// Only application scopes are known here: a person's scope is refused as
// unknown, and so it is by the database's catalogue key.
func (s *apiClientService) SetScopes(ctx context.Context, scope shared.Scope, id string, in []string) ([]string, error) {
	scopes, err := shared.NormalizeClientScopes(in)
	if err != nil {
		return nil, exceptions.NewAPIError(http.StatusBadRequest, err.Error(), nil)
	}
	n, err := apiclientscopes.NewAPIClientScopeDbService(s.db).Set(ctx, id, scope.ClientID, scopes)
	if err != nil {
		if exceptions.IsForeignKeyViolation(err) {
			return nil, exceptions.NewAPIError(http.StatusBadRequest, "Unknown scope", nil)
		}
		return nil, err
	}
	if n == apiclientscopes.NotFound {
		return nil, exceptions.ErrNotFound
	}
	s.audit.RecordWith(scope, "api_client.scopes_set", map[string]any{"api_client_id": id, "scopes": scopes})
	return scopes, nil
}

// SetProducts replaces the list wholesale. A product added must be a live
// subscription to a product that accepts API clients; one already on the list
// may stay, and earns no token until it is usable again.
func (s *apiClientService) SetProducts(ctx context.Context, scope shared.Scope, id string, productIDs []string) ([]models.Product, error) {
	n, err := apiclientproducts.NewAPIClientProductDbService(s.db).Set(ctx, id, scope.ClientID, productIDs)
	if err != nil {
		if exceptions.IsForeignKeyViolation(err) {
			return nil, errProducts
		}
		return nil, err
	}
	switch n {
	case apiclientproducts.NotFound:
		return nil, exceptions.ErrNotFound
	case apiclientproducts.NotAllowed:
		return nil, errProducts
	}
	a, err := s.summary(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(a.Products))
	for _, p := range a.Products {
		keys = append(keys, p.Key)
	}
	s.audit.RecordWith(scope, "api_client.products_set", map[string]any{"api_client_id": id, "products": keys})
	return a.Products, nil
}

// CreateSecret makes a secret and returns it with its value — the only time the
// value exists outside the application that will hold it. Only its hash and a
// short prefix are stored.
func (s *apiClientService) CreateSecret(ctx context.Context, scope shared.Scope, id string, lifetime *time.Duration) (models.NewSecret, error) {
	if _, err := s.summary(ctx, scope, id); err != nil {
		return models.NewSecret{}, err
	}
	raw, err := tokens.GenerateOpaque()
	if err != nil {
		return models.NewSecret{}, err
	}
	value := SecretPrefix + raw
	var expires *time.Time
	if lifetime != nil {
		t := time.Now().Add(*lifetime)
		expires = &t
	}
	byUser, byOwner := by(scope)
	row, err := apiclientsecrets.NewAPIClientSecretDbService(s.db).Create(ctx, id, scope.ClientID, apiclientsecrets.NewSecret{
		Hash: tokens.HashToken(value), Prefix: value[:shownPrefix], ExpiresAt: expires,
		ByUserID: byUser, ByOwnerID: byOwner,
	})
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.NewSecret{}, errTwoSecrets // the client exists: it already has two
	}
	if err != nil {
		return models.NewSecret{}, err
	}
	s.audit.RecordWith(scope, "api_client.secret_created", map[string]any{
		"api_client_id": id, "secret_id": row.ID, "prefix": row.Prefix, "expires_at": row.ExpiresAt,
	})
	return models.NewSecret{Secret: secret(row), ClientID: id, ClientSecret: value}, nil
}

func (s *apiClientService) RevokeSecret(ctx context.Context, scope shared.Scope, id, secretID string) error {
	prefix := ""
	if list, err := apiclientsecretcustoms.NewAPIClientSecretDbCustoms(s.db).List(ctx, id, scope.ClientID); err == nil {
		for _, x := range list {
			if x.ID == secretID {
				prefix = x.Prefix
			}
		}
	}
	n, err := apiclientsecrets.NewAPIClientSecretDbService(s.db).Revoke(ctx, secretID, id, scope.ClientID)
	if err != nil {
		return err
	}
	if n == 0 {
		return exceptions.ErrNotFound // unknown, another company's, or already revoked
	}
	s.audit.RecordWith(scope, "api_client.secret_revoked", map[string]any{
		"api_client_id": id, "secret_id": secretID, "prefix": prefix,
	})
	return nil
}

func clients(rows []dbmodels.APIClientSummary) []models.APIClient {
	out := make([]models.APIClient, 0, len(rows))
	for _, r := range rows {
		out = append(out, client(r))
	}
	return out
}

func client(r dbmodels.APIClientSummary) models.APIClient {
	a := models.APIClient{
		ID: r.ID, CompanyID: r.ClientID, CompanyName: r.CompanyName, Name: r.Name, IsActive: r.IsActive,
		Scopes: r.Scopes, Products: make([]models.Product, 0, len(r.Products)), LiveSecrets: r.LiveSecrets,
		LastUsedAt: r.LastUsedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	if r.Description != nil {
		a.Description = *r.Description
	}
	for _, p := range r.Products {
		a.Products = append(a.Products, models.Product{ID: p.ProductID, Key: p.ProductKey, Name: p.ProductName, Usable: p.Usable})
	}
	return a
}

func secret(x dbmodels.APIClientSecret) models.Secret {
	return models.Secret{
		ID: x.ID, Prefix: x.Prefix, ExpiresAt: x.ExpiresAt, RevokedAt: x.RevokedAt,
		LastUsedAt: x.LastUsedAt, CreatedAt: x.CreatedAt, IsLive: x.IsLive,
	}
}
