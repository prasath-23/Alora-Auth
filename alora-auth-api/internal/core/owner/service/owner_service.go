// Package service is the Owner console's own ground: the companies, their
// subscriptions, and the products App Central signs people in to. Everything the
// Owner does inside one company — its users, groups, policies, SSO — is the
// other features' services, reached through a scope the Owner controller builds.
package service

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/owner/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/clientproducts"
	clientproductcustoms "github.com/alora/auth/internal/database/services/clientproducts/customs"
	"github.com/alora/auth/internal/database/services/clients"
	clientcustoms "github.com/alora/auth/internal/database/services/clients/customs"
	"github.com/alora/auth/internal/database/services/products"
	productcustoms "github.com/alora/auth/internal/database/services/products/customs"
	"github.com/alora/auth/internal/database/services/sessions"
	"github.com/alora/auth/internal/exceptions"
)

// OwnerService administers companies, subscriptions and products.
type OwnerService interface {
	// CompanyExists reports whether a company id names a company.
	CompanyExists(ctx context.Context, clientID string) (bool, error)
	// ListCompanies lists every company.
	ListCompanies(ctx context.Context) ([]models.Company, error)
	// GetCompany reads one company.
	GetCompany(ctx context.Context, scope shared.Scope) (models.Company, error)
	// CreateCompany creates a company with its Admins group and default policy.
	CreateCompany(ctx context.Context, actor shared.Actor, in models.CompanyInput) (models.Company, error)
	// UpdateCompany changes a company.
	UpdateCompany(ctx context.Context, scope shared.Scope, in models.CompanyChanges) (models.Company, error)
	// SetDomain sets or clears a company's domain and whether it is verified.
	SetDomain(ctx context.Context, scope shared.Scope, domain *string, verified bool) (models.Company, error)
	// ListSubscriptions lists a company's subscriptions.
	ListSubscriptions(ctx context.Context, scope shared.Scope) ([]models.Subscription, error)
	// SetSubscription creates or changes a company's subscription to a product.
	SetSubscription(ctx context.Context, scope shared.Scope, productID string, in models.SubscriptionInput) error

	// ListProducts lists every product's registration.
	ListProducts(ctx context.Context) ([]models.Product, error)
	// GetProduct reads one product's registration.
	GetProduct(ctx context.Context, productID string) (models.Product, error)
	// CreateProduct registers a product.
	CreateProduct(ctx context.Context, actor shared.Actor, in models.ProductInput) (models.Product, error)
	// UpdateProduct changes a product's registration.
	UpdateProduct(ctx context.Context, actor shared.Actor, productID string, in models.ProductInput) (models.Product, error)
	// SetRedirectURIs replaces a product's redirect URIs.
	SetRedirectURIs(ctx context.Context, actor shared.Actor, productID string, uris []string) error
	// SetRoles replaces a product's role catalogue.
	SetRoles(ctx context.Context, actor shared.Actor, productID string, roles []string) error
	// RotateSecret issues a product a new client secret, shown once.
	RotateSecret(ctx context.Context, actor shared.Actor, productID string) (models.Secret, error)
}

type ownerService struct {
	db     *contexts.DbContext
	audit  auditservice.AuditService
	isProd bool
}

// NewOwnerService builds the service.
func NewOwnerService(db *contexts.DbContext, audit auditservice.AuditService, isProd bool) OwnerService {
	return &ownerService{db: db, audit: audit, isProd: isProd}
}

// platform is the Owner acting on the platform itself — a product, or a new
// company — recorded in the platform company's own trail.
func platform(a shared.Actor) shared.Scope {
	return shared.Scope{ClientID: a.ClientID, Actor: a, ByOwner: true}
}

func (s *ownerService) CompanyExists(ctx context.Context, clientID string) (bool, error) {
	_, err := clients.NewClientDbService(s.db).GetByID(ctx, clientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func toCompany(c dbmodels.Client, users int64) models.Company {
	return models.Company{
		ID: c.ID, Name: c.Name, Domain: c.Domain, DomainVerifiedAt: c.DomainVerifiedAt,
		SubscriptionStatus: string(c.SubscriptionStatus), MaxSeats: c.MaxSeats, IsActive: c.IsActive,
		IsPlatform: c.IsPlatform, UserCount: users, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

func (s *ownerService) ListCompanies(ctx context.Context) ([]models.Company, error) {
	rows, err := clientcustoms.NewClientDbCustoms(s.db).ListCompanies(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]models.Company, 0, len(rows))
	for _, r := range rows {
		out = append(out, toCompany(r.Client, r.UserCount))
	}
	return out, nil
}

func (s *ownerService) GetCompany(ctx context.Context, scope shared.Scope) (models.Company, error) {
	rows, err := clientcustoms.NewClientDbCustoms(s.db).ListCompanies(ctx)
	if err != nil {
		return models.Company{}, err
	}
	for _, r := range rows {
		if r.ID == scope.ClientID {
			return toCompany(r.Client, r.UserCount), nil
		}
	}
	return models.Company{}, exceptions.ErrNotFound
}

// CreateCompany creates an ordinary company. There is exactly one platform
// company, provisioned out of band, and nothing here can make another.
func (s *ownerService) CreateCompany(ctx context.Context, actor shared.Actor, in models.CompanyInput) (models.Company, error) {
	c, err := clients.NewClientDbService(s.db).Create(ctx, clients.NewClient{
		Name: strings.TrimSpace(in.Name), Domain: strings.ToLower(in.Domain),
		SubscriptionStatus: dbmodels.SubscriptionStatus(in.SubscriptionStatus), MaxSeats: in.MaxSeats,
		IsActive: in.IsActive,
	})
	if err != nil {
		return models.Company{}, err
	}
	s.audit.Record(shared.Scope{ClientID: c.ID, Actor: actor, ByOwner: true}, "company.created")
	return toCompany(c, 0), nil
}

var errPlatform = exceptions.NewAPIError(http.StatusConflict, "The platform company cannot be suspended", nil)

// companyBarsSignIn reports whether a company in this state admits no logins.
// It is exactly the condition the session gate enforces (tbl_clients.is_active),
// named here so a transition into it can END the company's sessions rather than
// leave them merely gated and revivable.
func companyBarsSignIn(c dbmodels.Client) bool {
	return !c.IsActive
}

func (s *ownerService) UpdateCompany(ctx context.Context, scope shared.Scope, in models.CompanyChanges) (models.Company, error) {
	cur, err := clients.NewClientDbService(s.db).GetByID(ctx, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.Company{}, exceptions.ErrNotFound
	}
	if err != nil {
		return models.Company{}, err
	}
	// Whether the company already barred sign-in, read BEFORE applying the change,
	// so a genuine transition into suspension is told apart from an edit of an
	// already-suspended company.
	wasBarred := companyBarsSignIn(cur)

	if in.Name != nil {
		cur.Name = strings.TrimSpace(*in.Name)
	}
	if in.SubscriptionStatus != nil {
		cur.SubscriptionStatus = dbmodels.SubscriptionStatus(*in.SubscriptionStatus)
	}
	if in.ClearMaxSeats {
		cur.MaxSeats = nil
	} else if in.MaxSeats != nil {
		cur.MaxSeats = in.MaxSeats
	}
	if in.IsActive != nil {
		cur.IsActive = *in.IsActive
	}
	// Suspending the platform company would lock every Owner out, with nobody
	// left who could undo it.
	if cur.IsPlatform && (!cur.IsActive || cur.SubscriptionStatus == dbmodels.SubscriptionSuspended ||
		cur.SubscriptionStatus == dbmodels.SubscriptionCancelled) {
		return models.Company{}, errPlatform
	}

	// Suspending a company (is_active → false) ENDS its sessions rather than
	// merely gating them: otherwise reactivating the company revives every login
	// a compromise-driven suspension was meant to kill. The revoke runs in the
	// SAME transaction as the status change, so the two can never diverge.
	endSessions := !wasBarred && companyBarsSignIn(cur)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return models.Company{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	out, err := clients.NewClientDbService(tx).Update(ctx, cur)
	if err != nil {
		return models.Company{}, err
	}
	if endSessions {
		if _, err := sessions.NewSessionDbService(tx).RevokeAllForClient(ctx, scope.ClientID, dbmodels.RevokeReasonSuspended); err != nil {
			return models.Company{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return models.Company{}, err
	}
	s.audit.Record(scope, "company.updated")
	return s.GetCompany(ctx, shared.Scope{ClientID: out.ID})
}

func (s *ownerService) SetDomain(ctx context.Context, scope shared.Scope, domain *string, verified bool) (models.Company, error) {
	if domain != nil {
		d := strings.ToLower(strings.TrimSpace(*domain))
		domain = &d
	}
	if _, err := clients.NewClientDbService(s.db).SetDomain(ctx, scope.ClientID, domain, verified); err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return models.Company{}, exceptions.ErrNotFound
		}
		if exceptions.IsUniqueViolation(err) {
			return models.Company{}, exceptions.NewAPIError(http.StatusConflict, "Another company has verified this domain", nil)
		}
		return models.Company{}, err
	}
	s.audit.Record(scope, "company.domain_set")
	return s.GetCompany(ctx, scope)
}

func (s *ownerService) ListSubscriptions(ctx context.Context, scope shared.Scope) ([]models.Subscription, error) {
	rows, err := clientproductcustoms.NewClientProductDbCustoms(s.db).ListForClient(ctx, scope.ClientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.Subscription, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.Subscription{
			ID: r.ID, ProductID: r.ProductID, ProductKey: r.ProductKey, ProductName: r.ProductName,
			IsActive: r.IsActive, SeatLimit: r.SeatLimit, StartsAt: r.StartsAt, EndsAt: r.EndsAt,
		})
	}
	return out, nil
}

// SetSubscription switches a subscription on or off, never deleting it. Turning
// it off ends access at once for App Central and at every product login's next
// refresh, where the lost access revokes the login.
func (s *ownerService) SetSubscription(ctx context.Context, scope shared.Scope, productID string, in models.SubscriptionInput) error {
	if _, err := clientproducts.NewClientProductDbService(s.db).Upsert(ctx, scope.ClientID, productID, in.IsActive, in.SeatLimit, in.EndsAt); err != nil {
		if exceptions.IsForeignKeyViolation(err) {
			return exceptions.ErrNotFound
		}
		return err
	}
	s.audit.Record(scope, "subscription.set")
	return nil
}

func (s *ownerService) ListProducts(ctx context.Context) ([]models.Product, error) {
	rows, err := productcustoms.NewProductDbCustoms(s.db).ListClients(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]models.Product, 0, len(rows))
	for _, r := range rows {
		p, err := s.withRegistration(ctx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *ownerService) GetProduct(ctx context.Context, productID string) (models.Product, error) {
	r, err := productcustoms.NewProductDbCustoms(s.db).Client(ctx, productID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.Product{}, exceptions.ErrNotFound
	}
	if err != nil {
		return models.Product{}, err
	}
	return s.withRegistration(ctx, r)
}

func (s *ownerService) withRegistration(ctx context.Context, r dbmodels.ProductClient) (models.Product, error) {
	customs := productcustoms.NewProductDbCustoms(s.db)
	uris, err := customs.RedirectURIs(ctx, r.ID)
	if err != nil {
		return models.Product{}, err
	}
	roles, err := customs.Roles(ctx, r.ID)
	if err != nil {
		return models.Product{}, err
	}
	p := models.Product{
		ID: r.ID, Key: r.Key, Name: r.Name, Description: r.Description, BaseURL: r.BaseURL,
		InitiateLoginURI: r.InitiateLoginURI, IsActive: r.IsActive, AcceptsAPIClients: r.AcceptsAPIClients,
		HasSecret: r.HasSecret, SecretRotatedAt: r.SecretRotatedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		RedirectURIs: make([]string, 0, len(uris)), Roles: make([]string, 0, len(roles)),
	}
	for _, u := range uris {
		p.RedirectURIs = append(p.RedirectURIs, u.RedirectURI)
	}
	for _, ro := range roles {
		p.Roles = append(p.Roles, ro.RoleName)
	}
	return p, nil
}

var (
	productKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{1,39}$`)
	roleName   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 _-]{0,63}$`)
)

// checkURL accepts an absolute http(s) URL with no fragment — https only in
// production, where a code or a launch travels to it.
func (s *ownerService) checkURL(field, raw string) error {
	if raw == "" {
		return nil
	}
	if u, ok := shared.AbsoluteURL(raw); !ok || (s.isProd && u.Scheme != "https") {
		return exceptions.NewAPIError(http.StatusBadRequest, field+" must be an absolute https URL with no fragment", nil)
	}
	return nil
}

func (s *ownerService) productFields(in models.ProductInput) (products.ProductFields, error) {
	for field, v := range map[string]string{"base_url": in.BaseURL, "initiate_login_uri": in.InitiateLoginURI} {
		if err := s.checkURL(field, v); err != nil {
			return products.ProductFields{}, err
		}
	}
	return products.ProductFields{
		Name: strings.TrimSpace(in.Name), Description: in.Description, BaseURL: in.BaseURL,
		InitiateLoginURI: in.InitiateLoginURI, IsActive: in.IsActive, AcceptsAPIClients: in.AcceptsAPIClients,
	}, nil
}

func (s *ownerService) CreateProduct(ctx context.Context, actor shared.Actor, in models.ProductInput) (models.Product, error) {
	if !productKey.MatchString(in.Key) {
		return models.Product{}, exceptions.NewAPIError(http.StatusBadRequest,
			"The key must be 2-40 letters, digits, '-' or '_', starting with a letter or digit", nil)
	}
	f, err := s.productFields(in)
	if err != nil {
		return models.Product{}, err
	}
	p, err := products.NewProductDbService(s.db).Create(ctx, in.Key, f)
	if err != nil {
		if exceptions.IsUniqueViolation(err) {
			return models.Product{}, exceptions.NewAPIError(http.StatusConflict, "A product with this key already exists", nil)
		}
		return models.Product{}, err
	}
	s.audit.Record(platform(actor), "product.created")
	return s.GetProduct(ctx, p.ID)
}

func (s *ownerService) UpdateProduct(ctx context.Context, actor shared.Actor, productID string, in models.ProductInput) (models.Product, error) {
	f, err := s.productFields(in)
	if err != nil {
		return models.Product{}, err
	}
	if _, err := products.NewProductDbService(s.db).Update(ctx, productID, f); err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return models.Product{}, exceptions.ErrNotFound
		}
		return models.Product{}, err
	}
	details := map[string]any{"product_id": productID}
	if in.AcceptsAPIClients != nil {
		details["accepts_api_clients"] = *in.AcceptsAPIClients
	}
	s.audit.RecordWith(platform(actor), "product.updated", details)
	return s.GetProduct(ctx, productID)
}

func (s *ownerService) exists(ctx context.Context, productID string) error {
	if _, err := products.NewProductDbService(s.db).GetByID(ctx, productID, false); err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return exceptions.ErrNotFound
		}
		return err
	}
	return nil
}

// SetRedirectURIs replaces the list wholesale. Codes are delivered only to one of
// these, compared byte for byte, so each is stored exactly as given.
func (s *ownerService) SetRedirectURIs(ctx context.Context, actor shared.Actor, productID string, uris []string) error {
	if err := s.exists(ctx, productID); err != nil {
		return err
	}
	for _, u := range uris {
		if u == "" {
			return exceptions.NewAPIError(http.StatusBadRequest, "A redirect URI cannot be empty", nil)
		}
		if err := s.checkURL("Each redirect URI", u); err != nil {
			return err
		}
	}
	if _, err := products.NewProductDbService(s.db).SetRedirectURIs(ctx, productID, uris); err != nil {
		return err
	}
	s.audit.Record(platform(actor), "product.redirect_uris_set")
	return nil
}

// SetRoles replaces the catalogue. A role still granted — directly or through a
// group — cannot be removed until its grants are.
func (s *ownerService) SetRoles(ctx context.Context, actor shared.Actor, productID string, roles []string) error {
	if err := s.exists(ctx, productID); err != nil {
		return err
	}
	for _, r := range roles {
		if !roleName.MatchString(r) {
			return exceptions.NewAPIError(http.StatusBadRequest,
				"A role is 1-64 letters, digits, spaces, '-' or '_', starting with a letter: "+r, nil)
		}
	}
	if _, err := products.NewProductDbService(s.db).SetRoles(ctx, productID, roles); err != nil {
		if exceptions.IsForeignKeyViolation(err) {
			return exceptions.NewAPIError(http.StatusConflict, "A role being removed is still granted", nil)
		}
		return err
	}
	s.audit.Record(platform(actor), "product.roles_set")
	return nil
}

// RotateSecret issues a new client secret. Only its hash is kept; the old one
// stops working at once, so a product rotates by deploying the new secret
// immediately after.
func (s *ownerService) RotateSecret(ctx context.Context, actor shared.Actor, productID string) (models.Secret, error) {
	raw, err := tokens.GenerateOpaque()
	if err != nil {
		return models.Secret{}, err
	}
	secret := "acs_" + raw
	n, err := products.NewProductDbService(s.db).SetClientSecret(ctx, productID, tokens.HashToken(secret))
	if err != nil {
		return models.Secret{}, err
	}
	if n == 0 {
		return models.Secret{}, exceptions.ErrNotFound
	}
	s.audit.Record(platform(actor), "product.secret_rotated")
	return models.Secret{ClientID: productID, ClientSecret: secret, RotatedAt: time.Now()}, nil
}
