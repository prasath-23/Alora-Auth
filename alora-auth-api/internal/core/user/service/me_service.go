package service

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/password"
	"github.com/alora/auth/internal/core/user/models"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/clients"
	groupcustoms "github.com/alora/auth/internal/database/services/groups/customs"
	permissioncustoms "github.com/alora/auth/internal/database/services/productpermissions/customs"
	"github.com/alora/auth/internal/database/services/sessions"
	"github.com/alora/auth/internal/database/services/users"
	userscopecustoms "github.com/alora/auth/internal/database/services/userscopes/customs"
	"github.com/alora/auth/internal/exceptions"
)

// MeService serves the caller's own account at App Central.
type MeService interface {
	// Me returns the caller's account, company and rights.
	Me(ctx context.Context, actor shared.Actor) (models.Me, error)
	// Apps returns the products the caller may launch.
	Apps(ctx context.Context, actor shared.Actor) ([]models.App, error)
	// ChangePassword replaces the caller's password after re-verifying the
	// current one.
	ChangePassword(ctx context.Context, actor shared.Actor, currentPassword, newPassword string) error
}

type meService struct {
	db     *contexts.DbContext
	audit  auditservice.AuditService
	issuer string
}

// NewMeService builds the self-service surface. issuer is what a launched
// product is told signed the user in.
func NewMeService(db *contexts.DbContext, audit auditservice.AuditService, issuer string) MeService {
	return &meService{db: db, audit: audit, issuer: issuer}
}

// Me is a rendering hint for App Central, not an authorization decision: each
// route re-checks its own scope server-side. Its scopes and products are what a
// login token minted at this moment would carry.
func (s *meService) Me(ctx context.Context, actor shared.Actor) (models.Me, error) {
	name, err := clients.NewClientDbService(s.db).NameByID(ctx, actor.ClientID)
	if err != nil {
		return models.Me{}, err
	}
	held, err := userscopecustoms.NewUserScopeDbCustoms(s.db).ListForUser(ctx, actor.ClientID, actor.UserID)
	if err != nil {
		return models.Me{}, err
	}
	sources, _ := scopeGrants(held)
	apps, err := permissioncustoms.NewProductPermissionDbCustoms(s.db).Apps(ctx, actor.UserID, actor.ClientID)
	if err != nil {
		return models.Me{}, err
	}
	products := make([]string, 0, len(apps))
	for _, a := range apps {
		products = append(products, a.ProductKey)
	}
	sort.Strings(products)
	manages, err := managedGroups(ctx, s.db, actor.UserID, actor.ClientID)
	if err != nil {
		return models.Me{}, err
	}
	return models.Me{
		UserID: actor.UserID, Email: actor.Email, CompanyID: actor.ClientID, CompanyName: name,
		IsAdmin: actor.InAdmins, IsOwner: actor.IsOwner, AuthenticatedAt: actor.AuthenticatedAt,
		Scopes: shared.TokenScopes(actor.Scopes, actor.IsOwner), ScopeSources: sources, Products: products,
		Manages: manages,
	}, nil
}

// managedGroups names the groups a user runs as a manager, by name.
func managedGroups(ctx context.Context, db *contexts.DbContext, userID, clientID string) ([]models.GroupRef, error) {
	rows, err := groupcustoms.NewGroupDbCustoms(db).ManagedBy(ctx, userID, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.GroupRef, 0, len(rows))
	for _, g := range rows {
		out = append(out, models.GroupRef{ID: g.ID, Name: g.Name})
	}
	return out, nil
}

// Apps lists the products the caller has access to right now, each with a
// launch URL: the product's initiate_login_uri (OpenID Connect Core §4), told
// which issuer to sign in with and where the user wants to land. The product's
// backend then starts an ordinary authorization request, which App Central
// answers at once because the user already has a session — and nothing a third
// party could inject: App Central never hands a product a code it did not ask
// for.
func (s *meService) Apps(ctx context.Context, actor shared.Actor) ([]models.App, error) {
	rows, err := permissioncustoms.NewProductPermissionDbCustoms(s.db).Apps(ctx, actor.UserID, actor.ClientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.App, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.App{
			ProductID: r.ProductID, Key: r.ProductKey, Name: r.ProductName, Description: r.ProductDescription,
			Roles: r.Roles, LaunchURL: s.launchURL(r),
		})
	}
	return out, nil
}

func (s *meService) launchURL(a dbmodels.UserApp) *string {
	if a.InitiateLoginURI == nil {
		return a.BaseURL
	}
	u, err := url.Parse(*a.InitiateLoginURI)
	if err != nil {
		return nil
	}
	q := u.Query()
	q.Set("iss", s.issuer)
	if a.BaseURL != nil {
		q.Set("target_link_uri", *a.BaseURL)
	}
	u.RawQuery = q.Encode()
	out := u.String()
	return &out
}

// ChangePassword requires the CURRENT password even though the caller already
// holds a valid token: that re-authentication is what stops a stolen access
// token from being escalated into permanent account takeover.
func (s *meService) ChangePassword(ctx context.Context, actor shared.Actor, currentPassword, newPassword string) error {
	user, err := users.NewUserDbService(s.db).GetByID(ctx, actor.UserID)
	if err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return exceptions.ErrUnauthorized
		}
		return err
	}
	// OAUTH_ONLY accounts have no password to change.
	if user.PasswordHash == nil {
		return exceptions.NewAPIError(http.StatusBadRequest, "This account signs in without a password", nil)
	}
	// 403, not 401: the caller's token was good. A 401 tells a client its token
	// is stale, and a client that then refreshes and retries would submit the
	// same guess twice.
	if !password.Verify(currentPassword, *user.PasswordHash) {
		return exceptions.NewAPIError(http.StatusForbidden, "Current password is incorrect", nil)
	}
	hash, err := password.Hash(newPassword)
	if err != nil {
		return exceptions.NewAPIError(http.StatusBadRequest, "Invalid request", nil)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	userDb := users.NewUserDbService(tx)
	if err := userDb.SetPassword(ctx, actor.UserID, actor.ClientID, hash); err != nil {
		return err
	}
	// Every session must end, this one included: if the password was changed
	// because of a suspected compromise, leaving the attacker's sessions alive —
	// at App Central or in any product — would defeat the point.
	if _, err := sessions.NewSessionDbService(tx).RevokeAllForUser(ctx, actor.UserID, dbmodels.RevokeReasonLogoutAll); err != nil {
		return err
	}
	if err := userDb.BumpPermissionsVersion(ctx, actor.UserID, actor.ClientID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.audit.Record(shared.TenantScope(actor), "password.changed")
	return nil
}
