// Package customs holds the tbl_users queries beyond CRUD: the view-backed reads
// (login candidates, token identity, company-scoped detail, login policy),
// lookups by address, and the keyset-paginated list.
package customs

import (
	"context"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// UserDbCustoms is the custom query surface of tbl_users.
type UserDbCustoms struct{ q *sqlc.Queries }

// NewUserDbCustoms binds the queries to a context: the pool or a transaction.
func NewUserDbCustoms(c contexts.Querier) *UserDbCustoms { return &UserDbCustoms{q: c.Queries()} }

// ListQuery selects one keyset page of a company's users. An empty Search or
// CursorID, and a nil CursorCreated, mean "no filter".
type ListQuery struct {
	ClientID      string
	Search        string
	CursorCreated *time.Time
	CursorID      string
	Take          int32
}

// ListPage returns one page, newest first.
func (s *UserDbCustoms) ListPage(ctx context.Context, q ListQuery) ([]models.UserListItem, error) {
	rows, err := s.q.ListUsers(ctx, sqlc.ListUsersParams{
		ClientID:      q.ClientID,
		Search:        services.TextOrNull(q.Search),
		CursorCreated: services.TimestamptzPtr(q.CursorCreated),
		CursorID:      services.TextOrNull(q.CursorID),
		Take:          q.Take,
	})
	if err != nil {
		return nil, err
	}
	out := make([]models.UserListItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.UserListItem{
			ID: r.ID, ClientID: r.ClientID, Email: r.Email, AccountType: models.AccountType(r.AccountType),
			IsActive: r.IsActive, PermissionsVersion: r.PermissionsVersion,
			LoginPolicyID: services.StringPtr(r.LoginPolicyID), IsAdmin: r.IsAdmin, IsOwner: r.IsOwner,
			CreatedAt: services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
		})
	}
	return out, nil
}

// CursorPosition resolves a user id to its keyset position within a company. A
// cursor from another company yields no rows.
func (s *UserDbCustoms) CursorPosition(ctx context.Context, userID, clientID string) (*time.Time, error) {
	createdAt, err := s.q.UserCursorPosition(ctx, sqlc.UserCursorPositionParams{PUserid: userID, PClientid: clientID})
	if err != nil {
		return nil, err
	}
	return services.TimePtr(createdAt), nil
}

// TenantScoped reads one live user inside a company.
func (s *UserDbCustoms) TenantScoped(ctx context.Context, userID, clientID string) (models.UserTenantScoped, error) {
	r, err := s.q.GetUserTenantScoped(ctx, sqlc.GetUserTenantScopedParams{PUserid: userID, PClientid: clientID})
	if err != nil {
		return models.UserTenantScoped{}, err
	}
	return tenantScoped(r), nil
}

// IdentityForToken reads a token subject with its liveness guard applied in SQL
// (active, not deleted, active company): zero rows means the account can no
// longer be issued anything.
func (s *UserDbCustoms) IdentityForToken(ctx context.Context, userID string) (models.UserIdentity, error) {
	r, err := s.q.GetUserIdentityForToken(ctx, userID)
	if err != nil {
		return models.UserIdentity{}, err
	}
	return identity(r), nil
}

// LoginCandidates lists the live password accounts that hold an address, across
// companies, at most ten and in a fixed order.
func (s *UserDbCustoms) LoginCandidates(ctx context.Context, email string) ([]models.UserCredential, error) {
	rows, err := s.q.ListLoginCandidates(ctx, email)
	if err != nil {
		return nil, err
	}
	out := make([]models.UserCredential, 0, len(rows))
	for _, r := range rows {
		out = append(out, models.UserCredential{
			ID: r.ID, ClientID: r.ClientID, Email: r.Email, PasswordHash: services.StringPtr(r.PasswordHash),
			AccountType: models.AccountType(r.AccountType), CreatedAt: services.TimePtr(r.CreatedAt),
		})
	}
	return out, nil
}

// IdentitiesByEmail lists every live account that holds an address, across
// companies and with or without a password: the accounts a first federated
// sign-in with a verified address may link to.
func (s *UserDbCustoms) IdentitiesByEmail(ctx context.Context, email string) ([]models.UserIdentity, error) {
	rows, err := s.q.ListUserIdentitiesByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	out := make([]models.UserIdentity, 0, len(rows))
	for _, r := range rows {
		out = append(out, identity(r))
	}
	return out, nil
}

// ForSSOLink reads the account a first SSO sign-in at one of the company's own
// connections may link to: a live, active member with this address.
func (s *UserDbCustoms) ForSSOLink(ctx context.Context, clientID, email string) (models.UserTenantScoped, error) {
	r, err := s.q.GetUserForSsoLink(ctx, sqlc.GetUserForSsoLinkParams{PClientid: clientID, PEmail: email})
	if err != nil {
		return models.UserTenantScoped{}, err
	}
	return tenantScoped(r), nil
}

// IDByEmail resolves a normalised address to a user id within a company.
func (s *UserDbCustoms) IDByEmail(ctx context.Context, clientID, email string) (string, error) {
	return s.q.UserIdByEmail(ctx, sqlc.UserIdByEmailParams{PClientid: clientID, PEmail: email})
}

// ActiveEmailExists reports whether a live member of the company owns the address.
func (s *UserDbCustoms) ActiveEmailExists(ctx context.Context, clientID, email string) (bool, error) {
	return s.q.ActiveEmailExists(ctx, sqlc.ActiveEmailExistsParams{PClientid: clientID, PEmail: email})
}

// LoginPolicy reads the login policy that applies to a live user: their own,
// else their highest-priority group's, else the company default.
func (s *UserDbCustoms) LoginPolicy(ctx context.Context, userID, clientID string) (models.UserLoginPolicy, error) {
	r, err := s.q.GetUserLoginPolicy(ctx, sqlc.GetUserLoginPolicyParams{PUserid: userID, PClientid: clientID})
	if err != nil {
		return models.UserLoginPolicy{}, err
	}
	return models.UserLoginPolicy{
		UserID: r.UserID, ClientID: r.ClientID, PolicyID: r.PolicyID, PolicyName: r.PolicyName,
		AllowPassword: r.AllowPassword, AllowGoogle: r.AllowGoogle,
		SSOConnectionID: services.StringPtr(r.SsoConnectionID), Source: r.Source,
	}, nil
}

func identity(r sqlc.VwUseridentity) models.UserIdentity {
	return models.UserIdentity{ID: r.ID, ClientID: r.ClientID, Email: r.Email, PermissionsVersion: r.PermissionsVersion}
}

func tenantScoped(r sqlc.VwUsertenantscoped) models.UserTenantScoped {
	return models.UserTenantScoped{
		ID: r.ID, ClientID: r.ClientID, Email: r.Email, AccountType: models.AccountType(r.AccountType),
		IsActive: r.IsActive, PermissionsVersion: r.PermissionsVersion,
		LoginPolicyID: services.StringPtr(r.LoginPolicyID), IsAdmin: r.IsAdmin, IsOwner: r.IsOwner,
		CreatedAt: services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
	}
}
