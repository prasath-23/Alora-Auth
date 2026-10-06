// Package users is the table service for tbl_users: its CRUD. Queries that read a
// view, look a user up by address or page through the table live in customs.
package users

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// UserDbService is the CRUD surface of tbl_users.
type UserDbService struct{ q *sqlc.Queries }

// NewUserDbService binds the service to a context: the pool or a transaction.
func NewUserDbService(c contexts.Querier) *UserDbService { return &UserDbService{q: c.Queries()} }

// Create inserts a user. A nil passwordHash stores NULL: an OAUTH_ONLY account has
// no password.
func (s *UserDbService) Create(ctx context.Context, clientID, email string, passwordHash *string, accountType models.AccountType) (models.User, error) {
	row, err := s.q.CreateUser(ctx, sqlc.CreateUserParams{
		ClientID: clientID, Email: email,
		PasswordHash: services.TextPtr(passwordHash), AccountType: sqlc.AccountType(accountType),
	})
	if err != nil {
		return models.User{}, err
	}
	return fromRow(row), nil
}

// GetByID reads one user, whatever its state.
func (s *UserDbService) GetByID(ctx context.Context, userID string) (models.User, error) {
	row, err := s.q.GetUserById(ctx, userID)
	if err != nil {
		return models.User{}, err
	}
	return fromRow(row), nil
}

// SetActive activates or deactivates a user within a company and reports how
// many rows changed: zero means there is no such user in that company.
func (s *UserDbService) SetActive(ctx context.Context, userID, clientID string, active bool) (int32, error) {
	return s.q.SetUserActive(ctx, sqlc.SetUserActiveParams{PUserid: userID, PClientid: clientID, PIsactive: active})
}

// SetPassword stores a new password hash. An OAUTH_ONLY account becomes HYBRID.
func (s *UserDbService) SetPassword(ctx context.Context, userID, clientID, passwordHash string) error {
	return s.q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{UserID: userID, ClientID: clientID, PasswordHash: passwordHash})
}

// BumpPermissionsVersion atomically increments permissions_version, which stales
// every product token already issued to the user.
func (s *UserDbService) BumpPermissionsVersion(ctx context.Context, userID, clientID string) error {
	return s.q.BumpPermissionsVersion(ctx, sqlc.BumpPermissionsVersionParams{PUserid: userID, PClientid: clientID})
}

// SetLoginPolicy assigns the user their own login policy, or with a nil policyID
// returns them to their groups' policy or the company default. It reports how
// many rows changed: zero means no such live user in that company. A policy of
// another company is a foreign-key violation.
func (s *UserDbService) SetLoginPolicy(ctx context.Context, userID, clientID string, policyID *string) (int32, error) {
	return s.q.SetUserLoginPolicy(ctx, sqlc.SetUserLoginPolicyParams{
		UserID: userID, ClientID: clientID, PolicyID: services.TextPtr(policyID),
	})
}

// CreatePlatformOwner makes a member of the platform company an Owner.
// Provisioning only: it fails under the application role by design, so only
// cmd/bootstrap, connected as the schema owner, can promote anyone.
func (s *UserDbService) CreatePlatformOwner(ctx context.Context, userID, clientID string) error {
	return s.q.CreatePlatformOwner(ctx, sqlc.CreatePlatformOwnerParams{PUserid: userID, PClientid: clientID})
}

func fromRow(r sqlc.TblUser) models.User {
	return models.User{
		ID: r.ID, ClientID: r.ClientID, Email: r.Email,
		PasswordHash: services.StringPtr(r.PasswordHash), AccountType: models.AccountType(r.AccountType),
		IsActive: r.IsActive, PermissionsVersion: r.PermissionsVersion,
		LoginPolicyID: services.StringPtr(r.LoginPolicyID),
		CreatedAt:     services.TimePtr(r.CreatedAt), UpdatedAt: services.TimePtr(r.UpdatedAt),
		DeletedAt: services.TimePtr(r.DeletedAt),
	}
}
