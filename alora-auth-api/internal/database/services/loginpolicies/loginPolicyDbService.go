// Package loginpolicies is the table service for tbl_login_policies: which
// sign-in methods a company allows, for whom. The list, the tenant-scoped read
// and the domain hint live in customs.
package loginpolicies

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// LoginPolicyDbService is the CRUD surface of tbl_login_policies.
type LoginPolicyDbService struct{ q *sqlc.Queries }

// NewLoginPolicyDbService binds the service to a context: the pool or a
// transaction.
func NewLoginPolicyDbService(c contexts.Querier) *LoginPolicyDbService {
	return &LoginPolicyDbService{q: c.Queries()}
}

// PolicyFields are a policy's settable columns. A nil SSOConnectionID means the
// policy offers no company SSO.
type PolicyFields struct {
	Name            string
	AllowPassword   bool
	AllowGoogle     bool
	SSOConnectionID *string
	Priority        int32
}

// Create inserts a policy. A name or priority already taken in the company is a
// unique violation; a policy allowing no method at all is a check violation; an
// SSO connection of another company is a foreign-key violation.
func (s *LoginPolicyDbService) Create(ctx context.Context, clientID string, f PolicyFields) (models.LoginPolicy, error) {
	row, err := s.q.CreateLoginPolicy(ctx, sqlc.CreateLoginPolicyParams{
		ClientID: clientID, Name: f.Name, AllowPassword: f.AllowPassword, AllowGoogle: f.AllowGoogle,
		SsoConnectionID: services.TextPtr(f.SSOConnectionID), Priority: f.Priority,
	})
	if err != nil {
		return models.LoginPolicy{}, err
	}
	return services.LoginPolicyFromRow(row), nil
}

// Update rewrites a policy within a company. A policy outside the company yields
// no rows.
func (s *LoginPolicyDbService) Update(ctx context.Context, policyID, clientID string, f PolicyFields) (models.LoginPolicy, error) {
	row, err := s.q.UpdateLoginPolicy(ctx, sqlc.UpdateLoginPolicyParams{
		PolicyID: policyID, ClientID: clientID, Name: f.Name,
		AllowPassword: f.AllowPassword, AllowGoogle: f.AllowGoogle,
		SsoConnectionID: services.TextPtr(f.SSOConnectionID), Priority: f.Priority,
	})
	if err != nil {
		return models.LoginPolicy{}, err
	}
	return services.LoginPolicyFromRow(row), nil
}

// Delete removes a policy that is not the company default and reports how many
// rows changed. A policy still assigned to a user or group is a foreign-key
// violation.
func (s *LoginPolicyDbService) Delete(ctx context.Context, policyID, clientID string) (int32, error) {
	return s.q.DeleteLoginPolicy(ctx, sqlc.DeleteLoginPolicyParams{PPolicyid: policyID, PClientid: clientID})
}

// SetDefault makes a policy the company default, in place of the old one, and
// reports 1, or 0 when no such policy is the company's.
func (s *LoginPolicyDbService) SetDefault(ctx context.Context, policyID, clientID string) (int32, error) {
	return s.q.SetDefaultLoginPolicy(ctx, sqlc.SetDefaultLoginPolicyParams{PPolicyid: policyID, PClientid: clientID})
}
