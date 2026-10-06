// Package service owns login policies: which sign-in methods a company allows,
// for whom, and the one rule every sign-in path and every refresh applies —
// "does this user's policy allow the method they signed in with?".
//
// A user's policy is their own assignment, else the highest-priority policy
// among their groups, else the company default (vw_UserLoginPolicy). Policies
// are the Owner's to define and assign; the enforcement is here so that no
// login path can forget it.
package service

import (
	"context"
	"errors"
	"net/http"
	"strings"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/policy/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/groups"
	"github.com/alora/auth/internal/database/services/loginpolicies"
	policycustoms "github.com/alora/auth/internal/database/services/loginpolicies/customs"
	"github.com/alora/auth/internal/database/services/users"
	usercustoms "github.com/alora/auth/internal/database/services/users/customs"
	"github.com/alora/auth/internal/exceptions"
)

// PolicyService resolves, enforces and administers login policies.
type PolicyService interface {
	// Resolve returns the policy that applies to a live user.
	Resolve(ctx context.Context, userID, clientID string) (models.Effective, error)
	// Allows reports whether the user's policy permits signing in with method —
	// for OIDC, at that connection. A user with no policy (deleted) is allowed
	// nothing.
	Allows(ctx context.Context, userID, clientID string, method dbmodels.IdpProvider, connectionID string) (bool, error)
	// Hint is what the login page may offer for an email domain.
	Hint(ctx context.Context, domain string) (models.Hint, bool, error)

	// List returns the scope's company's policies, highest priority first.
	List(ctx context.Context, scope shared.Scope) ([]models.Policy, error)
	// Create adds a policy.
	Create(ctx context.Context, scope shared.Scope, in models.PolicyInput) (models.Policy, error)
	// Update rewrites a policy.
	Update(ctx context.Context, scope shared.Scope, policyID string, in models.PolicyInput) (models.Policy, error)
	// Delete removes a policy that is neither the default nor assigned.
	Delete(ctx context.Context, scope shared.Scope, policyID string) error
	// SetDefault makes a policy the company default.
	SetDefault(ctx context.Context, scope shared.Scope, policyID string) error
	// AssignUser sets (or with nil clears) a user's own policy.
	AssignUser(ctx context.Context, scope shared.Scope, userID string, policyID *string) error
	// AssignGroup sets (or with nil clears) the policy a group's members sign in under.
	AssignGroup(ctx context.Context, scope shared.Scope, groupID string, policyID *string) error
}

type policyService struct {
	db    *contexts.DbContext
	audit auditservice.AuditService
}

// NewPolicyService builds the policy service.
func NewPolicyService(db *contexts.DbContext, audit auditservice.AuditService) PolicyService {
	return &policyService{db: db, audit: audit}
}

func (s *policyService) Resolve(ctx context.Context, userID, clientID string) (models.Effective, error) {
	p, err := usercustoms.NewUserDbCustoms(s.db).LoginPolicy(ctx, userID, clientID)
	if err != nil {
		return models.Effective{}, err
	}
	return models.Effective{
		PolicyID: p.PolicyID, PolicyName: p.PolicyName, AllowPassword: p.AllowPassword,
		AllowGoogle: p.AllowGoogle, SSOConnectionID: p.SSOConnectionID, Source: p.Source,
	}, nil
}

func (s *policyService) Allows(ctx context.Context, userID, clientID string, method dbmodels.IdpProvider, connectionID string) (bool, error) {
	p, err := s.Resolve(ctx, userID, clientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return Permits(p, method, connectionID), nil
}

// Permits is the rule itself: a method is allowed when the policy switches it
// on, and company SSO only at the connection the policy names.
func Permits(p models.Effective, method dbmodels.IdpProvider, connectionID string) bool {
	switch method {
	case dbmodels.IdpEmail:
		return p.AllowPassword
	case dbmodels.IdpGoogle:
		return p.AllowGoogle
	case dbmodels.IdpOIDC:
		return p.SSOConnectionID != nil && connectionID != "" && *p.SSOConnectionID == connectionID
	default:
		return false
	}
}

func (s *policyService) Hint(ctx context.Context, domain string) (models.Hint, bool, error) {
	h, err := policycustoms.NewLoginPolicyDbCustoms(s.db).DomainHint(ctx, strings.ToLower(domain))
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.Hint{}, false, nil
	}
	if err != nil {
		return models.Hint{}, false, err
	}
	return models.Hint{AllowPassword: h.AllowPassword, AllowGoogle: h.AllowGoogle, SSOConnectionID: h.ConnectionID}, true, nil
}

func (s *policyService) List(ctx context.Context, scope shared.Scope) ([]models.Policy, error) {
	rows, err := policycustoms.NewLoginPolicyDbCustoms(s.db).List(ctx, scope.ClientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.Policy, 0, len(rows))
	for _, r := range rows {
		out = append(out, toPolicy(r))
	}
	return out, nil
}

// errNoMethod and friends are the client errors a policy write maps to.
var (
	errNoMethod       = exceptions.NewAPIError(http.StatusBadRequest, "A policy must allow at least one sign-in method", nil)
	errUnknownSSO     = exceptions.NewAPIError(http.StatusBadRequest, "No such SSO connection in this company", nil)
	errPolicyConflict = exceptions.NewAPIError(http.StatusConflict, "A policy with this name or priority already exists", nil)
)

func mapWriteError(err error) error {
	switch {
	case exceptions.IsCheckViolation(err):
		return errNoMethod
	case exceptions.IsForeignKeyViolation(err):
		return errUnknownSSO
	case exceptions.IsUniqueViolation(err):
		return errPolicyConflict
	}
	return err
}

func fields(in models.PolicyInput) loginpolicies.PolicyFields {
	return loginpolicies.PolicyFields{
		Name: strings.TrimSpace(in.Name), AllowPassword: in.AllowPassword, AllowGoogle: in.AllowGoogle,
		SSOConnectionID: in.SSOConnectionID, Priority: in.Priority,
	}
}

func (s *policyService) Create(ctx context.Context, scope shared.Scope, in models.PolicyInput) (models.Policy, error) {
	if !in.AllowPassword && !in.AllowGoogle && in.SSOConnectionID == nil {
		return models.Policy{}, errNoMethod
	}
	p, err := loginpolicies.NewLoginPolicyDbService(s.db).Create(ctx, scope.ClientID, fields(in))
	if err != nil {
		return models.Policy{}, mapWriteError(err)
	}
	s.audit.Record(scope, "login_policy.created")
	return toPolicy(p), nil
}

func (s *policyService) Update(ctx context.Context, scope shared.Scope, policyID string, in models.PolicyInput) (models.Policy, error) {
	if !in.AllowPassword && !in.AllowGoogle && in.SSOConnectionID == nil {
		return models.Policy{}, errNoMethod
	}
	p, err := loginpolicies.NewLoginPolicyDbService(s.db).Update(ctx, policyID, scope.ClientID, fields(in))
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.Policy{}, exceptions.ErrNotFound
	}
	if err != nil {
		return models.Policy{}, mapWriteError(err)
	}
	// Sessions signed in with a method this change removes end at their next
	// refresh, where the policy is enforced again; nothing to do here.
	s.audit.Record(scope, "login_policy.updated")
	return toPolicy(p), nil
}

func (s *policyService) Delete(ctx context.Context, scope shared.Scope, policyID string) error {
	cur, err := policycustoms.NewLoginPolicyDbCustoms(s.db).Get(ctx, policyID, scope.ClientID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return exceptions.ErrNotFound
	}
	if err != nil {
		return err
	}
	if cur.IsDefault {
		return exceptions.NewAPIError(http.StatusConflict, "The default policy cannot be deleted; make another the default first", nil)
	}
	n, err := loginpolicies.NewLoginPolicyDbService(s.db).Delete(ctx, policyID, scope.ClientID)
	if exceptions.IsForeignKeyViolation(err) {
		return exceptions.NewAPIError(http.StatusConflict, "The policy is still assigned to a user or group", nil)
	}
	if err != nil {
		return err
	}
	if n == 0 {
		return exceptions.ErrNotFound
	}
	s.audit.Record(scope, "login_policy.deleted")
	return nil
}

func (s *policyService) SetDefault(ctx context.Context, scope shared.Scope, policyID string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed
	n, err := loginpolicies.NewLoginPolicyDbService(tx).SetDefault(ctx, policyID, scope.ClientID)
	if err != nil {
		return err
	}
	if n == 0 {
		return exceptions.ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.audit.Record(scope, "login_policy.default_set")
	return nil
}

func (s *policyService) AssignUser(ctx context.Context, scope shared.Scope, userID string, policyID *string) error {
	n, err := users.NewUserDbService(s.db).SetLoginPolicy(ctx, userID, scope.ClientID, policyID)
	if exceptions.IsForeignKeyViolation(err) {
		return exceptions.NewAPIError(http.StatusBadRequest, "No such policy in this company", nil)
	}
	if err != nil {
		return err
	}
	if n == 0 {
		return exceptions.ErrNotFound
	}
	s.audit.Record(scope, "login_policy.user_assigned")
	return nil
}

func (s *policyService) AssignGroup(ctx context.Context, scope shared.Scope, groupID string, policyID *string) error {
	n, err := groups.NewGroupDbService(s.db).SetLoginPolicy(ctx, groupID, scope.ClientID, policyID)
	if exceptions.IsForeignKeyViolation(err) {
		return exceptions.NewAPIError(http.StatusBadRequest, "No such policy in this company", nil)
	}
	if err != nil {
		return err
	}
	if n == 0 {
		return exceptions.ErrNotFound
	}
	s.audit.Record(scope, "login_policy.group_assigned")
	return nil
}

func toPolicy(p dbmodels.LoginPolicy) models.Policy {
	return models.Policy{
		ID: p.ID, Name: p.Name, AllowPassword: p.AllowPassword, AllowGoogle: p.AllowGoogle,
		SSOConnectionID: p.SSOConnectionID, Priority: p.Priority, IsDefault: p.IsDefault,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}
