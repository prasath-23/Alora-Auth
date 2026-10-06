// Package customs holds the tbl_login_policies queries beyond CRUD: the list, the
// tenant-scoped read, and the per-domain hint the login page offers methods by.
package customs

import (
	"context"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// LoginPolicyDbCustoms is the custom query surface of tbl_login_policies.
type LoginPolicyDbCustoms struct{ q *sqlc.Queries }

// NewLoginPolicyDbCustoms binds the queries to a context: the pool or a
// transaction.
func NewLoginPolicyDbCustoms(c contexts.Querier) *LoginPolicyDbCustoms {
	return &LoginPolicyDbCustoms{q: c.Queries()}
}

// List lists a company's policies, highest priority first.
func (s *LoginPolicyDbCustoms) List(ctx context.Context, clientID string) ([]models.LoginPolicy, error) {
	rows, err := s.q.ListLoginPolicies(ctx, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]models.LoginPolicy, 0, len(rows))
	for _, r := range rows {
		out = append(out, services.LoginPolicyFromRow(r))
	}
	return out, nil
}

// Get reads one policy within a company.
func (s *LoginPolicyDbCustoms) Get(ctx context.Context, policyID, clientID string) (models.LoginPolicy, error) {
	r, err := s.q.GetLoginPolicy(ctx, sqlc.GetLoginPolicyParams{PPolicyid: policyID, PClientid: clientID})
	if err != nil {
		return models.LoginPolicy{}, err
	}
	return services.LoginPolicyFromRow(r), nil
}

// DomainHint reads the methods to offer for an email domain: a company's SSO
// connection when the domain is registered on one, else what the company's
// default policy allows when the domain is its verified one. No rows means the
// domain is nobody's, and the page offers the defaults.
func (s *LoginPolicyDbCustoms) DomainHint(ctx context.Context, domain string) (models.DomainLoginHint, error) {
	r, err := s.q.GetDomainLoginHint(ctx, domain)
	if err != nil {
		return models.DomainLoginHint{}, err
	}
	return models.DomainLoginHint{
		Domain: r.Domain, ClientID: r.ClientID, ConnectionID: services.StringPtr(r.ConnectionID),
		AllowPassword: r.AllowPassword, AllowGoogle: r.AllowGoogle,
	}, nil
}
