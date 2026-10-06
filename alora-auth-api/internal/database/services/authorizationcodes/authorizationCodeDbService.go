// Package authorizationcodes is the table service for tbl_authorization_codes:
// the single-use codes the authorize endpoint issues. The atomic claim, the
// replay lookup and the sweep live in customs.
package authorizationcodes

import (
	"context"
	"time"

	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services"
	"github.com/alora/auth/internal/database/sqlc"
)

// AuthorizationCodeDbService is the CRUD surface of tbl_authorization_codes.
type AuthorizationCodeDbService struct{ q *sqlc.Queries }

// NewAuthorizationCodeDbService binds the service to a context: the pool or a
// transaction.
func NewAuthorizationCodeDbService(c contexts.Querier) *AuthorizationCodeDbService {
	return &AuthorizationCodeDbService{q: c.Queries()}
}

// NewCode is a code to issue. Only its hash is stored, never the code. An empty
// Nonce or Scope stores NULL.
type NewCode struct {
	CodeHash            string
	ProductID           string
	UserID              string
	ClientID            string
	ParentFamilyID      string // the central session the code was issued under
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Scope               string
	ExpiresAt           time.Time
}

// Create issues a code.
func (s *AuthorizationCodeDbService) Create(ctx context.Context, n NewCode) (models.AuthorizationCode, error) {
	row, err := s.q.CreateAuthorizationCode(ctx, sqlc.CreateAuthorizationCodeParams{
		CodeHash: n.CodeHash, ProductID: n.ProductID, UserID: n.UserID, ClientID: n.ClientID,
		ParentFamilyID: n.ParentFamilyID, RedirectUri: n.RedirectURI,
		CodeChallenge: n.CodeChallenge, CodeChallengeMethod: n.CodeChallengeMethod,
		Nonce: services.TextOrNull(n.Nonce), Scope: services.TextOrNull(n.Scope),
		ExpiresAt: services.Timestamptz(n.ExpiresAt),
	})
	if err != nil {
		return models.AuthorizationCode{}, err
	}
	return FromRow(row), nil
}

// SetIssuedFamily records the product family a code was exchanged for, so a
// later replay of the code can revoke exactly that login.
func (s *AuthorizationCodeDbService) SetIssuedFamily(ctx context.Context, codeID, familyID string) error {
	return s.q.SetCodeIssuedFamily(ctx, sqlc.SetCodeIssuedFamilyParams{PCodeid: codeID, PFamilyid: familyID})
}

// FromRow converts a tbl_authorization_codes row. Exported for the customs
// queries, which return the same row type.
func FromRow(r sqlc.TblAuthorizationCode) models.AuthorizationCode {
	return models.AuthorizationCode{
		ID: r.ID, CodeHash: r.CodeHash, ProductID: r.ProductID, UserID: r.UserID, ClientID: r.ClientID,
		ParentFamilyID: r.ParentFamilyID, RedirectURI: r.RedirectUri,
		CodeChallenge: r.CodeChallenge, CodeChallengeMethod: r.CodeChallengeMethod,
		Nonce: services.StringPtr(r.Nonce), Scope: services.StringPtr(r.Scope),
		ExpiresAt: services.TimePtr(r.ExpiresAt), UsedAt: services.TimePtr(r.UsedAt),
		IssuedFamilyID: services.StringPtr(r.IssuedFamilyID), CreatedAt: services.TimePtr(r.CreatedAt),
	}
}
