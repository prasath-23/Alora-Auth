// Package oauth implements the OAuth 2.0 Authorization Code + PKCE login flow.
//
// There is no "POST /auth/login" in this system. A client authenticates in two
// legs: POST /auth/authorize exchanges credentials for a short-lived, single-use
// authorization code, and POST /auth/token exchanges that code plus the PKCE
// verifier for tokens. The split means the credential-bearing request never
// returns a token, and the token-bearing request never sees a password.
package oauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/alora/auth/internal/crypto/password"
	"github.com/alora/auth/internal/crypto/pkce"
	"github.com/alora/auth/internal/crypto/tokens"
	"github.com/alora/auth/internal/platform/database"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/jackc/pgx/v5"
)

// CodeTTL bounds the window between authenticating and redeeming the code. Two
// minutes is ample for a redirect round-trip and short enough that a code leaked
// via browser history or a referrer header is almost certainly already dead.
const CodeTTL = 2 * time.Minute

type Service struct{ q *sqlc.Queries }

func NewService(q *sqlc.Queries) *Service { return &Service{q: q} }

// AuthorizeInput is the credential leg of the flow.
type AuthorizeInput struct {
	Email               string
	Password            string
	ProductID           string
	RedirectURL         string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
}

// Authorize verifies credentials and issues a single-use authorization code.
//
// Every failure path returns the SAME error (ErrInvalidCredentials → 401
// "Invalid email or password"). Distinguishing "no such user" from "wrong
// password" from "no subscription" would turn this endpoint into an account and
// tenant enumeration oracle.
func (s *Service) Authorize(ctx context.Context, in AuthorizeInput) (string, error) {
	// Only S256 is accepted. The "plain" method offers no protection against an
	// attacker who can observe the authorization request.
	if in.CodeChallengeMethod != "" && in.CodeChallengeMethod != "S256" {
		return "", httpx.ErrInvalidRequest
	}

	// Resolve the product FIRST: the redirect target must be validated even when
	// authentication is about to fail, so behaviour cannot be probed by
	// submitting bad credentials with different redirect URLs.
	product, err := s.q.GetProductById(ctx, sqlc.GetProductByIdParams{
		PProductid: in.ProductID, PActiveonly: true,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", httpx.ErrInvalidRequest
	}
	if err != nil {
		return "", err
	}
	if !sameOrigin(in.RedirectURL, product.BaseUrl.String) {
		// Open-redirect guard: a code may only ever be delivered to the product's
		// own origin, so a stolen authorization request cannot redirect to an
		// attacker's site carrying the code.
		return "", httpx.ErrInvalidRequest
	}

	user, err := s.q.GetUserCredentialByEmail(ctx, httpx.NormalizeEmail(in.Email))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	// Constant-work path: when the user does not exist (or is OAuth-only and has
	// no password), still run a full argon2 verification against a dummy hash so
	// the response time does not reveal whether the account exists.
	storedHash := password.DummyHash()
	found := err == nil
	if found && user.PasswordHash.Valid {
		storedHash = user.PasswordHash.String
	}
	ok := password.Verify(in.Password, storedHash)
	if !found || !user.PasswordHash.Valid || !ok {
		return "", httpx.ErrInvalidCredentials
	}

	// The user's tenant must actually hold a live subscription to this product.
	if _, err := s.q.ActiveSubscriptionId(ctx, sqlc.ActiveSubscriptionIdParams{
		PClientid: user.ClientID, PProductid: in.ProductID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", httpx.ErrInvalidCredentials // same opaque error
		}
		return "", err
	}

	code, err := tokens.GenerateOpaque()
	if err != nil {
		return "", err
	}
	if _, err := s.q.CreateAuthorizationCode(ctx, sqlc.CreateAuthorizationCodeParams{
		Code:                code,
		ProductID:           in.ProductID,
		UserID:              user.ID,
		RedirectUrl:         in.RedirectURL,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: "S256",
		State:               database.TextOrNull(in.State),
		ExpiresAt:           database.Timestamptz(time.Now().Add(CodeTTL)),
	}); err != nil {
		return "", err
	}
	return code, nil
}

// Redeemed is the verified result of exchanging an authorization code.
type Redeemed struct {
	UserID    string
	ProductID string
	State     string
}

// Redeem consumes an authorization code and verifies the PKCE proof.
//
// The code is claimed with a single atomic UPDATE ... WHERE used_at IS NULL AND
// expires_at > now() RETURNING, so two concurrent redemptions cannot both
// succeed: the second updates zero rows. A SELECT-then-UPDATE here would be a
// classic double-spend.
func (s *Service) Redeem(ctx context.Context, code, verifier, redirectURL string) (Redeemed, error) {
	row, err := s.q.ClaimAuthorizationCode(ctx, code)
	if errors.Is(err, pgx.ErrNoRows) {
		// Unknown, already-used, or expired — all indistinguishable to the caller.
		return Redeemed{}, httpx.ErrInvalidRequest
	}
	if err != nil {
		return Redeemed{}, err
	}

	// PKCE: proves the redeemer is the same party that began the flow, so a
	// stolen code alone is useless.
	if !pkce.VerifyS256(verifier, row.CodeChallenge) {
		return Redeemed{}, httpx.ErrInvalidRequest
	}
	// The redirect_url must match the one bound at issue time, re-checked here so
	// the binding cannot be swapped between the two legs.
	if redirectURL != "" && redirectURL != row.RedirectUrl {
		return Redeemed{}, httpx.ErrInvalidRequest
	}

	return Redeemed{UserID: row.UserID, ProductID: row.ProductID, State: row.State.String}, nil
}

// ProductKey returns a product's JWT audience key.
func (s *Service) ProductKey(ctx context.Context, productID string) (string, error) {
	key, err := s.q.ProductKeyById(ctx, productID)
	if err != nil {
		return "", err
	}
	return key, nil
}

// sameOrigin reports whether candidate shares scheme+host+port with base.
// Compared on parsed components, never by string prefix: "https://acme.io.evil"
// has the prefix "https://acme.io" but is a different origin.
func sameOrigin(candidate, base string) bool {
	if candidate == "" || base == "" {
		return false
	}
	c, err1 := url.Parse(candidate)
	b, err2 := url.Parse(base)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(c.Scheme, b.Scheme) && strings.EqualFold(c.Host, b.Host)
}
