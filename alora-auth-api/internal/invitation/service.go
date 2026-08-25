// Package invitation handles onboarding: an admin invites an email address, the
// recipient redeems a one-time token to create their account.
//
// The raw invite token is generated once, emailed, and NEVER stored — only its
// SHA-256 hash is persisted. A database leak therefore yields no usable invites.
package invitation

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/alora/auth/internal/crypto/password"
	"github.com/alora/auth/internal/crypto/tokens"
	"github.com/alora/auth/internal/platform/database"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InviteTTL bounds how long an outstanding invitation stays redeemable.
const InviteTTL = 7 * 24 * time.Hour

type Service struct {
	pool        *pgxpool.Pool
	q           *sqlc.Queries
	frontendURL string
}

func NewService(pool *pgxpool.Pool, q *sqlc.Queries, frontendURL string) *Service {
	return &Service{pool: pool, q: q, frontendURL: frontendURL}
}

type ProductGrant struct {
	ProductID string
	RoleName  string
}

type Created struct {
	ID        string
	Email     string
	RawToken  string
	InviteURL string
	ExpiresAt time.Time
}

// Create issues an invitation for email within the CALLER's tenant.
//
// clientID always comes from the caller's verified token, never from the request
// body — accepting a body-supplied tenant would let any admin invite users into
// somebody else's organisation.
func (s *Service) Create(ctx context.Context, clientID, invitedBy, email string, grants []ProductGrant) (Created, error) {
	email = httpx.NormalizeEmail(email)

	// Refuse if the address already belongs to a live member of this tenant.
	exists, err := s.q.ActiveEmailExists(ctx, sqlc.ActiveEmailExistsParams{PClientid: clientID, PEmail: email})
	if err != nil {
		return Created{}, err
	}
	if exists {
		return Created{}, httpx.NewAPIError(409, "A user with this email already exists", nil)
	}
	// One live invite per address per tenant, so a re-invite cannot create two
	// independently redeemable tokens.
	if _, err := s.q.GetPendingInviteByEmail(ctx, sqlc.GetPendingInviteByEmailParams{
		PClientid: clientID, PEmail: email,
	}); err == nil {
		return Created{}, httpx.NewAPIError(409, "An invitation for this email is already pending", nil)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Created{}, err
	}

	raw, hash, err := tokens.GenerateInviteToken()
	if err != nil {
		return Created{}, err
	}
	expires := time.Now().Add(InviteTTL)

	// The invite row and its product grants must appear together: a committed
	// invite with missing grants would silently onboard a user with no access.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Created{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := s.q.WithTx(tx)

	inv, err := qtx.CreateInvitation(ctx, sqlc.CreateInvitationParams{
		PEmail: email, PClientid: clientID, PInvitedbyuserid: invitedBy,
		PTokenhash: hash, PExpiresat: database.Timestamptz(expires),
	})
	if err != nil {
		return Created{}, err
	}

	// One CALL per grant, inside the same transaction. De-duped first: a repeated
	// product_id would violate the unique index and abort the whole transaction.
	seen := make(map[string]struct{}, len(grants))
	for _, g := range grants {
		if _, dup := seen[g.ProductID]; dup {
			continue
		}
		seen[g.ProductID] = struct{}{}
		if err := qtx.CreateInvitationProduct(ctx, sqlc.CreateInvitationProductParams{
			PInvitationid: inv.ID, PProductid: g.ProductID, PRolename: g.RoleName,
		}); err != nil {
			return Created{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Created{}, err
	}

	return Created{
		ID: inv.ID, Email: email, RawToken: raw,
		InviteURL: strings.TrimRight(s.frontendURL, "/") + "/invite/accept?token=" + raw,
		ExpiresAt: expires,
	}, nil
}

type Listed struct {
	ID        string     `json:"id"`
	Email     string     `json:"email"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt *time.Time `json:"created_at"`
}

// List returns the caller tenant's invitations. token_hash is never projected.
func (s *Service) List(ctx context.Context, clientID string) ([]Listed, error) {
	rows, err := s.q.ListInvitations(ctx, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]Listed, 0, len(rows))
	for _, r := range rows {
		out = append(out, Listed{
			ID: r.ID, Email: r.Email, Status: string(r.Status),
			ExpiresAt: database.TimePtr(r.ExpiresAt), CreatedAt: database.TimePtr(r.CreatedAt),
		})
	}
	return out, nil
}

// Revoke cancels a PENDING invitation. Tenant-scoped, so an id from another
// organisation affects zero rows and reports 404 rather than acting.
func (s *Service) Revoke(ctx context.Context, id, clientID, revokedBy string) error {
	n, err := s.q.RevokeInvitation(ctx, sqlc.RevokeInvitationParams{
		InvitationID: id, ClientID: clientID, RevokedByUserID: database.Text(revokedBy),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return httpx.ErrNotFound
	}
	return nil
}

// Preview is the unauthenticated invite-landing payload.
type Preview struct {
	Email      string     `json:"email"`
	ClientName string     `json:"client_name"`
	ExpiresAt  *time.Time `json:"expires_at"`
	Providers  []string   `json:"allowed_idp_providers"`
	Products   []Product  `json:"products"`
}

type Product struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Role string `json:"role_name"`
}

// Lookup renders an invite for its landing page, keyed by the RAW token (hashed
// here). Returns a single opaque error for unknown/expired/used so the endpoint
// cannot be used to probe which tokens exist.
func (s *Service) Lookup(ctx context.Context, rawToken string) (Preview, error) {
	// Two focused reads rather than one flat 1-to-many join: the products come
	// back as their own rows, so there is no NULL-padding to interpret.
	inv, err := s.q.GetPendingInvitation(ctx, tokens.HashToken(rawToken))
	if errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, httpx.NewAPIError(400, "Invitation not found, expired, or already used", nil)
	}
	if err != nil {
		return Preview{}, err
	}

	p := Preview{
		Email: inv.Email, ClientName: inv.ClientName,
		ExpiresAt: database.TimePtr(inv.ExpiresAt),
		Providers: make([]string, 0, len(inv.AllowedIdpProviders)),
		Products:  []Product{},
	}
	for _, idp := range inv.AllowedIdpProviders {
		p.Providers = append(p.Providers, string(idp))
	}

	grants, err := s.q.ListInvitationProducts(ctx, inv.ID)
	if err != nil {
		return Preview{}, err
	}
	for _, g := range grants {
		p.Products = append(p.Products, Product{
			Key: g.ProductKey, Name: g.ProductName, Role: g.RoleName,
		})
	}
	return p, nil
}

// AcceptGoogle redeems an invitation into an OAUTH_ONLY account (no password).
//
// The account is created but NOT linked to a Google identity yet: linking
// happens on the user's first federated sign-in, keyed by Google's stable
// `sub`. That ordering means we never bind an account to an identity we have
// not actually seen authenticate.
func (s *Service) AcceptGoogle(ctx context.Context, rawToken string) error {
	const generic = "Invitation not found, expired, or already used"
	hash := tokens.HashToken(rawToken)

	// The tenant must permit GOOGLE before an OAuth-only account is created,
	// otherwise the account would exist with no usable way to sign in.
	inv, err := s.q.GetPendingInvitation(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return httpx.NewAPIError(400, generic, nil)
	}
	if err != nil {
		return err
	}
	allowed := false
	for _, p := range inv.AllowedIdpProviders {
		if p == sqlc.IdpProviderGOOGLE {
			allowed = true
			break
		}
	}
	if !allowed {
		return httpx.NewAPIError(403, "Google sign-in is not enabled for this organisation", nil)
	}

	exists, err := s.q.ActiveEmailExists(ctx, sqlc.ActiveEmailExistsParams{
		PClientid: inv.ClientID, PEmail: inv.Email,
	})
	if err != nil {
		return err
	}
	if exists {
		return httpx.NewAPIError(409, "An account with this email already exists. Please log in instead.", nil)
	}
	return s.acceptTx(ctx, hash, pgtype.Text{}, sqlc.AccountTypeOAUTHONLY)
}

// Accept redeems an invitation and creates the user's account.
//
// The claim is a single atomic UPDATE guarded on status='PENDING' AND not
// expired, so two concurrent redemptions cannot both create an account. Account
// creation, product grants and the claim all share one transaction: any failure
// rolls back the whole thing, never leaving a consumed invite with no user.
func (s *Service) Accept(ctx context.Context, rawToken, plaintextPassword string) error {
	if plaintextPassword == "" {
		return httpx.ErrInvalidRequest
	}
	hash, err := password.Hash(plaintextPassword)
	if err != nil {
		// Over-length input is a client error, not a server fault.
		return httpx.NewAPIError(400, "Invalid request", err)
	}
	return s.acceptTx(ctx, tokens.HashToken(rawToken), database.Text(hash), sqlc.AccountTypeEMAIL)
}

// acceptTx performs the claim + account creation + grants in ONE transaction, so
// a failure can never leave a consumed invitation with no user behind it.
func (s *Service) acceptTx(ctx context.Context, tokenHash string, passwordHash pgtype.Text, accountType sqlc.AccountType) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := s.q.WithTx(tx)

	inv, err := qtx.ClaimInvitation(ctx, sqlc.ClaimInvitationParams{TokenHash: tokenHash})
	if errors.Is(err, pgx.ErrNoRows) {
		return httpx.NewAPIError(400, "Invitation not found, expired, or already used", nil)
	}
	if err != nil {
		return err
	}

	user, err := qtx.CreateUser(ctx, sqlc.CreateUserParams{
		ClientID: inv.ClientID, Email: inv.Email,
		PasswordHash: passwordHash, AccountType: accountType,
	})
	if err != nil {
		// Someone registered this address between the check and now.
		if httpx.IsUniqueViolation(err) {
			return httpx.NewAPIError(409, "A user with this email already exists", err)
		}
		return err
	}

	// Apply the product/role grants the invite carried.
	grants, err := qtx.ListInvitationProducts(ctx, inv.ID)
	if err != nil {
		return err
	}
	for _, g := range grants {
		if err := qtx.UpsertProductPermission(ctx, sqlc.UpsertProductPermissionParams{
			PUserid: user.ID, PClientid: inv.ClientID, PProductid: g.ProductID,
			PRolename: g.RoleName, PGrantedby: inv.InvitedByUserID,
		}); err != nil {
			return err
		}
	}

	// Link the new account back to the invitation for the audit trail.
	if err := qtx.SetInvitationAcceptedBy(ctx, sqlc.SetInvitationAcceptedByParams{
		PInvitationid: inv.ID, PAcceptedbyuserid: user.ID,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
