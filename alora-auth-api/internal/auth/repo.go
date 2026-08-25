// Package auth owns JWT payload assembly: the identity + roles that every access
// token carries. It is shared by the oauth (login) and session (refresh) features.
package auth

import (
	"context"
	"errors"

	"github.com/alora/auth/internal/middleware"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/jackc/pgx/v5"
)

type Repo struct{ q *sqlc.Queries }

func NewRepo(q *sqlc.Queries) *Repo { return &Repo{q: q} }

// Freshness implements middleware.FreshnessChecker.
// A missing row is reported as Found=false rather than an error: "user deleted"
// is an authorization outcome (401), not a server fault (500).
func (r *Repo) Freshness(ctx context.Context, userID string) (middleware.Freshness, error) {
	row, err := r.q.GetUserFreshness(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return middleware.Freshness{Found: false}, nil
	}
	if err != nil {
		return middleware.Freshness{}, err
	}
	return middleware.Freshness{
		PermissionsVersion: int(row.PermissionsVersion),
		IsActive:           row.IsActive,
		Deleted:            row.DeletedAt.Valid, // pgtype: Valid==true means NON-NULL
		Found:              true,
	}, nil
}

// Identity is the subject half of a token payload.
type Identity struct {
	UserID        string
	ClientID      string
	Email         string
	IsGlobalAdmin bool
	PermVersion   int
}

// LoadIdentity fetches a token subject WITH its liveness guard applied in SQL
// (is_active AND deleted_at IS NULL). Zero rows means the account was
// deprovisioned — surfaced as ErrAccountInactive (403), never as a 500.
func (r *Repo) LoadIdentity(ctx context.Context, userID string) (Identity, error) {
	row, err := r.q.GetUserIdentityForToken(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, httpx.ErrAccountInactive
	}
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		UserID: row.ID, ClientID: row.ClientID, Email: row.Email,
		IsGlobalAdmin: row.IsGlobalAdmin, PermVersion: int(row.PermissionsVersion),
	}, nil
}

// LoadRoles builds the product_key → role_name map for the JWT `roles` claim.
// Returns an EMPTY (non-nil) map when the user holds no grants: a nil map would
// marshal as JSON null and panic any consumer that ranges it.
func (r *Repo) LoadRoles(ctx context.Context, userID, clientID string) (map[string]string, error) {
	rows, err := r.q.ListUserProductRoles(ctx,
		sqlc.ListUserProductRolesParams{PUserid: userID, PClientid: clientID})
	if err != nil {
		return nil, err
	}
	roles := make(map[string]string, len(rows))
	for _, row := range rows {
		roles[row.ProductKey] = row.RoleName
	}
	return roles, nil
}

// HasGroupFeature implements middleware.FeatureChecker.
func (r *Repo) HasGroupFeature(ctx context.Context, featureKey, clientID, userID string) (bool, error) {
	ok, err := r.q.HasGroupFeature(ctx, sqlc.HasGroupFeatureParams{
		PFeaturekey: featureKey, PClientid: clientID, PUserid: userID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return ok, err
}

// IsVerifiedActiveDomain implements httpx.OriginVerifier for dynamic CORS.
func (r *Repo) IsVerifiedActiveDomain(ctx context.Context, host string) (bool, error) {
	_, err := r.q.ClientIdByVerifiedDomain(ctx, host)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
