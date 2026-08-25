package auth

import (
	"context"
	"time"

	"github.com/alora/auth/internal/crypto/jwtkeys"
)

// Service mints access tokens.
type Service struct {
	repo        *Repo
	accessTTL   time.Duration
	apiAudience string
}

func NewService(repo *Repo, accessTTL time.Duration, apiAudience string) *Service {
	return &Service{repo: repo, accessTTL: accessTTL, apiAudience: apiAudience}
}

// AccessTokenTTLSeconds is what the API advertises as expires_in.
func (s *Service) AccessTokenTTLSeconds() int { return int(s.accessTTL.Seconds()) }

// MintAccessToken builds and signs an access token for userID.
//
// Every claim is re-read from the DATABASE, never carried over from a previous
// token: that is what makes a permissions change or deactivation take effect on
// the very next refresh rather than 15 minutes later.
//
// productKey, when non-empty, adds "product:<key>" to the audience so a product
// backend can reject tokens minted for a different product.
func (s *Service) MintAccessToken(ctx context.Context, userID, productKey string) (string, Identity, error) {
	id, err := s.repo.LoadIdentity(ctx, userID) // liveness enforced in SQL
	if err != nil {
		return "", Identity{}, err
	}
	roles, err := s.repo.LoadRoles(ctx, id.UserID, id.ClientID)
	if err != nil {
		return "", Identity{}, err
	}

	claims := map[string]any{
		"client_id":       id.ClientID,
		"email":           id.Email,
		"roles":           roles,
		"pv":              id.PermVersion,
		"is_global_admin": id.IsGlobalAdmin,
	}
	aud := []string{s.apiAudience}
	if productKey != "" {
		aud = []string{"product:" + productKey, s.apiAudience}
	}
	tok, err := jwtkeys.Sign(id.UserID, claims, s.accessTTL, aud)
	if err != nil {
		return "", Identity{}, err
	}
	return tok, id, nil
}
