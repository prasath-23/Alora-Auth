// Package service owns every token App Central signs — its own access tokens,
// products' access tokens, and ID tokens — and the per-request authorization
// lookups behind the middleware chain. It is the ONLY package that calls
// jwtkeys.Sign*; an architecture test keeps it that way.
//
// Every claim is re-read from the database at the moment of minting, never
// carried over from an earlier token: that is what makes a role change, a
// deactivation or a lost subscription take effect at the next token rather
// than whenever the old one would have expired.
package service

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/alora/auth/internal/core/auth/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/jwtkeys"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	groupcustoms "github.com/alora/auth/internal/database/services/groups/customs"
	permissioncustoms "github.com/alora/auth/internal/database/services/productpermissions/customs"
	sessioncustoms "github.com/alora/auth/internal/database/services/sessions/customs"
	"github.com/alora/auth/internal/exceptions"
)

// ProductAudience is the audience of a product's tokens: "product:<key>".
func ProductAudience(productKey string) string { return "product:" + productKey }

// IDTokenTTL is how long an ID token is valid. It is consumed once, right after
// the code exchange, so it needs only long enough to cross the wire.
const IDTokenTTL = 10 * time.Minute

// AuthService signs tokens and answers the authorization lookups.
type AuthService interface {
	// MintCentral signs an App Central access token for a live central session.
	MintCentral(ctx context.Context, familyID string) (string, error)
	// MintProduct signs a person's product access token.
	MintProduct(ctx context.Context, t models.ProductToken) (string, error)
	// MintClient signs an application's product access token.
	MintClient(ctx context.Context, t models.ClientToken) (string, error)
	// MintID signs an ID token.
	MintID(ctx context.Context, t models.IDToken) (string, error)
	// AccessTokenTTLSeconds is what the API advertises as expires_in.
	AccessTokenTTLSeconds() int
	// LoadCaller decides whether a token's session still stands and what its
	// user may do (middlewares.CallerLoader).
	LoadCaller(ctx context.Context, userID, clientID, sessionID string) (shared.Actor, error)
	// JWKS is the public key set, encoded.
	JWKS() ([]byte, error)
	// Discovery is the OpenID Provider metadata.
	Discovery() models.Discovery
}

type authService struct {
	db          *contexts.DbContext
	accessTTL   time.Duration
	appAudience string
}

// NewAuthService builds the token service.
func NewAuthService(db *contexts.DbContext, accessTTL time.Duration, appCentralAudience string) AuthService {
	return &authService{db: db, accessTTL: accessTTL, appAudience: appCentralAudience}
}

func (s *authService) AccessTokenTTLSeconds() int { return int(s.accessTTL.Seconds()) }

// MintCentral signs App Central's own token: who ({sub, tenant_id, email}),
// which session (sid), and everything about App Central — the caller's scope
// and the products they may open — as of now. The session is re-checked here,
// so a token is never minted for a session that was revoked while the caller
// was on its way.
//
// scope and products are a SNAPSHOT for whoever reads the token; App Central
// itself decides every request from the database. av and pv are the versions
// the snapshot was taken at, read BEFORE the snapshot: a change in between then
// shows as a version mismatch at the next request, never as a stale snapshot
// carrying a current version.
func (s *authService) MintCentral(ctx context.Context, familyID string) (string, error) {
	g, err := sessioncustoms.NewSessionDbCustoms(s.db).Gate(ctx, familyID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return "", exceptions.ErrSessionInvalid
	}
	if err != nil {
		return "", err
	}
	if g.Kind != dbmodels.SessionCentral || !g.FamilyAlive || !g.UserActive || !g.ClientActive {
		return "", exceptions.ErrSessionInvalid
	}
	apps, err := permissioncustoms.NewProductPermissionDbCustoms(s.db).Apps(ctx, g.UserID, g.ClientID)
	if err != nil {
		return "", err
	}
	products := make([]string, 0, len(apps))
	for _, a := range apps {
		products = append(products, a.ProductKey)
	}
	sort.Strings(products)
	managed, err := groupcustoms.NewGroupDbCustoms(s.db).ManagedBy(ctx, g.UserID, g.ClientID)
	if err != nil {
		return "", err
	}
	manages := make([]string, 0, len(managed))
	for _, m := range managed {
		manages = append(manages, m.ID)
	}
	sort.Strings(manages)
	return jwtkeys.SignAccess(g.UserID, map[string]any{
		"tenant_id": g.ClientID,
		"email":     g.Email,
		"sid":       g.FamilyID,
		"scope":     strings.Join(shared.TokenScopes(shared.NewScopeSet(g.Scopes...), g.IsPlatformOwner), " "),
		"products":  products,
		"manages":   manages,
		"av":        g.AdminVersion,
		"pv":        g.PermissionsVersion,
	}, s.accessTTL, s.appAudience)
}

// MintProduct signs a person's token for exactly one product. Its roles are
// that product's only; its client_id is the product (RFC 9068); its sid is the
// product login, which introspection checks; principal says it speaks for a
// person.
func (s *authService) MintProduct(_ context.Context, t models.ProductToken) (string, error) {
	roles := t.Roles
	if roles == nil {
		roles = []string{} // never JSON null: a consumer that ranges it must not panic
	}
	return jwtkeys.SignAccess(t.UserID, map[string]any{
		"client_id": t.ProductID,
		"tenant_id": t.ClientID,
		"email":     t.Email,
		"roles":     roles,
		"sid":       t.FamilyID,
		"pv":        t.PermVersion,
		"principal": models.PrincipalUser,
	}, s.accessTTL, ProductAudience(t.ProductKey))
}

// MintClient signs an application's token for exactly one product: issued to an
// API client with client credentials (RFC 6749 §4.4). Its subject and client_id
// are the API client; it carries the scopes granted, no roles and no person;
// its sid is the secret it was issued under, which introspection checks, so
// revoking the secret ends the token. principal says it speaks for an
// application. There is no refresh token: the client asks again.
func (s *authService) MintClient(_ context.Context, t models.ClientToken) (string, error) {
	return jwtkeys.SignAccess(t.APIClientID, map[string]any{
		"client_id": t.APIClientID,
		"tenant_id": t.CompanyID,
		"scope":     strings.Join(t.Scopes, " "),
		"roles":     []string{},
		"sid":       t.SecretID,
		"principal": models.PrincipalClient,
	}, s.accessTTL, ProductAudience(t.ProductKey))
}

// MintID signs an OpenID Connect ID token for the product that asked for one.
func (s *authService) MintID(_ context.Context, t models.IDToken) (string, error) {
	claims := map[string]any{
		"auth_time": t.AuthTime.Unix(),
		"sid":       t.CentralFamilyID,
		"email":     t.Email,
		"tenant_id": t.ClientID,
	}
	if t.Nonce != "" {
		claims["nonce"] = t.Nonce
	}
	return jwtkeys.SignID(t.UserID, claims, IDTokenTTL, t.ProductID)
}

// LoadCaller admits a token only while its session is a live App Central login
// of that very user in that very company: not revoked, under its caps, holding a
// live refresh token, with the user and the company both active. What the
// caller may do — their scopes, whether they are an Owner — comes from the same
// read.
//
// A missing or dead session is an authorization outcome (401), not a server
// fault.
func (s *authService) LoadCaller(ctx context.Context, userID, clientID, sessionID string) (shared.Actor, error) {
	g, err := sessioncustoms.NewSessionDbCustoms(s.db).Gate(ctx, sessionID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return shared.Actor{}, exceptions.ErrUnauthorized
	}
	if err != nil {
		return shared.Actor{}, err
	}
	if g.Kind != dbmodels.SessionCentral || g.UserID != userID || g.ClientID != clientID ||
		!g.FamilyAlive || !g.UserActive || !g.ClientActive {
		return shared.Actor{}, exceptions.ErrUnauthorized
	}
	a := shared.Actor{
		UserID: g.UserID, ClientID: g.ClientID, Email: g.Email, SessionID: g.FamilyID,
		Scopes: shared.NewScopeSet(g.Scopes...), InAdmins: g.IsTenantAdmin, IsOwner: g.IsPlatformOwner,
		AdminVersion: g.AdminVersion, PermVersion: g.PermissionsVersion,
	}
	if g.AuthenticatedAt != nil {
		a.AuthenticatedAt = *g.AuthenticatedAt
	}
	return a, nil
}

func (s *authService) JWKS() ([]byte, error) { return jwtkeys.JWKS() }

// Discovery describes App Central as an OpenID Provider. It advertises only what
// is implemented: the code flow with S256 PKCE for products, client credentials
// for API clients, confidential clients authenticating with
// client_secret_basic, and RS256.
func (s *authService) Discovery() models.Discovery {
	iss := jwtkeys.Issuer()
	return models.Discovery{
		Issuer:                iss,
		AuthorizationEndpoint: iss + "/oauth/authorize",
		TokenEndpoint:         iss + "/oauth/token",
		JWKSURI:               iss + "/.well-known/jwks.json",
		RevocationEndpoint:    iss + "/oauth/revoke",
		IntrospectionEndpoint: iss + "/oauth/introspect",
		ResponseTypes:         []string{"code"},
		ResponseModes:         []string{"query"},
		GrantTypes:            []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypes:          []string{"public"},
		IDTokenAlgs:           []string{"RS256"},
		TokenAuthMethods:      []string{"client_secret_basic"},
		CodeChallengeMethods:  []string{"S256"},
		Scopes:                []string{"openid", "email", "profile"},
		Claims:                []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "email", "tenant_id"},
	}
}
