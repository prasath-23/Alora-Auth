// Package service is App Central as an OpenID Provider for the company's
// products: the authorization code flow with PKCE, for confidential clients
// only (every product has its own backend), with refresh-token rotation,
// revocation and introspection — and, for applications, the client-credentials
// grant, by which an API client gets a token for one product on its list.
//
// A product never sees a password. The browser reaches /oauth/authorize with an
// App Central session; the session, the product's registration and the user's
// access to the product are checked there, and a single-use code goes back to
// the product's exact registered redirect URI. The product's backend exchanges
// it, authenticating with its client secret, for tokens scoped to that product
// alone: an access token whose audience is "product:<key>" and whose roles are
// that product's only, a refresh token for a product login held under the App
// Central session, and, when asked for, an ID token.
package service

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	authmodels "github.com/alora/auth/internal/core/auth/models"
	authservice "github.com/alora/auth/internal/core/auth/service"
	"github.com/alora/auth/internal/core/oauth/models"
	sessionmodels "github.com/alora/auth/internal/core/session/models"
	sessionservice "github.com/alora/auth/internal/core/session/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/jwtkeys"
	"github.com/alora/auth/internal/core/shared/crypto/pkce"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	apiclientcustoms "github.com/alora/auth/internal/database/services/apiclients/customs"
	"github.com/alora/auth/internal/database/services/apiclientsecrets"
	apiclientsecretcustoms "github.com/alora/auth/internal/database/services/apiclientsecrets/customs"
	"github.com/alora/auth/internal/database/services/authorizationcodes"
	codecustoms "github.com/alora/auth/internal/database/services/authorizationcodes/customs"
	permissioncustoms "github.com/alora/auth/internal/database/services/productpermissions/customs"
	productcustoms "github.com/alora/auth/internal/database/services/products/customs"
	"github.com/alora/auth/internal/exceptions"
)

// CodeTTL bounds the window between authorizing and redeeming the code. Two
// minutes is ample for a redirect round-trip and short enough that a code leaked
// via browser history or a referrer header is almost certainly already dead.
const CodeTTL = 2 * time.Minute

// SupportedScopes are the scopes a product may ask for.
var SupportedScopes = map[string]bool{"openid": true, "email": true, "profile": true}

// OAuthService is the provider.
type OAuthService interface {
	// Client resolves an authorization request's client and checks its redirect
	// URI is registered, byte for byte. A failure here must NEVER redirect.
	Client(ctx context.Context, clientID, redirectURI string) (models.Client, error)
	// Authorize issues a code under the browser's App Central session.
	Authorize(ctx context.Context, in models.AuthorizeInput, rawCentral string, m shared.ClientMeta) (models.AuthorizeOutcome, error)
	// Authenticate checks a client's credentials at the token endpoint: a
	// product's, or an API client's.
	Authenticate(ctx context.Context, clientID, secret string) (models.Client, error)
	// ExchangeCode redeems a code for tokens.
	ExchangeCode(ctx context.Context, client models.Client, code, redirectURI, verifier string, m shared.ClientMeta) (models.TokenSet, error)
	// Refresh rotates a product refresh token.
	Refresh(ctx context.Context, client models.Client, rawToken string, m shared.ClientMeta) (models.TokenSet, error)
	// ClientCredentials issues an API client a token for one product on its list.
	ClientCredentials(ctx context.Context, client models.Client, resource, scope string) (models.TokenSet, error)
	// Revoke ends the product login a token belongs to (RFC 7009).
	Revoke(ctx context.Context, client models.Client, token string) error
	// Introspect reports whether a token is active right now (RFC 7662).
	Introspect(ctx context.Context, client models.Client, token string) (models.Introspection, error)
}

type oauthService struct {
	db       *contexts.DbContext
	auth     authservice.AuthService
	sessions sessionservice.SessionService
}

// NewOAuthService builds the provider.
func NewOAuthService(db *contexts.DbContext, auth authservice.AuthService, sessions sessionservice.SessionService) OAuthService {
	return &oauthService{db: db, auth: auth, sessions: sessions}
}

// errUnknownClient is the one answer for an authorization request whose client
// or redirect URI cannot be trusted: shown to the user, never redirected.
var errUnknownClient = exceptions.NewAPIError(http.StatusBadRequest, "Unknown application or unregistered redirect URI", nil)

func (s *oauthService) Client(ctx context.Context, clientID, redirectURI string) (models.Client, error) {
	if clientID == "" || redirectURI == "" {
		return models.Client{}, errUnknownClient
	}
	cred, err := productcustoms.NewProductDbCustoms(s.db).Credential(ctx, clientID)
	if errors.Is(err, exceptions.ErrNoRows) || (err == nil && !cred.IsActive) {
		return models.Client{}, errUnknownClient
	}
	if err != nil {
		return models.Client{}, err
	}
	// Exact match against the registered list: no prefix, no wildcard, no
	// normalisation. That is what makes delivering a code anywhere else
	// impossible (OAuth 2.0 Security BCP §4.1.3).
	ok, err := productcustoms.NewProductDbCustoms(s.db).IsRedirectURIRegistered(ctx, clientID, redirectURI)
	if err != nil {
		return models.Client{}, err
	}
	if !ok {
		return models.Client{}, errUnknownClient
	}
	return models.Client{ID: cred.ID, Kind: models.KindProduct, Key: cred.Key}, nil
}

// Authorize checks, in order: that the browser holds a usable App Central
// session (rotating its token, which keeps the session's idle timer running
// while its user lives in products), and that its user may use the product. Only
// then is a code issued, bound to the product, the redirect URI, the PKCE
// challenge, the nonce and the session.
func (s *oauthService) Authorize(ctx context.Context, in models.AuthorizeInput, rawCentral string, m shared.ClientMeta) (models.AuthorizeOutcome, error) {
	if rawCentral == "" {
		return models.AuthorizeOutcome{LoginRequired: true}, nil
	}
	var out models.AuthorizeOutcome
	iss, err := s.sessions.Rotate(ctx, rawCentral, sessionmodels.Want{Kind: sessionmodels.KindCentral}, m)
	switch {
	case err == nil:
		out.Central = &models.CentralCookie{Token: iss.RawToken, TTL: int64(iss.TTL().Seconds())}
	case errors.Is(err, exceptions.ErrRotationRace):
		// Another request of this browser rotated the session a moment ago. The
		// session is fine and that request carries its new cookie, so carry on
		// without one.
	case errors.Is(err, exceptions.ErrSessionInvalid):
		return models.AuthorizeOutcome{LoginRequired: true}, nil
	default:
		return models.AuthorizeOutcome{}, err
	}

	g, err := s.sessions.Gate(ctx, iss.FamilyID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.AuthorizeOutcome{LoginRequired: true}, nil
	}
	if err != nil {
		return models.AuthorizeOutcome{}, err
	}
	if !g.Usable || g.Kind != sessionmodels.KindCentral {
		return models.AuthorizeOutcome{LoginRequired: true}, nil
	}

	roles, err := permissioncustoms.NewProductPermissionDbCustoms(s.db).EffectiveRoles(ctx, g.UserID, g.ClientID, in.Client.ID)
	if err != nil {
		return models.AuthorizeOutcome{}, err
	}
	if len(roles) == 0 {
		out.AccessDenied = true
		return out, nil
	}

	code, err := tokens.GenerateOpaque()
	if err != nil {
		return models.AuthorizeOutcome{}, err
	}
	if _, err := authorizationcodes.NewAuthorizationCodeDbService(s.db).Create(ctx, authorizationcodes.NewCode{
		CodeHash:            tokens.HashToken(code), // only the hash is stored
		ProductID:           in.Client.ID,
		UserID:              g.UserID,
		ClientID:            g.ClientID,
		ParentFamilyID:      g.FamilyID,
		RedirectURI:         in.RedirectURI,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: "S256",
		Nonce:               in.Nonce,
		Scope:               in.Scope,
		ExpiresAt:           time.Now().Add(CodeTTL),
	}); err != nil {
		return models.AuthorizeOutcome{}, err
	}
	out.Code = code
	return out, nil
}

// Authenticate checks client_secret_basic credentials, for a product and an API
// client alike, through one lookup: a product has one secret, an API client up
// to two live ones. The presented secret is hashed once and compared, in
// constant time, with EVERY stored hash — and with a dummy when there is none —
// so how long the answer takes says nothing about which hash matched or whether
// the client exists. An unknown client, an inactive one, one with no usable
// secret and a wrong secret are the same invalid_client. Only after this does
// anything look at what kind of client it is.
func (s *oauthService) Authenticate(ctx context.Context, clientID, secret string) (models.Client, error) {
	if clientID == "" || secret == "" {
		return models.Client{}, models.InvalidClientError()
	}
	creds, err := apiclientcustoms.NewAPIClientDbCustoms(s.db).OAuthCredentials(ctx, clientID)
	if err != nil {
		return models.Client{}, err
	}
	presented := tokens.HashToken(secret)
	if len(creds) == 0 {
		tokens.EqualHash(presented, tokens.HashToken("")) // the same work as a real check
		return models.Client{}, models.InvalidClientError()
	}
	var match *dbmodels.OAuthClientCredential
	for i := range creds {
		if tokens.EqualHash(presented, creds[i].SecretHash) && creds[i].SecretHash != "" && match == nil {
			match = &creds[i]
		}
	}
	if match == nil || !match.IsActive {
		return models.Client{}, models.InvalidClientError()
	}
	switch match.Kind {
	case dbmodels.OAuthClientProduct:
		return models.Client{ID: match.OAuthClientID, Kind: models.KindProduct, Key: match.ProductKey}, nil
	case dbmodels.OAuthClientAPIClient:
		return models.Client{ID: match.OAuthClientID, Kind: models.KindAPIClient,
			CompanyID: match.CompanyID, SecretID: match.SecretID}, nil
	}
	return models.Client{}, models.InvalidClientError()
}

// errProductOnly refuses an API client the grants and endpoints of products'
// sign-in: it has no people to sign in.
var errProductOnly = models.UnauthorizedClientError("Only a product may use this; an API client uses client_credentials")

var errBadCode = models.InvalidGrantError("The authorization code is invalid, expired or already used")

// ExchangeCode redeems a code. The claim is one atomic UPDATE ... WHERE used_at
// IS NULL AND unexpired RETURNING, so two concurrent redemptions cannot both
// succeed. A code presented AFTER it was redeemed means it leaked, so the
// product login it opened is revoked (RFC 6749 §4.1.2).
func (s *oauthService) ExchangeCode(ctx context.Context, client models.Client, code, redirectURI, verifier string, m shared.ClientMeta) (models.TokenSet, error) {
	if client.Kind != models.KindProduct {
		return models.TokenSet{}, errProductOnly
	}
	if code == "" || redirectURI == "" || verifier == "" {
		return models.TokenSet{}, models.InvalidRequestError("code, redirect_uri and code_verifier are required")
	}
	hash := tokens.HashToken(code)
	codes := codecustoms.NewAuthorizationCodeDbCustoms(s.db)
	// The code is bound to the client it was issued to. Another client — even one
	// holding valid credentials of its own — is refused before the claim, so it
	// cannot burn a code it was never meant to see.
	prior, err := codes.ByHash(ctx, hash)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.TokenSet{}, errBadCode
	}
	if err != nil {
		return models.TokenSet{}, err
	}
	if prior.ProductID != client.ID {
		return models.TokenSet{}, errBadCode
	}
	row, err := codes.Claim(ctx, hash)
	if errors.Is(err, exceptions.ErrNoRows) {
		// Spent or expired. Spent means the code leaked: end what it opened.
		if prior.UsedAt != nil && prior.IssuedFamilyID != nil {
			if rerr := s.sessions.RevokeTree(ctx, *prior.IssuedFamilyID, dbmodels.RevokeReasonReuseDetected); rerr != nil {
				return models.TokenSet{}, rerr
			}
		}
		return models.TokenSet{}, errBadCode
	}
	if err != nil {
		return models.TokenSet{}, err
	}
	// And to the redirect URI it was delivered to, and the PKCE challenge of the
	// request that asked for it. Checked after the claim: a code presented with
	// the wrong proof is spent, since whoever holds it is not its requester.
	if row.RedirectURI != redirectURI || !pkce.VerifyS256(verifier, row.CodeChallenge) {
		return models.TokenSet{}, errBadCode
	}

	iss, err := s.sessions.CreateProduct(ctx, row.ParentFamilyID, row.UserID, row.ClientID, row.ProductID, m)
	if errors.Is(err, exceptions.ErrSessionInvalid) {
		// The App Central session the code was issued under has ended since.
		return models.TokenSet{}, errBadCode
	}
	if err != nil {
		return models.TokenSet{}, err
	}
	if err := authorizationcodes.NewAuthorizationCodeDbService(s.db).SetIssuedFamily(ctx, row.ID, iss.FamilyID); err != nil {
		return models.TokenSet{}, err
	}

	set, err := s.mint(ctx, client, iss)
	if err != nil {
		return models.TokenSet{}, err
	}
	scope := deref(row.Scope)
	if hasScope(scope, "openid") {
		g, err := s.sessions.Gate(ctx, iss.FamilyID)
		if err != nil {
			return models.TokenSet{}, err
		}
		id, err := s.auth.MintID(ctx, authmodels.IDToken{
			UserID: g.UserID, ClientID: g.ClientID, Email: g.Email, ProductID: client.ID,
			Nonce: deref(row.Nonce), AuthTime: g.AuthenticatedAt, CentralFamilyID: row.ParentFamilyID,
		})
		if err != nil {
			return models.TokenSet{}, err
		}
		set.IDToken = id
	}
	set.Scope = scope
	return set, nil
}

// mint signs the product access token for a product login, reading everything
// it asserts — including the roles — afresh. A login whose user has lost access
// since is revoked instead.
func (s *oauthService) mint(ctx context.Context, client models.Client, iss sessionmodels.Issued) (models.TokenSet, error) {
	g, err := s.sessions.Gate(ctx, iss.FamilyID)
	if err != nil {
		return models.TokenSet{}, err
	}
	roles, err := permissioncustoms.NewProductPermissionDbCustoms(s.db).EffectiveRoles(ctx, g.UserID, g.ClientID, client.ID)
	if err != nil {
		return models.TokenSet{}, err
	}
	if !g.Usable || len(roles) == 0 {
		if err := s.sessions.RevokeTree(ctx, iss.FamilyID, dbmodels.RevokeReasonAccessLost); err != nil {
			return models.TokenSet{}, err
		}
		return models.TokenSet{}, models.InvalidGrantError("The user no longer has access to this application")
	}
	at, err := s.auth.MintProduct(ctx, authmodels.ProductToken{
		UserID: g.UserID, ClientID: g.ClientID, Email: g.Email, ProductID: client.ID, ProductKey: client.Key,
		FamilyID: iss.FamilyID, Roles: roles, PermVersion: g.PermVersion,
	})
	if err != nil {
		return models.TokenSet{}, err
	}
	return models.TokenSet{AccessToken: at, RefreshToken: iss.RawToken, ExpiresIn: s.auth.AccessTokenTTLSeconds()}, nil
}

// Refresh rotates a product's refresh token. Only the product that holds the
// login may present it, and every rule is checked again on the way: the App
// Central session above it, the user, the company, the login policy and access
// to the product. A replayed token burns this product's login only.
func (s *oauthService) Refresh(ctx context.Context, client models.Client, rawToken string, m shared.ClientMeta) (models.TokenSet, error) {
	if client.Kind != models.KindProduct {
		return models.TokenSet{}, errProductOnly
	}
	if rawToken == "" {
		return models.TokenSet{}, models.InvalidRequestError("refresh_token is required")
	}
	iss, err := s.sessions.Rotate(ctx, rawToken, sessionmodels.Want{Kind: sessionmodels.KindProduct, ProductID: client.ID}, m)
	switch {
	case errors.Is(err, exceptions.ErrRotationRace):
		return models.TokenSet{}, models.ConcurrentRefreshError()
	case errors.Is(err, exceptions.ErrSessionInvalid):
		return models.TokenSet{}, models.InvalidGrantError("The refresh token is invalid, expired or revoked")
	case err != nil:
		return models.TokenSet{}, err
	}
	return s.mint(ctx, client, iss)
}

// ClientCredentials issues an application a token for one product on its list
// (RFC 6749 §4.4). The product is named by resource=product:<key> (RFC 8707); a
// product that is unknown, not on the list, or not usable right now — the
// client or its company off, the subscription over, the product off or no
// longer accepting API clients — is the same invalid_target, so the answer says
// nothing about products the client may not have. The scope is optional:
// without it the token carries every scope the client holds, with it only those
// asked for (an edit scope bringing its read scope), each of which the client
// must hold. The token lives as long as any access token and has no refresh
// token: the client asks again.
func (s *oauthService) ClientCredentials(ctx context.Context, client models.Client, resource, scope string) (models.TokenSet, error) {
	if client.Kind != models.KindAPIClient {
		return models.TokenSet{}, models.UnauthorizedClientError("Only an API client may use client_credentials")
	}
	key, ok := strings.CutPrefix(resource, authservice.ProductAudience(""))
	if !ok || key == "" {
		return models.TokenSet{}, models.InvalidTargetError()
	}
	g, err := apiclientcustoms.NewAPIClientDbCustoms(s.db).Grant(ctx, client.ID, key)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.TokenSet{}, models.InvalidTargetError()
	}
	if err != nil {
		return models.TokenSet{}, err
	}
	if !g.Usable || g.ClientID != client.CompanyID {
		return models.TokenSet{}, models.InvalidTargetError()
	}
	scopes := g.Scopes
	if strings.TrimSpace(scope) != "" {
		asked, err := shared.NormalizeClientScopes(strings.Fields(scope))
		if err != nil || !shared.NewScopeSet(g.Scopes...).Covers(asked) {
			return models.TokenSet{}, models.InvalidScopeError("The API client does not hold every scope asked for")
		}
		scopes = asked
	}
	if len(scopes) == 0 {
		return models.TokenSet{}, models.InvalidScopeError("The API client holds no scope yet")
	}
	if err := apiclientsecrets.NewAPIClientSecretDbService(s.db).Touch(ctx, client.SecretID, client.ID); err != nil {
		return models.TokenSet{}, err
	}
	at, err := s.auth.MintClient(ctx, authmodels.ClientToken{
		APIClientID: client.ID, CompanyID: client.CompanyID, ProductKey: key, SecretID: client.SecretID, Scopes: scopes,
	})
	if err != nil {
		return models.TokenSet{}, err
	}
	return models.TokenSet{AccessToken: at, ExpiresIn: s.auth.AccessTokenTTLSeconds(), Scope: strings.Join(scopes, " ")}, nil
}

// Revoke ends the product login a refresh or access token belongs to. Per RFC
// 7009 it succeeds whatever the token is — unknown, expired, another product's —
// so it cannot be used to probe; it only ever acts on the calling product's own
// logins. An application's token has no login to end: it lives fifteen minutes,
// and revoking the API client's secret ends it at once for introspection.
func (s *oauthService) Revoke(ctx context.Context, client models.Client, token string) error {
	if client.Kind != models.KindProduct {
		return errProductOnly
	}
	if token == "" {
		return nil
	}
	if fam, err := s.sessions.TokenFamily(ctx, token); err == nil {
		if fam.Kind == sessionmodels.KindProduct && fam.ProductID == client.ID {
			return s.sessions.RevokeTree(ctx, fam.FamilyID, dbmodels.RevokeReasonLogout)
		}
		return nil
	} else if !errors.Is(err, exceptions.ErrNoRows) {
		return err
	}
	if tok, err := jwtkeys.VerifyAccess(token, authservice.ProductAudience(client.Key)); err == nil {
		sid, _ := tok.Get("sid")
		if fam, _ := sid.(string); fam != "" {
			if g, err := s.sessions.Gate(ctx, fam); err == nil &&
				g.Kind == sessionmodels.KindProduct && g.ProductID == client.ID {
				return s.sessions.RevokeTree(ctx, fam, dbmodels.RevokeReasonLogout)
			}
		}
	}
	return nil
}

// Introspect reports whether a token is active RIGHT NOW, which is stronger than
// a signature check. For a person's token: the product login must be live, its
// App Central session too, the user and company active, access to the product
// held, and — for an access token — its roles still the current ones (the
// permissions version it was minted at). For an application's token: the API
// client and its company active, the secret it was issued under live, the
// product still on its list and usable, and every scope in the token still
// held. It answers only about tokens for the calling product.
func (s *oauthService) Introspect(ctx context.Context, client models.Client, token string) (models.Introspection, error) {
	inactive := models.Introspection{}
	if client.Kind != models.KindProduct {
		return inactive, errProductOnly
	}
	if token == "" {
		return inactive, nil
	}
	if tok, err := jwtkeys.VerifyAccess(token, authservice.ProductAudience(client.Key)); err == nil {
		cidV, _ := tok.Get("client_id")
		cid, _ := cidV.(string)
		sidV, _ := tok.Get("sid")
		sid, _ := sidV.(string)
		principal, _ := tok.Get("principal")
		tenantV, _ := tok.Get("tenant_id")
		tenant, _ := tenantV.(string)
		if principal == authmodels.PrincipalClient {
			scopeV, _ := tok.Get("scope")
			scope, _ := scopeV.(string)
			if cid == "" || cid != tok.Subject() || sid == "" {
				return inactive, nil
			}
			g, err := apiclientcustoms.NewAPIClientDbCustoms(s.db).Grant(ctx, cid, client.Key)
			if errors.Is(err, exceptions.ErrNoRows) {
				return inactive, nil
			}
			if err != nil {
				return models.Introspection{}, err
			}
			if !g.Usable || g.ClientID != tenant || !shared.NewScopeSet(g.Scopes...).Covers(strings.Fields(scope)) {
				return inactive, nil
			}
			live, err := apiclientsecretcustoms.NewAPIClientSecretDbCustoms(s.db).IsLive(ctx, sid, cid)
			if err != nil {
				return models.Introspection{}, err
			}
			if !live {
				return inactive, nil
			}
			return models.Introspection{
				Active: true, TokenType: "Bearer", Principal: authmodels.PrincipalClient, Subject: cid, ClientID: cid,
				TenantID: tenant, Scope: scope, Audience: authservice.ProductAudience(client.Key), Issuer: tok.Issuer(),
				SessionID: sid, ExpiresAt: tok.Expiration().Unix(), IssuedAt: tok.IssuedAt().Unix(),
			}, nil
		}
		if cid != client.ID || sid == "" {
			return inactive, nil
		}
		g, err := s.sessions.Gate(ctx, sid)
		if errors.Is(err, exceptions.ErrNoRows) {
			return inactive, nil
		}
		if err != nil {
			return models.Introspection{}, err
		}
		pv, _ := tok.Get("pv")
		if g.Kind != sessionmodels.KindProduct || g.ProductID != client.ID || g.UserID != tok.Subject() ||
			!g.Usable || toInt64(pv) != int64(g.PermVersion) {
			return inactive, nil
		}
		email, _ := tok.Get("email")
		out := models.Introspection{
			Active: true, TokenType: "Bearer", Principal: authmodels.PrincipalUser, Subject: tok.Subject(),
			ClientID: client.ID, TenantID: tenant, Audience: authservice.ProductAudience(client.Key),
			Issuer: tok.Issuer(), SessionID: sid, ExpiresAt: tok.Expiration().Unix(), IssuedAt: tok.IssuedAt().Unix(),
		}
		out.Email, _ = email.(string)
		out.Roles = stringList(tok.Get("roles"))
		return out, nil
	}

	fam, err := s.sessions.TokenFamily(ctx, token)
	if errors.Is(err, exceptions.ErrNoRows) {
		return inactive, nil
	}
	if err != nil {
		return models.Introspection{}, err
	}
	if !fam.TokenLive || !fam.Usable || fam.Kind != sessionmodels.KindProduct || fam.ProductID != client.ID {
		return inactive, nil
	}
	return models.Introspection{
		Active: true, TokenType: "refresh_token", Subject: fam.UserID, ClientID: client.ID,
		TenantID: fam.ClientID, Email: fam.Email, SessionID: fam.FamilyID, Issuer: jwtkeys.Issuer(),
	}, nil
}

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

func stringList(v any, ok bool) []string {
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// toInt64 normalizes a JSON number claim: encoding/json yields float64, jwx may
// yield json.Number or int64 depending on the decoder.
func toInt64(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case interface{ Int64() (int64, error) }:
		if i, err := n.Int64(); err == nil {
			return i
		}
	}
	return -1
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
