package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alora/auth/internal/core/login/models"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/pkce"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/linkedidentities"
	identitycustoms "github.com/alora/auth/internal/database/services/linkedidentities/customs"
	"github.com/alora/auth/internal/database/services/loginstates"
	ssocustoms "github.com/alora/auth/internal/database/services/ssoconnections/customs"
	usercustoms "github.com/alora/auth/internal/database/services/users/customs"
	"github.com/alora/auth/internal/exceptions"
	"github.com/alora/auth/internal/infrastructure"
)

// Callback failure codes, as the login page shows them.
const (
	CodeInvalidRequest   = "invalid_request"
	CodeStateMismatch    = "state_mismatch"
	CodeStateExpired     = "state_expired"
	CodeExchangeFailed   = "exchange_failed"
	CodeEmailUnverified  = "email_unverified"
	CodeUnavailable      = "account_unavailable" // no account, or its policy refuses the method
	CodeSSOUnavailable   = "sso_unavailable"
	CodeGoogleDisabled   = "google_disabled"
	CodeServerError      = "server_error"
	federatedStateMaxAge = shared.LoginStateMaxAge
)

func failure(code string) error { return &models.CallbackError{Code: code} }

// The longest subject (OpenID Connect Core §2) and address a sign-in accepts.
const (
	maxSubject = 255
	maxEmail   = 320
)

// checked is an ID token's claims as a sign-in may use them. A subject past the
// standard's limit, or one the database cannot store, makes the token malformed:
// the exchange failed, whatever the provider meant. An address that is no
// address is dropped, so the sign-in goes on as if the provider had sent none.
func checked(c infrastructure.IDClaims) (infrastructure.IDClaims, bool) {
	if len(c.Subject) > maxSubject || !shared.Storable(c.Subject) {
		return c, false
	}
	if len(c.Email) > maxEmail || !shared.Storable(c.Email) {
		c.Email, c.EmailVerified = "", false
	}
	return c, true
}

// ErrGoogleDisabled is the answer to a Google sign-in on a deployment with no
// Google client configured.
var ErrGoogleDisabled = exceptions.NewAPIError(http.StatusNotFound, "Google sign-in is not enabled", nil)

// ErrSSOUnavailable is the one answer to an SSO start that cannot proceed: no
// such connection, an inactive one, or one whose secret cannot be opened.
var ErrSSOUnavailable = exceptions.NewAPIError(http.StatusBadRequest, "Single sign-on is not available for this address", nil)

// pending mints the state, nonce and PKCE verifier of one round trip to a
// provider, and stores them under the state's hash.
func (s *loginService) pending(ctx context.Context, kind dbmodels.LoginStateKind, connectionID, returnTo string) (state, nonce, challenge string, err error) {
	if state, err = tokens.GenerateOpaque(); err != nil {
		return "", "", "", err
	}
	if nonce, err = tokens.GenerateOpaque(); err != nil {
		return "", "", "", err
	}
	verifier, err := pkce.NewVerifier()
	if err != nil {
		return "", "", "", err
	}
	if err := loginstates.NewLoginStateDbService(s.db).Create(ctx, loginstates.NewState{
		StateHash: tokens.HashToken(state), Kind: kind, ConnectionID: connectionID,
		Nonce: nonce, CodeVerifier: verifier, ReturnTo: shared.SafeReturnTo(returnTo),
		ExpiresAt: time.Now().Add(federatedStateMaxAge),
	}); err != nil {
		return "", "", "", err
	}
	return state, nonce, pkce.ChallengeS256(verifier), nil
}

// take checks the callback's state against the one bound to this browser, then
// consumes it: single use, so a replayed callback finds nothing.
func (s *loginService) take(ctx context.Context, kind dbmodels.LoginStateKind, cookieState, queryState string) (dbmodels.LoginState, error) {
	if queryState == "" {
		return dbmodels.LoginState{}, failure(CodeInvalidRequest)
	}
	// CSRF binding: the signed cookie must carry the SAME state as the query, or
	// the callback was not started by this browser.
	if subtle.ConstantTimeCompare([]byte(cookieState), []byte(queryState)) != 1 {
		return dbmodels.LoginState{}, failure(CodeStateMismatch)
	}
	st, err := loginstates.NewLoginStateDbService(s.db).Take(ctx, tokens.HashToken(queryState), kind)
	if errors.Is(err, exceptions.ErrNoRows) {
		return dbmodels.LoginState{}, failure(CodeStateExpired)
	}
	if err != nil {
		return dbmodels.LoginState{}, failure(CodeServerError)
	}
	return st, nil
}

// GoogleStart stores the round trip and returns Google's consent screen.
func (s *loginService) GoogleStart(ctx context.Context, returnTo string) (string, string, error) {
	if !s.google.Enabled() {
		return "", "", ErrGoogleDisabled
	}
	state, nonce, challenge, err := s.pending(ctx, dbmodels.LoginStateGoogle, "", returnTo)
	if err != nil {
		return "", "", err
	}
	u, err := s.google.AuthCodeURL(ctx, state, nonce, challenge)
	if err != nil {
		return "", "", err
	}
	return state, u, nil
}

// GoogleCallback verifies Google's ID token and signs in the accounts it proves.
//
// An existing link, by Google's STABLE subject, proves its account whatever the
// address says now: someone who changes their Google address keeps their
// accounts, and whoever later acquires the old address inherits none of them.
// Without a link, a VERIFIED address proves each live account that holds it, and
// is linked to it on the way in. Google sign-in never creates an account, and
// every account it proves must still have a policy that allows Google.
func (s *loginService) GoogleCallback(ctx context.Context, cookieState, queryState, code string, m shared.ClientMeta) (models.Outcome, error) {
	if !s.google.Enabled() {
		return models.Outcome{}, failure(CodeGoogleDisabled)
	}
	st, err := s.take(ctx, dbmodels.LoginStateGoogle, cookieState, queryState)
	if err != nil {
		return models.Outcome{}, err
	}
	if code == "" {
		return models.Outcome{}, failure(CodeInvalidRequest)
	}
	claims, err := s.google.Exchange(ctx, code, deref(st.CodeVerifier), deref(st.Nonce))
	if err != nil {
		return models.Outcome{}, failure(CodeExchangeFailed)
	}
	claims, usable := checked(claims)
	if !usable {
		return models.Outcome{}, failure(CodeExchangeFailed)
	}

	accounts, err := s.googleAccounts(ctx, claims)
	if err != nil {
		var ce *models.CallbackError
		if errors.As(err, &ce) {
			return models.Outcome{}, err
		}
		return models.Outcome{}, failure(CodeServerError)
	}
	var allowed []string
	for _, a := range accounts {
		ok, err := s.policy.Allows(ctx, a.ID, a.ClientID, dbmodels.IdpGoogle, "")
		if err != nil {
			return models.Outcome{}, failure(CodeServerError)
		}
		if ok {
			allowed = append(allowed, a.ID)
		}
	}
	out, err := s.conclude(ctx, allowed, dbmodels.IdpGoogle, "", deref(st.ReturnTo), m)
	if errors.Is(err, exceptions.ErrInvalidCredentials) {
		return models.Outcome{}, failure(CodeUnavailable)
	}
	if err != nil {
		return models.Outcome{}, failure(CodeServerError)
	}
	return out, nil
}

// googleAccounts is every live account a Google identity proves: those linked to
// its subject, then — for a verified address — each unlinked live account that
// holds the address, which it links.
func (s *loginService) googleAccounts(ctx context.Context, claims infrastructure.IDClaims) ([]dbmodels.UserIdentity, error) {
	links, err := identitycustoms.NewLinkedIdentityDbCustoms(s.db).GoogleOwners(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []dbmodels.UserIdentity
	for _, l := range links {
		if l.IsActive {
			seen[l.UserID] = true
			out = append(out, dbmodels.UserIdentity{ID: l.UserID, ClientID: l.ClientID, Email: l.Email})
		}
	}
	email := shared.NormalizeEmail(claims.Email)
	if email == "" {
		if len(out) == 0 {
			return nil, failure(CodeEmailUnverified)
		}
		return out, nil
	}
	if !claims.EmailVerified {
		// An unverified Google address proves nothing: anyone can put any
		// address on a Google account. Only existing links count.
		if len(out) == 0 {
			return nil, failure(CodeEmailUnverified)
		}
		return out, nil
	}
	identities, err := usercustoms.NewUserDbCustoms(s.db).IdentitiesByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	for _, id := range identities {
		if seen[id.ID] {
			continue
		}
		// Link only an account whose policy allows Google: an account whose
		// company signs in only with SSO must not acquire a Google binding at all.
		ok, err := s.policy.Allows(ctx, id.ID, id.ClientID, dbmodels.IdpGoogle, "")
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		_, err = linkedidentities.NewLinkedIdentityDbService(s.db).Create(ctx, linkedidentities.NewLink{
			UserID: id.ID, ClientID: id.ClientID, Provider: dbmodels.IdpGoogle, ProviderID: claims.Subject,
			EmailVerified: true, EmailAtLink: email,
		})
		if exceptions.IsUniqueViolation(err) {
			// The account is already bound to ANOTHER Google identity. The address
			// matching is not enough to rebind it.
			continue
		}
		if err != nil {
			return nil, err
		}
		seen[id.ID] = true
		out = append(out, id)
	}
	return out, nil
}

// SSOStart resolves the connection, stores the round trip and returns the
// provider's login page. The connection is found by id or, for an address, by
// its domain — never by whether the address has an account.
func (s *loginService) SSOStart(ctx context.Context, connectionID, email, returnTo string) (string, string, error) {
	if connectionID == "" && email != "" {
		hint, found, err := s.policy.Hint(ctx, domainOf(shared.NormalizeEmail(email)))
		if err != nil {
			return "", "", err
		}
		if found && hint.SSOConnectionID != nil {
			connectionID = *hint.SSOConnectionID
		}
	}
	if connectionID == "" {
		return "", "", ErrSSOUnavailable
	}
	conn, client, err := s.connection(ctx, connectionID)
	if err != nil {
		return "", "", err
	}
	state, nonce, challenge, err := s.pending(ctx, dbmodels.LoginStateOIDC, conn.ID, returnTo)
	if err != nil {
		return "", "", err
	}
	u, err := s.oidc.AuthCodeURL(ctx, conn.Issuer, client, state, nonce, challenge, nil)
	if err != nil {
		return "", "", ErrSSOUnavailable
	}
	return state, u, nil
}

// connection loads an ACTIVE connection of an active company, with its secret
// opened. The secret is sealed to the connection's own id, so a ciphertext
// copied from another connection's row does not open here.
func (s *loginService) connection(ctx context.Context, connectionID string) (dbmodels.SSOConnectionRuntime, infrastructure.OIDCClient, error) {
	conn, err := ssocustoms.NewSSOConnectionDbCustoms(s.db).Runtime(ctx, connectionID)
	if errors.Is(err, exceptions.ErrNoRows) {
		return dbmodels.SSOConnectionRuntime{}, infrastructure.OIDCClient{}, ErrSSOUnavailable
	}
	if err != nil {
		return dbmodels.SSOConnectionRuntime{}, infrastructure.OIDCClient{}, err
	}
	if !conn.IsActive || conn.ClientSecretCiphertext == nil || conn.SecretKeyID == nil {
		return dbmodels.SSOConnectionRuntime{}, infrastructure.OIDCClient{}, ErrSSOUnavailable
	}
	secret, err := s.box.Open(*conn.SecretKeyID, conn.ClientSecretCiphertext, []byte(conn.ID))
	if err != nil {
		return dbmodels.SSOConnectionRuntime{}, infrastructure.OIDCClient{}, ErrSSOUnavailable
	}
	return conn, infrastructure.OIDCClient{
		ClientID: conn.OIDCClientID, ClientSecret: string(secret), RedirectURI: s.cfg.SSORedirectURI, Scopes: conn.Scopes,
	}, nil
}

// SSOCallback verifies the provider's ID token and signs in the one account it
// proves in the connection's company.
//
// An existing link, by the provider's STABLE subject at this connection, proves
// its account. Without one, the first sign-in links by address, and only when
// all of these hold: the address is at a domain registered on the connection,
// the provider says it is verified (unless the Owner marked the connection as
// trusted to assert unverified addresses), and a live account with that address
// already exists in the company. SSO never creates an account, and nothing is
// accepted that the provider did not initiate through this state.
func (s *loginService) SSOCallback(ctx context.Context, cookieState, queryState, code string, m shared.ClientMeta) (models.Outcome, error) {
	st, err := s.take(ctx, dbmodels.LoginStateOIDC, cookieState, queryState)
	if err != nil {
		return models.Outcome{}, err
	}
	if code == "" || st.ConnectionID == nil {
		return models.Outcome{}, failure(CodeInvalidRequest)
	}
	conn, client, err := s.connection(ctx, *st.ConnectionID)
	if err != nil {
		return models.Outcome{}, failure(CodeSSOUnavailable)
	}
	claims, err := s.oidc.Exchange(ctx, conn.Issuer, client, code, deref(st.CodeVerifier), deref(st.Nonce))
	if err != nil {
		return models.Outcome{}, failure(CodeExchangeFailed)
	}
	claims, usable := checked(claims)
	if !usable {
		return models.Outcome{}, failure(CodeExchangeFailed)
	}

	userID, err := s.ssoAccount(ctx, conn, claims)
	if err != nil {
		var ce *models.CallbackError
		if errors.As(err, &ce) {
			return models.Outcome{}, err
		}
		return models.Outcome{}, failure(CodeServerError)
	}
	ok, err := s.policy.Allows(ctx, userID, conn.ClientID, dbmodels.IdpOIDC, conn.ID)
	if err != nil {
		return models.Outcome{}, failure(CodeServerError)
	}
	if !ok {
		return models.Outcome{}, failure(CodeUnavailable)
	}
	signed, err := s.open(ctx, userID, conn.ClientID, dbmodels.IdpOIDC, conn.ID, m)
	if err != nil {
		return models.Outcome{}, failure(CodeServerError)
	}
	return models.Outcome{Session: &signed, ReturnTo: shared.SafeReturnTo(deref(st.ReturnTo))}, nil
}

func (s *loginService) ssoAccount(ctx context.Context, conn dbmodels.SSOConnectionRuntime, claims infrastructure.IDClaims) (string, error) {
	link, err := identitycustoms.NewLinkedIdentityDbCustoms(s.db).ByConnection(ctx, conn.ID, claims.Subject)
	if err == nil {
		if !link.IsActive || link.ClientID != conn.ClientID {
			return "", failure(CodeUnavailable)
		}
		return link.UserID, nil
	}
	if !errors.Is(err, exceptions.ErrNoRows) {
		return "", err
	}

	email := shared.NormalizeEmail(claims.Email)
	domain := domainOf(email)
	if domain == "" || !contains(conn.Domains, domain) {
		return "", failure(CodeUnavailable)
	}
	if !claims.EmailVerified && !conn.TrustUnverifiedEmail {
		return "", failure(CodeEmailUnverified)
	}
	user, err := usercustoms.NewUserDbCustoms(s.db).ForSSOLink(ctx, conn.ClientID, email)
	if errors.Is(err, exceptions.ErrNoRows) {
		return "", failure(CodeUnavailable)
	}
	if err != nil {
		return "", err
	}
	if _, err := linkedidentities.NewLinkedIdentityDbService(s.db).Create(ctx, linkedidentities.NewLink{
		UserID: user.ID, ClientID: user.ClientID, Provider: dbmodels.IdpOIDC, ConnectionID: conn.ID,
		ProviderID: claims.Subject, EmailVerified: claims.EmailVerified, EmailAtLink: email,
	}); err != nil {
		if exceptions.IsUniqueViolation(err) {
			// The account is already bound to another subject at this connection.
			return "", failure(CodeUnavailable)
		}
		return "", err
	}
	return user.ID, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}
