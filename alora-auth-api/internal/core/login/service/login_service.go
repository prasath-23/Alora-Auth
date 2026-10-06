// Package service is how people sign in to App Central: with a password, with
// Google, or with their company's own SSO. Every path ends the same way — the
// user's login policy must allow the method, and only then is an App Central
// session opened — and every failure a caller could learn from looks the same.
//
// One address may hold accounts in several companies. The password path checks
// every such account, and when the password opens more than one, the person
// picks the company from a list that is shown only AFTER the first factor
// succeeded, so the list itself reveals nothing to someone without it.
package service

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	authservice "github.com/alora/auth/internal/core/auth/service"
	"github.com/alora/auth/internal/core/login/models"
	policyservice "github.com/alora/auth/internal/core/policy/service"
	sessionmodels "github.com/alora/auth/internal/core/session/models"
	sessionservice "github.com/alora/auth/internal/core/session/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/password"
	"github.com/alora/auth/internal/core/shared/crypto/secretbox"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/clients"
	"github.com/alora/auth/internal/database/services/loginstates"
	usercustoms "github.com/alora/auth/internal/database/services/users/customs"
	"github.com/alora/auth/internal/exceptions"
	"github.com/alora/auth/internal/infrastructure"
)

// LoginService signs people in to App Central.
type LoginService interface {
	// Password signs in with an address and password, or asks which company.
	Password(ctx context.Context, email, plaintext, returnTo string, m shared.ClientMeta) (models.Outcome, error)
	// Choices lists the companies a pending account choice offers.
	Choices(ctx context.Context, ticket string) ([]models.Company, error)
	// Choose completes a pending account choice.
	Choose(ctx context.Context, ticket, clientID string, m shared.ClientMeta) (models.Outcome, error)
	// Refresh rotates the App Central session and mints its access token.
	Refresh(ctx context.Context, rawToken string, m shared.ClientMeta) (models.Signed, error)
	// Logout ends the App Central session and every product login under it.
	Logout(ctx context.Context, rawToken string) error
	// Discover says which methods to offer for an address's domain.
	Discover(ctx context.Context, email string) (models.Discovery, error)

	// GoogleStart begins a Google sign-in: the state to bind to the browser and
	// the consent screen to send it to.
	GoogleStart(ctx context.Context, returnTo string) (state, consentURL string, err error)
	// GoogleCallback finishes one. Every error is a *models.CallbackError.
	GoogleCallback(ctx context.Context, cookieState, queryState, code string, m shared.ClientMeta) (models.Outcome, error)
	// SSOStart begins a company SSO sign-in at a connection, named directly or
	// found from an address's domain.
	SSOStart(ctx context.Context, connectionID, email, returnTo string) (state, loginURL string, err error)
	// SSOCallback finishes one. Every error is a *models.CallbackError.
	SSOCallback(ctx context.Context, cookieState, queryState, code string, m shared.ClientMeta) (models.Outcome, error)
}

// Config is what the login paths need from the deployment.
type Config struct {
	SSORedirectURI string
}

type loginService struct {
	db       *contexts.DbContext
	auth     authservice.AuthService
	sessions sessionservice.SessionService
	policy   policyservice.PolicyService
	google   *infrastructure.Google
	oidc     *infrastructure.OIDC
	box      *secretbox.Box
	cfg      Config
}

// NewLoginService builds the sign-in service.
func NewLoginService(db *contexts.DbContext, auth authservice.AuthService, sessions sessionservice.SessionService,
	policy policyservice.PolicyService, google *infrastructure.Google, oidc *infrastructure.OIDC,
	box *secretbox.Box, cfg Config) LoginService {
	return &loginService{db: db, auth: auth, sessions: sessions, policy: policy, google: google, oidc: oidc, box: box, cfg: cfg}
}

// ChoiceTTL bounds how long an account choice waits.
const ChoiceTTL = shared.ChooserMaxAge

// Password verifies credentials against every live password account that holds
// the address, then applies each account's login policy.
//
// Every failure returns the SAME error (ErrInvalidCredentials → 401 "Invalid
// email or password"): no account, a wrong password, and a right password on an
// account whose policy does not allow passwords are indistinguishable, so this
// endpoint cannot be used to learn which addresses exist or how their companies
// sign in. At least one full argon2 verification always runs — against a dummy
// hash when there is no account — so the response time does not tell either.
func (s *loginService) Password(ctx context.Context, email, plaintext, returnTo string, m shared.ClientMeta) (models.Outcome, error) {
	candidates, err := usercustoms.NewUserDbCustoms(s.db).LoginCandidates(ctx, shared.NormalizeEmail(email))
	if err != nil {
		return models.Outcome{}, err
	}
	if len(candidates) == 0 {
		password.Verify(plaintext, password.DummyHash())
		return models.Outcome{}, exceptions.ErrInvalidCredentials
	}
	var opened []dbmodels.UserCredential
	for _, cand := range candidates {
		if cand.PasswordHash != nil && password.Verify(plaintext, *cand.PasswordHash) {
			opened = append(opened, cand)
		}
	}
	var allowed []string
	for _, cand := range opened {
		ok, err := s.policy.Allows(ctx, cand.ID, cand.ClientID, dbmodels.IdpEmail, "")
		if err != nil {
			return models.Outcome{}, err
		}
		if ok {
			allowed = append(allowed, cand.ID)
		}
	}
	return s.conclude(ctx, allowed, dbmodels.IdpEmail, "", shared.SafeReturnTo(returnTo), m)
}

// conclude turns the accounts a sign-in proved into an outcome: nothing (the
// generic refusal), a session for the one account, or a choice between several.
func (s *loginService) conclude(ctx context.Context, userIDs []string, method dbmodels.IdpProvider, connectionID, returnTo string, m shared.ClientMeta) (models.Outcome, error) {
	switch len(userIDs) {
	case 0:
		return models.Outcome{}, exceptions.ErrInvalidCredentials
	case 1:
		id, err := usercustoms.NewUserDbCustoms(s.db).IdentityForToken(ctx, userIDs[0])
		if errors.Is(err, exceptions.ErrNoRows) {
			return models.Outcome{}, exceptions.ErrInvalidCredentials
		}
		if err != nil {
			return models.Outcome{}, err
		}
		signed, err := s.open(ctx, id.ID, id.ClientID, method, connectionID, m)
		if err != nil {
			return models.Outcome{}, err
		}
		return models.Outcome{Session: &signed, ReturnTo: returnTo}, nil
	}

	companies, err := s.companies(ctx, userIDs)
	if err != nil {
		return models.Outcome{}, err
	}
	ticket, err := tokens.GenerateOpaque()
	if err != nil {
		return models.Outcome{}, err
	}
	if err := loginstates.NewLoginStateDbService(s.db).Create(ctx, loginstates.NewState{
		StateHash: tokens.HashToken(ticket), Kind: dbmodels.LoginStateAccountChoice,
		ConnectionID: connectionID, ReturnTo: returnTo, CandidateUserIDs: userIDs, AuthMethod: &method,
		ExpiresAt: time.Now().Add(ChoiceTTL),
	}); err != nil {
		return models.Outcome{}, err
	}
	return models.Outcome{Ticket: ticket, Companies: companies, ReturnTo: returnTo}, nil
}

// open starts an App Central session and mints its first access token.
func (s *loginService) open(ctx context.Context, userID, clientID string, method dbmodels.IdpProvider, connectionID string, m shared.ClientMeta) (models.Signed, error) {
	iss, err := s.sessions.CreateCentral(ctx, userID, clientID, method, connectionID, m)
	if err != nil {
		return models.Signed{}, err
	}
	return s.signed(ctx, iss)
}

func (s *loginService) signed(ctx context.Context, iss sessionmodels.Issued) (models.Signed, error) {
	at, err := s.auth.MintCentral(ctx, iss.FamilyID)
	if err != nil {
		return models.Signed{}, err
	}
	return models.Signed{
		RefreshToken: iss.RawToken, RefreshTTL: iss.TTL(),
		AccessToken: at, ExpiresIn: s.auth.AccessTokenTTLSeconds(),
	}, nil
}

// companies names the companies of the given live accounts, skipping any that
// has since stopped being live.
func (s *loginService) companies(ctx context.Context, userIDs []string) ([]models.Company, error) {
	out := make([]models.Company, 0, len(userIDs))
	for _, uid := range userIDs {
		id, err := usercustoms.NewUserDbCustoms(s.db).IdentityForToken(ctx, uid)
		if errors.Is(err, exceptions.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		name, err := clients.NewClientDbService(s.db).NameByID(ctx, id.ClientID)
		if err != nil {
			return nil, err
		}
		out = append(out, models.Company{ClientID: id.ClientID, Name: name})
	}
	return out, nil
}

// errChoiceInvalid is the one answer for a choice that cannot be completed.
var errChoiceInvalid = exceptions.NewAPIError(http.StatusUnauthorized, "Sign-in expired, please sign in again", nil)

func (s *loginService) Choices(ctx context.Context, ticket string) ([]models.Company, error) {
	st, err := loginstates.NewLoginStateDbService(s.db).Get(ctx, tokens.HashToken(ticket), dbmodels.LoginStateAccountChoice)
	if errors.Is(err, exceptions.ErrNoRows) {
		return nil, errChoiceInvalid
	}
	if err != nil {
		return nil, err
	}
	return s.companies(ctx, st.CandidateUserIDs)
}

// Choose completes an account choice. The ticket is checked, then consumed in
// one statement, so it opens exactly one session however often it is replayed;
// the chosen account's policy is applied again, since time has passed.
func (s *loginService) Choose(ctx context.Context, ticket, clientID string, m shared.ClientMeta) (models.Outcome, error) {
	states := loginstates.NewLoginStateDbService(s.db)
	hash := tokens.HashToken(ticket)
	st, err := states.Get(ctx, hash, dbmodels.LoginStateAccountChoice)
	if errors.Is(err, exceptions.ErrNoRows) {
		return models.Outcome{}, errChoiceInvalid
	}
	if err != nil {
		return models.Outcome{}, err
	}
	// Resolve the choice BEFORE consuming the ticket, so a stale page choosing a
	// company that is not on offer does not cost the person their sign-in.
	var chosen *dbmodels.UserIdentity
	for _, uid := range st.CandidateUserIDs {
		id, err := usercustoms.NewUserDbCustoms(s.db).IdentityForToken(ctx, uid)
		if errors.Is(err, exceptions.ErrNoRows) {
			continue
		}
		if err != nil {
			return models.Outcome{}, err
		}
		if id.ClientID == clientID {
			chosen = &id
			break
		}
	}
	if chosen == nil || st.AuthMethod == nil {
		return models.Outcome{}, errChoiceInvalid
	}
	if _, err := states.Take(ctx, hash, dbmodels.LoginStateAccountChoice); err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return models.Outcome{}, errChoiceInvalid
		}
		return models.Outcome{}, err
	}
	conn := deref(st.ConnectionID)
	ok, err := s.policy.Allows(ctx, chosen.ID, chosen.ClientID, *st.AuthMethod, conn)
	if err != nil {
		return models.Outcome{}, err
	}
	if !ok {
		return models.Outcome{}, errChoiceInvalid
	}
	signed, err := s.open(ctx, chosen.ID, chosen.ClientID, *st.AuthMethod, conn, m)
	if err != nil {
		return models.Outcome{}, err
	}
	return models.Outcome{Session: &signed, ReturnTo: shared.SafeReturnTo(deref(st.ReturnTo))}, nil
}

// Refresh rotates the App Central session's token and mints a fresh access
// token. A benign concurrent rotation surfaces as exceptions.ErrRotationRace,
// unwrapped.
func (s *loginService) Refresh(ctx context.Context, rawToken string, m shared.ClientMeta) (models.Signed, error) {
	iss, err := s.sessions.Rotate(ctx, rawToken, sessionmodels.Want{Kind: sessionmodels.KindCentral}, m)
	if err != nil {
		return models.Signed{}, err
	}
	return s.signed(ctx, iss)
}

func (s *loginService) Logout(ctx context.Context, rawToken string) error {
	return s.sessions.Logout(ctx, rawToken)
}

// Discover answers from the domain alone — never from whether the address has
// an account — so every address at a domain gets the same answer.
func (s *loginService) Discover(ctx context.Context, email string) (models.Discovery, error) {
	d := models.Discovery{Password: true, Google: s.google.Enabled()}
	domain := domainOf(shared.NormalizeEmail(email))
	if domain == "" {
		return d, nil
	}
	hint, found, err := s.policy.Hint(ctx, domain)
	if err != nil {
		return models.Discovery{}, err
	}
	if !found {
		return d, nil
	}
	return models.Discovery{
		Password: hint.AllowPassword, Google: hint.AllowGoogle && s.google.Enabled(), SSOConnectionID: hint.SSOConnectionID,
	}, nil
}

func domainOf(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
