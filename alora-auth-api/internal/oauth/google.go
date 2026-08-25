package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alora/auth/internal/crypto/tokens"
	"github.com/alora/auth/internal/platform/database"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/alora/auth/internal/platform/httpx"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// stateTTL bounds a Google round-trip. Ten minutes is generous for a consent
// screen and short enough that a captured state parameter is quickly useless.
const stateTTL = 10 * time.Minute

// pendingState is the server side of the OAuth state parameter: the details a
// callback needs, held only under a random key the client cannot guess.
//
// These never travel to the browser in readable form. The browser gets a signed
// cookie carrying the same state value, so the callback must present BOTH — the
// cookie proves the request began in this browser (CSRF binding) and the store
// proves the state was minted by this server and not yet spent.
type pendingState struct {
	Nonce               string
	ProductID           string
	RedirectURL         string
	CodeChallenge       string
	CodeChallengeMethod string
	ClientState         string
	Expires             time.Time
}

// StateStore holds in-flight OAuth states.
//
// ⚠ PROCESS-LOCAL (Decision D6). Correct for a single instance; running multiple
// replicas requires externalising this to Redis, because the callback may land
// on a different pod than the one that started the flow.
type StateStore struct {
	mu sync.Mutex
	m  map[string]pendingState
}

func NewStateStore() *StateStore { return &StateStore{m: make(map[string]pendingState)} }

func (s *StateStore) Put(key string, v pendingState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Opportunistic sweep: without it an abandoned flow would leak an entry
	// forever, which an attacker could exploit to exhaust memory.
	now := time.Now()
	for k, e := range s.m {
		if now.After(e.Expires) {
			delete(s.m, k)
		}
	}
	s.m[key] = v
}

// Take returns and DELETES a state — single-use, so a replayed callback fails.
func (s *StateStore) Take(key string) (pendingState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	if !ok {
		return pendingState{}, false
	}
	delete(s.m, key)
	if time.Now().After(v.Expires) {
		return pendingState{}, false
	}
	return v, true
}

// GoogleConfig is the subset of provider settings this flow needs.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	FrontendURL  string
}

// GoogleHandler serves the federated-login leg.
type GoogleHandler struct {
	svc    *Service
	cfg    GoogleConfig
	states *StateStore
	jar    *httpx.CookieJar
	client *http.Client
	// tokenEndpoint / userinfoEndpoint are fields (not constants) so tests can
	// point them at a local stub instead of reaching Google.
	tokenEndpoint    string
	userinfoEndpoint string
}

func NewGoogleHandler(svc *Service, cfg GoogleConfig, jar *httpx.CookieJar) *GoogleHandler {
	return &GoogleHandler{
		svc: svc, cfg: cfg, states: NewStateStore(), jar: jar,
		client:           &http.Client{Timeout: 10 * time.Second},
		tokenEndpoint:    "https://oauth2.googleapis.com/token",
		userinfoEndpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
	}
}

// SetEndpoints overrides the provider endpoints (tests only).
func (g *GoogleHandler) SetEndpoints(token, userinfo string) {
	g.tokenEndpoint, g.userinfoEndpoint = token, userinfo
}

type startQuery struct {
	ProductID           string `form:"product_id"`
	RedirectURL         string `form:"redirect_url"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
	State               string `form:"state"`
}

// Start handles GET /auth/google — begins the federated flow.
func (g *GoogleHandler) Start(c *gin.Context) {
	var q startQuery
	_ = c.ShouldBindQuery(&q)
	if q.ProductID == "" || q.RedirectURL == "" || q.CodeChallenge == "" {
		httpx.FailWith(c, http.StatusBadRequest, "Invalid request")
		return
	}
	if q.CodeChallengeMethod != "" && q.CodeChallengeMethod != "S256" {
		httpx.FailWith(c, http.StatusBadRequest, "Invalid request")
		return
	}

	// The redirect target is validated HERE, before the user is sent to Google,
	// so an open-redirect attempt never reaches the consent screen.
	product, err := g.svc.q.GetProductById(c.Request.Context(), sqlc.GetProductByIdParams{
		PProductid: q.ProductID, PActiveonly: true,
	})
	if err != nil || !sameOrigin(q.RedirectURL, product.BaseUrl.String) {
		httpx.FailWith(c, http.StatusBadRequest, "Invalid request")
		return
	}

	state, err := tokens.GenerateOpaque()
	if err != nil {
		httpx.Fail(c, err)
		return
	}
	nonce, err := tokens.GenerateOpaque()
	if err != nil {
		httpx.Fail(c, err)
		return
	}

	g.states.Put(state, pendingState{
		Nonce: nonce, ProductID: q.ProductID, RedirectURL: q.RedirectURL,
		CodeChallenge: q.CodeChallenge, CodeChallengeMethod: "S256",
		ClientState: q.State, Expires: time.Now().Add(stateTTL),
	})
	// The signed cookie binds the callback to THIS browser: an attacker who
	// steals the state value alone still cannot complete the flow.
	g.jar.SetOAuthState(c, state)

	params := url.Values{
		"client_id":     {g.cfg.ClientID},
		"redirect_uri":  {g.cfg.RedirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"nonce":         {nonce},
		// Consent screens can be skipped, but we always want a fresh account
		// selection rather than silently reusing a signed-in Google account.
		"prompt": {"select_account"},
	}
	c.Redirect(http.StatusFound, "https://accounts.google.com/o/oauth2/v2/auth?"+params.Encode())
}

type googleTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// Callback handles GET /auth/google/callback.
//
// Errors redirect back to the frontend with a ?google_error= code rather than
// rendering an API error, because the user is in a browser mid-navigation.
func (g *GoogleHandler) Callback(c *gin.Context) {
	ctx := c.Request.Context()
	fail := func(code string) {
		g.jar.ClearOAuthState(c)
		c.Redirect(http.StatusFound,
			strings.TrimRight(g.cfg.FrontendURL, "/")+"/login?google_error="+url.QueryEscape(code))
	}

	state := c.Query("state")
	if state == "" || c.Query("code") == "" {
		fail("invalid_request")
		return
	}
	// CSRF binding: the signed cookie must carry the SAME state as the query.
	signed, err := c.Cookie(httpx.CookieOAuthState)
	if err != nil {
		fail("missing_state")
		return
	}
	cookieState, err := g.jar.Unsign(signed)
	if err != nil || cookieState != state {
		fail("state_mismatch")
		return
	}
	// Single-use: a replayed callback finds nothing.
	pending, ok := g.states.Take(state)
	if !ok {
		fail("state_expired")
		return
	}
	g.jar.ClearOAuthState(c)

	info, err := g.exchange(ctx, c.Query("code"))
	if err != nil {
		fail("exchange_failed")
		return
	}
	// An unverified Google address must never be trusted to match a local
	// account: anyone can claim an unverified address at some providers.
	if !info.EmailVerified || info.Email == "" || info.Sub == "" {
		fail("email_unverified")
		return
	}

	userID, err := g.resolveUser(ctx, info, pending.ProductID)
	if err != nil {
		fail("account_not_found")
		return
	}

	// Issue an authorization code exactly like the password flow, so the
	// browser-facing leg never carries a token.
	code, err := tokens.GenerateOpaque()
	if err != nil {
		fail("server_error")
		return
	}
	// The federated leg carries no client state of its own, so state is NULL.
	if _, err := g.svc.q.CreateAuthorizationCode(ctx, sqlc.CreateAuthorizationCodeParams{
		Code: code, ProductID: pending.ProductID, UserID: userID,
		RedirectUrl: pending.RedirectURL, CodeChallenge: pending.CodeChallenge,
		CodeChallengeMethod: "S256", State: pgtype.Text{},
		ExpiresAt: database.Timestamptz(time.Now().Add(CodeTTL)),
	}); err != nil {
		fail("server_error")
		return
	}

	target, err := url.Parse(pending.RedirectURL)
	if err != nil {
		fail("invalid_request")
		return
	}
	qs := target.Query()
	qs.Set("code", code)
	if pending.ClientState != "" {
		qs.Set("state", pending.ClientState)
	}
	target.RawQuery = qs.Encode()
	c.Redirect(http.StatusFound, target.String())
}

// exchange trades the Google authorization code for the caller's profile.
func (g *GoogleHandler) exchange(ctx context.Context, code string) (googleUserInfo, error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {g.cfg.ClientID},
		"client_secret": {g.cfg.ClientSecret},
		"redirect_uri":  {g.cfg.RedirectURI},
		"grant_type":    {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return googleUserInfo{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.client.Do(req)
	if err != nil {
		return googleUserInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return googleUserInfo{}, fmt.Errorf("google token endpoint: %s", resp.Status)
	}
	var tok googleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return googleUserInfo{}, err
	}

	// Prefer the id_token claims (signed by Google) and fall back to userinfo.
	if info, err := parseIDToken(tok.IDToken); err == nil && info.Sub != "" {
		return info, nil
	}
	if tok.AccessToken == "" {
		return googleUserInfo{}, errors.New("google: no usable token")
	}
	uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, g.userinfoEndpoint, nil)
	if err != nil {
		return googleUserInfo{}, err
	}
	uReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uResp, err := g.client.Do(uReq)
	if err != nil {
		return googleUserInfo{}, err
	}
	defer uResp.Body.Close()
	if uResp.StatusCode != http.StatusOK {
		return googleUserInfo{}, fmt.Errorf("google userinfo: %s", uResp.Status)
	}
	var info googleUserInfo
	if err := json.NewDecoder(uResp.Body).Decode(&info); err != nil {
		return googleUserInfo{}, err
	}
	return info, nil
}

// parseIDToken reads the claims payload of a JWT WITHOUT verifying its
// signature. That is safe ONLY because the token came directly from Google's
// token endpoint over TLS in the response to our authenticated request — it is
// never accepted from the client.
func parseIDToken(idToken string) (googleUserInfo, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return googleUserInfo{}, errors.New("malformed id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return googleUserInfo{}, err
	}
	// email_verified arrives as a bool from Google but as a string from some
	// providers, so accept either rather than silently treating it as false.
	var raw struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return googleUserInfo{}, err
	}
	verified := false
	switch v := raw.EmailVerified.(type) {
	case bool:
		verified = v
	case string:
		verified = v == "true"
	}
	return googleUserInfo{Sub: raw.Sub, Email: raw.Email, EmailVerified: verified}, nil
}

// resolveUser maps a Google identity to a local account.
//
// Federated login NEVER creates an account: a user must already have been
// invited. Auto-provisioning from a Google login would let anyone with a
// matching email domain into the tenant.
func (g *GoogleHandler) resolveUser(ctx context.Context, info googleUserInfo, _ string) (string, error) {
	// Preferred path: an existing link keyed by Google's STABLE subject id.
	// Matching on `sub` (not email) means a user who changes their Google email
	// keeps their account, and an attacker who acquires a recycled address does
	// not inherit one.
	link, err := g.svc.q.GetLinkedIdentity(ctx, sqlc.GetLinkedIdentityParams{
		Provider: sqlc.IdpProviderGOOGLE, ProviderID: info.Sub,
	})
	if err == nil {
		if !link.IsActive {
			return "", httpx.ErrAccountInactive
		}
		if err := g.assertTenantAllowsGoogle(ctx, link.ClientID); err != nil {
			return "", err
		}
		return link.UserID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	// First Google sign-in for an already-invited OAUTH_ONLY account: link it.
	//
	// The tenant is resolved from the email's DOMAIN against a client whose domain
	// is both present and VERIFIED (tbl_clients.domain_verified_at). Requiring
	// verification is what stops someone registering a Google account at an
	// unclaimed domain and landing inside somebody else's organisation.
	email := httpx.NormalizeEmail(info.Email)
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return "", errors.New("malformed email")
	}
	clientID, err := g.svc.q.ClientIdByVerifiedDomain(ctx, email[at+1:])
	if err != nil {
		return "", errors.New("no tenant for domain")
	}

	// The account must ALREADY exist as OAUTH_ONLY (i.e. it was invited).
	// Federated login never creates accounts.
	user, err := g.svc.q.GetOAuthLinkableUser(ctx, sqlc.GetOAuthLinkableUserParams{
		PClientid: clientID, PEmail: email,
	})
	if err != nil {
		return "", errors.New("no linkable account")
	}
	if err := g.assertTenantAllowsGoogle(ctx, user.ClientID); err != nil {
		return "", err
	}
	if _, err := g.svc.q.CreateLinkedIdentity(ctx, sqlc.CreateLinkedIdentityParams{
		UserID: user.ID, Provider: sqlc.IdpProviderGOOGLE,
		ProviderID: info.Sub, EmailVerified: info.EmailVerified,
	}); err != nil {
		return "", err
	}
	return user.ID, nil
}

// assertTenantAllowsGoogle enforces the per-tenant IdP policy: an organisation
// that has not enabled GOOGLE must not be reachable through it, and a suspended
// tenant must not be reachable at all.
func (g *GoogleHandler) assertTenantAllowsGoogle(ctx context.Context, clientID string) error {
	row, err := g.svc.q.GetClientOAuthGate(ctx, clientID)
	if err != nil {
		return err
	}
	if !row.IsActive {
		return httpx.ErrForbidden
	}
	for _, p := range row.AllowedIdpProviders {
		if p == sqlc.IdpProviderGOOGLE {
			return nil
		}
	}
	return httpx.ErrForbidden
}
