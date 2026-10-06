// Package controller serves App Central's OpenID Provider endpoints: the
// browser-facing /oauth/authorize, and the server-to-server token, revocation
// and introspection endpoints products call with their client secret.
package controller

import (
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alora/auth/internal/core/oauth/models"
	"github.com/alora/auth/internal/core/oauth/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// OAuthController serves /oauth/*.
type OAuthController struct {
	svc         service.OAuthService
	jar         *shared.CookieJar
	issuer      string
	frontendURL string
}

// NewOAuthController builds the controller. issuer is echoed as the iss
// parameter of every authorization response (RFC 9207); frontendURL is where
// the login page is.
func NewOAuthController(svc service.OAuthService, jar *shared.CookieJar, issuer, frontendURL string) *OAuthController {
	return &OAuthController{svc: svc, jar: jar, issuer: issuer, frontendURL: strings.TrimRight(frontendURL, "/")}
}

// Authorize handles GET /oauth/authorize.
//
//	@Summary		Authorization endpoint
//	@Description	A browser navigation, started by a product's backend (usually from its `initiate_login_uri` when App Central launches it). With a usable App Central session, and access to the product, it answers 302 straight back to `redirect_uri` with `code`, `state` and `iss` — no page is shown. Without a session it sends the browser to App Central's login page and resumes here afterwards; with `prompt=none` it answers `error=login_required` instead.
//	@Description
//	@Description	An unknown `client_id` or a `redirect_uri` that is not registered byte for byte is shown as an error here and never redirected. Every later failure redirects to `redirect_uri` with an OAuth error: `unsupported_response_type`, `invalid_request` (PKCE with S256 is required), `invalid_scope`, `login_required` or `access_denied` (no role in the product, no live subscription, or an inactive product). A parameter given twice is refused — `client_id` or `redirect_uri` here, any other with `invalid_request`.
//	@Tags			provider
//	@Param			response_type			query	string	true	"Must be code"	Enums(code)
//	@Param			client_id				query	string	true	"The product's id"
//	@Param			redirect_uri			query	string	true	"One of the product's registered redirect URIs, exactly"
//	@Param			scope					query	string	false	"openid email profile; openid adds an ID token"
//	@Param			state					query	string	false	"Echoed back on the redirect"
//	@Param			nonce					query	string	false	"Echoed in the ID token"
//	@Param			code_challenge			query	string	true	"base64url(sha256(code_verifier))"
//	@Param			code_challenge_method	query	string	true	"Must be S256"	Enums(S256)
//	@Param			prompt					query	string	false	"none: never show a page; login: always sign in again"
//	@Success		302						"To redirect_uri with a code, or to the login page"
//	@Failure		400	{object}	exceptions.ErrorResponse	"Unknown application or unregistered redirect URI"
//	@Router			/oauth/authorize [get]
func (h *OAuthController) Authorize(c *gin.Context) {
	var q models.AuthorizeRequest
	_ = c.ShouldBindQuery(&q)

	// A parameter given twice is refused (RFC 6749 §3.1): which copy counts must
	// not be something App Central and a proxy in front of it can disagree on.
	query := c.Request.URL.Query()
	if repeated(query, "client_id", "redirect_uri") {
		exceptions.Fail(c, errRepeatedClient)
		return
	}
	client, err := h.svc.Client(c.Request.Context(), q.ClientID, q.RedirectURI)
	if err != nil {
		// Before the redirect URI is known to be the product's own, nothing may be
		// sent to it: an open redirector is exactly what an attacker wants.
		exceptions.Fail(c, err)
		return
	}
	redirectErr := func(code, desc string) {
		h.redirect(c, q.RedirectURI, q.State, url.Values{"error": {code}, "error_description": {desc}})
	}

	if repeated(query, authorizeParams...) {
		redirectErr("invalid_request", "A parameter is repeated")
		return
	}
	if q.ResponseType != "code" {
		redirectErr("unsupported_response_type", "Only response_type=code is supported")
		return
	}
	if q.CodeChallengeMethod != "S256" || len(q.CodeChallenge) < 43 || len(q.CodeChallenge) > 128 {
		redirectErr("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	if len(q.State) > 1024 || len(q.Nonce) > 512 {
		redirectErr("invalid_request", "state or nonce is too long")
		return
	}
	for _, s := range strings.Fields(q.Scope) {
		if !service.SupportedScopes[s] {
			redirectErr("invalid_scope", "Unsupported scope "+s)
			return
		}
	}
	prompts := strings.Fields(q.Prompt)
	if contains(prompts, "none") && len(prompts) > 1 {
		redirectErr("invalid_request", "prompt=none cannot be combined")
		return
	}

	// prompt=login: sign in again whatever the session. The return path drops
	// the prompt, or the page would send the browser round in a circle.
	if contains(prompts, "login") {
		h.toLogin(c, withoutPrompt(c.Request.URL))
		return
	}

	raw, _ := h.jar.Central(c)
	out, err := h.svc.Authorize(c.Request.Context(), models.AuthorizeInput{
		Client: client, RedirectURI: q.RedirectURI, Scope: strings.Join(strings.Fields(q.Scope), " "),
		Nonce: q.Nonce, CodeChallenge: q.CodeChallenge,
	}, raw, shared.MetaFrom(c))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	if out.Central != nil {
		h.jar.SetCentral(c, out.Central.Token, time.Duration(out.Central.TTL)*time.Second)
	}
	switch {
	case out.LoginRequired:
		if raw != "" {
			h.jar.ClearCentral(c)
		}
		if contains(prompts, "none") {
			redirectErr("login_required", "Sign-in at App Central is required")
			return
		}
		h.toLogin(c, c.Request.URL)
	case out.AccessDenied:
		redirectErr("access_denied", "The user may not use this application")
	default:
		h.redirect(c, q.RedirectURI, q.State, url.Values{"code": {out.Code}})
	}
}

// redirect sends the browser to a (validated) redirect URI with the given
// parameters, the client's state, and the issuer (RFC 9207, so a client talking
// to several providers can tell which one answered).
func (h *OAuthController) redirect(c *gin.Context, redirectURI, state string, params url.Values) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	q := u.Query()
	for k, vs := range params {
		q[k] = vs
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", h.issuer)
	u.RawQuery = q.Encode()
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, u.String())
}

// toLogin sends the browser to the login page, which returns here afterwards.
func (h *OAuthController) toLogin(c *gin.Context, resume *url.URL) {
	returnTo := resume.Path
	if resume.RawQuery != "" {
		returnTo += "?" + resume.RawQuery
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, h.frontendURL+"/login?return_to="+url.QueryEscape(returnTo))
}

func withoutPrompt(u *url.URL) *url.URL {
	out := *u
	q := out.Query()
	q.Del("prompt")
	out.RawQuery = q.Encode()
	return &out
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// authorizeParams are the parameters /oauth/authorize reads. Any other is
// ignored, repeated or not, as RFC 6749 §3.1 requires of an unknown parameter.
var authorizeParams = []string{"response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
	"code_challenge", "code_challenge_method", "prompt"}

// errRepeatedClient answers a repeated client_id or redirect_uri, which is shown
// here and never redirected: which redirect URI would be trusted is the question.
var errRepeatedClient = exceptions.NewAPIError(http.StatusBadRequest, "client_id or redirect_uri is repeated", nil)

// repeated reports whether any of names appears more than once in q.
func repeated(q url.Values, names ...string) bool {
	for _, n := range names {
		if len(q[n]) > 1 {
			return true
		}
	}
	return false
}

// Token handles POST /oauth/token.
//
//	@Summary		Token endpoint
//	@Description	Called by a product's backend or an application, never a browser: form-encoded (application/x-www-form-urlencoded), authenticated with HTTP Basic (client_secret_basic, the client id and secret each form-encoded). Every response is `Cache-Control: no-store`.
//	@Description
//	@Description	`grant_type=authorization_code` redeems a code with `code`, `redirect_uri` (exactly as sent to /oauth/authorize) and the PKCE `code_verifier`. A code works once; presenting it again revokes the login it opened. The result is an access token for this product alone (audience `product:<key>`, this product's roles only, fifteen minutes), a refresh token, and — when the scope included openid — an ID token.
//	@Description
//	@Description	`grant_type=refresh_token` rotates the refresh token: the old one stops working, and replaying it revokes this product's login. Each refresh checks everything again — the App Central session above it, the user, the company, the login policy and the user's access to the product — and a login that no longer qualifies is ended.
//	@Description
//	@Description	`grant_type=client_credentials` is for API clients only (products use the two grants above): `resource=product:<key>` (RFC 8707) names one product on the client's list, and the optional `scope` asks for some of the scopes it holds (all of them without it). The result is an access token for that product (audience `product:<key>`, `principal` "client", its `scope`, no roles, fifteen minutes) with no refresh token and no ID token. A product unknown, not on the list or not usable is `invalid_target`; a scope the client lacks is `invalid_scope`; a grant the client may not use is `unauthorized_client`.
//	@Tags			provider
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			Authorization	header		string	true	"Basic base64(client_id:client_secret)"
//	@Param			grant_type		formData	string	true	"authorization_code, refresh_token or client_credentials"
//	@Param			code			formData	string	false	"authorization_code: the code"
//	@Param			redirect_uri	formData	string	false	"authorization_code: the redirect URI"
//	@Param			code_verifier	formData	string	false	"authorization_code: the PKCE verifier"
//	@Param			refresh_token	formData	string	false	"refresh_token: the refresh token"
//	@Param			resource		formData	string	false	"client_credentials: product:<key>"
//	@Param			scope			formData	string	false	"client_credentials: the scopes wanted, space-separated"
//	@Success		200				{object}	models.TokenResponse
//	@Failure		400				{object}	models.ErrorResponse	"invalid_request, invalid_grant, invalid_target, invalid_scope, unauthorized_client or unsupported_grant_type"
//	@Failure		401				{object}	models.ErrorResponse	"invalid_client"
//	@Failure		409				{object}	models.ErrorResponse	"A concurrent refresh of the same token"
//	@Router			/oauth/token [post]
func (h *OAuthController) Token(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	client, form, ok := h.authenticate(c)
	if !ok {
		return
	}
	var set models.TokenSet
	var err error
	switch form.Get("grant_type") {
	case "authorization_code":
		set, err = h.svc.ExchangeCode(c.Request.Context(), client, form.Get("code"), form.Get("redirect_uri"),
			form.Get("code_verifier"), shared.MetaFrom(c))
	case "refresh_token":
		set, err = h.svc.Refresh(c.Request.Context(), client, form.Get("refresh_token"), shared.MetaFrom(c))
	case "client_credentials":
		set, err = h.svc.ClientCredentials(c.Request.Context(), client, form.Get("resource"), form.Get("scope"))
	case "":
		err = models.InvalidRequestError("grant_type is required")
	default:
		err = models.UnsupportedGrantTypeError()
	}
	if err != nil {
		h.oauthFail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewTokenResponse(set))
}

// Revoke handles POST /oauth/revoke.
//
//	@Summary		Revocation endpoint (RFC 7009)
//	@Description	Ends the product login a refresh token or access token belongs to — for signing a user out of one product. Authenticated like the token endpoint, by products only: an API client is `unauthorized_client`. Always 200, whatever the token: an unknown token, an expired one or another product's is simply not acted on.
//	@Tags			provider
//	@Accept			x-www-form-urlencoded
//	@Param			Authorization	header		string	true	"Basic base64(client_id:client_secret)"
//	@Param			token			formData	string	true	"A refresh or access token"
//	@Success		200				"Done, or nothing to do"
//	@Failure		400				{object}	models.ErrorResponse	"unauthorized_client: an API client"
//	@Failure		401				{object}	models.ErrorResponse	"invalid_client"
//	@Router			/oauth/revoke [post]
func (h *OAuthController) Revoke(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	client, form, ok := h.authenticate(c)
	if !ok {
		return
	}
	if err := h.svc.Revoke(c.Request.Context(), client, form.Get("token")); err != nil {
		h.oauthFail(c, err)
		return
	}
	c.Status(http.StatusOK)
}

// Introspect handles POST /oauth/introspect.
//
//	@Summary		Introspection endpoint (RFC 7662)
//	@Description	Whether a token is usable RIGHT NOW — for a product that must honour sign-out and role changes within seconds rather than when its fifteen-minute token expires. A person's access token (`principal` "user") is active only while its product login, the App Central session above it, the user and the company are live, the user still has access, and its roles are still current. An application's (`principal` "client") is active only while its API client and company are on, the secret it was issued under is live, the product is still on the client's list and usable, and the client still holds every scope in it. A product may introspect only tokens for itself; anything else is `{"active": false}`. Products only: an API client is `unauthorized_client`.
//	@Tags			provider
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			Authorization	header		string	true	"Basic base64(client_id:client_secret)"
//	@Param			token			formData	string	true	"An access or refresh token"
//	@Success		200				{object}	models.IntrospectionResponse
//	@Failure		400				{object}	models.ErrorResponse	"unauthorized_client: an API client"
//	@Failure		401				{object}	models.ErrorResponse	"invalid_client"
//	@Router			/oauth/introspect [post]
func (h *OAuthController) Introspect(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	client, form, ok := h.authenticate(c)
	if !ok {
		return
	}
	res, err := h.svc.Introspect(c.Request.Context(), client, form.Get("token"))
	if err != nil {
		h.oauthFail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewIntrospectionResponse(res))
}

// authenticate reads the form body and the client's Basic credentials. It
// answers the request itself (and returns false) when either is unusable.
func (h *OAuthController) authenticate(c *gin.Context) (models.Client, url.Values, bool) {
	mt, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" {
		h.oauthFail(c, models.InvalidRequestError("The body must be application/x-www-form-urlencoded"))
		return models.Client{}, nil, false
	}
	if err := c.Request.ParseForm(); err != nil {
		h.oauthFail(c, models.InvalidRequestError("Malformed form body"))
		return models.Client{}, nil, false
	}
	form := c.Request.PostForm
	// Parameters are never read from the query string: a secret or code there
	// ends up in logs. And each may appear once (RFC 6749 §3.2).
	for k, vs := range form {
		if !shared.Storable(k) || !shared.AllStorable(vs) {
			h.oauthFail(c, models.InvalidRequestError("Parameters must be UTF-8 text without NUL characters"))
			return models.Client{}, nil, false
		}
		if len(vs) > 1 {
			h.oauthFail(c, models.InvalidRequestError("Parameter "+k+" is repeated"))
			return models.Client{}, nil, false
		}
	}
	id, secret, ok := basicAuth(c.GetHeader("Authorization"))
	if !ok || form.Get("client_secret") != "" || (form.Get("client_id") != "" && form.Get("client_id") != id) {
		// One method only: client_secret_basic. A secret in the body is refused
		// rather than silently ignored, so a misconfigured client finds out.
		h.oauthFail(c, models.InvalidClientError())
		return models.Client{}, nil, false
	}
	client, err := h.svc.Authenticate(c.Request.Context(), id, secret)
	if err != nil {
		h.oauthFail(c, err)
		return models.Client{}, nil, false
	}
	return client, form, true
}

// basicAuth decodes client_secret_basic: base64 of the form-encoded id and
// secret, joined by a colon (RFC 6749 §2.3.1).
func basicAuth(header string) (id, secret string, ok bool) {
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", "", false
	}
	encID, encSecret, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	if id, err = url.QueryUnescape(encID); err != nil {
		return "", "", false
	}
	if secret, err = url.QueryUnescape(encSecret); err != nil {
		return "", "", false
	}
	// A client id or secret the database cannot store is no client's: the same
	// invalid_client as any other failed authentication.
	return id, secret, id != "" && secret != "" && shared.Storable(id) && shared.Storable(secret)
}

// oauthFail renders an OAuth error as RFC 6749 §5.2 JSON; anything else is an
// ordinary server error.
func (h *OAuthController) oauthFail(c *gin.Context, err error) {
	var oe *models.Error
	if errors.As(err, &oe) {
		if oe.Status == http.StatusUnauthorized {
			c.Header("WWW-Authenticate", `Basic realm="app-central"`)
		}
		c.AbortWithStatusJSON(oe.Status, models.NewErrorResponse(oe))
		return
	}
	exceptions.Fail(c, err)
}
