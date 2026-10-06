// Package controller serves App Central sign-in: the password and account-choice
// steps, discovery, the App Central session's refresh and logout, and the
// Google and company SSO round trips.
package controller

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/alora/auth/internal/core/login/models"
	"github.com/alora/auth/internal/core/login/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// LoginController serves /auth/login/*, /auth/central/* and the federated
// round trips.
type LoginController struct {
	svc         service.LoginService
	jar         *shared.CookieJar
	frontendURL string
}

// NewLoginController builds the controller. frontendURL is App Central's origin,
// where a finished or failed round trip sends the browser.
func NewLoginController(svc service.LoginService, jar *shared.CookieJar, frontendURL string) *LoginController {
	return &LoginController{svc: svc, jar: jar, frontendURL: strings.TrimRight(frontendURL, "/")}
}

// Password handles POST /auth/login/password.
//
//	@Summary		Sign in with a password
//	@Description	Checks the password against every live account that holds the address. When exactly one opens and its company's login policy allows passwords, the App Central session starts: its refresh token is set as the HttpOnly session cookie and an App Central access token is returned. When the password opens accounts in several companies, the answer is `choose_company` with the list — shown only after the password was right — and POST /auth/login/choose completes it.
//	@Description
//	@Description	No account, a wrong password, and a right password on an account whose policy does not allow passwords all get the same 401, in the same time. Rate limited per minute by ip|email together.
//	@Tags			sign-in
//	@Accept			json
//	@Produce		json
//	@Param			request	body		models.PasswordLoginRequest	true	"Credentials"
//	@Success		200		{object}	models.LoginResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body or unknown field"
//	@Failure		401		{object}	exceptions.ErrorResponse	"Invalid email or password"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Cross-site request refused"
//	@Failure		415		{object}	exceptions.ErrorResponse	"Body is not application/json"
//	@Failure		429		{object}	exceptions.ErrorResponse	"Rate limited"
//	@Router			/auth/login/password [post]
func (h *LoginController) Password(c *gin.Context) {
	var req models.PasswordLoginRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	out, err := h.svc.Password(c.Request.Context(), req.Email, req.Password, req.ReturnTo, shared.MetaFrom(c))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	h.respond(c, out)
}

// respond sets the cookie an outcome calls for and renders it.
func (h *LoginController) respond(c *gin.Context, out models.Outcome) {
	if out.Session != nil {
		h.jar.SetCentral(c, out.Session.RefreshToken, out.Session.RefreshTTL)
		h.jar.ClearChooser(c)
	} else {
		h.jar.SetChooser(c, out.Ticket)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, models.NewLoginResponse(out))
}

// Choices handles GET /auth/login/choices.
//
//	@Summary		List the companies of a pending account choice
//	@Description	For the page shown after Google proved accounts in several companies. The choice is bound to this browser by an HttpOnly cookie and lasts five minutes.
//	@Tags			sign-in
//	@Produce		json
//	@Success		200	{object}	models.ChoicesResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"No pending choice"
//	@Router			/auth/login/choices [get]
func (h *LoginController) Choices(c *gin.Context) {
	ticket, ok := h.jar.Chooser(c)
	if !ok {
		exceptions.FailWith(c, http.StatusUnauthorized, "Sign-in expired, please sign in again")
		return
	}
	cs, err := h.svc.Choices(c.Request.Context(), ticket)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, models.NewChoicesResponse(cs))
}

// Choose handles POST /auth/login/choose.
//
//	@Summary		Complete an account choice
//	@Description	Starts the App Central session in the chosen company. The choice is single-use, and the chosen account's login policy is applied again.
//	@Tags			sign-in
//	@Accept			json
//	@Produce		json
//	@Param			request	body		models.ChooseRequest	true	"The company"
//	@Success		200		{object}	models.LoginResponse
//	@Failure		401		{object}	exceptions.ErrorResponse	"No pending choice, or the company is not on offer"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Cross-site request refused"
//	@Router			/auth/login/choose [post]
func (h *LoginController) Choose(c *gin.Context) {
	ticket, ok := h.jar.Chooser(c)
	if !ok {
		exceptions.FailWith(c, http.StatusUnauthorized, "Sign-in expired, please sign in again")
		return
	}
	var req models.ChooseRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	out, err := h.svc.Choose(c.Request.Context(), ticket, req.ClientID, shared.MetaFrom(c))
	if err != nil {
		h.jar.ClearChooser(c)
		exceptions.Fail(c, err)
		return
	}
	h.respond(c, out)
}

// Discover handles POST /auth/login/discover.
//
//	@Summary		Which sign-in methods to offer
//	@Description	Answers from the address's DOMAIN alone: a company that registered the domain on an SSO connection gets that connection; a company with that verified domain gets what its default policy allows; any other domain gets the defaults. Every address at a domain gets the same answer, so it reveals nothing about any account — and every sign-in path enforces the user's own policy regardless.
//	@Tags			sign-in
//	@Accept			json
//	@Produce		json
//	@Param			request	body		models.DiscoverRequest	true	"The address"
//	@Success		200		{object}	models.DiscoverResponse
//	@Router			/auth/login/discover [post]
func (h *LoginController) Discover(c *gin.Context) {
	var req models.DiscoverRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	d, err := h.svc.Discover(c.Request.Context(), req.Email)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewDiscoverResponse(d))
}

// Refresh handles POST /auth/central/refresh.
//
//	@Summary		Refresh the App Central session
//	@Description	Rotates the refresh token in the session cookie and returns a new App Central access token. Takes no body. The session's rules are checked again first: the user and company active, the login policy still allowing how the user signed in (a session that no longer qualifies is ended), and the absolute fourteen-day cap.
//	@Description
//	@Description	Presenting a token that was already rotated away means two parties hold the chain, so the session and every product login under it are revoked. The one exception is a benign concurrent rotation, answered 409 with the cookie left intact.
//	@Tags			sign-in
//	@Produce		json
//	@Success		200	{object}	models.CentralTokenResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Session invalid or expired; cookie cleared"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Cross-site request refused"
//	@Failure		409	{object}	exceptions.ErrorResponse	"Concurrent rotation — retry"
//	@Router			/auth/central/refresh [post]
func (h *LoginController) Refresh(c *gin.Context) {
	raw, ok := h.jar.Central(c)
	if !ok {
		h.jar.ClearCentral(c)
		exceptions.Fail(c, exceptions.ErrSessionInvalid)
		return
	}
	res, err := h.svc.Refresh(c.Request.Context(), raw, shared.MetaFrom(c))
	if err != nil {
		// A benign concurrent rotation must NOT clear the cookie: the winning
		// request's token is still valid and the client should simply retry.
		if !errors.Is(err, exceptions.ErrRotationRace) {
			h.jar.ClearCentral(c)
		}
		exceptions.Fail(c, err)
		return
	}
	h.jar.SetCentral(c, res.RefreshToken, res.RefreshTTL)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, models.NewCentralTokenResponse(res))
}

// Logout handles POST /auth/central/logout. Always 204: revealing whether the
// presented token existed would leak session state.
//
//	@Summary		Sign out of App Central
//	@Description	Ends the App Central session and every product login opened under it: no product can renew its tokens afterwards. A product access token already issued stays valid until it expires, unless the product introspects it. Always 204.
//	@Tags			sign-in
//	@Success		204	"Signed out, or there was nothing to end"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Cross-site request refused"
//	@Router			/auth/central/logout [post]
func (h *LoginController) Logout(c *gin.Context) {
	if raw, ok := h.jar.Central(c); ok {
		if err := h.svc.Logout(c.Request.Context(), raw); err != nil {
			exceptions.Fail(c, err)
			return
		}
	}
	h.jar.ClearCentral(c)
	h.jar.ClearChooser(c)
	c.Status(http.StatusNoContent)
}

// GoogleStart handles GET /auth/google/start.
//
//	@Summary		Begin Google sign-in
//	@Description	A browser navigation: answers 302 to Google's consent screen, with PKCE, a state bound to this browser by an HttpOnly cookie, and a nonce bound to the ID token. `return_to` must be a path on App Central; anything else is dropped.
//	@Tags			sign-in
//	@Param			return_to	query	string	false	"Where to go after signing in"
//	@Success		302						"Redirect to Google"
//	@Failure		302						"Redirect to /login?google_error=google_disabled when Google sign-in is not configured"
//	@Router			/auth/google/start [get]
func (h *LoginController) GoogleStart(c *gin.Context) {
	var q models.FederatedStartRequest
	_ = c.ShouldBindQuery(&q)
	state, u, err := h.svc.GoogleStart(c.Request.Context(), q.ReturnTo)
	if err != nil {
		if errors.Is(err, service.ErrGoogleDisabled) {
			h.fail(c, "google_error", service.CodeGoogleDisabled)
			return
		}
		exceptions.Fail(c, err)
		return
	}
	h.jar.SetLogin(c, state)
	c.Redirect(http.StatusFound, u)
}

// GoogleCallback handles GET /auth/google/callback.
//
//	@Summary		Google sign-in callback
//	@Description	The return leg from Google. Always answers 302: to the return path on success, to /login for a choice between companies, or to /login?google_error=<code> on failure.
//	@Description
//	@Description	The state must match the browser's cookie and still be pending (single use, ten minutes). Google's ID token must verify — RS256 against Google's keys, issuer, audience, expiry and nonce. A linked Google identity signs in its accounts; otherwise a verified address signs in, and links, each live account that holds it. Google never creates an account, and each account's policy must allow Google.
//	@Tags			sign-in
//	@Param			state	query	string	true	"Must match the browser's pending sign-in"
//	@Param			code	query	string	true	"Google's authorization code"
//	@Success		302						"Signed in, or on to the account choice"
//	@Failure		302						"Redirect to /login?google_error=invalid_request, state_mismatch, state_expired, exchange_failed, email_unverified, account_unavailable or server_error"
//	@Router			/auth/google/callback [get]
func (h *LoginController) GoogleCallback(c *gin.Context) {
	h.callback(c, "google_error", h.svc.GoogleCallback)
}

// SSOStart handles GET /auth/sso/start.
//
//	@Summary		Begin company SSO sign-in
//	@Description	A browser navigation: answers 302 to the company's identity provider, with PKCE, state and nonce. The connection is named by `connection_id`, or found from the domain of `email`.
//	@Tags			sign-in
//	@Param			connection_id	query	string	false	"The SSO connection"
//	@Param			email			query	string	false	"An address at a domain registered on a connection"
//	@Param			return_to		query	string	false	"Where to go after signing in"
//	@Success		302								"Redirect to the identity provider"
//	@Failure		302								"Redirect to /login?sso_error=sso_unavailable"
//	@Router			/auth/sso/start [get]
func (h *LoginController) SSOStart(c *gin.Context) {
	var q models.FederatedStartRequest
	_ = c.ShouldBindQuery(&q)
	state, u, err := h.svc.SSOStart(c.Request.Context(), q.ConnectionID, q.Email, q.ReturnTo)
	if err != nil {
		if errors.Is(err, service.ErrSSOUnavailable) {
			h.fail(c, "sso_error", service.CodeSSOUnavailable)
			return
		}
		exceptions.Fail(c, err)
		return
	}
	h.jar.SetLogin(c, state)
	c.Redirect(http.StatusFound, u)
}

// SSOCallback handles GET /auth/sso/callback.
//
//	@Summary		Company SSO sign-in callback
//	@Description	The return leg from the identity provider. Always answers 302. The ID token must verify against the provider's own keys (RS256), with its issuer, audience, authorized party, expiry and nonce. A linked subject signs in its account. Otherwise the first sign-in links by address — only at a domain registered on the connection, with a verified address (unless the Owner trusts the connection's addresses), to an account that already exists. SSO never creates an account.
//	@Tags			sign-in
//	@Param			state	query	string	true	"Must match the browser's pending sign-in"
//	@Param			code	query	string	true	"The provider's authorization code"
//	@Success		302						"Signed in"
//	@Failure		302						"Redirect to /login?sso_error=<code>"
//	@Router			/auth/sso/callback [get]
func (h *LoginController) SSOCallback(c *gin.Context) {
	h.callback(c, "sso_error", h.svc.SSOCallback)
}

func (h *LoginController) callback(c *gin.Context, param string,
	finish func(context.Context, string, string, string, shared.ClientMeta) (models.Outcome, error)) {
	cookieState, _ := h.jar.Login(c)
	h.jar.ClearLogin(c)
	// The provider reports a refusal (the user cancelled, or it declined) as an
	// error parameter instead of a code.
	if c.Query("error") != "" {
		h.fail(c, param, "cancelled")
		return
	}
	out, err := finish(c.Request.Context(), cookieState, c.Query("state"), c.Query("code"), shared.MetaFrom(c))
	if err != nil {
		var ce *models.CallbackError
		if errors.As(err, &ce) {
			h.fail(c, param, ce.Code)
			return
		}
		h.fail(c, param, service.CodeServerError)
		return
	}
	if out.Session == nil {
		h.jar.SetChooser(c, out.Ticket)
		c.Redirect(http.StatusFound, h.frontendURL+"/login?choose=1")
		return
	}
	h.jar.SetCentral(c, out.Session.RefreshToken, out.Session.RefreshTTL)
	target := out.ReturnTo
	if target == "" {
		target = "/"
	}
	c.Redirect(http.StatusFound, h.frontendURL+target)
}

// fail sends the browser back to the login page with a failure code the page
// understands. The code is from a closed set, never provider-supplied text.
func (h *LoginController) fail(c *gin.Context, param, code string) {
	c.Redirect(http.StatusFound, h.frontendURL+"/login?"+param+"="+url.QueryEscape(code))
}
