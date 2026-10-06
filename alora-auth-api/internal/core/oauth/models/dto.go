// Package models holds the OpenID Provider feature's DTOs and HTTP
// request/response models.
package models

import "net/http"

// Kinds of OAuth client.
const (
	KindProduct   = "PRODUCT"    // a product's backend, which signs people in
	KindAPIClient = "API_CLIENT" // an application, which uses client credentials
)

// Client is an OAuth client as the provider sees it: a product, or an API
// client.
type Client struct {
	ID        string // client_id
	Kind      string
	Key       string // a product's: tokens for it carry the audience "product:<key>"
	CompanyID string // an API client's company
	SecretID  string // an API client's: the secret it authenticated with
}

// AuthorizeInput is an authorization request whose client and redirect URI have
// already been validated.
type AuthorizeInput struct {
	Client        Client
	RedirectURI   string
	Scope         string
	Nonce         string
	CodeChallenge string
}

// CentralCookie is the App Central session's rotated refresh token, for the
// session cookie.
type CentralCookie struct {
	Token string
	TTL   int64 // seconds
}

// AuthorizeOutcome is what an authorization request produced.
type AuthorizeOutcome struct {
	Code          string         // set on success
	Central       *CentralCookie // set when the session's token was rotated
	LoginRequired bool           // no usable App Central session: sign in first
	AccessDenied  bool           // signed in, but not allowed to use the product
}

// TokenSet is a token endpoint response.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int
	Scope        string
}

// Introspection is an RFC 7662 answer. Only Active is set for an inactive token.
type Introspection struct {
	Active    bool
	TokenType string
	Principal string // who the token speaks for: a person ("user") or an application ("client")
	Subject   string
	ClientID  string
	TenantID  string
	Email     string
	Roles     []string
	Scope     string // an application token's scopes
	Audience  string
	Issuer    string
	SessionID string
	ExpiresAt int64
	IssuedAt  int64
}

// Error is an OAuth 2.0 error response (RFC 6749 §5.2): the status, the code a
// client acts on, and a description for its developers. It is never a secret.
type Error struct {
	Status      int
	Code        string
	Description string
}

func (e *Error) Error() string { return "oauth: " + e.Code + ": " + e.Description }

// The error codes, as RFC 6749 names them.
func InvalidRequestError(desc string) *Error {
	return &Error{http.StatusBadRequest, "invalid_request", desc}
}
func InvalidClientError() *Error {
	return &Error{http.StatusUnauthorized, "invalid_client", "Client authentication failed"}
}
func InvalidGrantError(desc string) *Error {
	return &Error{http.StatusBadRequest, "invalid_grant", desc}
}
func UnsupportedGrantTypeError() *Error {
	return &Error{http.StatusBadRequest, "unsupported_grant_type",
		"Only authorization_code, refresh_token and client_credentials are supported"}
}
func UnauthorizedClientError(desc string) *Error {
	return &Error{http.StatusBadRequest, "unauthorized_client", desc}
}
func InvalidScopeError(desc string) *Error {
	return &Error{http.StatusBadRequest, "invalid_scope", desc}
}

// InvalidTargetError is RFC 8707's answer for a resource that is missing,
// unknown, or not one the client may have a token for — one answer for all
// three, so it reveals nothing about products the client may not have.
func InvalidTargetError() *Error {
	return &Error{http.StatusBadRequest, "invalid_target",
		"resource must name a product this client may have a token for, as product:<key>"}
}

// ConcurrentRefreshError is a benign race: two requests of the product's backend
// refreshed the same token at once, and the other one won. The login is fine —
// the winner holds its new refresh token — so the loser must not treat this as
// a sign-out; it should use the token the winner stored.
func ConcurrentRefreshError() *Error {
	return &Error{http.StatusConflict, "invalid_grant", "Concurrent refresh of the same token; retry"}
}
