package models

// Response models. Fields are declared in alphabetical order of their JSON names.

// TokenResponse is a successful token endpoint response (RFC 6749 §5.1).
type TokenResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiYXQrand0In0..."`
	ExpiresIn    int    `json:"expires_in" example:"900"`
	IDToken      string `json:"id_token,omitempty" example:"eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0..."`
	RefreshToken string `json:"refresh_token,omitempty" example:"3f1c8a0e9d2b4f7a3c5e8b1d0a9f2c4e6f1c8a0e9d2b4f7a3c5e8b1d0a9f2c4e"`
	Scope        string `json:"scope,omitempty" example:"openid email"`
	TokenType    string `json:"token_type" example:"Bearer"`
} //@name OAuthTokenResponse

// NewTokenResponse renders a token set.
func NewTokenResponse(t TokenSet) TokenResponse {
	return TokenResponse{
		AccessToken: t.AccessToken, ExpiresIn: t.ExpiresIn, IDToken: t.IDToken,
		RefreshToken: t.RefreshToken, Scope: t.Scope, TokenType: "Bearer",
	}
}

// ErrorResponse is an OAuth 2.0 error (RFC 6749 §5.2).
type ErrorResponse struct {
	Error            string `json:"error" example:"invalid_grant"`
	ErrorDescription string `json:"error_description,omitempty" example:"The authorization code is invalid, expired or already used"`
} //@name OAuthError

// NewErrorResponse renders an OAuth error.
func NewErrorResponse(e *Error) ErrorResponse {
	return ErrorResponse{Error: e.Code, ErrorDescription: e.Description}
}

// IntrospectionResponse is an RFC 7662 answer. An inactive token is reported as
// {"active": false} and nothing else.
type IntrospectionResponse struct {
	Active    bool     `json:"active" example:"true"`
	Aud       string   `json:"aud,omitempty" example:"product:CRM"`
	ClientID  string   `json:"client_id,omitempty" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	Email     string   `json:"email,omitempty" example:"alice@acme.com"`
	Exp       int64    `json:"exp,omitempty" example:"1767225600"`
	Iat       int64    `json:"iat,omitempty" example:"1767224700"`
	Iss       string   `json:"iss,omitempty" example:"https://central.alora.io"`
	Principal string   `json:"principal,omitempty" example:"user" enums:"user,client"`
	Roles     []string `json:"roles,omitempty" example:"Admin"`
	Scope     string   `json:"scope,omitempty" example:"api:read grpc:read"`
	Sid       string   `json:"sid,omitempty" example:"7e8f9a0b-1c2d-3e4f-5a6b-7c8d9e0f1a2b"`
	Sub       string   `json:"sub,omitempty" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
	TenantID  string   `json:"tenant_id,omitempty" example:"5c6d7e8f-9a0b-1c2d-3e4f-5a6b7c8d9e0f"`
	TokenType string   `json:"token_type,omitempty" example:"Bearer"`
} //@name IntrospectionResponse

// NewIntrospectionResponse renders an introspection.
func NewIntrospectionResponse(i Introspection) IntrospectionResponse {
	if !i.Active {
		return IntrospectionResponse{}
	}
	return IntrospectionResponse{
		Active: true, Aud: i.Audience, ClientID: i.ClientID, Email: i.Email, Exp: i.ExpiresAt, Iat: i.IssuedAt,
		Iss: i.Issuer, Principal: i.Principal, Roles: i.Roles, Scope: i.Scope, Sid: i.SessionID, Sub: i.Subject,
		TenantID: i.TenantID, TokenType: i.TokenType,
	}
}
