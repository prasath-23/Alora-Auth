package models

import "time"

// Response models. Fields are declared in alphabetical order of their JSON names.

// ConnectionResponse is one SSO connection. The secret is never returned, only
// whether one is set.
type ConnectionResponse struct {
	ClientID             string     `json:"client_id" example:"0oa1b2c3d4e5f6g7h8i9"`
	CreatedAt            *time.Time `json:"created_at"`
	Domains              []string   `json:"domains" example:"acme.com"`
	HasSecret            bool       `json:"has_secret" example:"true"`
	ID                   string     `json:"id" example:"9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"`
	IsActive             bool       `json:"is_active" example:"true"`
	Issuer               string     `json:"issuer" example:"https://acme.okta.com"`
	Name                 string     `json:"name" example:"Acme Okta"`
	Scopes               string     `json:"scopes" example:"openid email profile"`
	TrustUnverifiedEmail bool       `json:"trust_unverified_email" example:"false"`
	UpdatedAt            *time.Time `json:"updated_at"`
} //@name SSOConnection

// NewConnectionResponse renders one connection.
func NewConnectionResponse(c Connection) ConnectionResponse {
	domains := c.Domains
	if domains == nil {
		domains = []string{}
	}
	return ConnectionResponse{
		ClientID: c.OIDCClientID, CreatedAt: c.CreatedAt, Domains: domains, HasSecret: c.HasSecret, ID: c.ID,
		IsActive: c.IsActive, Issuer: c.Issuer, Name: c.Name, Scopes: c.Scopes,
		TrustUnverifiedEmail: c.TrustUnverifiedEmail, UpdatedAt: c.UpdatedAt,
	}
}

// NewConnectionListResponse renders a company's connections; never null.
func NewConnectionListResponse(cs []Connection) []ConnectionResponse {
	out := make([]ConnectionResponse, 0, len(cs))
	for _, c := range cs {
		out = append(out, NewConnectionResponse(c))
	}
	return out
}

// TestResponse is what the provider's discovery document says.
type TestResponse struct {
	AuthorizationEndpoint string `json:"authorization_endpoint" example:"https://acme.okta.com/oauth2/v1/authorize"`
	Issuer                string `json:"issuer" example:"https://acme.okta.com"`
	JWKSURI               string `json:"jwks_uri" example:"https://acme.okta.com/oauth2/v1/keys"`
	TokenEndpoint         string `json:"token_endpoint" example:"https://acme.okta.com/oauth2/v1/token"`
} //@name SSOConnectionTest

// NewTestResponse renders a test.
func NewTestResponse(t TestResult) TestResponse {
	return TestResponse{
		AuthorizationEndpoint: t.AuthorizationEndpoint, Issuer: t.Issuer, JWKSURI: t.JWKSURI, TokenEndpoint: t.TokenEndpoint,
	}
}
