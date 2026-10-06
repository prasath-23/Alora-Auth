// Package models holds the SSO-connection feature's DTOs and HTTP
// request/response models.
package models

import "time"

// Connection is a company's OIDC identity provider, without its secret.
type Connection struct {
	ID                   string
	Name                 string
	Issuer               string
	OIDCClientID         string
	Scopes               string
	TrustUnverifiedEmail bool
	IsActive             bool
	HasSecret            bool
	Domains              []string
	CreatedAt            *time.Time
	UpdatedAt            *time.Time
}

// ConnectionInput is a connection's complete desired state. A nil ClientSecret
// keeps the stored one on update.
type ConnectionInput struct {
	Name                 string
	Issuer               string
	OIDCClientID         string
	ClientSecret         *string
	Scopes               string
	TrustUnverifiedEmail bool
	IsActive             bool
}

// TestResult is what the provider's discovery document says.
type TestResult struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
}
