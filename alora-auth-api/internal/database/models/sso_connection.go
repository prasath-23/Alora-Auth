package models

import "time"

// SSOConnection is a row of tbl_sso_connections: a company's own OIDC identity
// provider. The client secret is held only as ciphertext.
type SSOConnection struct {
	ID                     string
	ClientID               string
	Name                   string
	Issuer                 string
	OIDCClientID           string
	ClientSecretCiphertext []byte
	SecretKeyID            *string
	Scopes                 string
	TrustUnverifiedEmail   bool
	IsActive               bool
	CreatedAt              *time.Time
	UpdatedAt              *time.Time
}

// SSOConnectionRuntime is a row of vw_SsoConnectionRuntime: what the SSO sign-in
// path needs, including the encrypted secret and the connection's domains.
type SSOConnectionRuntime struct {
	ID                     string
	ClientID               string
	Name                   string
	Issuer                 string
	OIDCClientID           string
	ClientSecretCiphertext []byte
	SecretKeyID            *string
	Scopes                 string
	TrustUnverifiedEmail   bool
	IsActive               bool // the connection AND its company are active
	Domains                []string
}

// SSOConnectionSummary is a row of vw_SsoConnectionSummary: a connection without
// its secret, only whether one is set.
type SSOConnectionSummary struct {
	ID                   string
	ClientID             string
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
