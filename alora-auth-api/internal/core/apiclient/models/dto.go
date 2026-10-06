// Package models holds the API-client feature's DTOs and HTTP request/response
// models. An API client is an application's identity — a sync job, a backend,
// an agent — with no person behind it: a client ID and secret, the products it
// may get a token for, and where that token may be used (its scopes).
package models

import "time"

// APIClient is one API client with what it holds.
type APIClient struct {
	ID          string // also its OAuth client_id
	CompanyID   string
	CompanyName string
	Name        string
	Description string
	IsActive    bool
	Scopes      []string // application scopes, sorted
	Products    []Product
	LiveSecrets int32
	LastUsedAt  *time.Time
	CreatedAt   *time.Time
	UpdatedAt   *time.Time
}

// Product is a product on an API client's list, or one that could go on it.
// Usable is false for an entry that earns no token until it is usable again:
// its subscription or the product is off, or the product no longer accepts API
// clients.
type Product struct {
	ID     string
	Key    string
	Name   string
	Usable bool
}

// Detail is one API client with its secrets and the products that could go on
// its list.
type Detail struct {
	APIClient
	Secrets []Secret
	Choices []Product
}

// Secret is one of an API client's secrets — never the secret itself.
type Secret struct {
	ID         string
	Prefix     string // enough to tell two apart, never enough to use
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  *time.Time
	IsLive     bool
}

// NewSecret is a secret just made: the only time its plaintext leaves App
// Central, which keeps nothing but its hash.
type NewSecret struct {
	Secret
	ClientID     string // the API client's id, its OAuth client_id
	ClientSecret string
}

// Input is an API client's settable details. IsActive is ignored on create: a
// new client starts active, and can do nothing until it is given scopes,
// products and a secret.
type Input struct {
	Name        string
	Description string
	IsActive    bool
}
