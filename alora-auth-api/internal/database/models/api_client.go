package models

import "time"

// APIClient is a row of tbl_api_clients: an application's identity. Its ID is
// its OAuth client_id, "aci_" and a uuid, so it is never mistaken for a
// product's. Exactly one of CreatedByUserID and CreatedByOwnerID is set.
type APIClient struct {
	ID               string
	ClientID         string // its company
	Name             string
	Description      *string
	IsActive         bool
	CreatedByUserID  *string
	CreatedByOwnerID *string
	LastUsedAt       *time.Time
	CreatedAt        *time.Time
	UpdatedAt        *time.Time
}

// APIClientProduct is one product on an API client's list, as vw_ApiClientSummary
// aggregates them. Usable is false while the subscription or the product is
// switched off, or the product no longer accepts API clients: such an entry
// earns no token until it is usable again.
type APIClientProduct struct {
	ProductID   string `json:"product_id"`
	ProductKey  string `json:"product_key"`
	ProductName string `json:"product_name"`
	Usable      bool   `json:"usable"`
}

// APIClientSummary is a row of vw_ApiClientSummary: an API client with its
// company's name, its scopes, its products and how many live secrets it has.
type APIClientSummary struct {
	ID               string
	ClientID         string
	CompanyName      string
	Name             string
	Description      *string
	IsActive         bool
	CreatedByUserID  *string
	CreatedByOwnerID *string
	LastUsedAt       *time.Time
	CreatedAt        *time.Time
	UpdatedAt        *time.Time
	Scopes           []string // CLIENT scopes, sorted
	Products         []APIClientProduct
	LiveSecrets      int32
}

// APIClientSecret is a row of vw_ApiClientSecret: a secret without its hash. It
// is live until it is revoked or expires.
type APIClientSecret struct {
	ID               string
	APIClientID      string
	ClientID         string
	Prefix           string
	ExpiresAt        *time.Time
	RevokedAt        *time.Time
	LastUsedAt       *time.Time
	CreatedByUserID  *string
	CreatedByOwnerID *string
	CreatedAt        *time.Time
	IsLive           bool
}

// Kinds of OAuth client, as vw_OAuthClientCredential names them.
const (
	OAuthClientProduct   = "PRODUCT"
	OAuthClientAPIClient = "API_CLIENT"
)

// OAuthClientCredential is a row of vw_OAuthClientCredential: one secret a
// client id may authenticate with at the token endpoint. A product has one; an
// API client one per live secret. ProductKey is set for a product, CompanyID
// and SecretID for an API client.
type OAuthClientCredential struct {
	Kind          string
	OAuthClientID string
	ProductKey    string
	CompanyID     string
	SecretID      string
	SecretHash    string
	IsActive      bool
}

// APIClientGrant is a row of vw_ApiClientGrant: whether an API client may have a
// token for one product on its list right now, and the scopes it holds.
type APIClientGrant struct {
	APIClientID string
	ClientID    string // its company
	ProductID   string
	ProductKey  string
	Usable      bool
	Scopes      []string
}
