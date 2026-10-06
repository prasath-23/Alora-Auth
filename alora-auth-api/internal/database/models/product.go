package models

import "time"

// Product is a row of tbl_products: a product and its registration as an OAuth
// client. Only the secret's hash is ever stored.
type Product struct {
	ID               string
	Key              string
	Name             string
	Description      *string
	BaseURL          *string
	InitiateLoginURI *string
	ClientSecretHash *string
	SecretRotatedAt  *time.Time
	IsActive         bool
	// AcceptsAPIClients: API clients may get tokens for it. Off until the Owner
	// switches it on, so no product receives application tokens by accident.
	AcceptsAPIClients bool
	CreatedAt         *time.Time
	UpdatedAt         *time.Time
}

// ProductClient is a row of vw_ProductClient: a product's registration without
// its secret hash, only whether one is set.
type ProductClient struct {
	ID                string
	Key               string
	Name              string
	Description       *string
	BaseURL           *string
	InitiateLoginURI  *string
	IsActive          bool
	AcceptsAPIClients bool
	HasSecret         bool
	SecretRotatedAt   *time.Time
	CreatedAt         *time.Time
	UpdatedAt         *time.Time
}

// ProductCredential is a row of vw_ProductClientCredential: what client
// authentication at the token endpoint checks.
type ProductCredential struct {
	ID               string
	Key              string
	IsActive         bool
	ClientSecretHash *string
}

// ProductRole is a row of tbl_product_roles: one role in a product's catalogue.
type ProductRole struct {
	ProductID   string
	RoleName    string
	Description *string
	CreatedAt   *time.Time
}

// ProductRedirectURI is a row of tbl_product_redirect_uris: an exact redirect
// target a product registered.
type ProductRedirectURI struct {
	ProductID   string
	RedirectURI string
	CreatedAt   *time.Time
}
