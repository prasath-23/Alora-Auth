// Package models holds the Owner console's DTOs and HTTP request/response
// models: companies, their subscriptions, and the products App Central signs
// users in to.
package models

import "time"

// Company is one company as the Owner sees it.
type Company struct {
	ID                 string
	Name               string
	Domain             *string
	DomainVerifiedAt   *time.Time
	SubscriptionStatus string
	MaxSeats           *int32
	IsActive           bool
	IsPlatform         bool
	UserCount          int64
	CreatedAt          *time.Time
	UpdatedAt          *time.Time
}

// CompanyInput is a new company.
type CompanyInput struct {
	Name               string
	Domain             string
	SubscriptionStatus string
	MaxSeats           *int32
	IsActive           bool
}

// CompanyChanges is a partial update of a company; a nil field is left as is.
type CompanyChanges struct {
	Name               *string
	SubscriptionStatus *string
	MaxSeats           *int32
	ClearMaxSeats      bool
	IsActive           *bool
}

// Subscription is a company's subscription to one product.
type Subscription struct {
	ID          string
	ProductID   string
	ProductKey  string
	ProductName string
	IsActive    bool
	SeatLimit   *int32
	StartsAt    *time.Time
	EndsAt      *time.Time
}

// SubscriptionInput is the desired state of a subscription.
type SubscriptionInput struct {
	IsActive  bool
	SeatLimit *int32
	EndsAt    *time.Time
}

// Product is a product's registration as an OAuth client.
type Product struct {
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
	RedirectURIs      []string
	Roles             []string
	CreatedAt         *time.Time
	UpdatedAt         *time.Time
}

// ProductInput is a product's settable fields. A nil AcceptsAPIClients is off
// for a new product and unchanged for an update.
type ProductInput struct {
	Key               string // create only
	Name              string
	Description       string
	BaseURL           string
	InitiateLoginURI  string
	IsActive          bool
	AcceptsAPIClients *bool
}

// Secret is a product's new client secret, shown once.
type Secret struct {
	ClientID     string
	ClientSecret string
	RotatedAt    time.Time
}
