package models

import "time"

// ClientProduct is a row of tbl_client_products: a tenant's subscription to a
// product.
type ClientProduct struct {
	ID        string
	ClientID  string
	ProductID string
	IsActive  bool
	SeatLimit *int32
	StartsAt  *time.Time
	EndsAt    *time.Time
	CreatedAt *time.Time
}

// ClientProductDetail is a row of vw_ClientProductDetail: a subscription joined to
// its product.
type ClientProductDetail struct {
	ID                 string
	ClientID           string
	ProductID          string
	IsActive           bool
	SeatLimit          *int32
	StartsAt           *time.Time
	EndsAt             *time.Time
	CreatedAt          *time.Time
	ProductKey         string
	ProductName        string
	ProductDescription *string
	ProductBaseURL     *string
	ProductIsActive    bool
	// ProductAcceptsAPIClients: the Owner lets API clients get tokens for it.
	ProductAcceptsAPIClients bool
}
