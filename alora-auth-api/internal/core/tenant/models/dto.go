// Package models holds the tenant feature's DTOs and HTTP request/response
// models: a company's own record and its product subscriptions.
package models

import "time"

// Client is a company's record.
type Client struct {
	ID                 string
	Name               string
	Domain             *string
	DomainVerifiedAt   *time.Time
	SubscriptionStatus string
	MaxSeats           *int32
	IsActive           bool
	IsPlatform         bool
	CreatedAt          *time.Time
	UpdatedAt          *time.Time
}

// Subscription is one product the company subscribes to. ID is the
// SUBSCRIPTION id; the product itself is ProductID.
type Subscription struct {
	ID          string
	ProductID   string
	Key         string
	Name        string
	Description *string
	BaseURL     *string
	IsActive    bool
	SeatLimit   *int32
	StartsAt    *time.Time
	EndsAt      *time.Time
}
