package models

import "time"

// Client is a row of tbl_clients: a company (tenant). Exactly one is the
// platform company, whose members include the Owners.
type Client struct {
	ID                 string
	Name               string
	Domain             *string
	DomainVerifiedAt   *time.Time
	SubscriptionStatus SubscriptionStatus
	MaxSeats           *int32
	IsActive           bool
	IsPlatform         bool
	CreatedAt          *time.Time
	UpdatedAt          *time.Time
}

// CompanyListItem is a row of vw_CompanyListItem: a company with its live
// member count, as the Owner console lists it.
type CompanyListItem struct {
	Client
	UserCount int64
}
