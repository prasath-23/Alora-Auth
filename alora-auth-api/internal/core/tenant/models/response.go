package models

import "time"

// Response models. Fields are declared in alphabetical order of their JSON names.
// Nullable columns render as JSON null rather than "" or 0, so the UI can tell
// "unset" from "zero".

// ClientDetailResponse is a company's record. domain_verified_at is a nullable
// timestamp, not a boolean.
type ClientDetailResponse struct {
	CreatedAt          *time.Time `json:"created_at"`
	Domain             *string    `json:"domain" example:"acme.com"`
	DomainVerifiedAt   *time.Time `json:"domain_verified_at"`
	ID                 string     `json:"id" example:"5c6d7e8f-9a0b-1c2d-3e4f-5a6b7c8d9e0f"`
	IsActive           bool       `json:"is_active" example:"true"`
	IsPlatform         bool       `json:"is_platform" example:"false"`
	MaxSeats           *int32     `json:"max_seats" example:"100"`
	Name               string     `json:"name" example:"Acme Corp"`
	SubscriptionStatus string     `json:"subscription_status" example:"ACTIVE" enums:"TRIAL,ACTIVE,SUSPENDED,CANCELLED"`
	UpdatedAt          *time.Time `json:"updated_at"`
} //@name ClientDetail

// NewClientDetailResponse renders a company's record.
func NewClientDetailResponse(c Client) ClientDetailResponse {
	return ClientDetailResponse{
		CreatedAt: c.CreatedAt, Domain: c.Domain, DomainVerifiedAt: c.DomainVerifiedAt, ID: c.ID,
		IsActive: c.IsActive, IsPlatform: c.IsPlatform, MaxSeats: c.MaxSeats, Name: c.Name,
		SubscriptionStatus: c.SubscriptionStatus, UpdatedAt: c.UpdatedAt,
	}
}

// ProductListItemResponse is one subscription of the company. `id` is the
// SUBSCRIPTION id, not the product id.
type ProductListItemResponse struct {
	BaseURL     *string    `json:"base_url" example:"https://crm.acme.com"`
	Description *string    `json:"description"`
	EndsAt      *time.Time `json:"ends_at"`
	ID          string     `json:"id" example:"2b3c4d5e-6f70-8a9b-0c1d-2e3f4a5b6c7d"`
	IsActive    bool       `json:"is_active" example:"true"`
	Key         string     `json:"key" example:"CRM"`
	Name        string     `json:"name" example:"Acme CRM"`
	ProductID   string     `json:"product_id" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	SeatLimit   *int32     `json:"seat_limit" example:"50"`
	StartsAt    *time.Time `json:"starts_at"`
} //@name ProductListItem

// NewProductListResponse renders the subscriptions as a bare array; never null.
func NewProductListResponse(subs []Subscription) []ProductListItemResponse {
	out := make([]ProductListItemResponse, 0, len(subs))
	for _, s := range subs {
		out = append(out, ProductListItemResponse{
			BaseURL: s.BaseURL, Description: s.Description, EndsAt: s.EndsAt, ID: s.ID,
			IsActive: s.IsActive, Key: s.Key, Name: s.Name, ProductID: s.ProductID,
			SeatLimit: s.SeatLimit, StartsAt: s.StartsAt,
		})
	}
	return out
}
