package models

import "time"

// Response models. Fields are declared in alphabetical order of their JSON names.
// Collections are never null.

// CompanyResponse is one company.
type CompanyResponse struct {
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
	UserCount          int64      `json:"user_count" example:"42"`
} //@name Company

// NewCompanyResponse renders one company.
func NewCompanyResponse(c Company) CompanyResponse {
	return CompanyResponse{
		CreatedAt: c.CreatedAt, Domain: c.Domain, DomainVerifiedAt: c.DomainVerifiedAt, ID: c.ID,
		IsActive: c.IsActive, IsPlatform: c.IsPlatform, MaxSeats: c.MaxSeats, Name: c.Name,
		SubscriptionStatus: c.SubscriptionStatus, UpdatedAt: c.UpdatedAt, UserCount: c.UserCount,
	}
}

// NewCompanyListResponse renders the companies; never null.
func NewCompanyListResponse(cs []Company) []CompanyResponse {
	out := make([]CompanyResponse, 0, len(cs))
	for _, c := range cs {
		out = append(out, NewCompanyResponse(c))
	}
	return out
}

// SubscriptionResponse is one subscription. `id` is the subscription's.
type SubscriptionResponse struct {
	EndsAt      *time.Time `json:"ends_at"`
	ID          string     `json:"id" example:"2b3c4d5e-6f70-8a9b-0c1d-2e3f4a5b6c7d"`
	IsActive    bool       `json:"is_active" example:"true"`
	ProductID   string     `json:"product_id" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	ProductKey  string     `json:"product_key" example:"CRM"`
	ProductName string     `json:"product_name" example:"Acme CRM"`
	SeatLimit   *int32     `json:"seat_limit" example:"50"`
	StartsAt    *time.Time `json:"starts_at"`
} //@name Subscription

// NewSubscriptionListResponse renders a company's subscriptions; never null.
func NewSubscriptionListResponse(ss []Subscription) []SubscriptionResponse {
	out := make([]SubscriptionResponse, 0, len(ss))
	for _, s := range ss {
		out = append(out, SubscriptionResponse{
			EndsAt: s.EndsAt, ID: s.ID, IsActive: s.IsActive, ProductID: s.ProductID, ProductKey: s.ProductKey,
			ProductName: s.ProductName, SeatLimit: s.SeatLimit, StartsAt: s.StartsAt,
		})
	}
	return out
}

// ProductResponse is a product's registration. The client secret is never
// returned, only whether one is set.
type ProductResponse struct {
	AcceptsAPIClients bool       `json:"accepts_api_clients" example:"false"`
	BaseURL           *string    `json:"base_url" example:"https://crm.acme.com"`
	CreatedAt         *time.Time `json:"created_at"`
	Description       *string    `json:"description"`
	HasSecret         bool       `json:"has_secret" example:"true"`
	ID                string     `json:"id" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	InitiateLoginURI  *string    `json:"initiate_login_uri" example:"https://crm.acme.com/login/initiate"`
	IsActive          bool       `json:"is_active" example:"true"`
	Key               string     `json:"key" example:"CRM"`
	Name              string     `json:"name" example:"Acme CRM"`
	RedirectURIs      []string   `json:"redirect_uris" example:"https://crm.acme.com/oidc/callback"`
	Roles             []string   `json:"roles" example:"Admin,Editor,Viewer"`
	SecretRotatedAt   *time.Time `json:"secret_rotated_at"`
	UpdatedAt         *time.Time `json:"updated_at"`
} //@name ProductRegistration

// NewProductResponse renders a product.
func NewProductResponse(p Product) ProductResponse {
	return ProductResponse{
		AcceptsAPIClients: p.AcceptsAPIClients,
		BaseURL:           p.BaseURL, CreatedAt: p.CreatedAt, Description: p.Description, HasSecret: p.HasSecret, ID: p.ID,
		InitiateLoginURI: p.InitiateLoginURI, IsActive: p.IsActive, Key: p.Key, Name: p.Name,
		RedirectURIs: nonNil(p.RedirectURIs), Roles: nonNil(p.Roles), SecretRotatedAt: p.SecretRotatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

// NewProductListResponse renders the products; never null.
func NewProductListResponse(ps []Product) []ProductResponse {
	out := make([]ProductResponse, 0, len(ps))
	for _, p := range ps {
		out = append(out, NewProductResponse(p))
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// SecretResponse is a product's new client secret. It is shown this once and
// stored only as a hash: lose it and rotate again.
type SecretResponse struct {
	ClientID     string    `json:"client_id" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	ClientSecret string    `json:"client_secret" example:"acs_Rk9pX3VXYzV2cDFZa2dJd2Q0TGZaM2lPdkJjSmp0bFk"`
	RotatedAt    time.Time `json:"rotated_at"`
} //@name ProductSecret

// NewSecretResponse renders a new secret.
func NewSecretResponse(s Secret) SecretResponse {
	return SecretResponse{ClientID: s.ClientID, ClientSecret: s.ClientSecret, RotatedAt: s.RotatedAt}
}
