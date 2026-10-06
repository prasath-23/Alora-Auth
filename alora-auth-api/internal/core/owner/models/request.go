package models

import "time"

// Request models. Tags enforce presence and shape before any database work, and
// the binder rejects unknown fields.

// CreateCompanyRequest is a new company. It is created with its Admins group
// and its default login policy (password and Google).
type CreateCompanyRequest struct {
	Name               string `json:"name" validate:"required,notblank,min=1,max=200" example:"Acme Corp"`
	Domain             string `json:"domain" validate:"omitempty,fqdn,max=253" example:"acme.com"`
	SubscriptionStatus string `json:"subscription_status" validate:"omitempty,oneof=TRIAL ACTIVE SUSPENDED CANCELLED" example:"ACTIVE"`
	MaxSeats           *int32 `json:"max_seats" validate:"omitempty,min=1" example:"100"`
	IsActive           *bool  `json:"is_active" example:"true"`
} //@name CreateCompanyRequest

// Input is the request as the service takes it.
func (r CreateCompanyRequest) Input() CompanyInput {
	in := CompanyInput{Name: r.Name, Domain: r.Domain, SubscriptionStatus: r.SubscriptionStatus, MaxSeats: r.MaxSeats, IsActive: true}
	if in.SubscriptionStatus == "" {
		in.SubscriptionStatus = "ACTIVE"
	}
	if r.IsActive != nil {
		in.IsActive = *r.IsActive
	}
	return in
}

// UpdateCompanyRequest changes a company. Send only what changes. is_active
// false suspends the company: nobody in it can sign in or keep a session.
type UpdateCompanyRequest struct {
	Name               *string `json:"name" validate:"omitempty,notblank,min=1,max=200" example:"Acme Corporation"`
	SubscriptionStatus *string `json:"subscription_status" validate:"omitempty,oneof=TRIAL ACTIVE SUSPENDED CANCELLED" example:"SUSPENDED"`
	MaxSeats           *int32  `json:"max_seats" validate:"omitempty,min=1" example:"100"`
	ClearMaxSeats      bool    `json:"clear_max_seats" example:"false"`
	IsActive           *bool   `json:"is_active" example:"false"`
} //@name UpdateCompanyRequest

// Changes is the request as the service takes it.
func (r UpdateCompanyRequest) Changes() CompanyChanges {
	return CompanyChanges{Name: r.Name, SubscriptionStatus: r.SubscriptionStatus, MaxSeats: r.MaxSeats,
		ClearMaxSeats: r.ClearMaxSeats, IsActive: r.IsActive}
}

// SetDomainRequest sets or clears a company's email domain. A verified domain is
// how the login page recognises the company and how SSO domains are claimed.
type SetDomainRequest struct {
	Domain   *string `json:"domain" validate:"omitempty,fqdn,max=253" example:"acme.com"`
	Verified bool    `json:"verified" example:"true"`
} //@name SetCompanyDomainRequest

// SubscriptionRequest is the desired state of a company's subscription.
type SubscriptionRequest struct {
	IsActive  *bool      `json:"is_active" validate:"required" example:"true"`
	SeatLimit *int32     `json:"seat_limit" validate:"omitempty,min=1" example:"50"`
	EndsAt    *time.Time `json:"ends_at"`
} //@name SubscriptionRequest

// Input is the request as the service takes it.
func (r SubscriptionRequest) Input() SubscriptionInput {
	return SubscriptionInput{IsActive: *r.IsActive, SeatLimit: r.SeatLimit, EndsAt: r.EndsAt}
}

// CreateProductRequest registers a product. The key is permanent: every token
// for the product carries the audience "product:<key>". A product accepts API
// clients only when accepts_api_clients says so: off unless given.
type CreateProductRequest struct {
	Key               string `json:"key" validate:"required,min=2,max=40" example:"CRM"`
	Name              string `json:"name" validate:"required,notblank,min=1,max=200" example:"Acme CRM"`
	Description       string `json:"description" validate:"omitempty,max=1000" example:"Customer relationships"`
	BaseURL           string `json:"base_url" validate:"omitempty,url,max=2048" example:"https://crm.acme.com"`
	InitiateLoginURI  string `json:"initiate_login_uri" validate:"omitempty,url,max=2048" example:"https://crm.acme.com/login/initiate"`
	IsActive          *bool  `json:"is_active" example:"true"`
	AcceptsAPIClients *bool  `json:"accepts_api_clients" example:"false"`
} //@name CreateProductRequest

// Input is the request as the service takes it.
func (r CreateProductRequest) Input() ProductInput {
	in := ProductInput{Key: r.Key, Name: r.Name, Description: r.Description, BaseURL: r.BaseURL,
		InitiateLoginURI: r.InitiateLoginURI, IsActive: true, AcceptsAPIClients: r.AcceptsAPIClients}
	if r.IsActive != nil {
		in.IsActive = *r.IsActive
	}
	return in
}

// UpdateProductRequest is a product's complete settable state (the key
// excepted). Leaving accepts_api_clients out keeps whether the product accepts
// API clients.
type UpdateProductRequest struct {
	Name              string `json:"name" validate:"required,notblank,min=1,max=200" example:"Acme CRM"`
	Description       string `json:"description" validate:"omitempty,max=1000" example:"Customer relationships"`
	BaseURL           string `json:"base_url" validate:"omitempty,url,max=2048" example:"https://crm.acme.com"`
	InitiateLoginURI  string `json:"initiate_login_uri" validate:"omitempty,url,max=2048" example:"https://crm.acme.com/login/initiate"`
	IsActive          *bool  `json:"is_active" validate:"required" example:"true"`
	AcceptsAPIClients *bool  `json:"accepts_api_clients" example:"true"`
} //@name UpdateProductRequest

// Input is the request as the service takes it.
func (r UpdateProductRequest) Input() ProductInput {
	return ProductInput{Name: r.Name, Description: r.Description, BaseURL: r.BaseURL,
		InitiateLoginURI: r.InitiateLoginURI, IsActive: *r.IsActive, AcceptsAPIClients: r.AcceptsAPIClients}
}

// RedirectURIsRequest is the complete set of a product's redirect URIs. Codes
// are delivered only to one of these, matched byte for byte.
type RedirectURIsRequest struct {
	RedirectURIs []string `json:"redirect_uris" binding:"optional" validate:"omitempty,max=20,dive,url,max=2048" example:"https://crm.acme.com/oidc/callback"`
} //@name ProductRedirectURIsRequest

// RolesRequest is the complete role catalogue of a product.
type RolesRequest struct {
	Roles []string `json:"roles" binding:"optional" validate:"omitempty,max=50,dive,min=1,max=64" example:"Admin,Editor,Viewer"`
} //@name ProductRolesRequest
