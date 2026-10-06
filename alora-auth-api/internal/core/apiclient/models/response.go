package models

import "time"

// APIClientResponse is one API client: what it may get a token for and where
// the token may be used. Never a secret.
type APIClientResponse struct {
	CompanyID   string                     `json:"company_id" example:"5c6d7e8f-9a0b-1c2d-3e4f-5a6b7c8d9e0f"`
	CompanyName string                     `json:"company_name" example:"Acme Corp"`
	CreatedAt   *time.Time                 `json:"created_at"`
	Description string                     `json:"description" example:"Copies orders to the warehouse"`
	ID          string                     `json:"id" example:"aci_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
	IsActive    bool                       `json:"is_active" example:"true"`
	LastUsedAt  *time.Time                 `json:"last_used_at"`
	LiveSecrets int32                      `json:"live_secrets" example:"1"`
	Name        string                     `json:"name" example:"Nightly sync"`
	Products    []APIClientProductResponse `json:"products"`
	Scopes      []string                   `json:"scopes" example:"api:read,grpc:read"`
	UpdatedAt   *time.Time                 `json:"updated_at"`
} //@name APIClient

// APIClientProductResponse is a product on an API client's list, or one that
// could go on it. An entry that is not usable earns no token until it is again.
type APIClientProductResponse struct {
	ProductID   string `json:"product_id" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	ProductKey  string `json:"product_key" example:"CRM"`
	ProductName string `json:"product_name" example:"Acme CRM"`
	Usable      bool   `json:"usable" example:"true"`
} //@name APIClientProduct

// APIClientDetailResponse is one API client with its secrets (never their
// values) and the products that could go on its list.
type APIClientDetailResponse struct {
	APIClientResponse
	ProductChoices []APIClientProductResponse `json:"product_choices"`
	Secrets        []APIClientSecretResponse  `json:"secrets"`
} //@name APIClientDetail

// APIClientSecretResponse is one of an API client's secrets, told apart by its
// prefix.
type APIClientSecretResponse struct {
	CreatedAt  *time.Time `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	ID         string     `json:"id" example:"9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"`
	IsLive     bool       `json:"is_live" example:"true"`
	LastUsedAt *time.Time `json:"last_used_at"`
	Prefix     string     `json:"prefix" example:"acc_Xy12Ab34"`
	RevokedAt  *time.Time `json:"revoked_at"`
} //@name APIClientSecret

// IssuedSecretResponse is a secret just made, with its value: shown this once.
type IssuedSecretResponse struct {
	APIClientSecretResponse
	ClientID     string `json:"client_id" example:"aci_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
	ClientSecret string `json:"client_secret" example:"acc_Xy12Ab34..."`
} //@name NewAPIClientSecret

// APIClientScopesResponse echoes the scopes an API client now holds.
type APIClientScopesResponse struct {
	Scopes []string `json:"scopes" example:"api:read,grpc:read"`
} //@name APIClientScopesResponse

// APIClientProductsResponse echoes the products now on an API client's list.
type APIClientProductsResponse struct {
	Products []APIClientProductResponse `json:"products"`
} //@name APIClientProductsResponse

// NewAPIClientResponse renders an API client.
func NewAPIClientResponse(a APIClient) APIClientResponse {
	return APIClientResponse{
		CompanyID: a.CompanyID, CompanyName: a.CompanyName, CreatedAt: a.CreatedAt,
		Description: a.Description, ID: a.ID, IsActive: a.IsActive, LastUsedAt: a.LastUsedAt,
		LiveSecrets: a.LiveSecrets, Name: a.Name, Products: products(a.Products),
		Scopes: nonNil(a.Scopes), UpdatedAt: a.UpdatedAt,
	}
}

// NewAPIClientListResponse renders a list of API clients; never null.
func NewAPIClientListResponse(as []APIClient) []APIClientResponse {
	out := make([]APIClientResponse, 0, len(as))
	for _, a := range as {
		out = append(out, NewAPIClientResponse(a))
	}
	return out
}

// NewAPIClientDetailResponse renders one API client in full.
func NewAPIClientDetailResponse(d Detail) APIClientDetailResponse {
	secrets := make([]APIClientSecretResponse, 0, len(d.Secrets))
	for _, s := range d.Secrets {
		secrets = append(secrets, secret(s))
	}
	return APIClientDetailResponse{
		APIClientResponse: NewAPIClientResponse(d.APIClient),
		ProductChoices:    products(d.Choices), Secrets: secrets,
	}
}

// NewIssuedSecretResponse renders a secret just made, with its value.
func NewIssuedSecretResponse(n NewSecret) IssuedSecretResponse {
	return IssuedSecretResponse{APIClientSecretResponse: secret(n.Secret), ClientID: n.ClientID, ClientSecret: n.ClientSecret}
}

// NewAPIClientScopesResponse renders a written scope set; never null.
func NewAPIClientScopesResponse(scopes []string) APIClientScopesResponse {
	return APIClientScopesResponse{Scopes: nonNil(scopes)}
}

// NewAPIClientProductsResponse renders a written product list; never null.
func NewAPIClientProductsResponse(ps []Product) APIClientProductsResponse {
	return APIClientProductsResponse{Products: products(ps)}
}

func secret(s Secret) APIClientSecretResponse {
	return APIClientSecretResponse{
		CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt, ID: s.ID, IsLive: s.IsLive,
		LastUsedAt: s.LastUsedAt, Prefix: s.Prefix, RevokedAt: s.RevokedAt,
	}
}

func products(ps []Product) []APIClientProductResponse {
	out := make([]APIClientProductResponse, 0, len(ps))
	for _, p := range ps {
		out = append(out, APIClientProductResponse{ProductID: p.ID, ProductKey: p.Key, ProductName: p.Name, Usable: p.Usable})
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
