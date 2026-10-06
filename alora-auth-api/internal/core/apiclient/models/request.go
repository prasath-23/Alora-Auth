package models

import "time"

// Request models. Tags enforce presence and shape before any database work, and
// the binder rejects unknown fields.
//
// The binding:"optional" on the lists is read only by swag, which does not
// understand `dive` and would otherwise document the list itself as required;
// the binder validates with the validate tag alone.

// CreateAPIClientRequest names a new API client. It starts with no scopes, no
// products and no secret, so it can do nothing until each is chosen.
type CreateAPIClientRequest struct {
	Name        string `json:"name" validate:"required,notblank,min=1,max=100" example:"Nightly sync"`
	Description string `json:"description" validate:"omitempty,max=500" example:"Copies orders to the warehouse"`
} //@name CreateAPIClientRequest

// Input is the request as the service takes it.
func (r CreateAPIClientRequest) Input() Input {
	return Input{Name: r.Name, Description: r.Description, IsActive: true}
}

// UpdateAPIClientRequest is an API client's complete settable state. A client
// switched off gets no token, whatever its secrets.
type UpdateAPIClientRequest struct {
	Name        string `json:"name" validate:"required,notblank,min=1,max=100" example:"Nightly sync"`
	Description string `json:"description" validate:"omitempty,max=500" example:"Copies orders to the warehouse"`
	IsActive    *bool  `json:"is_active" validate:"required" example:"true"`
} //@name UpdateAPIClientRequest

// Input is the request as the service takes it.
func (r UpdateAPIClientRequest) Input() Input {
	return Input{Name: r.Name, Description: r.Description, IsActive: *r.IsActive}
}

// SetAPIClientScopesRequest is the COMPLETE set of where the credential may be
// used: any scope omitted is taken away. An edit scope brings its read scope.
type SetAPIClientScopesRequest struct {
	Scopes []string `json:"scopes" binding:"optional" validate:"omitempty,max=20,dive,required,max=64" example:"api:read,grpc:read"`
} //@name SetAPIClientScopesRequest

// SetAPIClientProductsRequest is the COMPLETE list of products the client may
// get a token for: any product omitted is taken off.
type SetAPIClientProductsRequest struct {
	ProductIDs []string `json:"product_ids" binding:"optional" validate:"omitempty,max=100,dive,uuid" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
} //@name SetAPIClientProductsRequest

// CreateAPIClientSecretRequest may limit a new secret's life; without it, the
// secret lives until it is revoked.
type CreateAPIClientSecretRequest struct {
	ExpiresInDays *int `json:"expires_in_days" validate:"omitempty,min=1,max=730" example:"90"`
} //@name CreateAPIClientSecretRequest

// Lifetime is how long the new secret lives, or nil for until revoked.
func (r CreateAPIClientSecretRequest) Lifetime() *time.Duration {
	if r.ExpiresInDays == nil {
		return nil
	}
	d := time.Duration(*r.ExpiresInDays) * 24 * time.Hour
	return &d
}
