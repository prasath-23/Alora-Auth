package models

// Request models. Tags enforce presence and shape before any database work, and
// the binder rejects unknown fields.

// PasswordLoginRequest signs in with an address and password.
type PasswordLoginRequest struct {
	Email    string `json:"email" validate:"required,email,max=320" example:"alice@acme.com"`
	Password string `json:"password" validate:"required,min=1,max=512" example:"correct-horse-battery-staple"`
	// ReturnTo is where App Central goes afterwards: a path on its own origin.
	ReturnTo string `json:"return_to" validate:"omitempty,max=2048" example:"/oauth/authorize?client_id=..."`
} //@name PasswordLoginRequest

// ChooseRequest completes an account choice.
type ChooseRequest struct {
	ClientID string `json:"client_id" validate:"required,uuid" example:"5c6d7e8f-9a0b-1c2d-3e4f-5a6b7c8d9e0f"`
} //@name ChooseCompanyRequest

// DiscoverRequest asks which methods to offer for an address. Only its domain is
// used.
type DiscoverRequest struct {
	Email string `json:"email" validate:"required,email,max=320" example:"alice@acme.com"`
} //@name LoginDiscoverRequest

// FederatedStartRequest is the query string that begins a Google or SSO sign-in.
type FederatedStartRequest struct {
	ReturnTo     string `form:"return_to"`
	ConnectionID string `form:"connection_id"`
	Email        string `form:"email"`
}
