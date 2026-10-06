package models

// Request models. Tags enforce presence and shape before any database work, and
// the binder rejects unknown fields.

// CreateInvitationRequest invites an address into a company, and names the
// groups the new account joins — which is what gives it access. There is no
// company field: it comes from the route.
type CreateInvitationRequest struct {
	Email    string   `json:"email" validate:"required,email,max=320" example:"newhire@acme.com"`
	GroupIDs []string `json:"group_ids" binding:"optional" validate:"omitempty,max=20,dive,uuid" example:"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
} //@name CreateInvitationRequest

// AcceptInvitationRequest redeems an invitation into a password account.
type AcceptInvitationRequest struct {
	Token    string `json:"token" validate:"required,max=256" example:"6f1c8a0e9d2b4f7a3c5e8b1d0a9f2c4e"`
	Password string `json:"password" validate:"required,min=8,max=512" example:"correct-horse-battery-staple"`
} //@name AcceptInvitationRequest

// AcceptFederatedRequest redeems an invitation into an account with no password,
// for someone who will sign in with Google or their company's SSO. The external
// identity is linked at the first sign-in, not here.
type AcceptFederatedRequest struct {
	Token string `json:"token" validate:"required,min=10,max=256" example:"6f1c8a0e9d2b4f7a3c5e8b1d0a9f2c4e"`
} //@name AcceptInvitationFederatedRequest
