package models

import "time"

// Response models. Fields are declared in alphabetical order of their JSON names.
// Collections are never null.

// CreateInvitationResponse returns the invite link so it can be shared by hand
// when SMTP is not configured. The raw token is never persisted.
type CreateInvitationResponse struct {
	Email     string    `json:"email" example:"newhire@acme.com"`
	ExpiresAt time.Time `json:"expires_at"`
	ID        string    `json:"id" example:"8c1d2e3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f"`
	InviteURL string    `json:"invite_url" example:"http://localhost:5173/accept-invitation?token=6f1c8a0e"`
} //@name CreateInvitationResponse

// NewCreateInvitationResponse renders an issued invitation.
func NewCreateInvitationResponse(c Created) CreateInvitationResponse {
	return CreateInvitationResponse{Email: c.Email, ExpiresAt: c.ExpiresAt, ID: c.ID, InviteURL: c.InviteURL}
}

// InvitationListItemResponse is one invitation. token_hash is never projected.
type InvitationListItemResponse struct {
	CreatedAt *time.Time `json:"created_at"`
	Email     string     `json:"email" example:"newhire@acme.com"`
	ExpiresAt *time.Time `json:"expires_at"`
	ID        string     `json:"id" example:"8c1d2e3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f"`
	Status    string     `json:"status" example:"PENDING" enums:"PENDING,ACCEPTED,EXPIRED,REVOKED"`
} //@name InvitationListItem

// NewInvitationListResponse renders the company's invitations; never null.
func NewInvitationListResponse(items []Listed) []InvitationListItemResponse {
	out := make([]InvitationListItemResponse, 0, len(items))
	for _, l := range items {
		out = append(out, InvitationListItemResponse{
			CreatedAt: l.CreatedAt, Email: l.Email, ExpiresAt: l.ExpiresAt, ID: l.ID, Status: l.Status,
		})
	}
	return out
}

// InvitationPreviewResponse renders the invite landing page for an
// unauthenticated visitor holding the raw token.
type InvitationPreviewResponse struct {
	ClientName string          `json:"client_name" example:"Acme Corp"`
	Email      string          `json:"email" example:"newhire@acme.com"`
	ExpiresAt  *time.Time      `json:"expires_at"`
	Groups     []string        `json:"groups" example:"Support"`
	Methods    MethodsResponse `json:"methods"`
} //@name InvitationPreview

// MethodsResponse is how the invitee will sign in.
type MethodsResponse struct {
	Google   bool `json:"google" example:"false"`
	Password bool `json:"password" example:"true"`
	SSO      bool `json:"sso" example:"false"`
} //@name InvitationMethods

// NewInvitationPreviewResponse renders a preview.
func NewInvitationPreviewResponse(p Preview) InvitationPreviewResponse {
	groups := p.Groups
	if groups == nil {
		groups = []string{}
	}
	return InvitationPreviewResponse{
		ClientName: p.ClientName, Email: p.Email, ExpiresAt: p.ExpiresAt, Groups: groups,
		Methods: MethodsResponse{Google: p.Methods.Google, Password: p.Methods.Password, SSO: p.Methods.SSO},
	}
}
