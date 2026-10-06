package models

import "time"

// Response models. Fields are declared in alphabetical order of their JSON names.

// SessionListItemResponse is one live sign-in: an App Central session, or one
// product's login under it. No token hash and no user id are projected.
type SessionListItemResponse struct {
	AuthMethod      string     `json:"auth_method" example:"EMAIL" enums:"EMAIL,GOOGLE,OIDC"`
	AuthenticatedAt *time.Time `json:"authenticated_at"`
	CreatedAt       *time.Time `json:"created_at"`
	DeviceLabel     string     `json:"device_label" example:"Chrome"`
	Email           string     `json:"email" example:"member@acme.com"`
	ID              string     `json:"id" example:"7e8f9a0b-1c2d-3e4f-5a6b-7c8d9e0f1a2b"`
	IPAddress       string     `json:"ip_address" example:"127.0.0.1"`
	Kind            string     `json:"kind" example:"CENTRAL" enums:"CENTRAL,PRODUCT"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	ProductKey      *string    `json:"product_key" example:"CRM"`
} //@name SessionListItem

// NewSessionListResponse renders the admin session list; never null.
func NewSessionListResponse(sessions []ActiveSession) []SessionListItemResponse {
	out := make([]SessionListItemResponse, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, SessionListItemResponse{
			AuthMethod: s.AuthMethod, AuthenticatedAt: s.AuthenticatedAt, CreatedAt: s.CreatedAt,
			DeviceLabel: s.DeviceLabel, Email: s.Email, ID: s.ID, IPAddress: s.IPAddress, Kind: s.Kind,
			LastSeenAt: s.LastSeenAt, ProductKey: s.ProductKey,
		})
	}
	return out
}
