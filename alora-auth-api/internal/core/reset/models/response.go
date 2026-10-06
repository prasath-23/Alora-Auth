package models

import "time"

// IssueResetResponse returns the expiry, plus the link ONLY when email is
// unavailable — a configured deployment never returns a takeover primitive in an
// API response. Fields are declared in alphabetical order of their JSON names,
// the order the map-based body this replaced serialised in.
type IssueResetResponse struct {
	ExpiresAt time.Time `json:"expires_at"`
	ResetURL  string    `json:"reset_url,omitempty" example:"http://localhost:5173/reset-password?token=c4e8b1d0"`
} //@name IssueResetResponse

// NewIssueResetResponse renders an issued reset.
func NewIssueResetResponse(i Issued) IssueResetResponse {
	r := IssueResetResponse{ExpiresAt: i.ExpiresAt}
	if i.ResetURL != nil {
		r.ResetURL = *i.ResetURL
	}
	return r
}
