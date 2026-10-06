package models

import "time"

// Response models. Fields are declared in alphabetical order of their JSON names.

// PolicyResponse is one login policy.
type PolicyResponse struct {
	AllowGoogle     bool       `json:"allow_google" example:"true"`
	AllowPassword   bool       `json:"allow_password" example:"true"`
	CreatedAt       *time.Time `json:"created_at"`
	ID              string     `json:"id" example:"9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"`
	IsDefault       bool       `json:"is_default" example:"false"`
	Name            string     `json:"name" example:"Contractors"`
	Priority        int32      `json:"priority" example:"10"`
	SSOConnectionID *string    `json:"sso_connection_id"`
	UpdatedAt       *time.Time `json:"updated_at"`
} //@name LoginPolicy

// NewPolicyResponse renders one policy.
func NewPolicyResponse(p Policy) PolicyResponse {
	return PolicyResponse{
		AllowGoogle: p.AllowGoogle, AllowPassword: p.AllowPassword, CreatedAt: p.CreatedAt, ID: p.ID,
		IsDefault: p.IsDefault, Name: p.Name, Priority: p.Priority, SSOConnectionID: p.SSOConnectionID,
		UpdatedAt: p.UpdatedAt,
	}
}

// NewPolicyListResponse renders a company's policies; never null.
func NewPolicyListResponse(ps []Policy) []PolicyResponse {
	out := make([]PolicyResponse, 0, len(ps))
	for _, p := range ps {
		out = append(out, NewPolicyResponse(p))
	}
	return out
}
