package models

// Request models. Tags enforce presence and shape before any database work, and
// the binder rejects unknown fields.

// PolicyRequest is the complete desired state of a login policy. At least one
// method must remain: a policy under which nobody can sign in is refused.
type PolicyRequest struct {
	Name            string  `json:"name" validate:"required,notblank,min=1,max=100" example:"Contractors"`
	AllowPassword   *bool   `json:"allow_password" validate:"required" example:"false"`
	AllowGoogle     *bool   `json:"allow_google" validate:"required" example:"false"`
	SSOConnectionID *string `json:"sso_connection_id" validate:"omitempty,uuid" example:"9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"`
	Priority        *int32  `json:"priority" validate:"required,min=-1000,max=1000" example:"10"`
} //@name LoginPolicyRequest

// Input is the request as the service takes it.
func (r PolicyRequest) Input() PolicyInput {
	return PolicyInput{
		Name: r.Name, AllowPassword: *r.AllowPassword, AllowGoogle: *r.AllowGoogle,
		SSOConnectionID: r.SSOConnectionID, Priority: *r.Priority,
	}
}

// AssignPolicyRequest sets the policy a user or group signs in under. A null
// policy_id removes the assignment, so the user falls back to their groups'
// policy or the company default.
type AssignPolicyRequest struct {
	PolicyID *string `json:"policy_id" validate:"omitempty,uuid" example:"9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"`
} //@name AssignLoginPolicyRequest
