package models

// Request models. Tags enforce presence and shape before any database work, and
// the binder rejects unknown fields.

// UpdateUserRequest activates or deactivates an account. Deactivation takes
// effect immediately: every session is revoked and every token stops working.
type UpdateUserRequest struct {
	IsActive *bool `json:"is_active" validate:"required" example:"false"`
} //@name UpdateUserRequest

// GrantRequest carries only the role; the user and product travel in the PATH.
// The role must be in the product's catalogue.
type GrantRequest struct {
	RoleName string `json:"role_name" validate:"required,max=64" example:"Editor"`
} //@name GrantRoleRequest

// ChangePasswordRequest re-authenticates with the current password: that is what
// stops a stolen access token from becoming permanent account takeover.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,min=1,max=512" example:"correct-horse-battery-staple"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=512" example:"a-different-long-passphrase"`
} //@name ChangePasswordRequest

// SetUserScopesRequest is the COMPLETE set of extra App Central scopes for one
// person: any scope omitted is taken away. Edit scopes bring their read scopes.
type SetUserScopesRequest struct {
	Scopes []string `json:"scopes" binding:"optional" validate:"omitempty,max=50,dive,required,max=64" example:"users:read,sessions:read"`
} //@name SetUserScopesRequest
