package models

// UpdateClientRequest renames the company, and that is all an Admin may change:
// its plan, its standing and its domain are the Owner's. The binder rejects
// unknown fields, so an attempt to send one is a 400 rather than silently
// ignored.
type UpdateClientRequest struct {
	Name string `json:"name" validate:"required,notblank,min=1,max=200" example:"Acme Corporation"`
} //@name UpdateClientRequest
