package models

// ResetPasswordRequest consumes a reset token. Field names mirror the Fastify
// contract EXACTLY: the field is `new_password` — NOT `password`, which is what
// the invite-accept body uses. Unknown fields are rejected, so the two are not
// interchangeable.
type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required,min=1,max=256" example:"c4e8b1d0a9f2c4e6f1c8a0e9d2b4f7a3"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=512" example:"correct-horse-battery-staple"`
} //@name ResetPasswordRequest
