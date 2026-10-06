// Package models holds the password-reset feature's DTOs and HTTP
// request/response models.
package models

import "time"

// Issued is a minted reset link. ResetURL is set ONLY when the link may be
// returned to the caller, which is when email is unavailable: a deployment with
// working mail never hands an account-takeover primitive back over the API.
type Issued struct {
	ExpiresAt time.Time
	ResetURL  *string
}
