package models

import "time"

// PasswordResetToken is a row of tbl_password_reset_tokens. Only the token's hash
// is ever stored.
type PasswordResetToken struct {
	ID        string
	UserID    string
	ClientID  string
	TokenHash string
	ExpiresAt *time.Time
	UsedAt    *time.Time
	CreatedBy string
	CreatedAt *time.Time
}

// ValidResetToken is a row of vw_ValidResetToken: an unused, unexpired token
// joined to its owner's state.
type ValidResetToken struct {
	ID        string
	UserID    string
	ClientID  string
	TokenHash string
	Email     string
	IsActive  bool
	DeletedAt *time.Time
}
