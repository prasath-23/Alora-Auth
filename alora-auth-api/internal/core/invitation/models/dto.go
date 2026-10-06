// Package models holds the invitation feature's DTOs and HTTP request/response
// models.
package models

import "time"

// Created is an issued invitation. The raw token appears only inside InviteURL
// and is never persisted.
type Created struct {
	ID        string
	Email     string
	InviteURL string
	ExpiresAt time.Time
}

// Listed is one invitation in the company's list. The token hash is never
// projected.
type Listed struct {
	ID        string
	Email     string
	Status    string
	ExpiresAt *time.Time
	CreatedAt *time.Time
}

// Methods are the ways an invitee will be able to sign in, per the login policy
// they will have.
type Methods struct {
	Password bool
	Google   bool
	SSO      bool
}

// Preview is the unauthenticated invite-landing payload.
type Preview struct {
	Email      string
	ClientName string
	ExpiresAt  *time.Time
	Methods    Methods
	Groups     []string
}
