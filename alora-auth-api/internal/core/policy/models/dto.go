// Package models holds the login-policy feature's DTOs and HTTP request/response
// models.
package models

import "time"

// Policy is one of a company's login policies.
type Policy struct {
	ID              string
	Name            string
	AllowPassword   bool
	AllowGoogle     bool
	SSOConnectionID *string
	Priority        int32
	IsDefault       bool
	CreatedAt       *time.Time
	UpdatedAt       *time.Time
}

// PolicyInput is the complete desired state of a policy.
type PolicyInput struct {
	Name            string
	AllowPassword   bool
	AllowGoogle     bool
	SSOConnectionID *string
	Priority        int32
}

// Effective is the policy that applies to one user, and where it came from:
// USER (their own), GROUP (their highest-priority group's) or DEFAULT.
type Effective struct {
	PolicyID        string
	PolicyName      string
	AllowPassword   bool
	AllowGoogle     bool
	SSOConnectionID *string
	Source          string
}

// Hint is what the login page may offer for an email domain. It says nothing
// about any account.
type Hint struct {
	AllowPassword   bool
	AllowGoogle     bool
	SSOConnectionID *string
}
