package models

import "time"

// LoginPolicy is a row of tbl_login_policies: which sign-in methods a company
// allows for the users it applies to.
type LoginPolicy struct {
	ID              string
	ClientID        string
	Name            string
	AllowPassword   bool
	AllowGoogle     bool
	SSOConnectionID *string
	Priority        int32
	IsDefault       bool
	CreatedAt       *time.Time
	UpdatedAt       *time.Time
}

// DomainLoginHint is a row of vw_DomainLoginHint: the sign-in methods to offer
// for an email domain. A hint for the login page only.
type DomainLoginHint struct {
	Domain        string
	ClientID      string
	ConnectionID  *string
	AllowPassword bool
	AllowGoogle   bool
}
