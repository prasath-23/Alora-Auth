// Package models holds the App Central sign-in feature's DTOs and HTTP
// request/response models.
package models

import "time"

// Signed is a completed sign-in or refresh: the App Central session's refresh
// token (for the HttpOnly cookie) and an access token for App Central's API.
type Signed struct {
	RefreshToken string
	RefreshTTL   time.Duration
	AccessToken  string
	ExpiresIn    int
}

// Company is one company an account choice offers.
type Company struct {
	ClientID string
	Name     string
}

// Outcome is what a sign-in step produced: a session, or a choice between the
// companies the person has an account in.
type Outcome struct {
	Session   *Signed   // set when signed in
	Ticket    string    // set when a choice is needed: binds it to this browser
	Companies []Company // the choice
	ReturnTo  string    // where to go afterwards, already checked to be App Central's own
}

// Discovery is which sign-in methods to offer for an email domain.
type Discovery struct {
	Password        bool
	Google          bool
	SSOConnectionID *string
}

// CallbackError is why a Google or SSO sign-in failed, as the code the login page
// understands.
type CallbackError struct{ Code string }

func (e *CallbackError) Error() string { return "sign-in callback: " + e.Code }
