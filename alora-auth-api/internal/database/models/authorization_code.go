package models

import "time"

// AuthorizationCode is a row of tbl_authorization_codes: a single-use code the
// authorize endpoint issued under a central session. Only its hash is stored.
type AuthorizationCode struct {
	ID                  string
	CodeHash            string
	ProductID           string
	UserID              string
	ClientID            string
	ParentFamilyID      string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               *string
	Scope               *string
	ExpiresAt           *time.Time
	UsedAt              *time.Time
	IssuedFamilyID      *string // the product family the code was exchanged for
	CreatedAt           *time.Time
}
