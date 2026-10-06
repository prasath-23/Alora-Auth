package models

import "time"

// LinkedIdentity is a row of tbl_linked_identities: an external identity (a
// Google subject, or a subject at one SSO connection) bound to a local account.
type LinkedIdentity struct {
	ID            string
	UserID        string
	ClientID      string
	Provider      IdpProvider
	ConnectionID  *string // set for OIDC links only
	ProviderID    string
	EmailVerified bool
	EmailAtLink   *string
	CreatedAt     *time.Time
}

// LinkedIdentityOwner is a row of vw_LinkedIdentityOwner: a link joined to its
// account's state.
type LinkedIdentityOwner struct {
	Provider     IdpProvider
	ConnectionID *string
	ProviderID   string
	UserID       string
	ClientID     string
	Email        string
	AccountType  AccountType
	IsActive     bool // the account AND its company are active
}
