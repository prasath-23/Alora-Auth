package models

import "time"

// LoginState is a row of tbl_login_states: a pending sign-in (a round trip to
// Google or an SSO provider) or an account choice. Only the state's hash is
// stored, and each is redeemed once.
type LoginState struct {
	StateHash        string
	Kind             LoginStateKind
	ConnectionID     *string
	Nonce            *string
	CodeVerifier     *string
	ReturnTo         *string
	CandidateUserIDs []string
	AuthMethod       *IdpProvider
	ExpiresAt        *time.Time
	CreatedAt        *time.Time
}
