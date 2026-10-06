package models

// IdpProvider is the "IdpProvider" enum: how a session was authenticated, and
// which kind of external identity a link binds.
type IdpProvider string

const (
	IdpEmail     IdpProvider = "EMAIL"
	IdpGoogle    IdpProvider = "GOOGLE"
	IdpMicrosoft IdpProvider = "MICROSOFT" // reserved
	IdpSAML      IdpProvider = "SAML"      // reserved
	IdpOIDC      IdpProvider = "OIDC"
)

// SubscriptionStatus is the "SubscriptionStatus" enum.
type SubscriptionStatus string

const (
	SubscriptionTrial     SubscriptionStatus = "TRIAL"
	SubscriptionActive    SubscriptionStatus = "ACTIVE"
	SubscriptionSuspended SubscriptionStatus = "SUSPENDED"
	SubscriptionCancelled SubscriptionStatus = "CANCELLED"
)

// AccountType is the "AccountType" enum.
type AccountType string

const (
	AccountTypeEmail     AccountType = "EMAIL"
	AccountTypeOAuthOnly AccountType = "OAUTH_ONLY"
	AccountTypeHybrid    AccountType = "HYBRID"
)

// InvitationStatus is the "InvitationStatus" enum.
type InvitationStatus string

const (
	InvitationPending  InvitationStatus = "PENDING"
	InvitationAccepted InvitationStatus = "ACCEPTED"
	InvitationExpired  InvitationStatus = "EXPIRED"
	InvitationRevoked  InvitationStatus = "REVOKED"
)

// RevokeReason is the "SessionRevokedReason" enum.
type RevokeReason string

const (
	RevokeReasonLogout        RevokeReason = "LOGOUT"
	RevokeReasonLogoutAll     RevokeReason = "LOGOUT_ALL"
	RevokeReasonReuseDetected RevokeReason = "REUSE_DETECTED"
	RevokeReasonAdmin         RevokeReason = "ADMIN"
	RevokeReasonExpired       RevokeReason = "EXPIRED"
	RevokeReasonPolicy        RevokeReason = "POLICY"
	RevokeReasonAccessLost    RevokeReason = "ACCESS_LOST"
	RevokeReasonSuspended     RevokeReason = "SUSPENDED"
)

// SessionKind is the "SessionKind" enum: a CENTRAL login at App Central, or a
// PRODUCT login that one product's backend holds under it.
type SessionKind string

const (
	SessionCentral SessionKind = "CENTRAL"
	SessionProduct SessionKind = "PRODUCT"
)

// LoginStateKind is the "LoginStateKind" enum: what a pending sign-in state is
// waiting for.
type LoginStateKind string

const (
	LoginStateGoogle        LoginStateKind = "GOOGLE"
	LoginStateOIDC          LoginStateKind = "OIDC"
	LoginStateAccountChoice LoginStateKind = "ACCOUNT_CHOICE"
)
