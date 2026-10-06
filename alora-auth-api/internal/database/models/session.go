package models

import "time"

// Session is a row of tbl_user_sessions: one refresh token, one generation of a
// session family.
type Session struct {
	ID               string
	UserID           string
	ClientID         string
	SessionUUID      string
	FamilyID         string
	Generation       int32
	RefreshTokenHash string
	PrevTokenHash    *string
	ExpiresAt        *time.Time
	RevokedAt        *time.Time
	RevokedReason    *RevokeReason
	IPAddress        *string
	DeviceLabel      *string
	UserAgent        *string
	LastSeenAt       *time.Time
	CreatedAt        *time.Time
	ReplacedByID     *string
}

// SessionOwner is a row of vw_SessionOwner: whose session a refresh token is,
// revoked or not.
type SessionOwner struct {
	ID               string
	FamilyID         string
	UserID           string
	ClientID         string
	RevokedAt        *time.Time
	RefreshTokenHash string
}

// SessionFamilyGate is a row of vw_SessionFamilyGate: everything that decides
// whether a session family may still be used, evaluated in one read.
type SessionFamilyGate struct {
	FamilyID           string
	UserID             string
	ClientID           string
	Kind               SessionKind
	ProductID          *string
	ParentFamilyID     *string
	AuthMethod         IdpProvider
	AuthConnectionID   *string
	AuthenticatedAt    *time.Time
	AbsoluteExpiresAt  *time.Time
	FamilyAlive        bool // not revoked, under its cap, holding a live token
	ParentAlive        bool // the same for the parent; true for a CENTRAL family
	UserActive         bool
	ClientActive       bool
	Email              string
	PermissionsVersion int32
	IsTenantAdmin      bool // a member of the company's ADMINS group
	IsPlatformOwner    bool
	HasAccess          bool // effective access to the family's product; true for CENTRAL
	AdminVersion       int32
	Scopes             []string // the user's effective App Central scopes, read fresh
}

// SessionFamilySummary is a row of vw_SessionFamilySummary: a live session
// family as the admin list shows it — whose it is by address, never by id, and
// no token hash.
type SessionFamilySummary struct {
	ID              string
	ClientID        string
	Kind            SessionKind
	ProductKey      *string
	AuthMethod      IdpProvider
	AuthenticatedAt *time.Time
	CreatedAt       *time.Time
	DeviceLabel     string
	IPAddress       string
	LastSeenAt      *time.Time
	Email           string
}
