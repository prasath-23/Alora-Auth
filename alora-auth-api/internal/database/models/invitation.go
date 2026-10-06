package models

import "time"

// Invitation is a row of tbl_invitations. Only the token's hash is ever stored.
// Exactly one of InvitedByUserID (a company Admin) and InvitedByOwnerID (a
// platform Owner) is set.
type Invitation struct {
	ID               string
	Email            string
	ClientID         string
	InvitedByUserID  *string
	InvitedByOwnerID *string
	TokenHash        string
	ExpiresAt        *time.Time
	Status           InvitationStatus
	AcceptedAt       *time.Time
	AcceptedByUserID *string
	RevokedAt        *time.Time
	RevokedByUserID  *string
	CreatedAt        *time.Time
	UpdatedAt        *time.Time
}

// InvitationListItem is a row of vw_InvitationListItem. It projects no token hash.
type InvitationListItem struct {
	ID        string
	ClientID  string
	Email     string
	Status    InvitationStatus
	ExpiresAt *time.Time
	CreatedAt *time.Time
}

// PendingInvitation is a row of vw_PendingInvitation: an invitation that is still
// redeemable (pending, unexpired, active company).
type PendingInvitation struct {
	ID               string
	Email            string
	ClientID         string
	InvitedByUserID  *string
	InvitedByOwnerID *string
	TokenHash        string
	ExpiresAt        *time.Time
	ClientName       string
}

// InvitationGroup is a row of vw_InvitationGroup: a group an invitation adds its
// user to.
type InvitationGroup struct {
	InvitationID string
	ClientID     string
	GroupID      string
	GroupName    string
}
