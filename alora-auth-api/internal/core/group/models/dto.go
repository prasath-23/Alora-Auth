// Package models holds the group feature's DTOs and HTTP request/response models.
// A group is how access is given: it gives its members App Central scopes and
// product roles, and may carry a login policy. Every company has an Admins
// group, which holds every scope.
package models

import "time"

// SystemAdmins is the system key of the company's Admins group.
const SystemAdmins = "ADMINS"

// ProductGrant is a product role a group confers.
type ProductGrant struct {
	ProductID  string
	ProductKey string
	RoleName   string
}

// GroupInput is a new group's complete state.
type GroupInput struct {
	Name          string
	Description   string
	Scopes        []string
	ProductGrants []ProductGrant
}

// GroupListItem is one group with what it grants and its member count.
type GroupListItem struct {
	ID            string
	Name          string
	Description   string
	SystemKey     *string
	LoginPolicyID *string
	Scopes        []string
	ProductGrants []ProductGrant
	MemberCount   int64
	CreatedAt     *time.Time
}

// GroupDetail is one group with its members and managers.
type GroupDetail struct {
	GroupListItem
	Members  []Member
	Managers []Manager
	// LoginPolicyName names the sign-in policy the group carries, if any: adding
	// someone to the group can put them under it.
	LoginPolicyName *string
}

// Manager is one person who runs a group: they add and remove its members, and
// nothing else.
type Manager struct {
	UserID           string
	Email            string
	AppointedAt      *time.Time
	AppointedByEmail string
	AppointedByOwner bool
}

// Appointment is a manager appointment that was made.
type Appointment struct {
	GroupID string
	UserID  string
}

// Member is one membership of a group.
type Member struct {
	UserID     string
	Email      string
	AssignedAt *time.Time
}

// Group is a group that was written.
type Group struct {
	ID            string
	Name          string
	Scopes        []string
	ProductGrants []ProductGrant
}

// MemberInput identifies the user to add by id or by email; the id wins.
type MemberInput struct {
	UserID string
	Email  string
}

// Membership is a membership that was created.
type Membership struct {
	GroupID string
	UserID  string
}
