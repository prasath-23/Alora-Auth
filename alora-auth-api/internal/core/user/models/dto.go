// Package models holds the user feature's DTOs and HTTP request/response models:
// company user administration, direct product grants, and the caller's own
// account and apps.
package models

import "time"

// ListQuery selects one keyset page of users. Take is already validated (1-100).
type ListQuery struct {
	Take   int
	Cursor string // an opaque user id; "" means the first page
	Search string
}

// UserPage is one page of users. NextCursor is nil on the last page.
type UserPage struct {
	Users      []UserListItem
	NextCursor *string
}

// UserListItem is one user in a page, with the groups they belong to.
type UserListItem struct {
	ID          string
	Email       string
	IsActive    bool
	IsAdmin     bool
	IsOwner     bool
	AccountType string
	CreatedAt   *time.Time
	Groups      []GroupRef
}

// GroupRef is the minimal reference to a group a user belongs to.
type GroupRef struct {
	ID        string
	Name      string
	SystemKey *string
}

// UserDetail is one user with their access, groups and login policy.
type UserDetail struct {
	ID          string
	Email       string
	AccountType string
	IsActive    bool
	IsAdmin     bool
	IsOwner     bool
	CreatedAt   *time.Time
	UpdatedAt   *time.Time
	// OwnPolicyID is the user's own login-policy assignment, if any.
	OwnPolicyID *string
	// Policy is the login policy that applies, and where it came from.
	Policy       *Policy
	DirectGrants []Grant
	Access       []Access
	Groups       []Membership
	// Scopes is every App Central scope the user holds, one entry per source;
	// ExtraScopes the ones given to them alone.
	Scopes      []ScopeGrant
	ExtraScopes []string
	// Manages is the groups the user runs as a manager.
	Manages []GroupRef
}

// ScopeGrant is one App Central scope a person holds, and where it comes from:
// a group (GroupID and GroupName set) or an extra (both nil).
type ScopeGrant struct {
	Scope     string
	Source    string // GROUP or EXTRA
	GroupID   *string
	GroupName *string
}

// Policy is the login policy that applies to a user.
type Policy struct {
	ID              string
	Name            string
	Source          string // USER, GROUP or DEFAULT
	AllowPassword   bool
	AllowGoogle     bool
	SSOConnectionID *string
}

// Grant is a product role granted to a user directly.
type Grant struct {
	ProductID   string
	ProductKey  string
	ProductName string
	RoleName    string
	ValidUntil  *time.Time
}

// Access is one role a user may use in a product right now, and where it comes
// from: DIRECT, or GROUP with the group.
type Access struct {
	ProductID   string
	ProductKey  string
	ProductName string
	RoleName    string
	Source      string
	GroupID     *string
}

// Membership is a group a user belongs to, with when they were added.
type Membership struct {
	ID         string
	Name       string
	SystemKey  *string
	AssignedAt *time.Time
}

// ActiveState is a user's state after an activate/deactivate.
type ActiveState struct {
	ID       string
	IsActive bool
}

// Me is the caller's own account.
type Me struct {
	UserID          string
	Email           string
	CompanyID       string
	CompanyName     string
	IsAdmin         bool
	IsOwner         bool
	Scopes          []string     // exactly what a login token minted now would carry
	ScopeSources    []ScopeGrant // where each App Central scope comes from
	Products        []string     // the keys of the products the caller may open
	Manages         []GroupRef   // the groups the caller runs as a manager
	AuthenticatedAt time.Time
}

// App is a product the caller may launch.
type App struct {
	ProductID   string
	Key         string
	Name        string
	Description *string
	Roles       []string
	// LaunchURL starts the product's own sign-in (OIDC third-party initiated
	// login). nil when the product registered no way in.
	LaunchURL *string
}
