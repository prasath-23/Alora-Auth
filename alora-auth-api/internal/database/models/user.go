package models

import "time"

// User is a row of tbl_users.
type User struct {
	ID                 string
	ClientID           string
	Email              string
	PasswordHash       *string // NULL for an OAUTH_ONLY account
	AccountType        AccountType
	IsActive           bool
	PermissionsVersion int32
	LoginPolicyID      *string // NULL: the policy comes from a group or the default
	CreatedAt          *time.Time
	UpdatedAt          *time.Time
	DeletedAt          *time.Time
}

// UserListItem is a row of vw_UserListItem. It projects no password hash and no
// deletion marker.
type UserListItem struct {
	ID                 string
	ClientID           string
	Email              string
	AccountType        AccountType
	IsActive           bool
	PermissionsVersion int32
	LoginPolicyID      *string
	IsAdmin            bool // a member of the company's Admins group
	IsOwner            bool // a platform Owner
	CreatedAt          *time.Time
	UpdatedAt          *time.Time
}

// UserTenantScoped is a row of vw_UserTenantScoped: a live user, looked up inside
// one company. It has the list row's shape.
type UserTenantScoped = UserListItem

// UserCredential is a row of vw_UserCredential: a live password account of an
// active company, the only rows a password login may consider.
type UserCredential struct {
	ID           string
	ClientID     string
	Email        string
	PasswordHash *string
	AccountType  AccountType
	CreatedAt    *time.Time
}

// UserIdentity is a row of vw_UserIdentity: a live account of an active company.
type UserIdentity struct {
	ID                 string
	ClientID           string
	Email              string
	PermissionsVersion int32
}

// UserLoginPolicy is a row of vw_UserLoginPolicy: the login policy that applies
// to a user, and where it came from (USER, GROUP or DEFAULT).
type UserLoginPolicy struct {
	UserID          string
	ClientID        string
	PolicyID        string
	PolicyName      string
	AllowPassword   bool
	AllowGoogle     bool
	SSOConnectionID *string
	Source          string
}
