package models

import "time"

// ProductPermission is a row of tbl_product_permissions: a role in one product
// granted to one user directly.
type ProductPermission struct {
	ID         string
	UserID     string
	ClientID   string
	ProductID  string
	RoleName   string
	GrantedBy  *string
	ValidFrom  *time.Time
	ValidUntil *time.Time
	CreatedAt  *time.Time
}

// UserProductRole is a row of vw_UserProductRole: a DIRECT grant joined to its
// product.
type UserProductRole struct {
	UserID      string
	ClientID    string
	ProductID   string
	ProductKey  string
	ProductName string
	RoleName    string
	ValidUntil  *time.Time
}

// EffectiveProductRole is a row of vw_EffectiveProductRole: one role a user may
// use in a product right now, granted directly (Source DIRECT) or through a
// group (Source GROUP, with GroupID).
type EffectiveProductRole struct {
	UserID      string
	ClientID    string
	ProductID   string
	ProductKey  string
	ProductName string
	RoleName    string
	Source      string
	GroupID     *string
}

// UserApp is a row of vw_UserApp: a product a user may launch, with every role
// they hold in it.
type UserApp struct {
	UserID             string
	ClientID           string
	ProductID          string
	ProductKey         string
	ProductName        string
	ProductDescription *string
	BaseURL            *string
	InitiateLoginURI   *string
	Roles              []string
}
