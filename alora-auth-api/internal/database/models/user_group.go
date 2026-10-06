package models

import "time"

// UserGroup is a row of tbl_user_groups: a group membership.
type UserGroup struct {
	UserID     string
	GroupID    string
	ClientID   string
	AssignedAt *time.Time
	AssignedBy *string
}

// UserGroupMembership is a row of vw_UserGroupMembership: a membership joined to
// its group's name.
type UserGroupMembership struct {
	UserID     string
	ClientID   string
	GroupID    string
	GroupName  string
	SystemKey  *string
	AssignedAt *time.Time
}
