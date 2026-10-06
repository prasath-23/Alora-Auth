package models

import "time"

// SystemGroupAdmins is the system_key of the group whose members administer
// their company. It is created with the company and can be neither renamed nor
// deleted.
const SystemGroupAdmins = "ADMINS"

// Group is a row of tbl_groups.
type Group struct {
	ID            string
	ClientID      string
	Name          string
	Description   *string
	SystemKey     *string // "ADMINS" for the company's Admins group, else NULL
	LoginPolicyID *string
	CreatedAt     *time.Time
	UpdatedAt     *time.Time
}

// GroupProductGrant is one product role a group confers on its members, as the
// group views aggregate them.
type GroupProductGrant struct {
	ProductID  string `json:"product_id"`
	ProductKey string `json:"product_key"`
	RoleName   string `json:"role_name"`
}

// GroupListItem is a row of vw_GroupListItem.
type GroupListItem struct {
	ID            string
	ClientID      string
	Name          string
	Description   *string
	SystemKey     *string
	LoginPolicyID *string
	CreatedAt     *time.Time
	UpdatedAt     *time.Time
	Scopes        []string // App Central scopes; the ADMINS group lists every person scope
	ProductGrants []GroupProductGrant
	MemberCount   int64
}

// GroupDetailRow is a row of vw_GroupDetailRow: one per member, or a single row
// with nil member fields for an empty group.
type GroupDetailRow struct {
	ID            string
	ClientID      string
	Name          string
	Description   *string
	SystemKey     *string
	LoginPolicyID *string
	CreatedAt     *time.Time
	Scopes        []string // App Central scopes; the ADMINS group lists every person scope
	ProductGrants []GroupProductGrant
	UserID        *string
	UserEmail     *string
	AssignedAt    *time.Time
}

// GroupManager is a row of vw_GroupManager: one person who runs a group — adds
// and removes its members, nothing else — and who appointed them.
type GroupManager struct {
	GroupID          string
	ClientID         string
	UserID           string
	Email            string
	AppointedAt      *time.Time
	AppointedByEmail string
	AppointedByOwner bool // appointed by a platform Owner rather than a user of the company
}
