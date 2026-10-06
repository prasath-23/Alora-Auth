package models

import "time"

// Response models. Fields are declared in alphabetical order of their JSON names.
// Collections are never null.

// GroupListItemResponse is one row of the group list.
type GroupListItemResponse struct {
	CreatedAt     *time.Time             `json:"created_at"`
	Description   string                 `json:"description" example:"Helpdesk staff"`
	ID            string                 `json:"id" example:"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
	LoginPolicyID *string                `json:"login_policy_id"`
	MemberCount   int64                  `json:"member_count" example:"4"`
	Name          string                 `json:"name" example:"Support"`
	ProductGrants []ProductGrantResponse `json:"product_grants"`
	Scopes        []string               `json:"scopes" example:"users:read,sessions:read"`
	SystemKey     *string                `json:"system_key" example:"ADMINS"`
} //@name GroupListItem

// ProductGrantResponse is one product role a group confers.
type ProductGrantResponse struct {
	ProductID  string `json:"product_id" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	ProductKey string `json:"product_key" example:"CRM"`
	RoleName   string `json:"role_name" example:"Viewer"`
} //@name GroupProductGrant

func productGrants(gs []ProductGrant) []ProductGrantResponse {
	out := make([]ProductGrantResponse, 0, len(gs))
	for _, g := range gs {
		out = append(out, ProductGrantResponse{ProductID: g.ProductID, ProductKey: g.ProductKey, RoleName: g.RoleName})
	}
	return out
}

func scopeList(fs []string) []string {
	if fs == nil {
		return []string{}
	}
	return fs
}

func listItem(g GroupListItem) GroupListItemResponse {
	return GroupListItemResponse{
		CreatedAt: g.CreatedAt, Description: g.Description, ID: g.ID,
		LoginPolicyID: g.LoginPolicyID, MemberCount: g.MemberCount, Name: g.Name,
		ProductGrants: productGrants(g.ProductGrants), Scopes: scopeList(g.Scopes), SystemKey: g.SystemKey,
	}
}

// NewGroupListResponse renders the groups as a bare array; never null.
func NewGroupListResponse(groups []GroupListItem) []GroupListItemResponse {
	out := make([]GroupListItemResponse, 0, len(groups))
	for _, g := range groups {
		out = append(out, listItem(g))
	}
	return out
}

// GroupDetailResponse is one group with its members and managers. Either list is
// empty when there are none, never null.
type GroupDetailResponse struct {
	GroupListItemResponse
	LoginPolicyName *string                `json:"login_policy_name" example:"SSO only"`
	Managers        []GroupManagerResponse `json:"managers"`
	Members         []GroupMemberResponse  `json:"members"`
} //@name GroupDetail

// GroupManagerResponse is one person who runs the group, and who appointed them.
type GroupManagerResponse struct {
	AppointedAt      *time.Time `json:"appointed_at"`
	AppointedByEmail string     `json:"appointed_by_email" example:"admin@acme.com"`
	AppointedByOwner bool       `json:"appointed_by_owner" example:"false"`
	Email            string     `json:"email" example:"lead@acme.com"`
	UserID           string     `json:"user_id" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
} //@name GroupManager

// GroupMemberResponse is one membership row.
type GroupMemberResponse struct {
	AssignedAt *time.Time `json:"assigned_at"`
	Email      string     `json:"email" example:"member@acme.com"`
	UserID     string     `json:"user_id" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
} //@name GroupMember

// NewGroupDetailResponse renders one group.
func NewGroupDetailResponse(g GroupDetail) GroupDetailResponse {
	members := make([]GroupMemberResponse, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, GroupMemberResponse{AssignedAt: m.AssignedAt, Email: m.Email, UserID: m.UserID})
	}
	managers := make([]GroupManagerResponse, 0, len(g.Managers))
	for _, m := range g.Managers {
		managers = append(managers, GroupManagerResponse{
			AppointedAt: m.AppointedAt, AppointedByEmail: m.AppointedByEmail, AppointedByOwner: m.AppointedByOwner,
			Email: m.Email, UserID: m.UserID,
		})
	}
	return GroupDetailResponse{
		GroupListItemResponse: listItem(g.GroupListItem), LoginPolicyName: g.LoginPolicyName,
		Managers: managers, Members: members,
	}
}

// GroupResponse echoes the group that was written.
type GroupResponse struct {
	ID            string                 `json:"id" example:"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
	Name          string                 `json:"name" example:"Support"`
	ProductGrants []ProductGrantResponse `json:"product_grants"`
	Scopes        []string               `json:"scopes" example:"users:read,sessions:read"`
} //@name GroupResponse

// NewGroupResponse renders a written group.
func NewGroupResponse(g Group) GroupResponse {
	return GroupResponse{ID: g.ID, Name: g.Name, ProductGrants: productGrants(g.ProductGrants), Scopes: scopeList(g.Scopes)}
}

// AddMemberResponse echoes the membership that was created.
type AddMemberResponse struct {
	GroupID string `json:"group_id" example:"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
	UserID  string `json:"user_id" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
} //@name AddMemberResponse

// NewAddMemberResponse renders a created membership.
func NewAddMemberResponse(m Membership) AddMemberResponse {
	return AddMemberResponse{GroupID: m.GroupID, UserID: m.UserID}
}

// AppointmentResponse echoes the manager appointment that was made.
type AppointmentResponse struct {
	GroupID string `json:"group_id" example:"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
	UserID  string `json:"user_id" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
} //@name GroupManagerAppointment

// NewAppointmentResponse renders an appointment.
func NewAppointmentResponse(a Appointment) AppointmentResponse {
	return AppointmentResponse{GroupID: a.GroupID, UserID: a.UserID}
}

// GroupScopesResponse echoes the scope set a group now gives.
type GroupScopesResponse struct {
	Scopes []string `json:"scopes" example:"users:read,sessions:read"`
} //@name GroupScopesResponse

// NewGroupScopesResponse renders a written scope set; never null.
func NewGroupScopesResponse(scopes []string) GroupScopesResponse {
	return GroupScopesResponse{Scopes: scopeList(scopes)}
}
