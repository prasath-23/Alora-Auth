package models

import "time"

// Response models. Fields are declared in alphabetical order of their JSON names.
// Collections are never null.

// UserListResponse is one keyset page of users. nextCursor is null on the last
// page; it is an opaque user id to the client.
type UserListResponse struct {
	NextCursor *string                `json:"nextCursor" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
	Users      []UserListItemResponse `json:"users"`
} //@name UserListResponse

// UserListItemResponse is one row of the user list. password_hash and deleted_at
// are not projected by the query at all.
type UserListItemResponse struct {
	AccountType string                 `json:"account_type" example:"EMAIL" enums:"EMAIL,OAUTH_ONLY,HYBRID"`
	CreatedAt   *time.Time             `json:"created_at"`
	Email       string                 `json:"email" example:"member@acme.com"`
	Groups      []UserGroupRefResponse `json:"groups"`
	ID          string                 `json:"id" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
	IsActive    bool                   `json:"is_active" example:"true"`
	IsAdmin     bool                   `json:"is_admin" example:"false"`
	IsOwner     bool                   `json:"is_owner" example:"false"`
} //@name UserListItem

// UserGroupRefResponse is the minimal group reference embedded in a user row.
type UserGroupRefResponse struct {
	ID        string  `json:"id" example:"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
	Name      string  `json:"name" example:"Support"`
	SystemKey *string `json:"system_key" example:"ADMINS"`
} //@name UserGroupRef

// NewUserListResponse renders one page.
func NewUserListResponse(p UserPage) UserListResponse {
	users := make([]UserListItemResponse, 0, len(p.Users))
	for _, u := range p.Users {
		groups := make([]UserGroupRefResponse, 0, len(u.Groups))
		for _, g := range u.Groups {
			groups = append(groups, UserGroupRefResponse{ID: g.ID, Name: g.Name, SystemKey: g.SystemKey})
		}
		users = append(users, UserListItemResponse{
			AccountType: u.AccountType, CreatedAt: u.CreatedAt, Email: u.Email, Groups: groups,
			ID: u.ID, IsActive: u.IsActive, IsAdmin: u.IsAdmin, IsOwner: u.IsOwner,
		})
	}
	return UserListResponse{NextCursor: p.NextCursor, Users: users}
}

// UserDetailResponse is the full company-scoped user record.
type UserDetailResponse struct {
	AccountType  string                        `json:"account_type" example:"EMAIL" enums:"EMAIL,OAUTH_ONLY,HYBRID"`
	Access       []UserAccessResponse          `json:"access"`
	CreatedAt    *time.Time                    `json:"created_at"`
	DirectGrants []UserGrantResponse           `json:"direct_grants"`
	Email        string                        `json:"email" example:"member@acme.com"`
	Groups       []UserGroupMembershipResponse `json:"groups"`
	ID           string                        `json:"id" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
	IsActive     bool                          `json:"is_active" example:"true"`
	IsAdmin      bool                          `json:"is_admin" example:"false"`
	IsOwner      bool                          `json:"is_owner" example:"false"`
	ExtraScopes  []string                      `json:"extra_scopes" example:"sessions:read"`
	LoginPolicy  *UserPolicyResponse           `json:"login_policy"`
	Manages      []ManagedGroupRef             `json:"manages"`
	OwnPolicyID  *string                       `json:"own_policy_id"`
	Scopes       []ScopeGrantResponse          `json:"scopes"`
	UpdatedAt    *time.Time                    `json:"updated_at"`
} //@name UserDetail

// ScopeGrantResponse is one App Central scope a person holds and where it comes
// from: a group, or an extra given to them alone.
type ScopeGrantResponse struct {
	GroupID   *string `json:"group_id" example:"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
	GroupName *string `json:"group_name" example:"Support"`
	Scope     string  `json:"scope" example:"users:read"`
	Source    string  `json:"source" example:"GROUP" enums:"GROUP,EXTRA"`
} //@name ScopeGrant

func scopeGrants(gs []ScopeGrant) []ScopeGrantResponse {
	out := make([]ScopeGrantResponse, 0, len(gs))
	for _, g := range gs {
		out = append(out, ScopeGrantResponse{GroupID: g.GroupID, GroupName: g.GroupName, Scope: g.Scope, Source: g.Source})
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// UserAccessResponse is one role a user may use right now, and where it comes
// from.
type UserAccessResponse struct {
	GroupID     *string `json:"group_id"`
	ProductID   string  `json:"product_id" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	ProductKey  string  `json:"product_key" example:"CRM"`
	ProductName string  `json:"product_name" example:"Acme CRM"`
	RoleName    string  `json:"role_name" example:"Editor"`
	Source      string  `json:"source" example:"GROUP" enums:"DIRECT,GROUP"`
} //@name UserAccess

// UserGrantResponse is one product role granted to the user directly.
type UserGrantResponse struct {
	ProductID   string     `json:"product_id" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	ProductKey  string     `json:"product_key" example:"CRM"`
	ProductName string     `json:"product_name" example:"Acme CRM"`
	RoleName    string     `json:"role_name" example:"Editor"`
	ValidUntil  *time.Time `json:"valid_until"`
} //@name UserGrant

// UserGroupMembershipResponse is a group the user belongs to.
type UserGroupMembershipResponse struct {
	AssignedAt *time.Time `json:"assigned_at"`
	ID         string     `json:"id" example:"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
	Name       string     `json:"name" example:"Support"`
	SystemKey  *string    `json:"system_key" example:"ADMINS"`
} //@name UserGroupMembership

// UserPolicyResponse is the login policy that applies to the user.
type UserPolicyResponse struct {
	AllowGoogle     bool    `json:"allow_google" example:"true"`
	AllowPassword   bool    `json:"allow_password" example:"true"`
	ID              string  `json:"id" example:"9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"`
	Name            string  `json:"name" example:"Default"`
	Source          string  `json:"source" example:"DEFAULT" enums:"USER,GROUP,DEFAULT"`
	SSOConnectionID *string `json:"sso_connection_id"`
} //@name UserLoginPolicy

// NewUserDetailResponse renders one user.
func NewUserDetailResponse(d UserDetail) UserDetailResponse {
	access := make([]UserAccessResponse, 0, len(d.Access))
	for _, a := range d.Access {
		access = append(access, UserAccessResponse{
			GroupID: a.GroupID, ProductID: a.ProductID, ProductKey: a.ProductKey,
			ProductName: a.ProductName, RoleName: a.RoleName, Source: a.Source,
		})
	}
	grants := make([]UserGrantResponse, 0, len(d.DirectGrants))
	for _, g := range d.DirectGrants {
		grants = append(grants, UserGrantResponse{
			ProductID: g.ProductID, ProductKey: g.ProductKey, ProductName: g.ProductName,
			RoleName: g.RoleName, ValidUntil: g.ValidUntil,
		})
	}
	groups := make([]UserGroupMembershipResponse, 0, len(d.Groups))
	for _, g := range d.Groups {
		groups = append(groups, UserGroupMembershipResponse{AssignedAt: g.AssignedAt, ID: g.ID, Name: g.Name, SystemKey: g.SystemKey})
	}
	var policy *UserPolicyResponse
	if d.Policy != nil {
		policy = &UserPolicyResponse{
			AllowGoogle: d.Policy.AllowGoogle, AllowPassword: d.Policy.AllowPassword, ID: d.Policy.ID,
			Name: d.Policy.Name, Source: d.Policy.Source, SSOConnectionID: d.Policy.SSOConnectionID,
		}
	}
	return UserDetailResponse{
		AccountType: d.AccountType, Access: access, CreatedAt: d.CreatedAt, DirectGrants: grants,
		Email: d.Email, ExtraScopes: nonNilStrings(d.ExtraScopes), Groups: groups, ID: d.ID, IsActive: d.IsActive,
		IsAdmin: d.IsAdmin, IsOwner: d.IsOwner, LoginPolicy: policy, Manages: groupRefs(d.Manages),
		OwnPolicyID: d.OwnPolicyID, Scopes: scopeGrants(d.Scopes), UpdatedAt: d.UpdatedAt,
	}
}

// UpdateUserResponse echoes the new state.
type UpdateUserResponse struct {
	ID       string `json:"id" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
	IsActive bool   `json:"is_active" example:"false"`
} //@name UpdateUserResponse

// NewUpdateUserResponse renders the new state.
func NewUpdateUserResponse(s ActiveState) UpdateUserResponse {
	return UpdateUserResponse{ID: s.ID, IsActive: s.IsActive}
}

// MeResponse is the caller's own account: who they are, in which company, and
// what App Central should show them. It is a rendering hint, not an
// authorization decision: every route re-checks its own guard.
type MeResponse struct {
	AuthenticatedAt time.Time            `json:"authenticated_at"`
	Company         MeCompanyResponse    `json:"company"`
	Email           string               `json:"email" example:"alice@acme.com"`
	ID              string               `json:"id" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
	IsAdmin         bool                 `json:"is_admin" example:"false"`
	IsOwner         bool                 `json:"is_owner" example:"false"`
	Manages         []ManagedGroupRef    `json:"manages"`
	Products        []string             `json:"products" example:"CRM,HR"`
	ScopeSources    []ScopeGrantResponse `json:"scope_sources"`
	Scopes          []string             `json:"scopes" example:"apps:read,users:read,users:edit"`
} //@name Me

// MeCompanyResponse names the caller's company.
type MeCompanyResponse struct {
	ID   string `json:"id" example:"5c6d7e8f-9a0b-1c2d-3e4f-5a6b7c8d9e0f"`
	Name string `json:"name" example:"Acme Corp"`
} //@name MeCompany

// NewMeResponse renders the caller's account.
func NewMeResponse(m Me) MeResponse {
	return MeResponse{
		AuthenticatedAt: m.AuthenticatedAt, Company: MeCompanyResponse{ID: m.CompanyID, Name: m.CompanyName},
		Email: m.Email, ID: m.UserID, IsAdmin: m.IsAdmin, IsOwner: m.IsOwner, Manages: groupRefs(m.Manages),
		Products: nonNilStrings(m.Products), ScopeSources: scopeGrants(m.ScopeSources), Scopes: nonNilStrings(m.Scopes),
	}
}

// ManagedGroupRef is a group someone runs as its manager.
type ManagedGroupRef struct {
	ID   string `json:"id" example:"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`
	Name string `json:"name" example:"Field sales"`
} //@name ManagedGroupRef

// groupRefs renders group references; never null.
func groupRefs(gs []GroupRef) []ManagedGroupRef {
	out := make([]ManagedGroupRef, 0, len(gs))
	for _, g := range gs {
		out = append(out, ManagedGroupRef{ID: g.ID, Name: g.Name})
	}
	return out
}

// AppResponse is one product the caller may launch.
type AppResponse struct {
	Description *string  `json:"description"`
	Key         string   `json:"key" example:"CRM"`
	LaunchURL   *string  `json:"launch_url" example:"https://crm.acme.com/login/initiate?iss=https%3A%2F%2Fcentral.alora.io&target_link_uri=https%3A%2F%2Fcrm.acme.com%2F"`
	Name        string   `json:"name" example:"Acme CRM"`
	ProductID   string   `json:"product_id" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	Roles       []string `json:"roles" example:"Editor"`
} //@name App

// NewAppListResponse renders the caller's apps; never null.
func NewAppListResponse(apps []App) []AppResponse {
	out := make([]AppResponse, 0, len(apps))
	for _, a := range apps {
		roles := a.Roles
		if roles == nil {
			roles = []string{}
		}
		out = append(out, AppResponse{
			Description: a.Description, Key: a.Key, LaunchURL: a.LaunchURL, Name: a.Name,
			ProductID: a.ProductID, Roles: roles,
		})
	}
	return out
}

// UserScopesResponse echoes a scope set that was written.
type UserScopesResponse struct {
	Scopes []string `json:"scopes" example:"users:read,sessions:read"`
} //@name UserScopesResponse

// NewUserScopesResponse renders a written scope set; never null.
func NewUserScopesResponse(scopes []string) UserScopesResponse {
	return UserScopesResponse{Scopes: nonNilStrings(scopes)}
}
