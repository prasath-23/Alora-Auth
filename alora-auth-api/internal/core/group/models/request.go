package models

// Request models. Tags enforce presence and shape before any database work, and
// the binder rejects unknown fields.
//
// The binding:"optional" on the lists is read only by swag, which does not
// understand `dive` and would otherwise document the list itself as required;
// the binder validates with the validate tag alone.

// CreateGroupRequest is a new group and everything it grants. Each scope must be
// in the catalogue (an edit scope brings its read scope). Product grants are the
// Owner's alone: each product must be one the company subscribes to, and each
// role in that product's catalogue.
type CreateGroupRequest struct {
	Name          string                `json:"name" validate:"required,notblank,min=1,max=100" example:"Support"`
	Description   string                `json:"description" validate:"omitempty,max=500" example:"Helpdesk staff"`
	Scopes        []string              `json:"scopes" binding:"optional" validate:"omitempty,max=50,dive,required,max=64" example:"users:read,sessions:read"`
	ProductGrants []ProductGrantRequest `json:"product_grants" binding:"optional" validate:"omitempty,dive"`
} //@name CreateGroupRequest

// ProductGrantRequest is one product role a group confers.
type ProductGrantRequest struct {
	ProductID string `json:"product_id" validate:"required,uuid" example:"3f7c1b2e-5d4a-4c8b-9e10-2a6b7c8d9e0f"`
	RoleName  string `json:"role_name" validate:"required,max=64" example:"Viewer"`
} //@name GroupProductGrantRequest

// Input is the request as the service takes it.
func (r CreateGroupRequest) Input() GroupInput {
	return GroupInput{Name: r.Name, Description: r.Description, Scopes: r.Scopes, ProductGrants: grants(r.ProductGrants)}
}

func grants(rs []ProductGrantRequest) []ProductGrant {
	out := make([]ProductGrant, 0, len(rs))
	for _, g := range rs {
		out = append(out, ProductGrant{ProductID: g.ProductID, RoleName: g.RoleName})
	}
	return out
}

// UpdateGroupRequest renames and re-describes a group. The Admins group keeps
// its name.
type UpdateGroupRequest struct {
	Name        string `json:"name" validate:"required,notblank,min=1,max=100" example:"Support"`
	Description string `json:"description" validate:"omitempty,max=500" example:"Helpdesk staff"`
} //@name UpdateGroupRequest

// SetGroupScopesRequest is the COMPLETE set of App Central scopes a group
// gives: any scope omitted is taken away. Edit scopes bring their read scopes.
type SetGroupScopesRequest struct {
	Scopes []string `json:"scopes" binding:"optional" validate:"omitempty,max=50,dive,required,max=64" example:"users:read,sessions:read"`
} //@name SetGroupScopesRequest

// SetProductGrantsRequest is the complete set of product roles a group confers.
type SetProductGrantsRequest struct {
	ProductGrants []ProductGrantRequest `json:"product_grants" binding:"optional" validate:"omitempty,dive"`
} //@name SetGroupProductGrantsRequest

// Grants is the request as the service takes it.
func (r SetProductGrantsRequest) Grants() []ProductGrant { return grants(r.ProductGrants) }

// AddMemberRequest identifies the user to add by EITHER id or email.
type AddMemberRequest struct {
	UserID string `json:"user_id" validate:"omitempty,uuid" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
	Email  string `json:"email" validate:"omitempty,email,max=320" example:"member@acme.com"`
} //@name AddMemberRequest

// Input is the request as the service takes it.
func (r AddMemberRequest) Input() MemberInput {
	return MemberInput{UserID: r.UserID, Email: r.Email}
}

// AppointManagerRequest names the person to make a group's manager by EITHER id
// or email.
type AppointManagerRequest struct {
	UserID string `json:"user_id" validate:"omitempty,uuid" example:"4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d"`
	Email  string `json:"email" validate:"omitempty,email,max=320" example:"lead@acme.com"`
} //@name AppointGroupManagerRequest

// Input is the request as the service takes it.
func (r AppointManagerRequest) Input() MemberInput {
	return MemberInput{UserID: r.UserID, Email: r.Email}
}
