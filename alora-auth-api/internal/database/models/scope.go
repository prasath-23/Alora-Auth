package models

// Scope kinds: a PERSON scope is what someone may do in App Central; a CLIENT
// scope is where an API client's credential may be used.
const (
	ScopeKindPerson = "PERSON"
	ScopeKindClient = "CLIENT"
)

// Where a person's scope comes from.
const (
	ScopeSourceGroup = "GROUP" // a group they belong to (the ADMINS group gives every person scope)
	ScopeSourceExtra = "EXTRA" // given to them alone
)

// Scope is a row of tbl_scopes: one entry of the closed catalogue.
type Scope struct {
	Scope       string
	Kind        string
	Feature     string
	Level       string
	Description string
	SortOrder   int32
}

// EffectiveScope is a row of vw_EffectiveScope: one scope a person holds, and
// where it comes from. GroupID and GroupName are nil for an extra.
type EffectiveScope struct {
	UserID    string
	ClientID  string
	Scope     string
	Source    string
	GroupID   *string
	GroupName *string
}
