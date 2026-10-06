// Package models holds the auth feature's DTOs and HTTP response models.
package models

import "time"

// ProductToken is what a product access token asserts: who, in which company,
// through which product login, with which of that product's roles.
type ProductToken struct {
	UserID      string
	ClientID    string // the user's company
	Email       string
	ProductID   string // the OAuth client the token is for
	ProductKey  string // the audience is "product:<key>"
	FamilyID    string // the product login it belongs to
	Roles       []string
	PermVersion int32
}

// ClientToken is what an application's product token asserts: which API
// client, of which company, with which scopes, under which of its secrets. It
// names no person and carries no roles.
type ClientToken struct {
	APIClientID string // sub and client_id: "aci_…"
	CompanyID   string
	ProductKey  string // the audience is "product:<key>"
	SecretID    string // sid: the secret it was issued under
	Scopes      []string
}

// Principals: who a product token speaks for.
const (
	PrincipalUser   = "user"   // a person, through a product login
	PrincipalClient = "client" // an application, through an API client
)

// IDToken is what an ID token asserts to the product that asked for it.
type IDToken struct {
	UserID          string
	ClientID        string
	Email           string
	ProductID       string // the audience
	Nonce           string
	AuthTime        time.Time
	CentralFamilyID string // sid: the App Central session the sign-in happened in
}

// Discovery is the OpenID Provider metadata.
type Discovery struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	RevocationEndpoint    string
	IntrospectionEndpoint string
	ResponseTypes         []string
	ResponseModes         []string
	GrantTypes            []string
	SubjectTypes          []string
	IDTokenAlgs           []string
	TokenAuthMethods      []string
	CodeChallengeMethods  []string
	Scopes                []string
	Claims                []string
}
