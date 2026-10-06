package models

// ConnectionRequest is a connection's complete desired state. client_secret is
// write-only: it is sealed on arrival and never returned; leave it out on an
// update to keep the stored one.
type ConnectionRequest struct {
	Name                 string  `json:"name" validate:"required,notblank,min=1,max=100" example:"Acme Okta"`
	Issuer               string  `json:"issuer" validate:"required,url,max=512" example:"https://acme.okta.com"`
	ClientID             string  `json:"client_id" validate:"required,max=256" example:"0oa1b2c3d4e5f6g7h8i9"`
	ClientSecret         *string `json:"client_secret" validate:"omitempty,min=1,max=1024" example:"s3cret-from-the-idp"`
	Scopes               string  `json:"scopes" validate:"omitempty,max=256" example:"openid email profile"`
	TrustUnverifiedEmail bool    `json:"trust_unverified_email" example:"false"`
	IsActive             *bool   `json:"is_active" validate:"required" example:"true"`
} //@name SSOConnectionRequest

// Input is the request as the service takes it.
func (r ConnectionRequest) Input() ConnectionInput {
	return ConnectionInput{
		Name: r.Name, Issuer: r.Issuer, OIDCClientID: r.ClientID, ClientSecret: r.ClientSecret,
		Scopes: r.Scopes, TrustUnverifiedEmail: r.TrustUnverifiedEmail, IsActive: *r.IsActive,
	}
}

// DomainsRequest is the complete set of email domains a connection signs in. A
// domain name is at most 253 characters (RFC 1035); the fqdn rule alone does not
// say so.
type DomainsRequest struct {
	Domains []string `json:"domains" binding:"optional" validate:"omitempty,max=50,dive,fqdn,max=253" example:"acme.com"`
} //@name SSOConnectionDomainsRequest
