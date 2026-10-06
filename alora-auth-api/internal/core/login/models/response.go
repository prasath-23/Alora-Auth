package models

// Response models. Fields are declared in alphabetical order of their JSON names.

// Sign-in statuses.
const (
	StatusAuthenticated = "authenticated"
	StatusChooseCompany = "choose_company"
)

// LoginResponse is the result of a sign-in step. When status is authenticated
// it carries App Central's access token (its refresh token is only ever in the
// HttpOnly session cookie); when choose_company, the companies to pick from.
type LoginResponse struct {
	AccessToken string                  `json:"access_token,omitempty" example:"eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiYXQrand0In0..."`
	Companies   []CompanyChoiceResponse `json:"companies,omitempty"`
	ExpiresIn   int                     `json:"expires_in,omitempty" example:"900"`
	ReturnTo    string                  `json:"return_to,omitempty" example:"/oauth/authorize?client_id=..."`
	Status      string                  `json:"status" example:"authenticated" enums:"authenticated,choose_company"`
	TokenType   string                  `json:"token_type,omitempty" example:"Bearer"`
} //@name LoginResponse

// CompanyChoiceResponse is one company an account choice offers.
type CompanyChoiceResponse struct {
	ClientID string `json:"client_id" example:"5c6d7e8f-9a0b-1c2d-3e4f-5a6b7c8d9e0f"`
	Name     string `json:"name" example:"Acme Corp"`
} //@name CompanyChoice

// NewLoginResponse renders a sign-in outcome.
func NewLoginResponse(o Outcome) LoginResponse {
	if o.Session != nil {
		return LoginResponse{
			AccessToken: o.Session.AccessToken, ExpiresIn: o.Session.ExpiresIn, ReturnTo: o.ReturnTo,
			Status: StatusAuthenticated, TokenType: "Bearer",
		}
	}
	return LoginResponse{Companies: companies(o.Companies), ReturnTo: o.ReturnTo, Status: StatusChooseCompany}
}

// ChoicesResponse lists the companies a pending account choice offers.
type ChoicesResponse struct {
	Companies []CompanyChoiceResponse `json:"companies"`
} //@name CompanyChoices

// NewChoicesResponse renders the companies; never null.
func NewChoicesResponse(cs []Company) ChoicesResponse {
	return ChoicesResponse{Companies: companies(cs)}
}

func companies(cs []Company) []CompanyChoiceResponse {
	out := make([]CompanyChoiceResponse, 0, len(cs))
	for _, c := range cs {
		out = append(out, CompanyChoiceResponse{ClientID: c.ClientID, Name: c.Name})
	}
	return out
}

// CentralTokenResponse is App Central's access token after a refresh. The refresh token
// is NOT in the body: it is rotated in the HttpOnly session cookie.
type CentralTokenResponse struct {
	AccessToken string `json:"access_token" example:"eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiYXQrand0In0..."`
	ExpiresIn   int    `json:"expires_in" example:"900"`
	TokenType   string `json:"token_type" example:"Bearer"`
} //@name CentralTokenResponse

// NewCentralTokenResponse renders a refresh.
func NewCentralTokenResponse(s Signed) CentralTokenResponse {
	return CentralTokenResponse{AccessToken: s.AccessToken, ExpiresIn: s.ExpiresIn, TokenType: "Bearer"}
}

// DiscoverResponse is which sign-in methods to offer for an address's domain. It
// is the same for every address at the domain, so it reveals nothing about any
// account.
type DiscoverResponse struct {
	Google   bool         `json:"google" example:"true"`
	Password bool         `json:"password" example:"true"`
	SSO      *SSOResponse `json:"sso"`
} //@name LoginDiscoverResponse

// SSOResponse names the company SSO connection to start at.
type SSOResponse struct {
	ConnectionID string `json:"connection_id" example:"9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"`
} //@name LoginDiscoverSSO

// NewDiscoverResponse renders a discovery.
func NewDiscoverResponse(d Discovery) DiscoverResponse {
	r := DiscoverResponse{Google: d.Google, Password: d.Password}
	if d.SSOConnectionID != nil {
		r.SSO = &SSOResponse{ConnectionID: *d.SSOConnectionID}
	}
	return r
}
