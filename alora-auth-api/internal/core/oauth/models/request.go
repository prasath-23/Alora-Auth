package models

// AuthorizeRequest is the query string of an authorization request (OpenID
// Connect Core §3.1.2.1, with PKCE). Its parameters are documented one by one on
// the route.
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type"`
	ClientID            string `form:"client_id"`
	RedirectURI         string `form:"redirect_uri"`
	Scope               string `form:"scope"`
	State               string `form:"state"`
	Nonce               string `form:"nonce"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
	Prompt              string `form:"prompt"`
}
