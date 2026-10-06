package models

// JWKSResponse is the public verification key set (RFC 7517). It exists for the
// API documentation only: the JWKS body is the JWK library's own encoding and is
// served as those bytes, never through this struct.
type JWKSResponse struct {
	Keys []map[string]interface{} `json:"keys"`
} //@name JWKS

// DiscoveryResponse is the OpenID Provider metadata document (OpenID Connect
// Discovery 1.0 §3, with RFC 9207's iss parameter).
type DiscoveryResponse struct {
	Issuer                            string   `json:"issuer" example:"https://central.alora.io"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint" example:"https://central.alora.io/oauth/authorize"`
	TokenEndpoint                     string   `json:"token_endpoint" example:"https://central.alora.io/oauth/token"`
	JWKSURI                           string   `json:"jwks_uri" example:"https://central.alora.io/.well-known/jwks.json"`
	RevocationEndpoint                string   `json:"revocation_endpoint" example:"https://central.alora.io/oauth/revoke"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint" example:"https://central.alora.io/oauth/introspect"`
	ResponseTypesSupported            []string `json:"response_types_supported" example:"code"`
	ResponseModesSupported            []string `json:"response_modes_supported" example:"query"`
	GrantTypesSupported               []string `json:"grant_types_supported" example:"authorization_code,refresh_token"`
	SubjectTypesSupported             []string `json:"subject_types_supported" example:"public"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported" example:"RS256"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported" example:"client_secret_basic"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported" example:"S256"`
	ScopesSupported                   []string `json:"scopes_supported" example:"openid,email,profile"`
	ClaimsSupported                   []string `json:"claims_supported" example:"sub,email"`
	AuthorizationResponseISSSupported bool     `json:"authorization_response_iss_parameter_supported" example:"true"`
} //@name OpenIDConfiguration

// NewDiscoveryResponse renders the metadata. The field order is the order the
// specification lists them in, which is what readers of the document expect.
func NewDiscoveryResponse(d Discovery) DiscoveryResponse {
	return DiscoveryResponse{
		Issuer: d.Issuer, AuthorizationEndpoint: d.AuthorizationEndpoint, TokenEndpoint: d.TokenEndpoint,
		JWKSURI: d.JWKSURI, RevocationEndpoint: d.RevocationEndpoint, IntrospectionEndpoint: d.IntrospectionEndpoint,
		ResponseTypesSupported: d.ResponseTypes, ResponseModesSupported: d.ResponseModes,
		GrantTypesSupported: d.GrantTypes, SubjectTypesSupported: d.SubjectTypes,
		IDTokenSigningAlgValuesSupported: d.IDTokenAlgs, TokenEndpointAuthMethodsSupported: d.TokenAuthMethods,
		CodeChallengeMethodsSupported: d.CodeChallengeMethods, ScopesSupported: d.Scopes, ClaimsSupported: d.Claims,
		AuthorizationResponseISSSupported: true,
	}
}
