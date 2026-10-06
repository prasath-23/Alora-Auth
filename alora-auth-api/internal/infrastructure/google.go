package infrastructure

import (
	"context"
	"net/url"
)

// GoogleIssuer is Google's OpenID Connect issuer.
const GoogleIssuer = "https://accounts.google.com"

// Google is Google sign-in: a preset of the generic OIDC client with Google's
// issuer and App Central's registration there. It is configured in code, not as
// a database row, because it is the same for every company.
type Google struct {
	oidc    *OIDC
	issuer  string
	client  OIDCClient
	enabled bool
}

// NewGoogle builds the preset. With an empty client id Google sign-in is off.
func NewGoogle(oidc *OIDC, clientID, clientSecret, redirectURI string) *Google {
	return &Google{
		oidc:    oidc,
		issuer:  GoogleIssuer,
		client:  OIDCClient{ClientID: clientID, ClientSecret: clientSecret, RedirectURI: redirectURI, Scopes: "openid email profile"},
		enabled: clientID != "",
	}
}

// Enabled reports whether Google sign-in is configured.
func (g *Google) Enabled() bool { return g.enabled }

// SetIssuer points the preset at another provider (tests only: a local stub that
// serves discovery, keys and a token endpoint as Google would).
func (g *Google) SetIssuer(issuer string) { g.issuer = issuer }

// AuthCodeURL is Google's consent screen for one sign-in. It always asks the
// user to choose an account, rather than silently reusing whichever Google
// account the browser is signed in to.
func (g *Google) AuthCodeURL(ctx context.Context, state, nonce, challenge string) (string, error) {
	return g.oidc.AuthCodeURL(ctx, g.issuer, g.client, state, nonce, challenge, url.Values{"prompt": {"select_account"}})
}

// Exchange trades Google's code for the verified claims of its ID token.
func (g *Google) Exchange(ctx context.Context, code, verifier, nonce string) (IDClaims, error) {
	return g.oidc.Exchange(ctx, g.issuer, g.client, code, verifier, nonce)
}
