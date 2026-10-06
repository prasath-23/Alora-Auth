package aloraauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// HTTPConfig is ClientCredentials over HTTP: the same API client, getting its
// tokens from App Central's token endpoint — for an application calling a
// product's REST API.
type HTTPConfig struct {
	// Issuer is App Central's issuer, e.g. "https://central.example.com"; the
	// token endpoint is its /oauth/token.
	Issuer string
	// ClientID and ClientSecret are the API client's credentials. They travel
	// in the Authorization header (client_secret_basic), never in the body.
	ClientID     string
	ClientSecret string
	// Product is the key of the product the tokens are for.
	Product string
	// Scopes asks for some of the scopes the API client holds; none asks for all.
	Scopes []string
}

// TokenSource asks App Central for tokens — client credentials, with the
// product named by resource=product:<key> — and keeps each until it expires.
func (c HTTPConfig) TokenSource(ctx context.Context) oauth2.TokenSource {
	cc := clientcredentials.Config{
		ClientID:       c.ClientID,
		ClientSecret:   c.ClientSecret,
		TokenURL:       strings.TrimRight(c.Issuer, "/") + "/oauth/token",
		Scopes:         c.Scopes,
		EndpointParams: url.Values{"resource": {"product:" + c.Product}},
		AuthStyle:      oauth2.AuthStyleInHeader,
	}
	return cc.TokenSource(ctx)
}

// Client returns an *http.Client that puts a current token on every request.
func (c HTTPConfig) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}
