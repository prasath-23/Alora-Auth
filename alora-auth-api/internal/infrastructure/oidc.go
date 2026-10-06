package infrastructure

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// OIDC is App Central acting as the CLIENT of an OpenID Connect provider:
// Google, or a company's own IdP (Okta, Entra ID, Google Workspace, ...).
//
// Everything a provider says is checked, because for a company connection the
// provider is configured by a customer and is not trusted:
//
//   - Discovery: the document's issuer must equal the configured issuer exactly
//     (OpenID Connect Discovery §4.3), so a document cannot claim to speak for
//     another issuer.
//   - ID tokens: RS256 only, the key found by kid in the provider's own JWKS
//     (re-fetched, at most once a minute, when a kid is unknown), then iss, aud,
//     azp, exp and the nonce.
//   - In production, outbound requests use https only, never reach a private,
//     loopback or link-local address (checked on the address actually dialled,
//     so DNS rebinding cannot slip past), and read at most 1 MB within 10 s.
type OIDC struct {
	http       *http.Client
	restricted bool

	mu        sync.Mutex
	providers map[string]*provider // by issuer
}

// OIDCOptions configures the client. Restricted is set in production.
type OIDCOptions struct {
	Restricted bool
	Timeout    time.Duration
}

const (
	maxProviderBody     = 1 << 20 // 1 MB
	discoveryTTL        = time.Hour
	jwksRefetchInterval = time.Minute
	idTokenSkew         = time.Minute
)

// ErrOIDC wraps every provider-side failure, so a caller can tell "the provider
// or its token was bad" from a local fault.
var ErrOIDC = errors.New("oidc")

func oidcErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrOIDC}, a...)...)
}

// NewOIDC builds the client.
func NewOIDC(opts OIDCOptions) *OIDC {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	if opts.Restricted {
		dialer.Control = refusePrivateAddress
	}
	transport := &http.Transport{
		Proxy:               nil, // a proxy would dial on our behalf, around the address check
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: timeout,
		MaxIdleConns:        16,
		IdleConnTimeout:     90 * time.Second,
	}
	return &OIDC{
		http: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// A provider's endpoints are named in its discovery document; a
			// redirect is a place nobody named, so it is not followed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		restricted: opts.Restricted,
		providers:  map[string]*provider{},
	}
}

// refusePrivateAddress is the dialer's last word on where a connection goes: it
// sees the resolved IP, after DNS, so a name that resolves somewhere internal is
// refused however it was spelled.
func refusePrivateAddress(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("oidc: refusing to dial unparsed address %q", host)
	}
	if IsPrivateAddress(ip) {
		return fmt.Errorf("oidc: refusing to dial private address %s", ip)
	}
	return nil
}

// IsPrivateAddress reports whether ip is anywhere a request from App Central
// must never be steered by a customer-configured URL: loopback, private,
// link-local (cloud metadata lives there), unspecified, multicast, or the
// shared and benchmark ranges.
func IsPrivateAddress(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, cidr := range []string{"100.64.0.0/10", "198.18.0.0/15", "0.0.0.0/8", "192.0.0.0/24", "240.0.0.0/4", "64:ff9b::/96"} {
		if _, n, _ := net.ParseCIDR(cidr); n.Contains(ip) {
			return true
		}
	}
	return false
}

// Provider is a discovered OpenID provider.
type Provider struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

type provider struct {
	meta       Provider
	discovered time.Time

	keysMu      sync.Mutex
	keys        jwk.Set
	keysFetched time.Time
}

// OIDCClient is App Central's registration at one provider.
type OIDCClient struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       string // space-separated; "openid" is always included
}

// Discover reads the provider's discovery document, cached for an hour.
func (o *OIDC) Discover(ctx context.Context, issuer string) (Provider, error) {
	p, err := o.provider(ctx, issuer)
	if err != nil {
		return Provider{}, err
	}
	return p.meta, nil
}

func (o *OIDC) provider(ctx context.Context, issuer string) (*provider, error) {
	o.mu.Lock()
	p, ok := o.providers[issuer]
	o.mu.Unlock()
	if ok && time.Since(p.discovered) < discoveryTTL {
		return p, nil
	}
	if err := o.checkURL(issuer); err != nil {
		return nil, err
	}
	var meta Provider
	if err := o.getJSON(ctx, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", &meta); err != nil {
		return nil, err
	}
	if meta.Issuer != issuer {
		return nil, oidcErr("discovery document names issuer %q, not %q", meta.Issuer, issuer)
	}
	for name, u := range map[string]string{
		"authorization_endpoint": meta.AuthorizationEndpoint, "token_endpoint": meta.TokenEndpoint, "jwks_uri": meta.JWKSURI,
	} {
		if err := o.checkURL(u); err != nil {
			return nil, oidcErr("discovery %s: %v", name, err)
		}
	}
	p = &provider{meta: meta, discovered: time.Now()}
	o.mu.Lock()
	o.providers[issuer] = p
	o.mu.Unlock()
	return p, nil
}

// checkURL refuses anything but an absolute https URL in restricted mode, and
// anything but http(s) otherwise.
func (o *OIDC) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return oidcErr("%q is not an absolute URL", raw)
	}
	if u.Scheme == "https" || (!o.restricted && u.Scheme == "http") {
		return nil
	}
	return oidcErr("%q must use https", raw)
}

func (o *OIDC) getJSON(ctx context.Context, u string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	return o.do(req, dst)
}

func (o *OIDC) do(req *http.Request, dst any) error {
	resp, err := o.http.Do(req)
	if err != nil {
		return oidcErr("%s %s: %v", req.Method, req.URL.Host, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBody+1))
	if err != nil {
		return oidcErr("read %s: %v", req.URL.Host, err)
	}
	if len(body) > maxProviderBody {
		return oidcErr("%s answered more than %d bytes", req.URL.Host, maxProviderBody)
	}
	if resp.StatusCode != http.StatusOK {
		return oidcErr("%s %s answered %s", req.Method, req.URL.Host, resp.Status)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return oidcErr("decode %s: %v", req.URL.Host, err)
	}
	return nil
}

// AuthCodeURL is where to send the browser to sign in at the provider, with
// PKCE (S256), a state bound to this browser and a nonce bound to the ID token.
// extra adds provider-specific parameters (Google's prompt, a login_hint).
func (o *OIDC) AuthCodeURL(ctx context.Context, issuer string, c OIDCClient, state, nonce, challenge string, extra url.Values) (string, error) {
	p, err := o.provider(ctx, issuer)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(p.meta.AuthorizationEndpoint)
	if err != nil {
		return "", oidcErr("authorization_endpoint: %v", err)
	}
	q := u.Query()
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", c.RedirectURI)
	q.Set("scope", scopes(c.Scopes))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func scopes(s string) string {
	fields := strings.Fields(s)
	for _, f := range fields {
		if f == "openid" {
			return strings.Join(fields, " ")
		}
	}
	return strings.Join(append([]string{"openid"}, fields...), " ")
}

// IDClaims are the parts of a verified ID token a sign-in uses.
type IDClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// Exchange trades an authorization code (with its PKCE verifier) for tokens and
// returns the verified claims of the ID token, which is required.
func (o *OIDC) Exchange(ctx context.Context, issuer string, c OIDCClient, code, verifier, nonce string) (IDClaims, error) {
	p, err := o.provider(ctx, issuer)
	if err != nil {
		return IDClaims{}, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.RedirectURI},
		"code_verifier": {verifier},
	}
	basic := supportsBasic(p.meta.TokenAuthMethods)
	if !basic {
		form.Set("client_id", c.ClientID)
		form.Set("client_secret", c.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return IDClaims{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		// RFC 6749 §2.3.1: each half is form-encoded before joining.
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := o.do(req, &tok); err != nil {
		return IDClaims{}, err
	}
	if tok.IDToken == "" {
		return IDClaims{}, oidcErr("the token response carries no id_token")
	}
	return o.VerifyIDToken(ctx, issuer, c.ClientID, tok.IDToken, nonce)
}

// supportsBasic applies the discovery default: a provider that lists no methods
// supports client_secret_basic (OpenID Connect Discovery §3).
func supportsBasic(methods []string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if m == "client_secret_basic" {
			return true
		}
	}
	return false
}

// VerifyIDToken verifies an ID token from issuer for clientID with the expected
// nonce, and returns its claims.
func (o *OIDC) VerifyIDToken(ctx context.Context, issuer, clientID, raw, nonce string) (IDClaims, error) {
	p, err := o.provider(ctx, issuer)
	if err != nil {
		return IDClaims{}, err
	}
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeyProvider(jws.KeyProviderFunc(func(ctx context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
			// RS256 is pinned: "none", HS256 (which would verify against a public
			// key used as a MAC secret) and every other algorithm are refused.
			if sig.ProtectedHeaders().Algorithm() != jwa.RS256 {
				return oidcErr("ID token algorithm %q is not RS256", sig.ProtectedHeaders().Algorithm())
			}
			key, err := o.key(ctx, p, sig.ProtectedHeaders().KeyID())
			if err != nil {
				return err
			}
			sink.Key(jwa.RS256, key)
			return nil
		})),
		jwt.WithValidate(true),
		jwt.WithAudience(clientID),
		jwt.WithAcceptableSkew(idTokenSkew),
	)
	if err != nil {
		return IDClaims{}, oidcErr("ID token: %v", err)
	}
	if !issuerMatches(tok.Issuer(), issuer) {
		return IDClaims{}, oidcErr("ID token issuer %q is not %q", tok.Issuer(), issuer)
	}
	// OpenID Connect Core §3.1.3.7: with several audiences an azp must name us,
	// and an azp that is present must be us.
	azp, _ := tok.Get("azp")
	azpStr, _ := azp.(string)
	if (len(tok.Audience()) > 1 && azpStr == "") || (azp != nil && azpStr != clientID) {
		return IDClaims{}, oidcErr("ID token azp %v is not this client", azp)
	}
	if tok.Expiration().Unix() <= 0 || tok.IssuedAt().Unix() <= 0 || tok.Subject() == "" {
		return IDClaims{}, oidcErr("ID token lacks exp, iat or sub")
	}
	got, _ := tok.Get("nonce")
	if s, _ := got.(string); nonce == "" || s != nonce {
		return IDClaims{}, oidcErr("ID token nonce does not match this sign-in")
	}
	claims := IDClaims{Subject: tok.Subject()}
	if v, ok := tok.Get("email"); ok {
		claims.Email, _ = v.(string)
	}
	// email_verified is a boolean at Google but a string at some providers.
	switch v, _ := tok.Get("email_verified"); t := v.(type) {
	case bool:
		claims.EmailVerified = t
	case string:
		claims.EmailVerified = t == "true"
	}
	return claims, nil
}

// issuerMatches compares an ID token's iss with the configured issuer. Google
// alone issues tokens under a second spelling of its issuer, which its own
// documentation says to accept.
func issuerMatches(got, want string) bool {
	if got == want {
		return true
	}
	return want == GoogleIssuer && got == "accounts.google.com"
}

// key finds the provider's signing key by kid, re-fetching the JWKS when the kid
// is unknown — a provider rotates by publishing a new key before using it — but
// at most once a minute, so a stream of tokens with made-up kids cannot turn
// App Central into a request amplifier against the provider.
func (o *OIDC) key(ctx context.Context, p *provider, kid string) (*rsa.PublicKey, error) {
	p.keysMu.Lock()
	defer p.keysMu.Unlock()
	if p.keys == nil || (lookup(p.keys, kid) == nil && time.Since(p.keysFetched) > jwksRefetchInterval) {
		var raw json.RawMessage
		if err := o.getJSON(ctx, p.meta.JWKSURI, &raw); err != nil {
			return nil, err
		}
		set, err := jwk.Parse(raw)
		if err != nil {
			return nil, oidcErr("jwks: %v", err)
		}
		p.keys, p.keysFetched = set, time.Now()
	}
	k := lookup(p.keys, kid)
	if k == nil {
		return nil, oidcErr("no signing key %q at the provider", kid)
	}
	var pub rsa.PublicKey
	if err := k.Raw(&pub); err != nil {
		return nil, oidcErr("signing key %q is not RSA", kid)
	}
	return &pub, nil
}

// lookup finds a key by kid. A token without a kid is accepted only when the set
// holds exactly one key, so there is nothing to choose between.
func lookup(set jwk.Set, kid string) jwk.Key {
	if kid == "" {
		if set.Len() == 1 {
			k, _ := set.Key(0)
			return k
		}
		return nil
	}
	k, ok := set.LookupKeyID(kid)
	if !ok {
		return nil
	}
	return k
}
