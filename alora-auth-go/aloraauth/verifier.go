package aloraauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Principals: who a token speaks for.
const (
	PrincipalUser   = "user"   // a person, signed in through the product
	PrincipalClient = "client" // an application, through an API client
)

// ErrInvalidToken is what every verification failure wraps: the token is not
// one this product may accept, and the caller is to be refused.
var ErrInvalidToken = errors.New("aloraauth: invalid token")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, a...))
}

// VerifierConfig says whose tokens to accept.
type VerifierConfig struct {
	// Issuer is App Central's issuer, exactly as its tokens and its discovery
	// document name it, e.g. "https://central.example.com".
	Issuer string
	// Product is this product's key: its tokens' audience is "product:<Product>".
	Product string
	// JWKSURL is where App Central publishes its signing keys. Empty: read from
	// the issuer's discovery document, whose issuer must then match.
	JWKSURL string
	// HTTPClient fetches the discovery document and the keys. nil: a client
	// with a ten-second timeout.
	HTTPClient *http.Client
	// Leeway tolerates clock skew on a token's expiry and issue time. 0: thirty
	// seconds.
	Leeway time.Duration
}

// Verifier checks App Central's access tokens for one product. It is safe for
// concurrent use, and meant to live as long as the product does.
type Verifier struct {
	cfg      VerifierConfig
	audience string
	client   *http.Client
	now      func() time.Time
	// refetch is how soon after a successful fetch an unknown key id may fetch
	// the keys again; retry, how soon after a failed one.
	refetch, retry time.Duration

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	jwksURL   string
	fetchedAt time.Time
	lastOK    bool
}

// NewVerifier builds a verifier. It fetches nothing until the first token.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Product == "" {
		return nil, errors.New("aloraauth: a verifier needs Issuer and Product")
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 30 * time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{
		cfg: cfg, audience: "product:" + cfg.Product, client: client, now: time.Now,
		refetch: time.Minute, retry: 5 * time.Second, keys: map[string]*rsa.PublicKey{}, jwksURL: cfg.JWKSURL,
	}, nil
}

// Verify checks a token — its signature, algorithm, type, issuer, audience and
// lifetime — and returns what it says. Any failure wraps ErrInvalidToken, save
// a failure to reach App Central for its keys.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, invalid("not a JWT")
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, invalid("malformed header")
	}
	// The algorithm is pinned, never taken from the token: "none" and HS256
	// (a public key used as an HMAC secret) are the classic forgeries.
	if header.Alg != "RS256" {
		return nil, invalid("algorithm %q is not RS256", header.Alg)
	}
	if typ := strings.TrimPrefix(strings.ToLower(header.Typ), "application/"); typ != "at+jwt" {
		return nil, invalid("not an access token (typ %q)", header.Typ)
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, invalid("malformed signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return nil, invalid("bad signature")
	}

	var raw rawClaims
	if err := decodeSegment(parts[1], &raw); err != nil {
		return nil, invalid("malformed claims")
	}
	now := v.now()
	switch {
	case raw.Iss != v.cfg.Issuer:
		return nil, invalid("issued by %q, not %q", raw.Iss, v.cfg.Issuer)
	case !slices.Contains(raw.Aud, v.audience):
		return nil, invalid("not for %s", v.audience)
	case raw.Exp == nil:
		return nil, invalid("no expiry")
	case !now.Before(raw.Exp.Add(v.cfg.Leeway)):
		return nil, invalid("expired")
	case raw.Iat != nil && raw.Iat.After(now.Add(v.cfg.Leeway)):
		return nil, invalid("issued in the future")
	case raw.Nbf != nil && raw.Nbf.After(now.Add(v.cfg.Leeway)):
		return nil, invalid("not valid yet")
	case raw.Sub == "":
		return nil, invalid("no subject")
	}
	c := &Claims{
		Subject: raw.Sub, ClientID: raw.ClientID, TenantID: raw.TenantID, Principal: raw.Principal,
		Scopes: strings.Fields(raw.Scope), Roles: raw.Roles, Email: raw.Email, Audience: raw.Aud,
		Issuer: raw.Iss, ExpiresAt: raw.Exp.Time, ID: raw.Jti,
	}
	if raw.Iat != nil {
		c.IssuedAt = raw.Iat.Time
	}
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	if c.Roles == nil {
		c.Roles = []string{}
	}
	return c, nil
}

// key returns the signing key a token names, fetching App Central's keys when
// it is not yet known — at most once a minute, so tokens naming made-up keys
// cannot turn the product into a hammer on App Central.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, invalid("no key id")
	}
	v.mu.RLock()
	k, ok := v.keys[kid]
	v.mu.RUnlock()
	if ok {
		return k, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok { // fetched while this call waited
		return k, nil
	}
	wait := v.refetch
	if !v.lastOK {
		wait = v.retry
	}
	if v.fetchedAt.IsZero() || v.now().Sub(v.fetchedAt) >= wait {
		v.fetchedAt = v.now()
		v.lastOK = false
		if err := v.fetch(ctx); err != nil {
			return nil, err
		}
		v.lastOK = true
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, invalid("unknown signing key %q", kid)
}

// fetch replaces the known keys with App Central's current set: a key no
// longer published is no longer accepted. Called with the write lock held.
func (v *Verifier) fetch(ctx context.Context) error {
	if v.jwksURL == "" {
		var doc struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := v.getJSON(ctx, strings.TrimRight(v.cfg.Issuer, "/")+"/.well-known/openid-configuration", &doc); err != nil {
			return err
		}
		// A discovery document for another issuer names somebody else's keys.
		if doc.Issuer != v.cfg.Issuer || doc.JWKSURI == "" {
			return fmt.Errorf("aloraauth: the discovery document names issuer %q, not %q", doc.Issuer, v.cfg.Issuer)
		}
		v.jwksURL = doc.JWKSURI
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := v.getJSON(ctx, v.jwksURL, &set); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(k.N)
		e, errE := base64.RawURLEncoding.DecodeString(k.E)
		if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	v.keys = keys
	return nil
}

// getJSON reads a small JSON document: App Central's metadata or keys.
func (v *Verifier) getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("aloraauth: %w", err)
	}
	res, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("aloraauth: fetching %s: %w", url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("aloraauth: fetching %s: %s", url, res.Status)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(dst); err != nil {
		return fmt.Errorf("aloraauth: reading %s: %w", url, err)
	}
	return nil
}

// Claims is what a verified token says.
type Claims struct {
	Subject   string   // the person, or the API client ("aci_…")
	ClientID  string   // the client the token was issued to: the product (a person's) or the API client
	TenantID  string   // the company
	Principal string   // PrincipalUser or PrincipalClient
	Scopes    []string // an application's: what it may do
	Roles     []string // a person's: their roles in this product
	Email     string   // a person's
	Audience  []string
	Issuer    string
	ExpiresAt time.Time
	IssuedAt  time.Time
	ID        string // jti
}

// HasScope reports whether the token carries scope.
func (c *Claims) HasScope(scope string) bool { return slices.Contains(c.Scopes, scope) }

// HasRole reports whether a person's token carries role.
func (c *Claims) HasRole(role string) bool { return slices.Contains(c.Roles, role) }

// IsApplication reports whether the token speaks for an application.
func (c *Claims) IsApplication() bool { return c.Principal == PrincipalClient }

type rawClaims struct {
	Iss       string       `json:"iss"`
	Sub       string       `json:"sub"`
	Aud       audience     `json:"aud"`
	Exp       *numericDate `json:"exp"`
	Iat       *numericDate `json:"iat"`
	Nbf       *numericDate `json:"nbf"`
	Jti       string       `json:"jti"`
	ClientID  string       `json:"client_id"`
	TenantID  string       `json:"tenant_id"`
	Principal string       `json:"principal"`
	Scope     string       `json:"scope"`
	Roles     []string     `json:"roles"`
	Email     string       `json:"email"`
}

// audience is a JWT aud: one string, or a list of them.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// numericDate is a JWT time: seconds since the epoch.
type numericDate struct{ time.Time }

func (d *numericDate) UnmarshalJSON(b []byte) error {
	var secs float64
	if err := json.Unmarshal(b, &secs); err != nil {
		return err
	}
	d.Time = time.Unix(int64(secs), 0)
	return nil
}

func decodeSegment(s string, dst any) error {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}
